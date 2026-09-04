//! Integration-style regression tests for the TLS passthrough data plane (P04).
//!
//! These start real listener tasks, drive them with a real `tokio-rustls` client and
//! a stub TCP backend, and assert the behaviours the rebuild must guarantee:
//!
//! * a listener actually reaches `Running` (no axum-0.8 wildcard-route panic — the
//!   defect this rebuild replaces);
//! * a bind conflict surfaces a real `Error` state instead of a hardcoded `running`;
//! * an HTTPS request round-trips to the backend and its body returns;
//! * full-duplex/bidirectional bytes round-trip (the WebSocket-equivalence case);
//! * a cert change on disk is served on the next handshake with no restart and no
//!   watcher-thread panic.
//!
//! Tests use unique entry names so their per-entry cert dirs never collide, and
//! ephemeral ports grabbed from the OS.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use koi_common::integration::{TlsIdentityMaterial, TlsIdentitySnapshot, TlsIdentitySource};
use koi_common::status::StatusFeed;

use crate::config::ProxyEntry;
use crate::listener::{spawn_listener_with_tls, ListenerHandle, ListenerState, ListenerStatus};
use crate::tls::CertSource;

// ── Helpers ─────────────────────────────────────────────────────────

fn test_overrides_dir() -> std::path::PathBuf {
    koi_common::test::ensure_data_dir("koi-proxy-data-plane-tests").join("proxy-certs")
}

fn spawn_test_listener(entry: ProxyEntry) -> ListenerHandle {
    spawn_listener_with_tls(entry, test_overrides_dir(), None)
}

/// Grab an ephemeral port the OS is willing to hand out, then release it.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    listener.local_addr().expect("local_addr").port()
}

fn entry(name: &str, listen_port: u16, backend: String) -> ProxyEntry {
    ProxyEntry {
        name: name.to_string(),
        listen_port,
        backend,
        allow_remote: false,
    }
}

/// Write a fresh self-signed cert+key to Proxy's `proxy-certs/<name>/` override;
/// return the cert DER so a handshake's served cert can be compared against it.
fn write_cert(name: &str, extra_san: &str) -> Vec<u8> {
    let dir = test_overrides_dir().join(name);
    std::fs::create_dir_all(&dir).expect("create cert dir");
    let sans = vec![
        "localhost".to_string(),
        name.to_string(),
        extra_san.to_string(),
    ];
    let generated = rcgen::generate_simple_self_signed(sans).expect("generate cert");
    // key first, fullchain last, to narrow the rotation race window.
    std::fs::write(dir.join("key.pem"), generated.key_pair.serialize_pem()).expect("write key");
    std::fs::write(dir.join("fullchain.pem"), generated.cert.pem()).expect("write cert");
    generated.cert.der().as_ref().to_vec()
}

#[derive(Clone)]
struct TestTlsIdentitySource {
    feed: StatusFeed<TlsIdentitySnapshot>,
}

impl TestTlsIdentitySource {
    fn new(initial: TlsIdentitySnapshot) -> Self {
        Self {
            feed: StatusFeed::new(initial),
        }
    }

    fn publish(&self, snapshot: TlsIdentitySnapshot) {
        self.feed.publish(snapshot);
    }
}

impl TlsIdentitySource for TestTlsIdentitySource {
    fn tls_identity(&self) -> Arc<TlsIdentitySnapshot> {
        self.feed.current()
    }

    fn watch_tls_identity(&self) -> watch::Receiver<Arc<TlsIdentitySnapshot>> {
        self.feed.subscribe()
    }
}

fn generated_identity(hostname: &str) -> (TlsIdentityMaterial, Vec<u8>) {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), hostname.to_string()])
            .expect("generate identity");
    let der = generated.cert.der().as_ref().to_vec();
    (
        TlsIdentityMaterial {
            hostname: hostname.to_string(),
            certificate_chain_pem: Arc::from(generated.cert.pem()),
            private_key_pem: Arc::from(generated.key_pair.serialize_pem()),
            trust_anchor_pem: Arc::from(generated.cert.pem()),
        },
        der,
    )
}

/// Wait for the listener to report a given state. Returns false if the sender is dropped
/// first (e.g. the listener task panicked). The budget is generous (30s) because every
/// data-plane test runs a `multi_thread` runtime, so the full `cargo test --workspace`
/// parallel run heavily oversubscribes cores — a tight timeout flaked on listener
/// bring-up under that load, not on a real failure. This is a correctness wait, not a
/// latency assertion: a real "never starts" still fails (just later).
async fn wait_for_state(rx: &mut watch::Receiver<ListenerStatus>, target: ListenerState) -> bool {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if rx.borrow_and_update().state == target {
                return true;
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn wait_for_cert_source(
    rx: &mut watch::Receiver<ListenerStatus>,
    target: CertSource,
) -> bool {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if rx.borrow_and_update().cert_source == target {
                return true;
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// A rustls client config that accepts any server certificate (tests assert on the
/// served cert directly; the CA chain is not under test).
fn insecure_client_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Arc::new(config)
}

async fn tls_connect(port: u16) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = tokio_rustls::TlsConnector::from(insecure_client_config());
    let server_name =
        rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("server name");
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    connector.connect(server_name, tcp).await
}

/// Open a TLS connection and return the served end-entity cert DER.
async fn served_cert_der(port: u16) -> Option<Vec<u8>> {
    let tls = tls_connect(port).await.ok()?;
    let (_, conn) = tls.get_ref();
    conn.peer_certificates()
        .and_then(|chain| chain.first())
        .map(|cert| cert.as_ref().to_vec())
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
        ]
    }
}

/// A stub backend that writes a fixed HTTP response then closes.
async fn spawn_http_backend(body: &'static str) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut scratch = [0u8; 1024];
                let _ = sock.read(&mut scratch).await; // best-effort: drain request
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(response.as_bytes()).await;
                // drop -> close, giving the client a clean read-to-EOF
            });
        }
    });
    port
}

/// A stub backend that greets the client immediately (server-initiated bytes),
/// then echoes whatever it receives. Proves full-duplex passthrough.
async fn spawn_greeting_echo_backend(greeting: &'static str) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                if sock.write_all(greeting.as_bytes()).await.is_err() {
                    return;
                }
                let mut buf = [0u8; 64];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

// ── Tests ───────────────────────────────────────────────────────────

/// Regression for verification-2026-06 claim 1: the old data plane registered an
/// axum `/*path` route that panics under axum 0.8 inside a spawned task. The
/// passthrough listener must reach `Running` with no panic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listener_reaches_running_without_panic() {
    let port = free_port();
    let listener = spawn_test_listener(entry("p04-running", port, "127.0.0.1:9".to_string()));
    let mut rx = listener.watch_status();

    assert!(
        wait_for_state(&mut rx, ListenerState::Running).await,
        "listener never reached Running (panic or bind failure?)"
    );

    listener.shutdown().await;
}

/// A second entry on an already-bound port must surface a real `Error` state with
/// detail — not a hardcoded `running: true`, and without taking down the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bind_conflict_reports_error_state() {
    let port = free_port();

    let listener_a = spawn_test_listener(entry("p04-conflict-a", port, "127.0.0.1:9".to_string()));
    let mut rx_a = listener_a.watch_status();
    assert!(
        wait_for_state(&mut rx_a, ListenerState::Running).await,
        "first listener should bind"
    );

    let listener_b = spawn_test_listener(entry("p04-conflict-b", port, "127.0.0.1:9".to_string()));
    let mut rx_b = listener_b.watch_status();
    assert!(
        wait_for_state(&mut rx_b, ListenerState::Error).await,
        "second listener should report Error on the conflicting port"
    );

    let status = rx_b.borrow().clone();
    assert_eq!(status.state, ListenerState::Error);
    assert!(
        status.error.is_some(),
        "error state must carry a message, got {status:?}"
    );

    // The first listener is unaffected.
    assert_eq!(rx_a.borrow().state, ListenerState::Running);

    listener_a.shutdown().await;
    listener_b.shutdown().await;
}

/// HTTPS request through the proxy reaches the backend and its body returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_request_round_trips_to_backend() {
    let backend_port = spawn_http_backend("hello-koi").await;
    let listen_port = free_port();
    let listener = spawn_test_listener(entry(
        "p04-roundtrip",
        listen_port,
        format!("127.0.0.1:{backend_port}"),
    ));
    let mut rx = listener.watch_status();
    assert!(wait_for_state(&mut rx, ListenerState::Running).await);

    let mut tls = tls_connect(listen_port).await.expect("tls connect");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.expect("read response");
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("hello-koi"),
        "backend body not returned through proxy: {text:?}"
    );

    listener.shutdown().await;
}

/// Server-initiated bytes (greeting) reach the client, then client bytes are echoed
/// back — full-duplex passthrough, the property a WebSocket needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bidirectional_full_duplex_round_trips() {
    let backend_port = spawn_greeting_echo_backend("HELLO").await;
    let listen_port = free_port();
    let listener = spawn_test_listener(entry(
        "p04-duplex",
        listen_port,
        format!("127.0.0.1:{backend_port}"),
    ));
    let mut rx = listener.watch_status();
    assert!(wait_for_state(&mut rx, ListenerState::Running).await);

    let mut tls = tls_connect(listen_port).await.expect("tls connect");

    // backend -> client (server spoke first)
    let mut greeting = [0u8; 5];
    tls.read_exact(&mut greeting).await.expect("read greeting");
    assert_eq!(&greeting, b"HELLO");

    // client -> backend -> client (echo)
    tls.write_all(b"PING").await.expect("write ping");
    let mut echoed = [0u8; 4];
    tls.read_exact(&mut echoed).await.expect("read echo");
    assert_eq!(&echoed, b"PING");

    listener.shutdown().await;
}

/// Listener teardown releases admission and its socket, but a connection that
/// was already accepted drains naturally instead of being severed by a config
/// replacement or operator removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_connection_drains_after_listener_shutdown() {
    let backend_port = spawn_greeting_echo_backend("READY").await;
    let listen_port = free_port();
    let listener = spawn_test_listener(entry(
        "p04-drain",
        listen_port,
        format!("127.0.0.1:{backend_port}"),
    ));
    let mut status = listener.watch_status();
    assert!(wait_for_state(&mut status, ListenerState::Running).await);

    let mut tls = tls_connect(listen_port).await.expect("tls connect");
    let mut greeting = [0u8; 5];
    tls.read_exact(&mut greeting).await.expect("read greeting");
    assert_eq!(&greeting, b"READY");

    let mut connections = listener.shutdown().await;
    tls.write_all(b"PING").await.expect("write after shutdown");
    let mut echoed = [0u8; 4];
    tls.read_exact(&mut echoed)
        .await
        .expect("accepted connection keeps draining");
    assert_eq!(&echoed, b"PING");
    drop(tls);
    connections
        .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(1))
        .await;
}

/// Cancelling the caller cannot detach terminal Proxy shutdown. The retained
/// domain owner completes connection drain without a cleanup retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_runtime_shutdown_converges_without_retry() {
    let backend_port = spawn_greeting_echo_backend("READY").await;
    let listen_port = free_port();
    let root = std::env::temp_dir().join(format!(
        "koi-proxy-cancelled-shutdown-{}",
        koi_common::id::generate_short_id()
    ));
    std::fs::create_dir_all(&root).expect("runtime data dir");
    let core = Arc::new(
        crate::ProxyCore::open(root.join("config.toml"), root.join("proxy-certs"))
            .expect("proxy core"),
    );
    let runtime = crate::ProxyRuntime::new(core);
    let desired = entry(
        "cancelled-shutdown",
        listen_port,
        format!("127.0.0.1:{backend_port}"),
    );
    runtime.upsert(desired).await.expect("arm listener");
    let mut status = runtime.watch_status();
    tokio::time::timeout(Duration::from_secs(5), async {
        while status.borrow_and_update().proxies[0].state != "running" {
            status.changed().await.expect("Proxy status remains open");
        }
    })
    .await
    .expect("listener running");

    let mut tls = tls_connect(listen_port).await.expect("tls connect");
    let mut greeting = [0_u8; 5];
    tls.read_exact(&mut greeting).await.expect("read greeting");
    assert_eq!(&greeting, b"READY");

    let retry = runtime.clone();
    let shutdown = tokio::spawn(async move { retry.shutdown().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if runtime.status().proxies[0].state == "stopped" {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal status published");
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.abort();
    let _ = shutdown.await;

    drop(tls);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let lifecycle = runtime.inner.lifecycle.lock().await;
            if lifecycle.active.is_empty()
                && lifecycle.retiring.is_empty()
                && lifecycle.draining.is_empty()
            {
                break;
            }
            drop(lifecycle);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retained shutdown completes without a retry");

    // A later observer joins the already-complete terminal fence.
    runtime
        .shutdown()
        .await
        .expect("later observer sees completed Proxy shutdown");
}

/// A cert file change on disk is served on the next handshake without a restart,
/// and the notify→tokio bridge does not panic (the old watcher's second defect).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cert_change_on_disk_is_served_without_restart() {
    let name = "p04-hotreload";
    let der_a = write_cert(name, "a.example.test");
    let listen_port = free_port();
    let listener = spawn_test_listener(entry(name, listen_port, "127.0.0.1:9".to_string()));
    let mut rx = listener.watch_status();
    assert!(wait_for_state(&mut rx, ListenerState::Running).await);

    // First handshake serves cert A.
    let first = served_cert_der(listen_port).await.expect("served cert A");
    assert_eq!(first, der_a, "initial cert should be the on-disk cert A");

    // Rotate the cert on disk.
    let der_b = write_cert(name, "b.example.test");
    assert_ne!(der_a, der_b, "rotated cert must differ");

    // Poll handshakes (tolerating the brief write race) until cert B is served.
    let mut served_b = false;
    for _ in 0..50 {
        if served_cert_der(listen_port).await.as_deref() == Some(der_b.as_slice()) {
            served_b = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        served_b,
        "rotated cert B was not hot-reloaded onto the listener"
    );

    listener.shutdown().await;
}

/// The Certmesh adapter is a real latest-value input: rotation replaces the
/// served key without a listener restart, and withdrawal immediately falls
/// back instead of retaining revoked material.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn composed_identity_rotates_and_withdraws_without_stale_tls() {
    let name = format!("tls-port-{}", koi_common::id::generate_short_id());
    let overrides = std::env::temp_dir().join(format!(
        "koi-proxy-overrides-{}",
        koi_common::id::generate_short_id()
    ));
    let (material_a, der_a) = generated_identity(&name);
    let source = Arc::new(TestTlsIdentitySource::new(TlsIdentitySnapshot {
        revision: 1,
        material: Some(material_a),
    }));
    let identity: Arc<dyn TlsIdentitySource> = source.clone();
    let listen_port = free_port();
    let listener = spawn_listener_with_tls(
        entry(&name, listen_port, "127.0.0.1:9".to_string()),
        overrides.clone(),
        Some(identity),
    );
    let mut status = listener.watch_status();
    assert!(wait_for_state(&mut status, ListenerState::Running).await);
    assert_eq!(status.borrow().cert_source, CertSource::Certmesh);
    let initial_revision = status.borrow().cert_revision;
    assert_eq!(
        served_cert_der(listen_port).await.as_deref(),
        Some(der_a.as_slice())
    );

    let (material_b, der_b) = generated_identity(&name);
    source.publish(TlsIdentitySnapshot {
        revision: 2,
        material: Some(material_b),
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while status.borrow_and_update().cert_revision == initial_revision {
            status
                .changed()
                .await
                .expect("certificate selection status remains live");
        }
    })
    .await
    .expect("same-source certificate rotation must advance status");
    assert_eq!(status.borrow().cert_source, CertSource::Certmesh);
    let mut rotated = false;
    for _ in 0..50 {
        if served_cert_der(listen_port).await.as_deref() == Some(der_b.as_slice()) {
            rotated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(rotated, "rotated composed identity was not served");

    source.publish(TlsIdentitySnapshot {
        revision: 3,
        material: None,
    });
    assert!(
        wait_for_cert_source(&mut status, CertSource::SelfSigned).await,
        "withdrawn trust identity must change the listener status"
    );
    let fallback = served_cert_der(listen_port)
        .await
        .expect("self-signed fallback certificate");
    assert_ne!(fallback, der_b, "withdrawn identity remained live");

    listener.shutdown().await;
    let _ = std::fs::remove_dir_all(overrides);
}
