//! The posture-adaptive same-port listener supervisor (ADR-020 §5).
//!
//! [`serve_adaptive`] binds one TCP socket and **never rebinds it**. Each accepted
//! connection's first byte is peeked and dispatched against the node's posture *at
//! accept time*: a TLS ClientHello is served mTLS when this node is secure;
//! plaintext is served when Open. Because the socket is never closed, a posture
//! flip (plain↔mTLS) only changes how *new* connections are handled — an in-flight
//! connection is never dropped. This is Istio PERMISSIVE done safely (ADR-020 §13).
//!
//! Refusals are loud, not silent: a plaintext dial to a secure node is refused
//! (secure-by-default), and a TLS dial to an Open node is refused (no identity to
//! terminate TLS with). The supervisor reacts to `watch_posture()` so the moment a
//! CA appears (or is destroyed) the protocol for new connections changes with no
//! restart — which also makes the consumer's single `serve` call mode-transparent.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use koi_certmesh::serve::{
    serve_mtls, serve_plain, AdaptiveServerConfig, TLS_HANDSHAKE_FIRST_BYTE,
};
use koi_certmesh::CertmeshCore;
use koi_common::posture::Posture;

/// How long to wait for a connection's first byte before giving up. Bounds a
/// stalled/slow-loris dial so a single connection cannot pin a task forever.
const PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// Run a posture-adaptive listener on `addr` until `cancel` fires (ADR-020 §5).
///
/// Binds once; serves plaintext when this node is Open and mTLS when it is secure,
/// flipping per *new* connection on a posture change without dropping in-flight
/// ones. Returns `Err` only if the initial bind fails; per-connection and
/// posture-rebuild errors are logged, not propagated.
pub async fn serve_adaptive(
    core: Arc<CertmeshCore>,
    router: Router,
    addr: SocketAddr,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let mut posture_rx = core.watch_posture();
    let mut posture = *posture_rx.borrow_and_update();
    let mut tls_config = build_tls_config(&core, posture).await;
    tracing::info!(%addr, ?posture, "same-port dial: listening");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            changed = posture_rx.changed() => {
                if changed.is_err() {
                    return Ok(()); // the certmesh core was dropped
                }
                posture = *posture_rx.borrow_and_update();
                tls_config = build_tls_config(&core, posture).await;
                tracing::info!(
                    ?posture,
                    "same-port dial: posture changed — new connections use the updated protocol"
                );
            }
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "same-port dial: accept error");
                        continue;
                    }
                };
                let router = router.clone();
                let cancel_conn = cancel.clone();
                let secure = posture.signed;
                let cfg = tls_config.clone();
                tokio::spawn(async move {
                    dispatch_connection(tcp, peer, secure, cfg, router, cancel_conn).await;
                });
            }
        }
    }
}

/// Build the mTLS server config for the current posture: `Some` (from this node's
/// live leaf) when secure, `None` when Open. Logged loudly if a secure node cannot
/// build one (secure connections will then be refused, never silently downgraded).
async fn build_tls_config(core: &CertmeshCore, posture: Posture) -> Option<AdaptiveServerConfig> {
    if !posture.signed {
        return None;
    }
    let id = core.local_identity().await?;
    match AdaptiveServerConfig::from_identity(&id.cert_pem, &id.key_pem, &id.ca_cert_pem) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::error!(
                error = %e,
                "same-port dial: secure posture but could not build mTLS config — \
                 secure connections will be refused"
            );
            None
        }
    }
}

/// Peek one byte to classify the connection, then dispatch by `(secure, is_tls)`.
async fn dispatch_connection(
    tcp: TcpStream,
    peer: SocketAddr,
    secure: bool,
    cfg: Option<AdaptiveServerConfig>,
    router: Router,
    cancel: CancellationToken,
) {
    let mut first = [0u8; 1];
    let n = match tokio::time::timeout(PEEK_TIMEOUT, tcp.peek(&mut first)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!(%peer, error = %e, "same-port dial: peek failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "same-port dial: peek timed out");
            return;
        }
    };
    if n == 0 {
        return; // the client closed before sending anything
    }
    let is_tls = first[0] == TLS_HANDSHAKE_FIRST_BYTE;

    match (secure, is_tls) {
        (true, true) => match cfg {
            Some(cfg) => serve_mtls(tcp, cfg, router, cancel).await,
            None => tracing::warn!(
                %peer,
                "same-port dial: secure posture but no mTLS config available — dropping TLS connection"
            ),
        },
        (true, false) => {
            // Secure node, plaintext client → refuse (secure-by-default). Dropping
            // `tcp` closes it; the refusal is logged, never a silent downgrade.
            tracing::warn!(
                %peer,
                "same-port dial: refused a plaintext connection to a secure node (mTLS required)"
            );
        }
        (false, false) => serve_plain(tcp, router, cancel).await,
        (false, true) => {
            tracing::warn!(
                %peer,
                "same-port dial: refused a TLS connection to an Open node (no identity to terminate TLS)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Extension;
    use axum::routing::{get, post};
    use koi_certmesh::http::ClientCn;
    use koi_certmesh::{ca, roster::Roster, CertmeshCore, CertmeshPaths};

    /// An isolated, wiped data dir per test (NOT the process-wide `ensure_data_dir`,
    /// which would clobber sibling tests' CA state).
    fn isolated_paths(tag: &str) -> CertmeshPaths {
        let dir = std::env::temp_dir().join(format!("koi-emb-serve-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        CertmeshPaths::with_data_dir(dir)
    }

    fn open_core(tag: &str) -> Arc<CertmeshCore> {
        Arc::new(CertmeshCore::uninitialized_with_paths(isolated_paths(tag)))
    }

    /// A secure (Authenticated) core: a CA + a self-enrolled leaf on disk.
    async fn secure_core(tag: &str) -> Arc<CertmeshCore> {
        std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
        let paths = isolated_paths(tag);
        let ca = ca::create_ca("test-pass", &[3u8; 32], &paths).unwrap().0;
        let roster = Roster::new(false, false, None);
        let core = CertmeshCore::new_with_paths(ca, roster, None, paths);
        core.self_enroll().await.expect("self-enroll");
        assert!(core.posture().signed, "core should be secure");
        Arc::new(core)
    }

    fn plain_router() -> Router {
        Router::new().route("/ping", get(|| async { "pong" }))
    }

    fn cn_router() -> Router {
        Router::new().route(
            "/echo",
            post(|Extension(ClientCn(cn)): Extension<ClientCn>| async move { cn }),
        )
    }

    /// Both a plain GET route and an mTLS-CN POST route, so one running listener can
    /// be probed before and after a posture flip.
    fn combined_router() -> Router {
        Router::new()
            .route("/ping", get(|| async { "pong" }))
            .route(
                "/echo",
                post(|Extension(ClientCn(cn)): Extension<ClientCn>| async move { cn }),
            )
    }

    async fn bind_addr() -> SocketAddr {
        // Bind ephemeral, read the port, drop the listener so serve_adaptive can
        // rebind it. A brief reuse race is acceptable in a test.
        let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        l.local_addr().unwrap()
    }

    #[tokio::test]
    async fn open_node_serves_plaintext() {
        let core = open_core("open-plain");
        let addr = bind_addr().await;
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_adaptive(core, plain_router(), addr, cancel.clone()));
        // Let the listener bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (status, body) = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping")
            .await
            .expect("plain GET to Open node");
        assert_eq!(status, 200);
        assert_eq!(body, "pong");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn secure_node_serves_mtls() {
        let core = secure_core("secure-mtls").await;
        let id = core.local_identity().await.expect("identity");
        let addr = bind_addr().await;
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_adaptive(
            Arc::clone(&core),
            cn_router(),
            addr,
            cancel.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Dial mTLS with our own CA-signed leaf as the client identity.
        let (status, body) = koi_certmesh::mtls::post_json(
            &addr.ip().to_string(),
            addr.port(),
            "/echo",
            "{}",
            &id.cert_pem,
            &id.key_pem,
            &id.ca_cert_pem,
        )
        .await
        .expect("mTLS POST to secure node");
        assert_eq!(status, 200);
        assert_eq!(body, id.hostname, "the server authenticated our leaf CN");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn secure_node_refuses_plaintext() {
        let core = secure_core("secure-refuse-plain").await;
        let addr = bind_addr().await;
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_adaptive(core, plain_router(), addr, cancel.clone()));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A plaintext GET to a secure node must not succeed.
        let result = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping").await;
        assert!(
            result.is_err() || result.as_ref().unwrap().0 != 200,
            "secure node must refuse plaintext; got {result:?}"
        );

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn open_node_refuses_tls() {
        let core = open_core("open-refuse-tls");
        // Build a throwaway client identity from a standalone CA to attempt a TLS dial.
        let client = secure_core("open-refuse-tls-client").await;
        let id = client.local_identity().await.unwrap();
        let addr = bind_addr().await;
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_adaptive(core, cn_router(), addr, cancel.clone()));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A TLS dial to an Open node (no server cert) must fail at the handshake.
        let result = koi_certmesh::mtls::post_json(
            &addr.ip().to_string(),
            addr.port(),
            "/echo",
            "{}",
            &id.cert_pem,
            &id.key_pem,
            &id.ca_cert_pem,
        )
        .await;
        assert!(result.is_err(), "Open node must refuse TLS; got {result:?}");

        cancel.cancel();
        let _ = server.await;
    }

    #[tokio::test]
    async fn live_flip_open_to_secure_without_restart() {
        std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
        let paths = isolated_paths("flip");
        let core = Arc::new(CertmeshCore::uninitialized_with_paths(paths));
        let addr = bind_addr().await;
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_adaptive(
            Arc::clone(&core),
            combined_router(),
            addr,
            cancel.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // While Open: plaintext works.
        let (status, body) = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping")
            .await
            .expect("plain works while Open");
        assert_eq!(status, 200);
        assert_eq!(body, "pong");

        // Flip to secure on the LIVE core (create → self-enroll → posture watch).
        let req = koi_certmesh::protocol::CreateCaRequest {
            passphrase: "pond-pass-strong".to_string(),
            entropy_hex: koi_common::encoding::hex_encode(&[8u8; 32]),
            operator: None,
            enrollment_open: false,
            requires_approval: false,
            auto_unlock: false,
            totp_secret_hex: None,
        };
        core.create(req).await.expect("create CA");
        // Let the supervisor observe the posture change and rebuild its config.
        tokio::time::sleep(Duration::from_millis(250)).await;

        // SAME port, no restart: plaintext is now refused…
        let plain = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping").await;
        assert!(
            plain.is_err() || plain.as_ref().unwrap().0 != 200,
            "plaintext must be refused after the flip; got {plain:?}"
        );

        // …and mTLS now works on that same port.
        let id = core.local_identity().await.expect("identity after create");
        let (status, body) = koi_certmesh::mtls::post_json(
            &addr.ip().to_string(),
            addr.port(),
            "/echo",
            "{}",
            &id.cert_pem,
            &id.key_pem,
            &id.ca_cert_pem,
        )
        .await
        .expect("mTLS works after the flip");
        assert_eq!(status, 200);
        assert_eq!(body, id.hostname);

        cancel.cancel();
        let _ = server.await;
    }
}
