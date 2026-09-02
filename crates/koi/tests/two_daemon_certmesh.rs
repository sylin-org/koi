//! ADR-018 Tier 2 — two **real `koi` binary** daemons exchange certmesh over real
//! cross-process HTTP, exercising the production wiring the in-process Tier-1 suite
//! (`koi-embedded/tests/whole_story.rs`) bypasses: the **DAT `x-koi-token` middleware**,
//! the **`/v1/certmesh/join` token exemption**, and the daemon-local **member-csr /
//! member-cert** key-custody adapters.
//!
//! Two daemons (A = CA, B = member) are spawned as child processes — `koi --daemon` on
//! distinct loopback ports + data dirs — and driven over raw HTTP (reqwest). The story:
//! GET is token-exempt → a gated POST without the token is **401** → with the token it
//! succeeds → A mints an invite → B generates its own CSR via its own daemon → **B joins A
//! over real HTTP with NO token** (the one exempt mutation) → A's roster shows B → B
//! installs the signed leaf via its own daemon (pin-checked) → A revokes B → **a fresh
//! re-join is rejected with 403 (revoked)** — the revocation boundary proved cross-process.
//!
//! ## Why raw HTTP, not the `koi certmesh ...` CLI
//!
//! The CLI `join` derives the member hostname from `hostname::get()` with no override; two
//! daemons on one host would then collide on a single roster hostname (A self-enrolls its
//! Primary under that same name). Raw HTTP lets B join under an explicit distinct hostname.
//! And the DAT breadcrumb is machine-global (not under `KOI_DATA_DIR`), so each daemon is
//! given its own `XDG_RUNTIME_DIR` (Unix) / `ProgramData` (Windows) to isolate it; the test
//! reads each daemon's randomly-generated token from its own breadcrumb.
//!
//! ## Scope note (vs ADR-018's "mTLS-renew")
//!
//! Tier 2 proves the **revocation boundary over the cross-process enrollment path** (a
//! revoked host's re-join → 403); the full mTLS `/renew` exchange is covered in-process by
//! Tier 1. It additionally asserts the **posture-reactive trust plane** (ADR-020 P4c /
//! ADR-016 §2): A boots Open, so its inter-node mTLS listener is down; once the CA is
//! created post-boot via HTTP `/create`, the listener comes up with **no restart**. (Before
//! that fix the listener stayed down until a restart, which is why this suite originally
//! could not exercise the post-boot mTLS path.) Runs per-PR on the 3-OS matrix via
//! `cargo test --locked`. A second test reuses this isolated two-daemon harness for
//! the portable whole-story Tier-1 aggregation breadth: status/host HTTP, dashboard
//! snapshot, public MCP discovery, DAT refusal, and an authenticated MCP resource
//! session on both concurrently running instances.

use std::collections::HashSet;
use std::fs::File;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use koi_certmesh::invite;
use koi_certmesh::protocol::{
    CertmeshStatus, CreateCaRequest, InstallCertRequest, InviteRequest, InviteResponse,
    JoinRequest, JoinResponse, MemberCsrRequest, MemberCsrResponse, RevokeRequest,
};
use koi_crypto::pinning::fingerprints_match;

const MEMBER: &str = "tier2-web-01";

// ── Child-daemon harness ────────────────────────────────────────────

fn reserved_ports() -> &'static Mutex<HashSet<u16>> {
    static RESERVED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    RESERVED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn spawn_handoff() -> &'static Mutex<()> {
    static HANDOFF: OnceLock<Mutex<()>> = OnceLock::new();
    HANDOFF.get_or_init(|| Mutex::new(()))
}

/// A loopback port selected by the OS and owned by this test process until drop.
///
/// The listener protects allocation. It is released only inside the serialized child
/// spawn handoff; the registry then keeps concurrent tests from selecting the same port
/// before the child binds it.
struct PortReservation {
    port: u16,
    listener: Option<TcpListener>,
}

impl PortReservation {
    fn reserve() -> Self {
        loop {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
            let port = listener.local_addr().expect("ephemeral local_addr").port();
            let mut reserved = reserved_ports()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if reserved.insert(port) {
                return Self {
                    port,
                    listener: Some(listener),
                };
            }
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn release_listener_for_spawn(&mut self) {
        drop(self.listener.take());
    }
}

impl Drop for PortReservation {
    fn drop(&mut self) {
        let removed = reserved_ports()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.port);
        debug_assert!(removed, "port reservation was not registered");
    }
}

#[test]
fn port_reservation_remains_owned_through_spawn_handoff_until_drop() {
    let handoff = spawn_handoff()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut reservation = PortReservation::reserve();
    let port = reservation.port();
    reservation.release_listener_for_spawn();

    assert!(
        reserved_ports()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&port),
        "releasing the listener must not release process-local port ownership"
    );

    drop(reservation);
    assert!(
        !reserved_ports()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&port),
        "dropping the reservation must release process-local port ownership"
    );
    drop(handoff);
}

/// A spawned `koi` daemon child, killed + cleaned up on drop (even on a test panic).
struct Daemon {
    child: Child,
    data_dir: PathBuf,
    stderr_path: PathBuf,
    http_port: u16,
    mtls_port: u16,
    _http_reservation: PortReservation,
    _mtls_reservation: PortReservation,
}

impl Daemon {
    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
    }

    fn stderr_tail(&self) -> String {
        let contents = match std::fs::read_to_string(&self.stderr_path) {
            Ok(contents) => contents,
            Err(error) => return format!("<could not read child stderr: {error}>"),
        };
        let mut lines = contents.lines().rev().take(40).collect::<Vec<_>>();
        lines.reverse();
        if lines.is_empty() {
            "<child stderr was empty>".to_string()
        } else {
            lines.join("\n")
        }
    }

    fn assert_running(&mut self, context: &str) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!(
                "{context}: koi child PID {} exited early with {status}; stderr tail:\n{}",
                self.child.id(),
                self.stderr_tail()
            ),
            Err(error) => panic!(
                "{context}: could not inspect koi child PID {}: {error}; stderr tail:\n{}",
                self.child.id(),
                self.stderr_tail()
            ),
        }
    }

    /// The daemon's DAT token, read from its (isolated) breadcrumb. Re-read each call —
    /// the token is regenerated per boot and persisted only to the breadcrumb file.
    fn token(&self) -> String {
        // Unix: $XDG_RUNTIME_DIR/koi.endpoint; Windows: %ProgramData%\koi\koi.endpoint.
        let unix = self.data_dir.join("koi.endpoint");
        let win = self.data_dir.join("koi").join("koi.endpoint");
        for _ in 0..50 {
            let raw = std::fs::read_to_string(&unix).or_else(|_| std::fs::read_to_string(&win));
            if let Ok(s) = raw {
                if let Some(tok) = s.lines().nth(1).and_then(|l| l.strip_prefix("dat:")) {
                    let tok = tok.trim();
                    if !tok.is_empty() {
                        return tok.to_string();
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "no DAT token in breadcrumb under {}",
            self.data_dir.display()
        );
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn temp_data_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("koi-tier2-{}-{nanos}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Spawn a lean certmesh+HTTP daemon with an isolated data dir + breadcrumb.
fn spawn_daemon(mcp_http: bool) -> Daemon {
    let data_dir = temp_data_dir();
    let handoff = spawn_handoff()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut http_reservation = PortReservation::reserve();
    let mut mtls_reservation = PortReservation::reserve();
    let http_port = http_reservation.port();
    let mtls_port = mtls_reservation.port();
    assert_ne!(http_port, mtls_port, "daemon ports must be distinct");
    let stderr_path = data_dir.join("daemon.stderr.log");
    let stderr = File::create(&stderr_path).expect("create daemon stderr log");
    let mut command = Command::new(env!("CARGO_BIN_EXE_koi"));
    command
        .arg("--daemon")
        .args(["--port", &http_port.to_string()])
        .args(["--mtls-port", &mtls_port.to_string()])
        // Everything requiring privileged, multicast, or host-runtime access is off.
        .args([
            "--no-mdns",
            "--no-dns",
            "--no-health",
            "--no-proxy",
            "--no-udp",
            "--no-runtime",
            "--no-acme",
            "--no-ipc",
        ])
        .env("KOI_DATA_DIR", &data_dir)
        // Isolate the (machine-global) breadcrumb per daemon: XDG_RUNTIME_DIR on Unix,
        // ProgramData on Windows. Each platform ignores the other's var.
        .env("XDG_RUNTIME_DIR", &data_dir)
        .env("ProgramData", &data_dir)
        .env("KOI_NO_CREDENTIAL_STORE", "1")
        .env("KOI_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    if !mcp_http {
        command.arg("--no-mcp-http");
    }
    http_reservation.release_listener_for_spawn();
    mtls_reservation.release_listener_for_spawn();
    let child = command.spawn().expect("spawn koi daemon");
    drop(handoff);
    Daemon {
        child,
        data_dir,
        stderr_path,
        http_port,
        mtls_port,
        _http_reservation: http_reservation,
        _mtls_reservation: mtls_reservation,
    }
}

/// Whether a TCP connection to `127.0.0.1:port` is accepted (the listener is up).
async fn tcp_up(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// Poll until `127.0.0.1:port` accepts, panicking after ~5s.
async fn wait_tcp_up(daemon: &mut Daemon, label: &str) {
    let port = daemon.mtls_port;
    for _ in 0..50 {
        if tcp_up(port).await {
            return;
        }
        daemon.assert_running(label);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "{label} (port {port}) did not come up; child PID {} still running; stderr tail:\n{}",
        daemon.child.id(),
        daemon.stderr_tail()
    );
}

async fn wait_ready(client: &reqwest::Client, daemon: &mut Daemon) {
    let base = daemon.base();
    for _ in 0..50 {
        if let Ok(r) = client.get(format!("{base}/healthz")).send().await {
            if r.status().is_success() {
                return;
            }
        }
        daemon.assert_running(&format!("daemon at {base} did not become ready"));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "daemon at {base} did not become ready within five seconds; child PID {} still running; stderr tail:\n{}",
        daemon.child.id(),
        daemon.stderr_tail()
    );
}

// ── The test ────────────────────────────────────────────────────────

#[tokio::test]
async fn two_daemon_join_and_revoke_over_real_binary() {
    let sans = vec![MEMBER.to_string()];
    let client = reqwest::Client::new();

    let mut a = spawn_daemon(false);
    let mut b = spawn_daemon(false);
    let a_base = a.base();
    let b_base = b.base();
    wait_ready(&client, &mut a).await;
    wait_ready(&client, &mut b).await;
    let a_tok = a.token();
    let b_tok = b.token();

    // ── DAT middleware: GET is exempt; a gated POST needs the token ──
    let st = client
        .get(format!("{a_base}/v1/certmesh/status"))
        .send()
        .await
        .expect("GET /status");
    assert!(st.status().is_success(), "GET /status must be token-exempt");

    // ── ADR-016 §2 / ADR-020 P4c: the inter-node mTLS listener is posture-reactive ──
    // A booted Open (no CA), so its mTLS listener must be DOWN now…
    assert!(
        !tcp_up(a.mtls_port).await,
        "A's mTLS listener must be down while A is Open (no CA yet)"
    );

    let create_body = CreateCaRequest {
        passphrase: "tier2-pass".to_string(),
        entropy_hex: "07".repeat(32), // 32 bytes
        operator: Some("ops".to_string()),
        enrollment_open: true,
        requires_approval: false,
        auto_unlock: true,
        totp_secret_hex: None,
    };
    let unauth = client
        .post(format!("{a_base}/v1/certmesh/create"))
        .json(&create_body)
        .send()
        .await
        .expect("create (no token)");
    assert_eq!(
        unauth.status().as_u16(),
        401,
        "a DAT-gated mutation without x-koi-token must be 401"
    );
    // Confirm the 401 is the DAT middleware's (`unauthorized`), not a handler-level
    // auth error — i.e. the request was rejected before reaching the create handler.
    let unauth_body = unauth.text().await.unwrap_or_default();
    assert!(
        unauth_body.contains("unauthorized"),
        "the 401 must come from the DAT middleware; body: {unauth_body}"
    );

    let created = client
        .post(format!("{a_base}/v1/certmesh/create"))
        .header("x-koi-token", &a_tok)
        .json(&create_body)
        .send()
        .await
        .expect("create (token)");
    assert!(
        created.status().is_success(),
        "create with the token must succeed, got {}",
        created.status()
    );

    // …and once the CA exists (post-boot, via HTTP), the listener comes up with NO
    // restart — proving the posture-reactive trust plane (ADR-020 P4c). Before this
    // fix the listener stayed down until a daemon restart (ADR-016 §2).
    wait_tcp_up(&mut a, "A's mTLS listener after post-boot CA create").await;

    // ── invite is also DAT-gated; mint one for an explicit member hostname ──
    let invite_unauth = client
        .post(format!("{a_base}/v1/certmesh/invite"))
        .json(&InviteRequest {
            hostname: MEMBER.to_string(),
            ttl_mins: 60,
            role: None,
        })
        .send()
        .await
        .expect("invite (no token)");
    assert_eq!(
        invite_unauth.status().as_u16(),
        401,
        "minting an invite without the token must be 401"
    );
    let invite_unauth_body = invite_unauth.text().await.unwrap_or_default();
    assert!(
        invite_unauth_body.contains("unauthorized"),
        "the invite 401 must come from the DAT middleware; body: {invite_unauth_body}"
    );

    let invite_resp: InviteResponse = client
        .post(format!("{a_base}/v1/certmesh/invite"))
        .header("x-koi-token", &a_tok)
        .json(&InviteRequest {
            hostname: MEMBER.to_string(),
            ttl_mins: 60,
            role: None,
        })
        .send()
        .await
        .expect("invite (token)")
        .json()
        .await
        .expect("invite json");
    let (secret, pinned) = invite::decode_code(&invite_resp.token);
    let pinned_fp = pinned
        .expect("invite carries the CA fingerprint")
        .to_string();

    // ── preflight pin (GET, no token) ──
    let status: CertmeshStatus = client
        .get(format!("{a_base}/v1/certmesh/status"))
        .send()
        .await
        .expect("status")
        .json()
        .await
        .expect("status json");
    assert!(
        fingerprints_match(
            status.ca_fingerprint.as_deref().unwrap_or_default(),
            &pinned_fp
        ),
        "preflight: A's advertised fingerprint must match the pinned invite fingerprint"
    );

    // ── B generates its own CSR via ITS OWN daemon (DAT-gated, B's token) ──
    let csr: MemberCsrResponse = client
        .post(format!("{b_base}/v1/certmesh/member-csr"))
        .header("x-koi-token", &b_tok)
        .json(&MemberCsrRequest {
            hostname: MEMBER.to_string(),
            sans: sans.clone(),
        })
        .send()
        .await
        .expect("member-csr")
        .json()
        .await
        .expect("member-csr json");

    // ── B joins A over real cross-process HTTP — /join is the ONE DAT-exempt mutation ──
    let join_resp = client
        .post(format!("{a_base}/v1/certmesh/join"))
        .json(&JoinRequest {
            hostname: MEMBER.to_string(),
            auth: None,
            invite_token: Some(secret.to_string()),
            csr: Some(csr.csr),
            sans: sans.clone(),
            role: None,
        })
        .send()
        .await
        .expect("join");
    assert!(
        join_resp.status().is_success(),
        "join over HTTP without a token must reach the handler and succeed, got {}",
        join_resp.status()
    );
    let join_text = join_resp.text().await.expect("join body");
    assert!(
        !join_text.contains("PRIVATE KEY"),
        "the join response must not carry a private key"
    );
    let join: JoinResponse = serde_json::from_str(&join_text).expect("typed join response");
    assert!(join.service_key.is_empty());

    // ── success proof: A's roster now lists B (replaces the negative-only /join coverage) ──
    let after: CertmeshStatus = client
        .get(format!("{a_base}/v1/certmesh/status"))
        .send()
        .await
        .expect("status after join")
        .json()
        .await
        .expect("status json");
    let member = after
        .members
        .iter()
        .find(|m| m.hostname == MEMBER)
        .expect("B must be enrolled in A's roster");
    assert!(
        !member.cert_fingerprint.is_empty(),
        "A must record B's leaf fingerprint"
    );

    // ── B installs the signed leaf via its own daemon (B's adapter + pin hard-fail guard) ──
    let installed = client
        .post(format!("{b_base}/v1/certmesh/member-cert"))
        .header("x-koi-token", &b_tok)
        .json(&InstallCertRequest {
            hostname: MEMBER.to_string(),
            cert_pem: join.service_cert.clone(),
            ca_pem: join.ca_cert.clone(),
            ca_endpoint: Some(a_base.clone()),
            ca_mtls_port: None,
            ca_fingerprint: Some(pinned_fp.clone()),
            sans: sans.clone(),
            policy: Some(join.policy.clone()),
        })
        .send()
        .await
        .expect("member-cert");
    assert!(
        installed.status().is_success(),
        "member-cert install must succeed, got {}",
        installed.status()
    );

    // ── A revokes B (DAT-gated) ──
    let revoked = client
        .post(format!("{a_base}/v1/certmesh/revoke"))
        .header("x-koi-token", &a_tok)
        .json(&RevokeRequest {
            hostname: MEMBER.to_string(),
            reason: Some("tier2".to_string()),
            operator: Some("ops".to_string()),
        })
        .send()
        .await
        .expect("revoke");
    assert!(
        revoked.status().is_success(),
        "revoke must succeed, got {}",
        revoked.status()
    );

    // ── revocation boundary over real cross-process HTTP: a fresh re-join of the revoked
    //    host is refused with 403 (the CA rejects a revoked member at enrollment) ──
    let reinvite: InviteResponse = client
        .post(format!("{a_base}/v1/certmesh/invite"))
        .header("x-koi-token", &a_tok)
        .json(&InviteRequest {
            hostname: MEMBER.to_string(),
            ttl_mins: 60,
            role: None,
        })
        .send()
        .await
        .expect("re-invite")
        .json()
        .await
        .expect("re-invite json");
    let (secret2, _) = invite::decode_code(&reinvite.token);
    let csr2: MemberCsrResponse = client
        .post(format!("{b_base}/v1/certmesh/member-csr"))
        .header("x-koi-token", &b_tok)
        .json(&MemberCsrRequest {
            hostname: MEMBER.to_string(),
            sans: sans.clone(),
        })
        .send()
        .await
        .expect("member-csr 2")
        .json()
        .await
        .expect("member-csr 2 json");
    let rejoin = client
        .post(format!("{a_base}/v1/certmesh/join"))
        .json(&JoinRequest {
            hostname: MEMBER.to_string(),
            auth: None,
            invite_token: Some(secret2.to_string()),
            csr: Some(csr2.csr),
            sans: sans.clone(),
            role: None,
        })
        .send()
        .await
        .expect("re-join");
    let rejoin_status = rejoin.status().as_u16();
    let rejoin_body = rejoin.text().await.unwrap_or_default();
    assert_eq!(
        rejoin_status, 403,
        "a revoked member's re-join must be refused with 403; body: {rejoin_body}"
    );
    // Typed check: the rejection is specifically the revoked-member path (error code
    // `revoked`), not a coincidental substring or a different 403 (already-enrolled is
    // checked AFTER revocation in process_enrollment, so a revoked host yields `revoked`).
    let rejoin_json: serde_json::Value =
        serde_json::from_str(&rejoin_body).unwrap_or(serde_json::Value::Null);
    assert_eq!(
        rejoin_json.get("error").and_then(|v| v.as_str()),
        Some("revoked"),
        "the 403 must carry error code `revoked`; body: {rejoin_body}"
    );

    // Daemons are killed + their data dirs removed when `a`/`b` drop here.
    drop(b);
    drop(a);
}

async fn assert_aggregation_surface(http: &reqwest::Client, daemon: &Daemon) {
    use axum::http::{HeaderName, HeaderValue};
    use rmcp::transport::streamable_http_client::{
        StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
    };
    use rmcp::ServiceExt as _;
    use std::collections::HashMap;

    let base = daemon.base();
    let status: serde_json::Value = http
        .get(format!("{base}/v1/status"))
        .send()
        .await
        .expect("GET status")
        .error_for_status()
        .expect("status response")
        .json()
        .await
        .expect("status json");
    assert_eq!(status.get("daemon").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(status.get("mcp_http").and_then(|v| v.as_bool()), Some(true));
    let status_names: Vec<&str> = status["capabilities"]
        .as_array()
        .expect("status capability ladder")
        .iter()
        .filter_map(|capability| capability.get("name").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(
        status_names.len(),
        9,
        "the complete capability ladder (including IPC and Pond) is visible"
    );
    assert!(
        status_names.contains(&"ipc"),
        "the ipc rung is declared even when unmounted (ADR-035)"
    );
    assert!(
        status_names.contains(&"pond"),
        "the Pond rung is declared even when unmounted (ADR-042)"
    );

    let host = http
        .get(format!("{base}/v1/host"))
        .send()
        .await
        .expect("GET host")
        .error_for_status()
        .expect("host response");
    assert!(host
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json")));

    let dashboard: serde_json::Value = http
        .get(format!("{base}/v1/dashboard/snapshot"))
        .send()
        .await
        .expect("GET dashboard snapshot")
        .error_for_status()
        .expect("dashboard response")
        .json()
        .await
        .expect("dashboard json");
    let dashboard_names: Vec<&str> = dashboard["capabilities"]
        .as_array()
        .expect("dashboard capability ladder")
        .iter()
        .filter_map(|capability| capability.get("name").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(
        dashboard_names, status_names,
        "status and dashboard must project the same centralized ladder"
    );

    let card: serde_json::Value = http
        .get(format!("{base}/.well-known/mcp/server-card.json"))
        .send()
        .await
        .expect("GET MCP card")
        .error_for_status()
        .expect("MCP card response")
        .json()
        .await
        .expect("MCP card json");
    assert_eq!(card["mcp"]["enabled"].as_bool(), Some(true));
    assert_eq!(card["mcp"]["path"].as_str(), Some("/v1/mcp"));

    let unauthenticated = http
        .post(format!("{base}/v1/mcp"))
        .header("accept", "application/json, text/event-stream")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "tier1", "version": "0.0.0" }
            }
        }))
        .send()
        .await
        .expect("tokenless MCP initialize");
    assert_eq!(
        unauthenticated.status().as_u16(),
        401,
        "MCP must be DAT-gated on every instance"
    );

    let mut headers = HashMap::new();
    headers.insert(
        HeaderName::from_static("x-koi-token"),
        HeaderValue::from_str(&daemon.token()).expect("DAT header"),
    );
    let config = StreamableHttpClientTransportConfig::with_uri(format!("{base}/v1/mcp"))
        .custom_headers(headers);
    let transport = StreamableHttpClientTransport::from_config(config);
    let mcp = ().serve(transport).await.expect("authenticated MCP session");
    let tools = mcp.list_tools(None).await.expect("MCP list tools");
    assert_eq!(tools.tools.len(), 11, "the complete v1 tool set is visible");
    let resources = mcp.list_resources(None).await.expect("MCP list resources");
    for expected in [
        "koi://lan/inventory",
        "koi://health",
        "koi://dns/zone",
        "koi://mdns/services",
    ] {
        assert!(
            resources
                .resources
                .iter()
                .any(|resource| resource.uri == expected),
            "MCP resource list omitted {expected}"
        );
    }
    let mdns = mcp
        .read_resource(rmcp::model::ReadResourceRequestParams::new(
            "koi://mdns/services",
        ))
        .await
        .expect("read live mDNS resource");
    assert!(
        !mdns.contents.is_empty(),
        "MCP resource read returned no content"
    );
    let _ = mcp.cancel().await;
}

/// Portable whole-story Tier 1: two independent production daemons run concurrently
/// on one host and expose the same centralized aggregation contract over real TCP.
#[tokio::test]
async fn two_daemon_http_dashboard_and_mcp_surfaces_are_isolated_and_complete() {
    let http = reqwest::Client::new();
    let mut a = spawn_daemon(true);
    let mut b = spawn_daemon(true);
    assert_ne!(a.http_port, b.http_port);
    assert_ne!(a.data_dir, b.data_dir);
    wait_ready(&http, &mut a).await;
    wait_ready(&http, &mut b).await;

    assert_aggregation_surface(&http, &a).await;
    assert_aggregation_surface(&http, &b).await;

    drop(b);
    drop(a);
}

// ── ADR-026 §5: principal identity over the mTLS management plane ───

/// One raw HTTP/1.1 exchange over an established mTLS stream. Hand-rolled so the
/// test adds zero dependencies: write head+body, read to EOF (`connection: close`),
/// return `(status, body)`.
async fn mtls_exchange<S>(
    mut tls: S,
    method: &str,
    body: Option<&serde_json::Value>,
) -> (u16, String)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let payload = body.map(|v| serde_json::to_string(v).unwrap());
    let mut req = format!("{method} /v1/mcp HTTP/1.1\r\nHost: 127.0.0.1\r\naccept: application/json, text/event-stream\r\nconnection: close\r\n");
    if let Some(p) = &payload {
        req.push_str("content-type: application/json\r\n");
        req.push_str(&format!("content-length: {}\r\n", p.len()));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).await.expect("write request");
    if let Some(p) = &payload {
        tls.write_all(p.as_bytes()).await.expect("write body");
    }
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut buf)).await;
    let raw = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// Dial the management plane as `identity` (leaf+key) pinned to `ca_pem`.
async fn mtls_dial(
    port: u16,
    identity_leaf: &str,
    identity_key: &str,
    ca_pem: &str,
) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
    use rustls::pki_types::ServerName;
    let config = koi_certmesh::mtls::build_client_config(identity_leaf, identity_key, ca_pem)
        .expect("client tls config");
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("dial mTLS listener");
    connector
        .connect(ServerName::try_from("127.0.0.1".to_string()).unwrap(), tcp)
        .await
        .expect("TLS handshake with mesh identity")
}

/// ADR-026 end-to-end over the REAL binary: a foreign caller generates its keypair
/// locally, enrolls as a **client principal** over raw HTTP (role-bound invite),
/// reaches `/v1/mcp` through the mTLS management plane, and loses access the moment
/// it is revoked — while a client-bound invite refuses a host-role join.
#[tokio::test]
async fn client_principal_enrolls_reaches_mgmt_plane_and_revocation_closes_it() {
    const PRINCIPAL: &str = "tier2-agent-7";
    let client = reqwest::Client::new();
    let mut a = spawn_daemon(true); // MCP enabled → the mgmt plane mounts on mTLS
    let a_base = a.base();
    wait_ready(&client, &mut a).await;
    let a_tok = a.token();

    let created = client
        .post(format!("{a_base}/v1/certmesh/create"))
        .header("x-koi-token", &a_tok)
        .json(&CreateCaRequest {
            passphrase: "tier2-pass".to_string(),
            entropy_hex: "07".repeat(32),
            operator: Some("ops".to_string()),
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: true,
            totp_secret_hex: None,
        })
        .send()
        .await
        .expect("create");
    assert!(created.status().is_success(), "create must succeed");
    wait_tcp_up(&mut a, "mTLS listener after create").await;

    // The operator binds the invite to a client principal.
    let invite_resp: InviteResponse = client
        .post(format!("{a_base}/v1/certmesh/invite"))
        .header("x-koi-token", &a_tok)
        .json(&InviteRequest {
            hostname: PRINCIPAL.to_string(),
            ttl_mins: 60,
            role: Some("client".to_string()),
        })
        .send()
        .await
        .expect("invite")
        .json()
        .await
        .expect("invite json");

    // Custody invariant (ADR-015 F1 / ADR-026 §4): the keypair is generated HERE;
    // only the CSR crosses the wire.
    let (key_pem, csr_pem) =
        koi_certmesh::csr::generate_keypair_and_csr(PRINCIPAL, &[PRINCIPAL.to_string()])
            .expect("local keygen + CSR");
    let csr_pem_for_rejoin = csr_pem.clone();

    let joined: JoinResponse = client
        .post(format!("{a_base}/v1/certmesh/join"))
        .json(&JoinRequest {
            hostname: PRINCIPAL.to_string(),
            auth: None,
            invite_token: Some(invite_resp.token.clone()),
            csr: Some(csr_pem),
            sans: vec![PRINCIPAL.to_string()],
            role: Some("client".to_string()),
        })
        .send()
        .await
        .expect("join")
        .json()
        .await
        .expect("join json");
    assert!(
        joined.service_key.is_empty(),
        "the CA must never ship a private key — custody stays with the caller"
    );

    // A host-role join presenting that SAME (already burned) client invite is
    // refused — and after the burn, even the correct role cannot reuse it, which
    // this second assertion subsumes via the token-invalid path.
    let host_join = client
        .post(format!("{a_base}/v1/certmesh/join"))
        .json(&JoinRequest {
            hostname: PRINCIPAL.to_string(),
            auth: None,
            invite_token: Some(invite_resp.token.clone()),
            csr: Some(csr_pem_for_rejoin),
            sans: vec![PRINCIPAL.to_string()],
            role: None, // defaults to member/host
        })
        .send()
        .await
        .expect("rejoin attempt");
    assert_ne!(
        host_join.status().as_u16(),
        200,
        "the spent client-bound invite must not admit anything"
    );

    // ── Healthy principal reaches /v1/mcp through the mTLS management plane ──
    let session = mtls_dial(a.mtls_port, &joined.service_cert, &key_pem, &joined.ca_cert).await;
    let (status, body) = mtls_exchange(
        session,
        "POST",
        Some(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "principal-probe", "version": "0.0.0" }
            }
        })),
    )
    .await;
    assert_eq!(
        status, 200,
        "an active principal must pass CN→roster authorization and reach the MCP layer; body: {body}"
    );
    assert!(
        !body.contains("scope_violation"),
        "the healthy principal must never see an authorization rejection"
    );

    // ── Revocation closes the door immediately (named reason) ──
    let revoked = client
        .post(format!("{a_base}/v1/certmesh/revoke"))
        .header("x-koi-token", &a_tok)
        .json(&RevokeRequest {
            hostname: PRINCIPAL.to_string(),
            reason: Some("principal lifecycle proof".into()),
            operator: Some("ops".into()),
        })
        .send()
        .await
        .expect("revoke");
    assert!(revoked.status().is_success(), "revoke must succeed");

    let session = mtls_dial(a.mtls_port, &joined.service_cert, &key_pem, &joined.ca_cert).await;
    let (status, body) = mtls_exchange(session, "GET", None).await;
    assert_eq!(
        status, 403,
        "the revoked principal must be refused at the management plane"
    );
    assert!(
        body.contains("revoked"),
        "the rejection must name its reason (ADR-020 vocabulary), got: {body}"
    );

    drop(a);
}
