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
//! `cargo test --locked` (this is the koi-net crate's first integration test).

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use koi_certmesh::invite;
use koi_certmesh::protocol::{
    CertmeshStatus, CreateCaRequest, InstallCertRequest, InviteRequest, InviteResponse,
    JoinRequest, JoinResponse, MemberCsrRequest, MemberCsrResponse, RevokeRequest,
};
use koi_crypto::pinning::fingerprints_match;

const MEMBER: &str = "tier2-web-01";

// ── Child-daemon harness ────────────────────────────────────────────

/// A spawned `koi` daemon child, killed + cleaned up on drop (even on a test panic).
struct Daemon {
    child: Child,
    data_dir: PathBuf,
    http_port: u16,
    mtls_port: u16,
}

impl Daemon {
    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
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

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Spawn a lean certmesh+HTTP-only `koi` daemon with an isolated data dir + breadcrumb.
fn spawn_daemon() -> Daemon {
    let data_dir = temp_data_dir();
    let http_port = free_port();
    let mtls_port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_koi"))
        .arg("--daemon")
        .args(["--port", &http_port.to_string()])
        .args(["--mtls-port", &mtls_port.to_string()])
        // certmesh + http only — everything else off (avoids privileged/multicast ports).
        .args([
            "--no-mdns",
            "--no-dns",
            "--no-health",
            "--no-proxy",
            "--no-udp",
            "--no-runtime",
            "--no-acme",
            "--no-mcp-http",
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
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn koi daemon");
    Daemon {
        child,
        data_dir,
        http_port,
        mtls_port,
    }
}

/// Whether a TCP connection to `127.0.0.1:port` is accepted (the listener is up).
async fn tcp_up(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// Poll until `127.0.0.1:port` accepts, panicking after ~5s.
async fn wait_tcp_up(port: u16, label: &str) {
    for _ in 0..50 {
        if tcp_up(port).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{label} (port {port}) did not come up");
}

async fn wait_ready(client: &reqwest::Client, base: &str) {
    for _ in 0..150 {
        if let Ok(r) = client.get(format!("{base}/healthz")).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("daemon at {base} did not become ready");
}

// ── The test ────────────────────────────────────────────────────────

#[tokio::test]
async fn two_daemon_join_and_revoke_over_real_binary() {
    let sans = vec![MEMBER.to_string()];
    let client = reqwest::Client::new();

    let a = spawn_daemon();
    let b = spawn_daemon();
    let a_base = a.base();
    let b_base = b.base();
    wait_ready(&client, &a_base).await;
    wait_ready(&client, &b_base).await;
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
    wait_tcp_up(a.mtls_port, "A's mTLS listener after post-boot CA create").await;

    // ── invite is also DAT-gated; mint one for an explicit member hostname ──
    let invite_unauth = client
        .post(format!("{a_base}/v1/certmesh/invite"))
        .json(&InviteRequest {
            hostname: MEMBER.to_string(),
            ttl_mins: 60,
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
