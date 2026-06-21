//! Tier-1 cross-participant certmesh integration suite (ADR-018).
//!
//! These tests close the single biggest pre-1.0 test-quality gap: until now every
//! real-socket certmesh test ran client *and* server in one `CertmeshCore` on
//! `127.0.0.1`, and CI's "3-OS matrix" only proved each OS compiles+unit-passes in
//! isolation — never that two *participants* exchange certificates. Here two **embedded
//! Koi daemons** (A = CA, B = member) run in one process on distinct loopback ports +
//! data dirs and drive the canonical "whole story" over the *real* surfaces:
//!
//!   create → open-enrollment → invite → **B joins over real HTTP** (preflight pins
//!   A's fingerprint) → **B member-pull rotate-key renewal over real mTLS** → trust-bundle
//!   pull → **A revokes B** → **B's next /renew over mTLS = 403** + bundle `self_revoked`
//!   → F3 (wrong-fingerprint invite aborts at preflight) → F7 (TOTP lockout survives a CA
//!   restart) → F11 (a tampered `machine.bind` boots the CA LOCKED).
//!
//! Pure Rust, no shell, no child processes → cross-platform by construction, so a plain
//! `cargo test --locked` (what `ci.yml` runs on ubuntu/windows/macos) executes it per-PR
//! on all three OSes with no workflow change. Ephemeral ports + per-daemon unique data
//! dirs keep it parallel-safe under the default (parallel) `cargo test`.
//!
//! ## Design note — where the mTLS server comes from
//!
//! ADR-018's prerequisite anticipated adding an `mtls_port` knob to the embedded builder
//! "because two daemons can't share 5642". The trust model is **asymmetric**: only the CA
//! runs an mTLS *server*; a member is a pure mTLS *client*. So there is exactly one mTLS
//! server in the whole story and no port to deconflict — the builder knob is unnecessary.
//! These tests instead stand A's mTLS inter-node listener up on an ephemeral `127.0.0.1:0`
//! port via the public `koi_certmesh::mtls` primitive — the *same* `build_server_config` +
//! `serve(core.inter_node_routes())` that the binary's 12-line `adapters::mtls::start`
//! wraps — so the renew-handler / TLS / 403-boundary coverage is identical with zero new
//! production surface. The plain-HTTP legs (join, status, trust-bundle) go over A's real
//! embedded HTTP adapter.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use tokio_util::sync::CancellationToken;

use koi_certmesh::protocol::{CreateCaRequest, JoinRequest, JoinResponse, RenewRequest};
use koi_certmesh::roster::CertPolicy;
use koi_certmesh::{
    invite, member, mtls, BundleOutcome, CertmeshCore, CertmeshError, CertmeshPaths, RenewOutcome,
};
use koi_crypto::pinning::fingerprints_match;

use koi_embedded::{Builder, KoiHandle, ServiceMode};

// ── Test harness ────────────────────────────────────────────────────

/// A unique temp data dir per call. A monotonic counter guarantees uniqueness even
/// when parallel tests start within the same (coarse, on macOS) clock tick — copied
/// from `tests/embedded.rs`, which fixed exactly that same-tick collision flake.
fn temp_data_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "koi-whole-story-{}-{nanos}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Grab a free loopback TCP port (bind to :0, read it back, drop the listener).
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    l.local_addr().expect("local_addr").port()
}

/// Start an embedded Koi daemon with only certmesh + the HTTP adapter enabled. mDNS and
/// DNS are off so the test never touches privileged ports (DNS :53) or multicast sockets.
async fn start_daemon(data_dir: &Path, http_port: u16) -> KoiHandle {
    Builder::new()
        .data_dir(data_dir)
        .service_mode(ServiceMode::EmbeddedOnly)
        .mdns(false)
        .dns_enabled(false)
        .health(false)
        .proxy(false)
        .udp(false)
        .certmesh(true)
        .http(true)
        .http_port(http_port)
        .build()
        .expect("build embedded")
        .start()
        .await
        .expect("start embedded")
}

/// Poll `GET {base}/healthz` until the embedded HTTP adapter is bound (it spins up in a
/// background task, so `start()` returning does not guarantee the socket is listening).
async fn wait_ready(client: &reqwest::Client, base: &str) {
    for _ in 0..100 {
        if let Ok(r) = client.get(format!("{base}/healthz")).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("HTTP server at {base} did not become ready");
}

/// Create A's CA through the running daemon's own core (the production `create` path:
/// self-enrolls A as Primary, records `machine.bind`, configures auto-unlock, emits the
/// `ca_initialized` audit entry), with enrollment open. Returns nothing — assertions are
/// made by the caller against the shared core.
async fn create_ca(a_core: &CertmeshCore) {
    a_core
        .create(CreateCaRequest {
            passphrase: "whole-story-pass".to_string(),
            entropy_hex: "07".repeat(32), // 32 bytes
            operator: Some("ops".to_string()),
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: true,
            totp_secret_hex: None,
        })
        .await
        .expect("create CA");
}

/// A member's recorded fingerprint in A's roster (empty string if absent).
async fn roster_fingerprint(a_core: &CertmeshCore, hostname: &str) -> String {
    a_core
        .certmesh_status()
        .await
        .members
        .into_iter()
        .find(|m| m.hostname == hostname)
        .map(|m| m.cert_fingerprint)
        .unwrap_or_default()
}

// ── The whole story: join over HTTP → renew over mTLS → revoke → 403 + self_revoked ──

#[tokio::test]
async fn whole_story_join_renew_revoke_over_http_and_mtls() {
    let host = "web-01";
    let sans = vec![host.to_string()];
    let client = reqwest::Client::new();

    // ── A: the CA daemon ──
    let a_dir = temp_data_dir();
    let a_http = free_port();
    let a_handle = start_daemon(&a_dir, a_http).await;
    let a_base = format!("http://127.0.0.1:{a_http}");
    wait_ready(&client, &a_base).await;
    let a_core = a_handle
        .certmesh()
        .expect("certmesh handle")
        .core()
        .expect("core");

    // Step 1: create (auto-unlock). Assert CA initialized, machine.bind written, audit.
    create_ca(&a_core).await;
    let a_paths = CertmeshPaths::with_data_dir(a_dir.clone());
    assert!(
        a_paths.machine_bind_path().exists(),
        "create must record machine.bind"
    );
    assert!(
        a_core.read_audit_log().unwrap().contains("ca_initialized"),
        "create must audit ca_initialized"
    );
    let status = a_core.certmesh_status().await;
    assert!(status.ca_initialized && !status.ca_locked);
    assert_eq!(status.member_count, 1, "CA self-enrolls as Primary");

    // Step 2: mint a host-bound invite (`<secret>.<ca_fp>`).
    let invite_code = a_core
        .mint_invite(host, 60)
        .await
        .expect("mint invite")
        .token;
    let (secret, pinned) = invite::decode_code(&invite_code);
    let pinned_fp = pinned
        .expect("invite carries the CA fingerprint")
        .to_string();

    // Step 3: stand up A's mTLS inter-node listener on an ephemeral port (the public
    // primitive the binary's mTLS adapter wraps).
    let leaf = a_core
        .self_enroll()
        .await
        .expect("CA self-enroll for mTLS leaf");
    let tls = mtls::build_server_config(&leaf.cert_pem, &leaf.key_pem, &leaf.ca_cert_pem)
        .expect("mTLS server config");
    let mtls_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mTLS");
    let mtls_port = mtls_listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let mtls_router = Router::new().nest("/v1/certmesh", a_core.inter_node_routes());
    let mtls_server = tokio::spawn(mtls::serve(mtls_router, mtls_listener, tls, cancel.clone()));

    // ── B: the member daemon ──
    let b_dir = temp_data_dir();
    let b_http = free_port();
    let b_handle = start_daemon(&b_dir, b_http).await;
    let b_core = b_handle
        .certmesh()
        .expect("certmesh handle")
        .core()
        .expect("core");
    let b_paths = CertmeshPaths::with_data_dir(b_dir.clone());

    // Step 4: B joins over REAL HTTP — preflight pin, CSR, POST /join, install.
    //
    // Preflight: read A's advertised fingerprint and confirm it matches the pin baked
    // into the invite *before* sending anything.
    let preflight: serde_json::Value = client
        .get(format!("{a_base}/v1/certmesh/status"))
        .send()
        .await
        .expect("preflight status")
        .json()
        .await
        .expect("status json");
    let advertised = preflight["ca_fingerprint"]
        .as_str()
        .expect("status advertises ca_fingerprint");
    assert!(
        fingerprints_match(advertised, &pinned_fp),
        "preflight: advertised CA fingerprint must match the pinned invite fingerprint"
    );

    // B generates its own keypair+CSR (the private key is written 0600 locally and never
    // leaves B).
    let csr = b_core
        .prepare_member_csr(host, &sans)
        .await
        .expect("member CSR");
    let cert_dir = b_paths.certs_dir().join(host);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(cert_dir.join("key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "member private key must be 0600");
    }

    // POST /join over real HTTP (embedded mounts the certmesh routes with no token).
    let join_resp = client
        .post(format!("{a_base}/v1/certmesh/join"))
        .json(&JoinRequest {
            hostname: host.to_string(),
            auth: None,
            invite_token: Some(secret.to_string()),
            csr: Some(csr),
            sans: sans.clone(),
        })
        .send()
        .await
        .expect("join request");
    assert!(
        join_resp.status().is_success(),
        "join over HTTP must succeed, got {}",
        join_resp.status()
    );
    let raw: serde_json::Value = join_resp.json().await.expect("join json");
    assert!(
        raw.get("service_key").is_none(),
        "CSR-flow join must NOT return a private key on the wire"
    );
    // Defence in depth against the key leaking under any *other* field name: no PEM
    // private-key block may appear anywhere in the response body.
    assert!(
        !raw.to_string().contains("PRIVATE KEY"),
        "the join response must not carry a private key under any field"
    );
    let join: JoinResponse = serde_json::from_value(raw).expect("typed join response");
    assert!(join.service_key.is_empty());

    // Install the signed leaf with a pin hard-fail (the wrong-pin path is covered by the
    // F3 test). Arms member.json for renewal against A's HTTP port (mTLS port defaults to
    // 5642 here; we override it next).
    b_core
        .install_member_cert(
            host,
            &join.service_cert,
            &join.ca_cert,
            Some(a_base.as_str()),
            Some(pinned_fp.as_str()),
            &sans,
            Some(join.policy.clone()),
        )
        .await
        .expect("install member cert");
    assert_eq!(
        a_core.certmesh_status().await.member_count,
        2,
        "B is now enrolled in A's roster"
    );

    // Point the armed member state at A's ephemeral mTLS port and force "due" (the
    // renew-threshold exceeds the leaf lifetime so a fresh leaf is always renewable).
    // `install_member_cert` cannot record a non-default mTLS port, so we rewrite it here —
    // the supported way to target an ephemeral test port.
    let member_path = b_paths.member_state_path();
    let mut st = member::load(&member_path).expect("renewal armed");
    assert_eq!(st.ca_host, "127.0.0.1");
    assert_eq!(
        st.ca_http_port, a_http,
        "ca_http_port armed from the endpoint"
    );
    st.ca_mtls_port = mtls_port;
    st.policy = CertPolicy {
        leaf_lifetime_days: 90,
        renew_threshold_days: 365,
        grace_days: 14,
    };
    member::save(&member_path, &st).expect("save member state");

    // Step 5: B pulls a rotate-key renewal over real mTLS. The key ROTATES locally and A
    // records the new fingerprint.
    let old_key = std::fs::read_to_string(cert_dir.join("key.pem")).unwrap();
    let fp_before = roster_fingerprint(&a_core, host).await;
    assert!(!fp_before.is_empty(), "A recorded B's enrolled fingerprint");

    let outcome = b_core.renew_self_if_due().await.expect("renew over mTLS");
    assert!(
        matches!(outcome, RenewOutcome::Renewed { .. }),
        "expected Renewed, got {outcome:?}"
    );
    let new_key = std::fs::read_to_string(cert_dir.join("key.pem")).unwrap();
    assert_ne!(
        old_key, new_key,
        "renewal must ROTATE the member private key"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(cert_dir.join("key.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "rotated key must stay 0600");
    }
    let fp_after = roster_fingerprint(&a_core, host).await;
    assert_ne!(
        fp_before, fp_after,
        "A's roster must record the rotated leaf fingerprint"
    );
    assert!(!fp_after.is_empty());

    // `renew_self_if_due` rewrites member.json (it refreshes the installed cert's
    // coordinates) and would reset `ca_mtls_port` to the 5642 default, so re-pin the
    // ephemeral test port. The post-revoke probe at step 8 dials `mtls_port` directly and
    // does not depend on this, but a future renewal driven through `renew_self_if_due`
    // would, so keep member.json honest.
    let mut st = member::load(&member_path).expect("load member state after renew");
    st.ca_mtls_port = mtls_port;
    member::save(&member_path, &st).expect("re-pin mTLS port in member state");

    // Step 6: B pulls + verifies the signed trust bundle (ES256 + anti-rollback). A
    // second pull with no roster change is idempotent. Capture the seq to prove the
    // post-revoke bundle is strictly newer (the anti-rollback floor advanced).
    let first_seq = match b_core.pull_trust_bundle().await.expect("bundle pull") {
        BundleOutcome::Updated { seq, self_revoked } => {
            assert!(!self_revoked);
            seq
        }
        other => panic!("expected Updated, got {other:?}"),
    };
    assert!(
        matches!(
            b_core.pull_trust_bundle().await.unwrap(),
            BundleOutcome::NoChange { .. }
        ),
        "an unchanged roster must yield NoChange"
    );

    // Step 7: A revokes B.
    a_core
        .revoke_member(host, Some("ops".into()), Some("integration-test".into()))
        .await
        .expect("revoke");

    // Step 8 — boundary revocation over LIVE mTLS (the gap that was 0% e2e): B's leaf
    // still chains to the CA so the TLS handshake completes, but the app layer rejects the
    // revoked member with 403. Present B's current (valid) leaf directly. Step 5's
    // successful renew already proved the CN check + handshake pass for this leaf+hostname,
    // so the only thing that changed is the revocation — and we assert the 403 body names
    // the revocation path (not a CN-mismatch / no-mTLS 403).
    let b_cert = std::fs::read_to_string(cert_dir.join("cert.pem")).unwrap();
    let b_key = std::fs::read_to_string(cert_dir.join("key.pem")).unwrap();
    let b_ca = std::fs::read_to_string(cert_dir.join("ca.pem")).unwrap();
    let renew_body = serde_json::to_string(&RenewRequest {
        hostname: host.to_string(),
        // The handler rejects a revoked member *before* parsing the CSR, so the body's
        // CSR value is never inspected here.
        csr: "unused-after-revocation".to_string(),
    })
    .unwrap();
    let (renew_status, renew_resp_body) = mtls::post_json(
        "127.0.0.1",
        mtls_port,
        koi_certmesh::http::paths::RENEW,
        &renew_body,
        &b_cert,
        &b_key,
        &b_ca,
    )
    .await
    .expect("mTLS renew round-trip completes (handshake ok)");
    assert_eq!(
        renew_status, 403,
        "a revoked member's /renew over mTLS must be rejected with 403"
    );
    assert!(
        renew_resp_body.contains("revoked"),
        "the 403 must be the revocation path (not CN-mismatch/no-mTLS); body: {renew_resp_body}"
    );

    // ...and B's next trust-bundle pull tells it that it is revoked, on a strictly newer
    // seq (the revocation bumped the monotonic roster sequence).
    match b_core
        .pull_trust_bundle()
        .await
        .expect("post-revoke bundle pull")
    {
        BundleOutcome::Updated { seq, self_revoked } => {
            assert!(
                self_revoked,
                "B must detect its own revocation in the bundle"
            );
            assert!(
                seq > first_seq,
                "revocation must advance the roster seq ({seq} should exceed {first_seq})"
            );
        }
        other => panic!("expected Updated(self_revoked), got {other:?}"),
    }

    // ── teardown ──
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), mtls_server).await;
    b_handle.shutdown().await.expect("shutdown B");
    a_handle.shutdown().await.expect("shutdown A");
    let _ = std::fs::remove_dir_all(&a_dir);
    let _ = std::fs::remove_dir_all(&b_dir);
}

// ── F3: an invite carrying the wrong CA fingerprint aborts at preflight ──

#[tokio::test]
async fn wrong_fingerprint_invite_aborts_at_preflight() {
    let host = "f3-host";
    let sans = vec![host.to_string()];
    let client = reqwest::Client::new();

    let a_dir = temp_data_dir();
    let a_http = free_port();
    let a_handle = start_daemon(&a_dir, a_http).await;
    let a_base = format!("http://127.0.0.1:{a_http}");
    wait_ready(&client, &a_base).await;
    let a_core = a_handle.certmesh().unwrap().core().unwrap();
    create_ca(&a_core).await;

    // A genuine invite pins A's real fingerprint; a forged invite carries an attacker's.
    let real_code = a_core.mint_invite(host, 60).await.unwrap().token;
    let (secret, real_fp) = invite::decode_code(&real_code);
    let real_fp = real_fp.unwrap().to_string();
    let forged_fp = "0".repeat(64);

    // (a) Preflight: a joiner pinning the forged fingerprint compares it against what the
    // live CA advertises and aborts BEFORE generating or sending any CSR.
    let preflight: serde_json::Value = client
        .get(format!("{a_base}/v1/certmesh/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let advertised = preflight["ca_fingerprint"].as_str().unwrap();
    assert!(
        fingerprints_match(advertised, &real_fp),
        "sanity: the genuine invite pin matches the live CA"
    );
    assert!(
        !fingerprints_match(advertised, &forged_fp),
        "F3: a wrong-fingerprint invite must fail the preflight pin check"
    );

    // (b) Defence-in-depth: even if a joiner skipped the preflight and obtained a real
    // CA-signed leaf, `install_member_cert` re-derives the CA cert's fingerprint and
    // HARD-FAILS when the out-of-band pin does not match — so a forged pin can never arm
    // a member. Exercise that production guard directly (the preflight above is binary-only
    // CLI code; this is the library-level enforcement reachable from the embedded API).
    let b_dir = temp_data_dir();
    let b_core =
        CertmeshCore::uninitialized_with_paths(CertmeshPaths::with_data_dir(b_dir.clone()));
    let csr = b_core.prepare_member_csr(host, &sans).await.unwrap();
    let join: JoinResponse = client
        .post(format!("{a_base}/v1/certmesh/join"))
        .json(&JoinRequest {
            hostname: host.to_string(),
            auth: None,
            invite_token: Some(secret.to_string()),
            csr: Some(csr),
            sans: sans.clone(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let forged = b_core
        .install_member_cert(
            host,
            &join.service_cert,
            &join.ca_cert,
            Some(a_base.as_str()),
            Some(&forged_fp),
            &sans,
            Some(join.policy.clone()),
        )
        .await;
    assert!(
        matches!(forged, Err(CertmeshError::InvalidPayload(_))),
        "F3: install with a forged pin must hard-fail, got {forged:?}"
    );
    // The genuine pin installs — proving the guard discriminates rather than always failing.
    b_core
        .install_member_cert(
            host,
            &join.service_cert,
            &join.ca_cert,
            Some(a_base.as_str()),
            Some(&real_fp),
            &sans,
            Some(join.policy),
        )
        .await
        .expect("install with the genuine pin must succeed");

    a_handle.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&a_dir);
    let _ = std::fs::remove_dir_all(&b_dir);
}

// ── F7: a TOTP enrollment lockout survives a CA restart ──

/// POST a guaranteed-wrong TOTP join and return the HTTP status. The code is 7 digits:
/// a real TOTP code is exactly 6, and the constant-time compare returns false on a length
/// mismatch, so this can NEVER accidentally authenticate (no flake from a fixed 6-digit
/// code coinciding with the unknown auto-generated secret's current window).
async fn bad_totp_join(client: &reqwest::Client, base: &str, hostname: &str) -> u16 {
    client
        .post(format!("{base}/v1/certmesh/join"))
        .json(&JoinRequest {
            hostname: hostname.to_string(),
            auth: Some(koi_crypto::auth::AuthResponse::Totp {
                code: "0000000".to_string(),
            }),
            invite_token: None,
            csr: None,
            sans: vec![],
        })
        .send()
        .await
        .expect("totp join request")
        .status()
        .as_u16()
}

#[tokio::test]
async fn totp_lockout_persists_across_ca_restart() {
    let host = "f7-host";
    let client = reqwest::Client::new();

    let a_dir = temp_data_dir();
    let a_http = free_port();
    let a_handle = start_daemon(&a_dir, a_http).await;
    let a_base = format!("http://127.0.0.1:{a_http}");
    wait_ready(&client, &a_base).await;
    let a_core = a_handle.certmesh().unwrap().core().unwrap();
    create_ca(&a_core).await;

    // MAX_FAILURES is 3: the first two bad codes are 401 (invalid auth), the third trips
    // the lockout and returns 429.
    assert_eq!(bad_totp_join(&client, &a_base, host).await, 401);
    assert_eq!(bad_totp_join(&client, &a_base, host).await, 401);
    assert_eq!(
        bad_totp_join(&client, &a_base, host).await,
        429,
        "the third bad TOTP must trip the lockout"
    );

    // The lockout is persisted (totp-throttle.json) — assert it directly via the
    // serde-round-tripping RateLimiter, independent of any in-memory state.
    let a_paths = CertmeshPaths::with_data_dir(a_dir.clone());
    let throttle = std::fs::read(a_paths.rate_limiter_path()).expect("throttle persisted");
    let limiter: koi_crypto::totp::RateLimiter =
        serde_json::from_slice(&throttle).expect("throttle parses");
    assert!(limiter.is_locked(), "persisted limiter must be locked");

    // Restart A on the same data dir (a fresh daemon reloads the persisted throttle).
    a_handle.shutdown().await.unwrap();
    let a_http2 = free_port();
    let a_handle = start_daemon(&a_dir, a_http2).await;
    let a_base2 = format!("http://127.0.0.1:{a_http2}");
    wait_ready(&client, &a_base2).await;

    // Confirm the rebuilt CA auto-unlocked, so a 429 below is rate-limiting — not a 503
    // from a locked CA (which would also be a non-200 but for the wrong reason).
    let a_core2 = a_handle.certmesh().unwrap().core().unwrap();
    assert!(
        !a_core2.certmesh_status().await.ca_locked,
        "the rebuilt CA must auto-unlock so the 429 is rate-limiting, not ca_locked"
    );

    // A fresh limiter would return 401 (invalid code, attempts remaining); a persisted
    // lockout returns 429 immediately. That distinction is the whole point of F7.
    assert_eq!(
        bad_totp_join(&client, &a_base2, host).await,
        429,
        "the lockout must survive a CA restart"
    );

    a_handle.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&a_dir);
}

// ── F11: a tampered machine.bind boots the CA LOCKED (clone-refusal) ──

#[tokio::test]
async fn tampered_machine_binding_boots_ca_locked() {
    let client = reqwest::Client::new();

    let a_dir = temp_data_dir();
    let a_http = free_port();
    let a_handle = start_daemon(&a_dir, a_http).await;
    let a_base = format!("http://127.0.0.1:{a_http}");
    wait_ready(&client, &a_base).await;
    let a_core = a_handle.certmesh().unwrap().core().unwrap();

    // Create with auto-unlock so an UNtampered reboot would auto-unlock — that makes the
    // lock-on-tamper assertion meaningful.
    create_ca(&a_core).await;
    assert!(
        !a_core.certmesh_status().await.ca_locked,
        "a freshly created CA with auto-unlock is unlocked"
    );

    let a_paths = CertmeshPaths::with_data_dir(a_dir.clone());
    let bind_path = a_paths.machine_bind_path();
    assert!(bind_path.exists(), "create recorded machine.bind");

    // Shut down, overwrite machine.bind with a foreign fingerprint (a clone/restore onto
    // different hardware), then reboot on the same data dir.
    a_handle.shutdown().await.unwrap();
    std::fs::write(&bind_path, "0".repeat(64)).expect("tamper machine.bind");

    let a_http2 = free_port();
    let a_handle = start_daemon(&a_dir, a_http2).await;
    let a_core = a_handle.certmesh().unwrap().core().unwrap();

    assert!(
        a_core.certmesh_status().await.ca_locked,
        "F11: a tampered machine.bind must boot the CA LOCKED (auto-unlock refused)"
    );
    assert!(
        a_core
            .read_audit_log()
            .unwrap()
            .contains("auto_unlock_refused_machine_changed"),
        "F11: the refusal must be audited"
    );

    a_handle.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&a_dir);
}
