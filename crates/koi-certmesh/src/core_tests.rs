//! Unit tests for `CertmeshCore` and the certmesh crate internals.
//!
//! Extracted from `lib.rs` (the former `#[cfg(test)] mod tests` block) to keep the
//! facade file thin (certmesh M2). As a child module of the crate root it retains
//! access to the crate-private items it exercises (`CertmeshState`, free helpers,
//! `super::*`).

use super::*;
use crate::roster::{MemberRole, MemberStatus, RosterMember};
use chrono::{Duration, Utc};

// ── ADR-020 P1: posture oracle ──────────────────────────────────

// Each posture test gets its OWN isolated data dir. We deliberately do NOT
// use `koi_common::test::ensure_data_dir` here: that returns a process-wide
// `OnceLock` dir shared by every test in this binary, so wiping it (to get a
// clean slate) would destroy sibling tests' CA/vault/roster state. posture()
// reads only the injected `CertmeshPaths`, so an isolated dir is sufficient.
fn isolated_posture_paths(tag: &str) -> CertmeshPaths {
    let dir = std::env::temp_dir().join(format!("koi-cm-posture-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    CertmeshPaths::with_data_dir(dir)
}

fn posture_member_state(hostname: &str) -> crate::member::MemberState {
    crate::member::MemberState {
        hostname: hostname.to_string(),
        ca_host: "ca-host".to_string(),
        ca_mtls_port: 5642,
        ca_http_port: 5641,
        ca_fingerprint: "fp".to_string(),
        sans: vec![hostname.to_string()],
        policy: crate::roster::CertPolicy::default(),
        last_bundle_seq: 0,
        reload_hook: None,
    }
}

fn write_posture_leaf(paths: &CertmeshPaths, hostname: &str) {
    let leaf = paths.certs_dir().join(hostname);
    std::fs::create_dir_all(&leaf).unwrap();
    std::fs::write(leaf.join("cert.pem"), b"leaf-cert").unwrap();
    std::fs::write(leaf.join("key.pem"), b"leaf-key").unwrap();
}

#[test]
fn posture_is_open_without_identity() {
    let paths = isolated_posture_paths("open");
    let core = CertmeshCore::uninitialized_with_paths(paths);
    assert_eq!(core.posture(), koi_common::posture::Posture::OPEN);
}

#[test]
fn posture_is_authenticated_with_member_identity() {
    let paths = isolated_posture_paths("auth");
    let hostname = CertmeshCore::local_hostname().expect("local hostname");
    crate::member::save(&paths.member_state_path(), &posture_member_state(&hostname)).unwrap();
    write_posture_leaf(&paths, &hostname);
    let core = CertmeshCore::uninitialized_with_paths(paths);
    let p = core.posture();
    assert!(p.signed);
    assert!(!p.encrypted);
    assert_eq!(p.level(), koi_common::posture::PostureLevel::Authenticated);
}

#[test]
fn posture_ignores_orphan_leaf_without_anchor() {
    let paths = isolated_posture_paths("orphan");
    let hostname = CertmeshCore::local_hostname().expect("local hostname");
    // Leaf present but no CA and no member.json — an unanchored orphan.
    write_posture_leaf(&paths, &hostname);
    let core = CertmeshCore::uninitialized_with_paths(paths);
    assert_eq!(core.posture(), koi_common::posture::Posture::OPEN);
}

#[tokio::test]
async fn local_identity_is_none_when_open() {
    let paths = isolated_posture_paths("local-id-open");
    let core = CertmeshCore::uninitialized_with_paths(paths);
    assert!(core.local_identity().await.is_none());
}

#[tokio::test]
async fn local_identity_loads_after_self_enroll() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let paths = isolated_posture_paths("local-id");
    let ca = ca::create_ca("test-pass", &[7u8; 32], &paths).unwrap().0;
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths);
    core.self_enroll().await.expect("self-enroll");

    let id = core.local_identity().await.expect("identity present");
    assert_eq!(id.hostname, CertmeshCore::local_hostname().unwrap());
    assert!(id.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(id.key_pem.contains("BEGIN"));
    assert_eq!(id.ca_fingerprint.len(), 64); // sha256 hex
                                             // A fresh 90-day leaf (renew at 30 days remaining) is healthy.
    assert!(!id.renewal.expired);
    assert!(!id.renewal.renew_overdue);
    assert!(id.renewal.expires_in_days > 30);
    // Redacted Debug must never leak key material.
    assert!(!format!("{id:?}").contains("BEGIN"));
}

#[tokio::test]
async fn ensure_identity_none_when_open() {
    let paths = isolated_posture_paths("ensure-open");
    let core = CertmeshCore::uninitialized_with_paths(paths);
    assert!(core.ensure_identity().await.is_none());
}

#[tokio::test]
async fn ensure_identity_self_enrolls_ca_node() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let paths = isolated_posture_paths("ensure-ca");
    let ca = ca::create_ca("test-pass", &[9u8; 32], &paths).unwrap().0;
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths);

    // No leaf yet → Open.
    assert!(!core.posture().signed);
    // ensure_identity self-enrolls the CA node and returns a live identity.
    let id = core.ensure_identity().await.expect("identity after ensure");
    assert_eq!(id.hostname, CertmeshCore::local_hostname().unwrap());
    assert!(core.posture().signed);
    // Idempotent: a second call reuses the fresh leaf (no re-issue).
    let id2 = core
        .ensure_identity()
        .await
        .expect("identity still present");
    assert_eq!(id2.cert_pem, id.cert_pem);
}

#[tokio::test]
async fn posture_watch_observes_transitions_and_coalesces() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let paths = isolated_posture_paths("watch");
    let ca = ca::create_ca("test-pass", &[5u8; 32], &paths).unwrap().0;
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths);

    let mut rx = core.watch_posture();
    assert!(!rx.borrow_and_update().signed, "no leaf yet → Open");

    // self_enroll writes the leaf and publishes → Open→Authenticated observed.
    core.self_enroll().await.expect("self-enroll");
    assert!(rx.has_changed().unwrap(), "self-enroll must notify");
    assert!(rx.borrow_and_update().signed);

    // A second self_enroll re-issues the leaf but the posture is unchanged →
    // the watch coalesces (no spurious PostureChanged — silence is correct here,
    // an upgrade is not).
    core.self_enroll().await.expect("re-enroll");
    assert!(
        !rx.has_changed().unwrap(),
        "an unchanged posture must not notify"
    );

    // destroy tears the identity down → Authenticated→Open observed (a degrade
    // is as loud as the upgrade, ADR-020 §13).
    core.destroy().await.expect("destroy");
    assert!(rx.has_changed().unwrap(), "destroy must notify");
    assert!(!rx.borrow_and_update().signed);
}

fn test_paths() -> CertmeshPaths {
    CertmeshPaths::with_data_dir(koi_common::test::ensure_data_dir("koi-certmesh-core-tests"))
}

fn make_test_ca() -> ca::CaState {
    ca::create_ca("test-pass", &[42u8; 32], &test_paths())
        .unwrap()
        .0
}

// Posture booleans for the named presets (UX labels only).
// Just Me = (open, no approval); My Organization = (closed, approval).
const JUST_ME: (bool, bool) = (true, false);
const MY_ORG: (bool, bool) = (false, true);

fn make_test_roster_with_member(hostname: &str, role: MemberRole) -> Roster {
    let mut r = Roster::new(JUST_ME.0, JUST_ME.1, None);
    r.members.push(RosterMember {
        hostname: hostname.to_string(),
        role,
        enrolled_at: Utc::now(),
        enrolled_by: None,
        cert_fingerprint: "fp-test".to_string(),
        cert_expires: Utc::now() + Duration::days(25),
        cert_sans: vec![hostname.to_string(), format!("{hostname}.local")],
        cert_path: String::new(),
        status: MemberStatus::Active,
        reload_hook: None,
        last_seen: None,
        pinned_ca_fingerprint: Some("pinned-fp".to_string()),
        proxy_entries: Vec::new(),
    });
    r
}

fn make_unlocked_core(ca: ca::CaState, roster: Roster) -> CertmeshCore {
    let totp = koi_crypto::totp::generate_secret();
    let auth_state = koi_crypto::auth::AuthState::Totp(totp);
    CertmeshCore::new_with_paths(ca, roster, Some(auth_state), test_paths())
}

fn make_locked_core(roster: Roster) -> CertmeshCore {
    CertmeshCore::locked_with_paths(roster, test_paths())
}

// ── auto-unlock vault round-trip ─────────────────────────────────
#[test]
fn auto_unlock_key_round_trips_through_vault() {
    // `save_auto_unlock_key_at` persists the passphrase in the koi-crypto
    // vault and deletes the legacy plaintext file; `read_auto_unlock_key`
    // must read it back from that same vault. This is the contract the
    // embedded boot path relies on. Regression guard: the boot reader
    // used to read the (now deleted) plaintext file and boot LOCKED.
    let base = koi_common::test::ensure_data_dir("koi-certmesh-autounlock-tests");
    let paths = CertmeshPaths::with_data_dir(base.join("autounlock-roundtrip"));

    CertmeshCore::save_auto_unlock_key_at(&paths, "test-secret-pass").unwrap();

    // The plaintext key file must not be the source of truth.
    assert!(
        !paths.auto_unlock_key_path().exists(),
        "save_auto_unlock_key_at must not leave a plaintext key file behind"
    );

    let recovered = CertmeshCore::read_auto_unlock_key(&paths).unwrap();
    assert_eq!(
        recovered.as_ref().map(|z| z.as_str()),
        Some("test-secret-pass"),
        "the auto-unlock passphrase must round-trip through the vault"
    );

    // A data dir with no stored key reads back as None (boots locked).
    let empty = CertmeshPaths::with_data_dir(base.join("autounlock-empty"));
    assert!(CertmeshCore::read_auto_unlock_key(&empty)
        .unwrap()
        .is_none());
}

// ── renew_self_if_due ─────────────────────────────────────────────

#[tokio::test]
async fn renew_self_if_due_is_noop_without_member_state() {
    // A node that never joined a mesh (no member.json) has nothing to pull.
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);
    let outcome = core.renew_self_if_due().await.expect("no-op succeeds");
    assert!(matches!(outcome, RenewOutcome::NotApplicable));
}

// ── renew_ca_self_leaf_if_due (CA cornerstone self-renewal) ───────

#[tokio::test]
async fn renew_ca_self_leaf_if_due_is_noop_without_ca() {
    // A node with no local CA is not a cornerstone — nothing to self-renew.
    let paths = isolated_posture_paths("ca-renew-noca");
    let core = CertmeshCore::uninitialized_with_paths(paths);
    let outcome = core
        .renew_ca_self_leaf_if_due()
        .await
        .expect("no-op succeeds");
    assert!(
        matches!(outcome, RenewOutcome::NotApplicable),
        "got {outcome:?}"
    );
}

#[tokio::test]
async fn renew_ca_self_leaf_if_due_not_due_when_fresh() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let paths = isolated_posture_paths("ca-renew-fresh");
    let ca = ca::create_ca("test-pass", &[11u8; 32], &paths).unwrap().0;
    // Default policy: 90-day leaves, renew at 30 days remaining.
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths);

    // Issue the initial CA self leaf (~90 days out).
    core.self_enroll().await.expect("initial self-enroll");

    // A fresh 90-day leaf is well outside the 30-day threshold → not due.
    let outcome = core
        .renew_ca_self_leaf_if_due()
        .await
        .expect("due-check ok");
    assert!(
        matches!(outcome, RenewOutcome::NotDue { .. }),
        "got {outcome:?}"
    );
}

#[tokio::test]
async fn renew_ca_self_leaf_if_due_renews_when_due() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let paths = isolated_posture_paths("ca-renew-due");
    let ca = ca::create_ca("test-pass", &[12u8; 32], &paths).unwrap().0;
    let mut roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    // Threshold > lifetime → the self leaf is always within the renewal window.
    roster.metadata.policy = crate::roster::CertPolicy {
        leaf_lifetime_days: 90,
        renew_threshold_days: 365,
        grace_days: 14,
    };
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths);

    let mut events = core.subscribe();

    // Issue the initial self leaf, then drive a due-renewal.
    core.self_enroll().await.expect("initial self-enroll");
    let outcome = core.renew_ca_self_leaf_if_due().await.expect("renewal ok");
    assert!(
        matches!(outcome, RenewOutcome::Renewed { .. }),
        "got {outcome:?}"
    );

    // A CertRenewed event must have been emitted (drain past the self_enroll
    // MemberJoined events to find it).
    let mut saw_renewed = false;
    while let Ok(ev) = events.try_recv() {
        if matches!(ev, CertmeshEvent::CertRenewed { .. }) {
            saw_renewed = true;
        }
    }
    assert!(
        saw_renewed,
        "expected a CertRenewed event after CA self-renewal"
    );
}

/// End-to-end member-pull renewal over a real mTLS connection (ADR-017 F6).
///
/// Proves the whole loop without the test host: a member enrolls (CSR), then
/// pulls a rotate-key renewal from the CA's mTLS `/renew` — the request carries
/// ONLY a CSR, the member's key ROTATES locally, and the CA records the new
/// fingerprint. The key-custody invariant holds across renewal.
#[tokio::test]
async fn member_pull_renewal_round_trip() {
    use crate::roster::CertPolicy;

    // `ensure_data_dir` returns a process-wide shared base (OnceLock, prefix is
    // only honored on the first call), so carve a test-unique subdir — otherwise
    // this test's `remove_dir_all` races other e2e tests sharing `base/ca`.
    let base = koi_common::test::ensure_data_dir("koi-certmesh-renew-e2e").join("renew-e2e");
    let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
    let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
    let _ = std::fs::remove_dir_all(ca_paths.data_dir());
    let _ = std::fs::remove_dir_all(member_paths.data_dir());

    // ── CA side: create CA, self-enroll (server leaf for the mTLS listener) ──
    let (ca_state, _master) = ca::create_ca("e2e-pass", &[7u8; 32], &ca_paths).unwrap();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
    let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());
    let server_leaf = ca_core.self_enroll().await.expect("CA self-enroll");

    // ── Member side: generate keypair+CSR, enroll via invite, install cert ──
    let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());
    let csr = member_core
        .prepare_member_csr("renew-host", &["renew-host".to_string()])
        .await
        .expect("member CSR");
    let invite = ca_core
        .mint_invite("renew-host", 60)
        .await
        .expect("invite")
        .token;
    let join = ca_core
        .enroll(&protocol::JoinRequest {
            hostname: "renew-host".to_string(),
            auth: None,
            invite_token: Some(invite),
            csr: Some(csr),
            sans: vec!["renew-host".to_string()],
        })
        .await
        .expect("enroll");
    assert!(join.service_key.is_empty(), "enroll must not return a key");
    member_core
        .install_member_cert(
            "renew-host",
            &join.service_cert,
            &join.ca_cert,
            Some("http://127.0.0.1:5641"),
            Some(&join.ca_fingerprint),
            &["renew-host".to_string()],
            Some(join.policy.clone()),
        )
        .await
        .expect("install");

    // ── Stand up the CA's mTLS inter-node listener ──
    let config = mtls::build_server_config(
        &server_leaf.cert_pem,
        &server_leaf.key_pem,
        &server_leaf.ca_cert_pem,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = tokio_util::sync::CancellationToken::new();
    // Mirror the binary's mTLS adapter, which nests the inter-node router under
    // the crate prefix so the served path is `/v1/certmesh/renew`.
    let app = Router::new().nest("/v1/certmesh", ca_core.inter_node_routes());
    let server = tokio::spawn(mtls::serve(app, listener, config, cancel.clone()));

    // Point the armed member state at the ephemeral test port and force "due".
    let mut st = member::load(&member_paths.member_state_path()).expect("renewal armed");
    assert_eq!(st.ca_host, "127.0.0.1");
    st.ca_mtls_port = port;
    st.policy = CertPolicy {
        leaf_lifetime_days: 90,
        renew_threshold_days: 365, // > leaf lifetime → always due
        grace_days: 14,
    };
    member::save(&member_paths.member_state_path(), &st).unwrap();

    let cert_dir = member_paths.certs_dir().join("renew-host");
    let old_key = std::fs::read_to_string(cert_dir.join("key.pem")).unwrap();
    let old_cert = std::fs::read_to_string(cert_dir.join("cert.pem")).unwrap();

    // ── Member pulls the renewal over mTLS ──
    let outcome = member_core.renew_self_if_due().await.expect("renewal ok");
    assert!(
        matches!(outcome, RenewOutcome::Renewed { .. }),
        "expected Renewed, got {outcome:?}"
    );

    let new_key = std::fs::read_to_string(cert_dir.join("key.pem")).unwrap();
    let new_cert = std::fs::read_to_string(cert_dir.join("cert.pem")).unwrap();
    assert_ne!(
        old_key, new_key,
        "renewal must ROTATE the member private key"
    );
    assert_ne!(old_cert, new_cert, "renewal must install a fresh leaf");
    assert!(new_cert.contains("BEGIN CERTIFICATE"));
    assert!(new_key.contains("PRIVATE KEY"));

    // The CA roster recorded the rotated leaf's fingerprint.
    let new_fp = koi_crypto::pinning::fingerprint_sha256(pem::parse(&new_cert).unwrap().contents());
    {
        let roster = ca_core.state.roster.lock().await;
        let member = roster
            .find_member("renew-host")
            .expect("member in CA roster");
        assert_eq!(
            member.cert_fingerprint, new_fp,
            "CA roster must record the rotated leaf fingerprint"
        );
    }

    cancel.cancel();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(base.join("ca"));
    let _ = std::fs::remove_dir_all(base.join("member"));
}

/// End-to-end trust-bundle pull (ADR-017 P1/F4): the CA serves a signed bundle
/// over HTTP; a member pulls it, verifies the signature against its pin,
/// accepts a newer `seq`, no-ops on an unchanged one, rejects a rollback, and
/// detects its own revocation.
#[tokio::test]
async fn trust_bundle_pull_round_trip() {
    // Test-unique subdir under the shared base (see renew test note).
    let base = koi_common::test::ensure_data_dir("koi-certmesh-bundle-e2e").join("bundle-e2e");
    let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
    let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
    let _ = std::fs::remove_dir_all(ca_paths.data_dir());
    let _ = std::fs::remove_dir_all(member_paths.data_dir());

    // CA with one enrolled member (enroll bumps seq to >= 1).
    let (ca_state, _m) = ca::create_ca("be2e", &[5u8; 32], &ca_paths).unwrap();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
    let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());
    let (_k, csr) =
        csr::generate_keypair_and_csr("bundle-host", &["bundle-host".to_string()]).unwrap();
    let invite = ca_core.mint_invite("bundle-host", 60).await.unwrap().token;
    ca_core
        .enroll(&protocol::JoinRequest {
            hostname: "bundle-host".to_string(),
            auth: None,
            invite_token: Some(invite),
            csr: Some(csr),
            sans: vec!["bundle-host".to_string()],
        })
        .await
        .unwrap();
    let pin = ca::ca_fingerprint_from_disk(&ca_paths).unwrap();

    // Serve the certmesh routes (incl. GET /trust-bundle) over plain HTTP,
    // nested under the crate prefix exactly as the binary mounts them.
    let app = Router::new().nest("/v1/certmesh", crate::http::routes(ca_core.state.clone()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    // Arm the member with a pin and a fresh (seq 0) anti-rollback floor.
    member::save(
        &member_paths.member_state_path(),
        &member::MemberState {
            hostname: "bundle-host".to_string(),
            ca_host: "127.0.0.1".to_string(),
            ca_mtls_port: 5642,
            ca_http_port: port,
            ca_fingerprint: pin.clone(),
            sans: vec!["bundle-host".to_string()],
            policy: crate::roster::CertPolicy::default(),
            last_bundle_seq: 0,
            reload_hook: None,
        },
    )
    .unwrap();
    let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());

    // First pull → Updated (the CA's seq is >= 1 after the enroll).
    match member_core.pull_trust_bundle().await.expect("pull ok") {
        BundleOutcome::Updated { seq, self_revoked } => {
            assert!(seq >= 1, "expected a bumped seq, got {seq}");
            assert!(!self_revoked);
        }
        other => panic!("expected Updated, got {other:?}"),
    }
    let stored = member::load(&member_paths.member_state_path()).unwrap();
    assert!(
        stored.last_bundle_seq >= 1,
        "member persisted the bundle seq"
    );

    // Second pull, no roster change → NoChange (idempotent).
    assert!(matches!(
        member_core.pull_trust_bundle().await.unwrap(),
        BundleOutcome::NoChange { .. }
    ));

    // Revoke the member on the CA → next pull sees self_revoked + a higher seq.
    ca_core
        .revoke_member("bundle-host", Some("op".into()), Some("test".into()))
        .await
        .unwrap();
    match member_core.pull_trust_bundle().await.expect("pull ok") {
        BundleOutcome::Updated { self_revoked, .. } => {
            assert!(
                self_revoked,
                "member must detect its own revocation in the bundle"
            );
        }
        other => panic!("expected Updated(self_revoked), got {other:?}"),
    }

    server.abort();
    let _ = std::fs::remove_dir_all(base.join("ca"));
    let _ = std::fs::remove_dir_all(base.join("member"));
}

// ── renew_member (ADR-021, CA-side transport-agnostic renewal) ────

/// A renewal CSR for a member that was never enrolled is refused with NotFound.
#[tokio::test]
async fn renew_member_unknown_member_is_not_found() {
    let ca = make_test_ca();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None); // empty roster
    let core = make_unlocked_core(ca, roster);
    let (_k, csr) = csr::generate_keypair_and_csr("ghost", &["ghost".to_string()]).unwrap();
    let err = core.renew_member("ghost", &csr).await.unwrap_err();
    assert!(matches!(err, CertmeshError::NotFound(_)), "got {err:?}");
}

/// A revoked member's renewal is refused with Revoked (and audited at the
/// CA boundary, ADR-017 F9/F14).
#[tokio::test]
async fn renew_member_revoked_is_rejected() {
    let ca = make_test_ca();
    let mut roster = make_test_roster_with_member("revoked-host", MemberRole::Primary);
    roster.members[0].status = MemberStatus::Revoked;
    let core = make_unlocked_core(ca, roster);
    let (_k, csr) =
        csr::generate_keypair_and_csr("revoked-host", &["revoked-host".to_string()]).unwrap();
    let err = core.renew_member("revoked-host", &csr).await.unwrap_err();
    assert!(matches!(err, CertmeshError::Revoked(_)), "got {err:?}");
}

/// THE critical invariant: a renewal CSR can never EXPAND its SAN set. A CSR
/// requesting a name not recorded at enrollment is rejected with InvalidPayload
/// — loudly, not silently narrowed.
#[tokio::test]
async fn renew_member_san_expansion_is_rejected() {
    let ca = make_test_ca();
    // Authorized SANs for "san-host" are ["san-host", "san-host.local"].
    let roster = make_test_roster_with_member("san-host", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);
    // The CSR sneaks in an extra, unauthorized name.
    let (_k, csr) = csr::generate_keypair_and_csr(
        "san-host",
        &["san-host".to_string(), "evil.lan".to_string()],
    )
    .unwrap();
    let err = core.renew_member("san-host", &csr).await.unwrap_err();
    assert!(
        matches!(err, CertmeshError::InvalidPayload(_)),
        "a SAN-expansion attempt must be rejected with InvalidPayload, got {err:?}"
    );
    assert_eq!(koi_common::error::ErrorCode::from(&err).http_status(), 400);
}

/// An expired member cert is STILL renewable — renewal is the fix for expiry, so
/// the CA must not gate renewal on the member's current cert validity.
#[tokio::test]
async fn renew_member_expired_cert_still_renews() {
    let ca = make_test_ca();
    let mut roster = make_test_roster_with_member("stale-host", MemberRole::Primary);
    roster.members[0].cert_expires = Utc::now() - Duration::days(5); // already expired
    let core = make_unlocked_core(ca, roster);
    let (_k, csr) =
        csr::generate_keypair_and_csr("stale-host", &["stale-host".to_string()]).unwrap();
    let resp = core
        .renew_member("stale-host", &csr)
        .await
        .expect("an expired cert must still renew");
    assert!(resp.service_cert.contains("BEGIN CERTIFICATE"));
}

/// Happy path: a valid rotate-key CSR yields a signed leaf, the roster records
/// the rotated fingerprint, and a `CertRenewed` event is emitted.
#[tokio::test]
async fn renew_member_happy_path_issues_and_records() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("good-host", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);
    let mut events = core.state.event_tx.subscribe();

    let (_k, csr) = csr::generate_keypair_and_csr(
        "good-host",
        &["good-host".to_string(), "good-host.local".to_string()],
    )
    .unwrap();
    let resp = core
        .renew_member("good-host", &csr)
        .await
        .expect("renewal succeeds");

    assert_eq!(resp.hostname, "good-host");
    assert!(resp.service_cert.contains("BEGIN CERTIFICATE"));
    assert!(resp.ca_cert.contains("BEGIN CERTIFICATE"));
    assert_eq!(resp.ca_fingerprint.len(), 64, "sha256 hex");
    // N4: the response carries the CA's lifecycle policy so a member can compute
    // an accurate renewal schedule without arming member.json.
    assert_eq!(resp.policy, roster::CertPolicy::default());

    // The roster recorded the rotated leaf's fingerprint + last_seen.
    let issued_fp =
        koi_crypto::pinning::fingerprint_sha256(pem::parse(&resp.service_cert).unwrap().contents());
    {
        let roster = core.state.roster.lock().await;
        let m = roster.find_member("good-host").expect("member present");
        assert_eq!(
            m.cert_fingerprint, issued_fp,
            "roster must record the rotated fingerprint"
        );
        assert!(m.last_seen.is_some());
    }

    // A CertRenewed event fired (the CA-side emission, ADR-021).
    let ev = events.try_recv().expect("CertRenewed emitted");
    assert!(
        matches!(ev, CertmeshEvent::CertRenewed { .. }),
        "got {ev:?}"
    );
}

/// A locked (or absent) CA cannot sign renewals.
#[tokio::test]
async fn renew_member_ca_locked_is_rejected() {
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_locked_core(roster);
    let (_k, csr) = csr::generate_keypair_and_csr("node-01", &["node-01".to_string()]).unwrap();
    let err = core.renew_member("node-01", &csr).await.unwrap_err();
    assert!(
        matches!(
            err,
            CertmeshError::CaLocked | CertmeshError::CaNotInitialized
        ),
        "got {err:?}"
    );
}

// ── N3 public leaf parsers (ADR-022) ─────────────────────────────

#[test]
fn leaf_parsers_read_an_arbitrary_leaf() {
    let ca = make_test_ca();
    let issued = ca::issue_certificate(&ca, "leaf-host", &["leaf-host".to_string()], 30).unwrap();

    assert_eq!(
        crate::leaf_cn(&issued.cert_pem).as_deref(),
        Some("leaf-host")
    );
    let exp = crate::leaf_not_after_utc(&issued.cert_pem).expect("expiry parses");
    let days = (exp - Utc::now()).num_days();
    assert!((28..=31).contains(&days), "expected ~30 days, got {days}");

    // Garbage in → None, never a panic.
    assert!(crate::leaf_cn("not a pem").is_none());
    assert!(crate::leaf_not_after_utc("not a pem").is_none());
}

// ── F3 install pin enforcement ───────────────────────────────────

/// F3: when a pinned fingerprint is supplied, `install_member_cert` must
/// hard-fail (writing nothing, arming nothing) if the CA cert does not match
/// it — a MITM that substituted its own CA at join is rejected before any file
/// is written or any root is trusted. The correct pin installs and arms.
#[tokio::test]
async fn install_member_cert_rejects_pin_mismatch() {
    // Test-unique subdir under the shared base (see renew test note).
    let base = koi_common::test::ensure_data_dir("koi-certmesh-installpin").join("installpin");
    let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
    let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
    let _ = std::fs::remove_dir_all(ca_paths.data_dir());
    let _ = std::fs::remove_dir_all(member_paths.data_dir());

    let (ca_state, _m) = ca::create_ca("ip", &[3u8; 32], &ca_paths).unwrap();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
    let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());

    let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());
    let csr = member_core
        .prepare_member_csr("pin-host", &["pin-host".to_string()])
        .await
        .unwrap();
    let invite = ca_core.mint_invite("pin-host", 60).await.unwrap();
    // The invite code embeds the real CA fingerprint (F3).
    let (secret, real_fp) = invite::decode_code(&invite.token);
    let real_fp = real_fp
        .expect("invite code carries the CA fingerprint")
        .to_string();
    assert_eq!(real_fp, invite.ca_fingerprint);
    let join = ca_core
        .enroll(&protocol::JoinRequest {
            hostname: "pin-host".to_string(),
            auth: None,
            invite_token: Some(secret.to_string()),
            csr: Some(csr),
            sans: vec!["pin-host".to_string()],
        })
        .await
        .unwrap();

    // Wrong pin → hard-fail; no cert written, renewal not armed.
    let wrong_fp = "0".repeat(64);
    let err = member_core
        .install_member_cert(
            "pin-host",
            &join.service_cert,
            &join.ca_cert,
            Some("http://127.0.0.1:5641"),
            Some(&wrong_fp),
            &["pin-host".to_string()],
            Some(join.policy.clone()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, CertmeshError::InvalidPayload(_)),
        "got {err:?}"
    );
    let cert_dir = member_paths.certs_dir().join("pin-host");
    assert!(
        !cert_dir.join("cert.pem").exists(),
        "no cert must be written on pin mismatch"
    );
    assert!(
        member::load(&member_paths.member_state_path()).is_none(),
        "renewal must not be armed on pin mismatch"
    );

    // Correct pin (the one embedded in the invite) → installs + arms.
    let dir = member_core
        .install_member_cert(
            "pin-host",
            &join.service_cert,
            &join.ca_cert,
            Some("http://127.0.0.1:5641"),
            Some(&real_fp),
            &["pin-host".to_string()],
            Some(join.policy.clone()),
        )
        .await
        .unwrap();
    assert!(std::path::Path::new(&dir).join("cert.pem").exists());
    assert!(
        member::load(&member_paths.member_state_path()).is_some(),
        "correct pin arms renewal"
    );

    let _ = std::fs::remove_dir_all(base.join("ca"));
    let _ = std::fs::remove_dir_all(base.join("member"));
}

/// F5: a verified trust-bundle pull restores a corrupted on-disk `ca.pem`
/// (the trust anchor the mTLS renewal client loads), keeping it in sync with
/// the signed mesh truth.
#[tokio::test]
async fn pull_trust_bundle_self_heals_ca_anchor() {
    // Test-unique subdir under the shared base (see renew test note).
    let base = koi_common::test::ensure_data_dir("koi-certmesh-anchor-heal").join("anchor-heal");
    let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
    let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
    let _ = std::fs::remove_dir_all(ca_paths.data_dir());
    let _ = std::fs::remove_dir_all(member_paths.data_dir());

    let (ca_state, _m) = ca::create_ca("heal", &[6u8; 32], &ca_paths).unwrap();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
    let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());

    let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());
    let csr = member_core
        .prepare_member_csr("heal-host", &["heal-host".to_string()])
        .await
        .unwrap();
    let invite = ca_core.mint_invite("heal-host", 60).await.unwrap();
    let (secret, fp) = invite::decode_code(&invite.token);
    let pin = fp.unwrap().to_string();
    let join = ca_core
        .enroll(&protocol::JoinRequest {
            hostname: "heal-host".to_string(),
            auth: None,
            invite_token: Some(secret.to_string()),
            csr: Some(csr),
            sans: vec!["heal-host".to_string()],
        })
        .await
        .unwrap();
    member_core
        .install_member_cert(
            "heal-host",
            &join.service_cert,
            &join.ca_cert,
            Some("http://127.0.0.1:5641"),
            Some(&pin),
            &["heal-host".to_string()],
            Some(join.policy.clone()),
        )
        .await
        .unwrap();

    // Serve the certmesh routes (incl. GET /trust-bundle) over plain HTTP.
    let app = Router::new().nest("/v1/certmesh", crate::http::routes(ca_core.state.clone()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    // Point the armed member's HTTP port at the ephemeral test server.
    let mut st = member::load(&member_paths.member_state_path()).unwrap();
    st.ca_http_port = port;
    member::save(&member_paths.member_state_path(), &st).unwrap();

    // Corrupt the on-disk anchor, then pull → it is healed from the bundle.
    let anchor = member_paths.certs_dir().join("heal-host").join("ca.pem");
    std::fs::write(&anchor, b"-----BEGIN CERTIFICATE-----\nGARBAGE\n").unwrap();
    member_core.pull_trust_bundle().await.expect("pull ok");

    let restored = std::fs::read_to_string(&anchor).unwrap();
    assert!(
        !restored.contains("GARBAGE"),
        "anchor must be self-healed from the verified bundle"
    );
    assert_eq!(
        restored, join.ca_cert,
        "anchor now matches the signed CA cert"
    );

    server.abort();
    let _ = std::fs::remove_dir_all(base.join("ca"));
    let _ = std::fs::remove_dir_all(base.join("member"));
}

// ── health_check ─────────────────────────────────────────────────

#[tokio::test]
async fn health_check_returns_error_when_ca_locked() {
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_locked_core(roster);
    let request = protocol::HealthRequest {
        hostname: "node-01".to_string(),
        pinned_ca_fingerprint: "some-fp".to_string(),
    };
    let result = core.health_check(&request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn health_check_validates_matching_fingerprint() {
    let ca = make_test_ca();
    let ca_fp = ca::ca_fingerprint(&ca);
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);

    let request = protocol::HealthRequest {
        hostname: "node-01".to_string(),
        pinned_ca_fingerprint: ca_fp,
    };
    let result = core.health_check(&request).await.unwrap();
    assert!(result.valid);
    assert!(!result.ca_fingerprint.is_empty());
}

#[tokio::test]
async fn health_check_rejects_mismatched_fingerprint() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);

    let request = protocol::HealthRequest {
        hostname: "node-01".to_string(),
        pinned_ca_fingerprint: "wrong-fingerprint".to_string(),
    };
    let result = core.health_check(&request).await.unwrap();
    assert!(!result.valid);
}

#[tokio::test]
async fn health_check_updates_last_seen() {
    let ca = make_test_ca();
    let ca_fp = ca::ca_fingerprint(&ca);
    let mut roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    // Ensure last_seen is None initially
    roster.members[0].last_seen = None;
    let core = make_unlocked_core(ca, roster);

    let request = protocol::HealthRequest {
        hostname: "node-01".to_string(),
        pinned_ca_fingerprint: ca_fp,
    };
    core.health_check(&request).await.unwrap();

    // Verify last_seen was updated via the roster state
    let roster = core.state.roster.lock().await;
    assert!(roster.members[0].last_seen.is_some());
}

// ── promote ──────────────────────────────────────────────────────

#[tokio::test]
async fn promote_returns_error_when_ca_locked() {
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_locked_core(roster);
    let dummy_pk = [0u8; 32];
    let result = core.promote(&dummy_pk).await;
    assert!(matches!(result, Err(CertmeshError::CaLocked)));
}

#[tokio::test]
async fn promote_returns_encrypted_material() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);

    let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
    let client_pub = client_kp.public_key_bytes();

    let response = core.promote(&client_pub).await.unwrap();
    assert!(!response.encrypted_ca_key.ciphertext.is_empty());
    assert!(!response.auth_data.is_null());
    assert!(!response.roster_json.is_empty());
    assert!(response.ca_cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(response.ephemeral_public.is_some());
}

#[tokio::test]
async fn promote_response_can_be_accepted_with_dh() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);

    let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
    let client_pub = client_kp.public_key_bytes();

    let response = core.promote(&client_pub).await.unwrap();
    assert!(response.ephemeral_public.is_some());

    // Accept the promotion on the standby side using DH
    let (ca_key, accepted_auth, accepted_roster) =
        failover::accept_promotion(&response, client_kp).unwrap();
    assert!(!ca_key.public_key_pem().unwrap().is_empty());
    assert_eq!(accepted_auth.method_name(), "totp");
    assert_eq!(accepted_roster.members.len(), 1);
}

// ── local_hostname ───────────────────────────────────────────────

#[test]
fn local_hostname_returns_some() {
    let hostname = CertmeshCore::local_hostname();
    assert!(hostname.is_some());
    assert!(!hostname.unwrap().is_empty());
}

// ── validate_hostname (F15, RFC 1123) ────────────────────────────

#[test]
fn validate_hostname_rfc1123() {
    let label63 = "a".repeat(63);
    for ok in [
        "web-01",
        "node-granite-spring",
        "a",
        "a.b.c",
        "x1.local",
        label63.as_str(),
    ] {
        assert!(validate_hostname(ok).is_ok(), "{ok:?} should be valid");
    }

    let label64 = "a".repeat(64);
    let over253 = vec!["a"; 200].join(".");
    for bad in [
        "",           // empty
        " ",          // space
        "host name",  // embedded space
        "host/name",  // path separator
        "host\\name", // path separator
        "host:1",     // colon (Windows drive / ADS)
        "..",         // empty labels
        "host..name", // empty interior label
        "-host",      // leading hyphen
        "host-",      // trailing hyphen
        "host_name",  // underscore is not RFC 1123
        label64.as_str(),
        over253.as_str(),
    ] {
        assert!(
            validate_hostname(bad).is_err(),
            "{bad:?} should be rejected"
        );
    }
}

// ── F11 machine binding ──────────────────────────────────────────

#[test]
fn machine_binding_detects_change() {
    let paths = CertmeshPaths::with_data_dir(
        koi_common::test::ensure_data_dir("koi-certmesh-core-tests").join("machinebind"),
    );
    let _ = std::fs::remove_dir_all(paths.data_dir());
    let bind = paths.machine_bind_path();
    std::fs::create_dir_all(bind.parent().unwrap()).unwrap();

    // No recorded binding → not machine-checked (pre-F11 CA) → ok.
    assert!(machine_binding_ok(&paths));

    // A binding that matches this host → ok (when a machine-id is available).
    if let Some(current) = koi_crypto::vault::machine_fingerprint() {
        std::fs::write(&bind, current.as_bytes()).unwrap();
        assert!(machine_binding_ok(&paths), "matching binding must pass");
    }

    // A binding that no longer matches (a clone/restore) → fail safe.
    std::fs::write(
        &bind,
        b"0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    assert!(
        !machine_binding_ok(&paths),
        "a changed machine fingerprint must refuse auto-unlock"
    );

    let _ = std::fs::remove_dir_all(paths.data_dir());
}

// ── F7 persisted rate limiter ────────────────────────────────────

#[test]
fn rate_limiter_lockout_survives_reload() {
    let paths = CertmeshPaths::with_data_dir(
        koi_common::test::ensure_data_dir("koi-certmesh-core-tests").join("ratelimit"),
    );
    let _ = std::fs::remove_dir_all(paths.data_dir());

    // No persisted file yet → fresh limiter, not locked.
    let mut rl = load_rate_limiter(&paths);
    assert!(!rl.is_locked());

    // Drive it into lockout, then persist.
    for _ in 0..3 {
        let _ = rl.check_and_record(false);
    }
    assert!(rl.is_locked(), "limiter must lock after MAX_FAILURES");
    persist_rate_limiter(&paths, &rl).unwrap();

    // A fresh load (simulating a daemon restart) must still be locked (F7).
    let reloaded = load_rate_limiter(&paths);
    assert!(
        reloaded.is_locked(),
        "persisted lockout must survive a restart"
    );

    let _ = std::fs::remove_dir_all(paths.data_dir());
}

// ── build_status ─────────────────────────────────────────────────

#[test]
fn build_status_locked_ca() {
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let status = build_status(&test_paths(), &None, &roster, None);
    assert!(status.ca_locked);
    assert_eq!(status.member_count, 1);
    assert_eq!(status.members.len(), 1);
    assert_eq!(status.members[0].hostname, "node-01");
    assert_eq!(status.members[0].role, "primary");
}

#[test]
fn build_status_unlocked_ca() {
    let ca = make_test_ca();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let status = build_status(&test_paths(), &Some(ca), &roster, None);
    assert!(!status.ca_locked);
    assert_eq!(status.member_count, 0);
}

#[test]
fn build_status_member_roles_lowercase() {
    let mut roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    roster.members.push(RosterMember {
        hostname: "standby-01".to_string(),
        role: MemberRole::Standby,
        enrolled_at: Utc::now(),
        enrolled_by: None,
        cert_fingerprint: "fp".to_string(),
        cert_expires: Utc::now(),
        cert_sans: vec![],
        cert_path: String::new(),
        status: MemberStatus::Active,
        reload_hook: None,
        last_seen: None,
        pinned_ca_fingerprint: None,
        proxy_entries: Vec::new(),
    });
    let status = build_status(&test_paths(), &None, &roster, None);
    assert_eq!(status.members[0].role, "standby");
    assert_eq!(status.members[0].status, "active");
}

// ── Enrollment toggle facade tests ──────────────────────────────

#[tokio::test]
async fn open_enrollment_changes_state() {
    let ca = make_test_ca();
    let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".into()));
    let core = make_unlocked_core(ca, roster);

    // Initially closed (My Organization)
    let status = core.certmesh_status().await;
    assert_eq!(status.enrollment_state, roster::EnrollmentState::Closed);
    assert!(!status.enrollment_open);

    // Open
    core.open_enrollment().await.unwrap();
    let status = core.certmesh_status().await;
    assert_eq!(status.enrollment_state, roster::EnrollmentState::Open);
    assert!(status.enrollment_open);
}

#[tokio::test]
async fn close_enrollment_changes_state() {
    let ca = make_test_ca();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = make_unlocked_core(ca, roster);

    // Initially open for Just Me
    let status = core.certmesh_status().await;
    assert_eq!(status.enrollment_state, roster::EnrollmentState::Open);

    // Close
    core.close_enrollment().await.unwrap();
    let status = core.certmesh_status().await;
    assert_eq!(status.enrollment_state, roster::EnrollmentState::Closed);
    assert!(!status.enrollment_open);
}

#[tokio::test]
async fn rotate_auth_fails_when_ca_locked() {
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = make_locked_core(roster);
    let result = core.rotate_auth("test-pass", None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn build_status_reports_posture_booleans() {
    let ca = make_test_ca();
    let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".into()));
    let status = build_status(&test_paths(), &Some(ca), &roster, None);
    assert!(!status.enrollment_open);
    assert!(status.requires_approval);
    assert_eq!(status.enrollment_state, roster::EnrollmentState::Closed);
}

// ── CertmeshCore::uninitialized_with_paths(test_paths()) state ─────────────────────────

#[tokio::test]
async fn uninitialized_core_status_shows_empty_roster() {
    let core = CertmeshCore::uninitialized_with_paths(test_paths());
    let status = core.certmesh_status().await;
    // ca_initialized reflects filesystem state, not in-memory state.
    // ca_locked is false because we have no CA at all (not locked, just absent).
    assert_eq!(status.member_count, 0);
    assert!(status.members.is_empty());
    // The in-memory CA is None, so ca_locked should be true
    // (None means "no key loaded" which is the locked state).
    assert!(status.ca_locked);
}

#[tokio::test]
async fn uninitialized_core_enroll_returns_error() {
    let core = CertmeshCore::uninitialized_with_paths(test_paths());
    let request = protocol::JoinRequest {
        hostname: "node-05".to_string(),
        auth: Some(koi_crypto::auth::AuthResponse::Totp {
            code: "123456".to_string(),
        }),
        invite_token: None,
        csr: None,
        sans: vec![],
    };
    let result = core.enroll(&request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn uninitialized_core_promote_returns_error() {
    let core = CertmeshCore::uninitialized_with_paths(test_paths());
    let dummy_pk = [0u8; 32];
    let result = core.promote(&dummy_pk).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn uninitialized_core_renew_self_is_noop() {
    let core = CertmeshCore::uninitialized_with_paths(test_paths());
    let outcome = core.renew_self_if_due().await.expect("no-op succeeds");
    assert!(matches!(outcome, RenewOutcome::NotApplicable));
}

#[tokio::test]
async fn uninitialized_core_rotate_auth_returns_error() {
    let core = CertmeshCore::uninitialized_with_paths(test_paths());
    let result = core.rotate_auth("passphrase", None).await;
    assert!(result.is_err());
}

// ── node_role ──────────────────────────────────────────────────────

#[tokio::test]
async fn node_role_returns_none_for_empty_roster() {
    let ca = make_test_ca();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = make_unlocked_core(ca, roster);
    // Empty roster has no members, so node_role returns None
    // (regardless of local hostname)
    let role = core.node_role().await;
    // May or may not match the local hostname - depends on environment
    // but for an empty roster it should always be None
    assert!(role.is_none());
}

#[tokio::test]
async fn node_role_returns_role_for_matching_hostname() {
    let ca = make_test_ca();
    let hostname = CertmeshCore::local_hostname().unwrap();
    let roster = make_test_roster_with_member(&hostname, MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);
    let role = core.node_role().await;
    assert_eq!(role, Some(MemberRole::Primary));
}

// ── pinned_ca_fingerprint ──────────────────────────────────────────

#[tokio::test]
async fn pinned_ca_fingerprint_returns_none_for_empty_roster() {
    let ca = make_test_ca();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = make_unlocked_core(ca, roster);
    let fp = core.pinned_ca_fingerprint().await;
    assert!(fp.is_none());
}

#[tokio::test]
async fn pinned_ca_fingerprint_returns_value_for_matching_member() {
    let ca = make_test_ca();
    let hostname = CertmeshCore::local_hostname().unwrap();
    let mut roster = make_test_roster_with_member(&hostname, MemberRole::Primary);
    roster.members[0].pinned_ca_fingerprint = Some("test-pinned-fp".to_string());
    let core = make_unlocked_core(ca, roster);
    let fp = core.pinned_ca_fingerprint().await;
    assert_eq!(fp.as_deref(), Some("test-pinned-fp"));
}

// ── Capability::status() ───────────────────────────────────────────

#[tokio::test]
async fn capability_status_uninitialised() {
    let core = CertmeshCore::uninitialized_with_paths(test_paths());
    let status = core.status().await;
    assert_eq!(status.name, "certmesh");
    // When no CA files exist on disk this is a healthy "ready" state.
    // On a dev machine with existing CA files it appears as "CA locked"
    // because the filesystem check sees them but the core has no loaded CA.
    if test_paths().is_ca_initialized() {
        assert!(!status.healthy);
        assert!(
            status.summary.contains("locked"),
            "unexpected summary: {}",
            status.summary
        );
    } else {
        assert!(status.healthy);
        assert!(
            status.summary.contains("ready"),
            "unexpected summary: {}",
            status.summary
        );
    }
}

#[tokio::test]
async fn capability_status_locked() {
    // Deterministic + isolated: a CA on disk (so `is_ca_initialized()` is true)
    // plus a core holding no in-memory key IS the "CA locked" state. Using an
    // isolated dir (rather than the shared `test_paths()`) makes the assertion
    // independent of whatever a sibling test left in the shared data dir — the
    // previous form only reported "locked" if some other test had created a CA
    // there first, so test-scheduling order could flip it to a healthy "ready".
    let paths = isolated_posture_paths("cap-status-locked");
    ca::create_ca("test-pass", &[42u8; 32], &paths).expect("create CA on disk");
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = CertmeshCore::locked_with_paths(roster, paths);
    let status = core.status().await;
    assert_eq!(status.name, "certmesh");
    assert!(
        !status.healthy,
        "a CA on disk with no loaded key must be unhealthy (locked)"
    );
    assert!(
        status.summary.contains("locked"),
        "summary: {}",
        status.summary
    );
}

#[tokio::test]
async fn capability_status_unlocked() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);
    let status = core.status().await;
    assert_eq!(status.name, "certmesh");
    assert!(status.healthy);
    assert!(
        status.summary.contains("1 member"),
        "summary: {}",
        status.summary
    );
}

// ── certmesh_status facade ─────────────────────────────────────────

#[tokio::test]
async fn certmesh_status_reports_posture() {
    let ca = make_test_ca();
    let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("ops".to_string()));
    let totp = koi_crypto::totp::generate_secret();
    let auth = koi_crypto::auth::AuthState::Totp(totp);
    let core = CertmeshCore::new_with_paths(ca, roster, Some(auth), test_paths());
    let status = core.certmesh_status().await;
    // My Organization posture: closed enrollment, approval required.
    assert!(!status.enrollment_open);
    assert!(status.requires_approval);
}

// ── set_reload_hook facade ─────────────────────────────────────────

/// An absolute reload-hook command valid for the host platform.
const ABS_HOOK: &str = if cfg!(windows) {
    "C:\\Windows\\System32\\cmd.exe"
} else {
    "/usr/bin/systemctl"
};

#[tokio::test]
async fn set_reload_hook_unknown_member_returns_error() {
    let ca = make_test_ca();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = make_unlocked_core(ca, roster);
    let result = core.set_reload_hook("nonexistent", ABS_HOOK).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn set_reload_hook_sets_hook_for_known_member() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);
    core.set_reload_hook("node-01", ABS_HOOK).await.unwrap();
    let roster = core.state.roster.lock().await;
    assert_eq!(roster.members[0].reload_hook.as_deref(), Some(ABS_HOOK));
}

/// The domain method (not just the HTTP facade) must reject a relative-path
/// hook. This is the intended strengthening: a direct library caller that
/// bypasses HTTP still gets the absolute-path check.
#[tokio::test]
async fn set_reload_hook_rejects_relative_path() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);
    // A bare command name with no path separator is PATH-relative.
    let result = core
        .set_reload_hook("node-01", "systemctl restart nginx")
        .await;
    assert!(
        result.is_err(),
        "relative-path hook must be rejected by the core method"
    );
    // And the member's hook must remain unset (validation runs before mutation).
    let roster = core.state.roster.lock().await;
    assert!(roster.members[0].reload_hook.is_none());
}

/// Forbidden shell metacharacters are rejected by the core method.
#[tokio::test]
async fn set_reload_hook_rejects_shell_metacharacters() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);
    let malicious = format!("{ABS_HOOK}; rm -rf /");
    let result = core.set_reload_hook("node-01", &malicious).await;
    assert!(result.is_err());
}

// ── decode_hex (moved from http.rs) ──────────────────────────────

#[test]
fn decode_hex_valid() {
    assert_eq!(decode_hex("0011ff"), Some(vec![0x00, 0x11, 0xff]));
}

#[test]
fn decode_hex_invalid() {
    assert_eq!(decode_hex("zz"), None);
}

#[test]
fn decode_hex_odd_length() {
    assert_eq!(decode_hex("abc"), None);
}

// ── CertmeshCore::create happy path ──────────────────────────────

/// Direct unit coverage of the relocated CA-creation orchestration
/// (previously only reachable via the HTTP create_handler). Verifies a
/// fresh, uninitialized CA becomes initialized, unlocked, and
/// self-enrolls the CA node as the primary member.
#[tokio::test]
async fn create_initializes_ca_and_self_enrolls_primary() {
    // Isolated, uninitialized data dir so is_ca_initialized() starts false.
    let base = koi_common::test::ensure_data_dir("koi-certmesh-create-tests");
    let paths = CertmeshPaths::with_data_dir(base.join("create-happy-path"));
    // Ensure a clean slate even if a prior run left artifacts behind.
    let _ = std::fs::remove_dir_all(paths.data_dir());
    assert!(
        !paths.is_ca_initialized(),
        "precondition: CA must not be initialized before create()"
    );

    let core = CertmeshCore::uninitialized_with_paths(paths.clone());

    let req = protocol::CreateCaRequest {
        passphrase: "test-pass-strong".to_string(),
        entropy_hex: koi_common::encoding::hex_encode(&[7u8; 32]),
        operator: Some("ops".to_string()),
        enrollment_open: true,
        requires_approval: false,
        auto_unlock: false,
        totp_secret_hex: None,
    };

    let resp = core.create(req).await.expect("create should succeed");
    assert!(
        !resp.ca_fingerprint.is_empty(),
        "create should return a CA fingerprint"
    );

    // CA is now initialized on disk and unlocked in memory.
    assert!(paths.is_ca_initialized());
    let status = core.certmesh_status().await;
    assert!(status.ca_initialized);
    assert!(!status.ca_locked, "CA should be unlocked after create");

    // The CA node self-enrolled as the primary member.
    assert_eq!(status.member_count, 1, "CA node should self-enroll");
    assert_eq!(status.members.len(), 1);
    assert_eq!(status.members[0].role, "primary");
}

/// create() rejects a second initialization with a Conflict (→ 409).
#[tokio::test]
async fn create_on_initialized_ca_returns_conflict() {
    let base = koi_common::test::ensure_data_dir("koi-certmesh-create-tests");
    let paths = CertmeshPaths::with_data_dir(base.join("create-conflict"));
    let _ = std::fs::remove_dir_all(paths.data_dir());
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());

    let mk_req = || protocol::CreateCaRequest {
        passphrase: "test-pass-strong".to_string(),
        entropy_hex: koi_common::encoding::hex_encode(&[9u8; 32]),
        operator: None,
        enrollment_open: true,
        requires_approval: false,
        auto_unlock: false,
        totp_secret_hex: None,
    };

    core.create(mk_req()).await.expect("first create succeeds");
    let err = core
        .create(mk_req())
        .await
        .expect_err("second create must fail");
    assert!(
        matches!(err, CertmeshError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );
    assert_eq!(koi_common::error::ErrorCode::from(&err).http_status(), 409);
}

/// create() rejects malformed entropy with InvalidPayload (→ 400).
#[tokio::test]
async fn create_with_bad_entropy_returns_invalid_payload() {
    let base = koi_common::test::ensure_data_dir("koi-certmesh-create-tests");
    let paths = CertmeshPaths::with_data_dir(base.join("create-bad-entropy"));
    let _ = std::fs::remove_dir_all(paths.data_dir());
    let core = CertmeshCore::uninitialized_with_paths(paths);

    let req = protocol::CreateCaRequest {
        passphrase: "test-pass-strong".to_string(),
        entropy_hex: "bad".to_string(),
        operator: None,
        enrollment_open: true,
        requires_approval: false,
        auto_unlock: false,
        totp_secret_hex: None,
    };
    let err = core.create(req).await.expect_err("bad entropy must fail");
    assert!(
        matches!(err, CertmeshError::InvalidPayload(_)),
        "expected InvalidPayload, got {err:?}"
    );
    assert_eq!(koi_common::error::ErrorCode::from(&err).http_status(), 400);
}
