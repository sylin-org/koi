//! Unit tests for `CertmeshCore` and the certmesh crate internals.
//!
//! Extracted from `lib.rs` (the former `#[cfg(test)] mod tests` block) to keep the
//! facade file thin (certmesh M2). As a child module of the crate root it retains
//! access to the crate-private items it exercises (`CertmeshState`, free helpers,
//! `super::*`).

use super::*;
use crate::roster::{MemberRole, MemberStatus, RosterMember};
use chrono::{Duration, Utc};

const TEST_LOCAL_HOSTNAME: &str = "certmesh-test-host";

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

#[cfg(unix)]
fn write_executable_script(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
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
        last_bundle_digest: None,
        revoked_fingerprints: Vec::new(),
        self_revoked: false,
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
fn member_with_incoherent_identity_fails_closed() {
    let paths = isolated_posture_paths("auth");
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    crate::member::save(&paths.member_state_path(), &posture_member_state(&hostname)).unwrap();
    write_posture_leaf(&paths, &hostname);
    let core = CertmeshCore::uninitialized_with_paths(paths);
    let status = core.status();
    assert_eq!(status.role, CertmeshRole::Member);
    assert_eq!(status.identity.condition, IdentityCondition::Invalid);
    assert_eq!(status.posture, koi_common::posture::Posture::OPEN);
    assert!(status.diagnosis.is_red());
}

#[test]
fn posture_ignores_orphan_leaf_without_anchor() {
    let paths = isolated_posture_paths("orphan");
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    // Leaf present (cert+key only) but no CA, no member.json, and no leaf-local
    // ca.pem anchor — an unanchored orphan.
    write_posture_leaf(&paths, &hostname);
    let core = CertmeshCore::uninitialized_with_paths(paths);
    assert_eq!(core.posture(), koi_common::posture::Posture::OPEN);
}

#[test]
fn posture_authenticated_with_leaf_local_ca_anchor() {
    // A CA-signed leaf installed WITH its `ca.pem` anchor, but no `member.json`
    // and not a CA — the embedded consumer that holds a leaf and drives its own
    // renewal over a non-mTLS plane (ADR-022). The leaf-local ca.pem anchors it as
    // a real identity, distinguishing it from the orphan above (which lacks ca.pem).
    let paths = isolated_posture_paths("leaf-ca-anchor");
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    let source_paths = isolated_posture_paths("leaf-ca-anchor-source");
    let ca = ca::create_ca("test-pass", &[11u8; 32], &source_paths)
        .unwrap()
        .0;
    let issued = ca::issue_certificate(
        &ca,
        &hostname,
        std::slice::from_ref(&hostname),
        ca::DEFAULT_LEAF_LIFETIME_DAYS,
    )
    .unwrap();
    crate::certfiles::write_cert_files_to(&paths.certs_dir().join(&hostname), &issued).unwrap();
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());
    assert!(core.posture().signed);
    let healthy = core.status();
    assert_eq!(healthy.role, CertmeshRole::Member);
    assert!(healthy.role.requires_authentication());
    assert_eq!(healthy.identity.condition, IdentityCondition::Healthy);
    assert!(healthy.authority.is_none());

    // Once a durable member record exists it is authoritative. Corrupting it
    // must withdraw otherwise-valid TLS material rather than silently falling
    // back to the anchored-leaf compatibility path.
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    std::fs::write(paths.member_state_path(), b"{corrupt-member-record").unwrap();
    let corrupt = CertmeshCore::load_with_paths(paths, "internal", TEST_LOCAL_HOSTNAME).unwrap();
    assert_eq!(corrupt.status().role, CertmeshRole::Member);
    assert_eq!(
        corrupt.status().identity.condition,
        IdentityCondition::Invalid
    );
    assert!(!corrupt.status().posture.signed);
    assert!(corrupt.tls_identity().material.is_none());
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
    assert_eq!(id.hostname, TEST_LOCAL_HOSTNAME);
    assert!(id.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(id.key_pem.contains("BEGIN"));
    assert_eq!(id.ca_fingerprint.len(), 64); // sha256 hex
                                             // A fresh 7-day leaf (renew at 3 days remaining, ADR-027) is healthy.
    assert!(!id.renewal.expired);
    assert!(!id.renewal.renew_overdue);
    assert!(id.renewal.expires_in_days > 3);
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
    assert_eq!(id.hostname, TEST_LOCAL_HOSTNAME);
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

    let mut rx = core.watch_status();
    let mut roster_rx = core.watch_roster_snapshot();
    let mut tls_rx = core.watch_tls_identity();
    let mut anchor_rx = core.watch_ca_anchor();
    assert!(!rx.borrow_and_update().posture.signed, "no leaf yet → Open");
    assert!(roster_rx.borrow_and_update().active_members.is_empty());
    assert!(tls_rx.borrow_and_update().material.is_none());
    let initial_anchor = anchor_rx
        .borrow_and_update()
        .anchor()
        .expect("authority CA anchor must be observable")
        .expect("authority CA is the desired trust anchor")
        .clone();
    assert!(initial_anchor.certificate_pem.contains("BEGIN CERTIFICATE"));
    assert!(!format!("{initial_anchor:?}").contains("BEGIN CERTIFICATE"));

    // self_enroll writes the leaf and publishes → Open→Authenticated observed.
    core.self_enroll().await.expect("self-enroll");
    assert!(rx.has_changed().unwrap(), "self-enroll must notify");
    assert!(rx.borrow_and_update().posture.signed);
    assert!(
        roster_rx.has_changed().unwrap(),
        "self-enroll must publish the member"
    );
    let first_roster = roster_rx.borrow_and_update().clone();
    assert_eq!(first_roster.active_members.len(), 1);
    assert!(tls_rx.has_changed().unwrap(), "TLS material must notify");
    let tls = tls_rx
        .borrow_and_update()
        .material
        .as_ref()
        .expect("healthy identity material")
        .clone();
    assert_eq!(tls.hostname, TEST_LOCAL_HOSTNAME);
    assert!(tls.certificate_chain_pem.contains("BEGIN CERTIFICATE"));
    assert!(tls.private_key_pem.contains("BEGIN"));
    assert!(!format!("{tls:?}").contains("BEGIN"));

    // Same-count member mutations are observable too; consumers must never use
    // member count as a substitute for the domain revision.
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    core.add_alias_sans(&hostname, &["alias.internal".to_string()])
        .await
        .expect("add alias");
    assert!(
        roster_rx.has_changed().unwrap(),
        "member update must notify"
    );
    let changed_roster = roster_rx.borrow_and_update().clone();
    assert_eq!(changed_roster.active_members.len(), 1);
    assert!(changed_roster.revision > first_roster.revision);
    assert!(changed_roster.active_members[0]
        .sans
        .contains(&"alias.internal".to_string()));
    assert!(rx.has_changed().unwrap());
    rx.borrow_and_update();
    assert!(
        !tls_rx.has_changed().unwrap(),
        "roster change is not TLS churn"
    );

    // A second self_enroll reuses the current leaf and changes no projection.
    core.self_enroll().await.expect("re-enroll");
    assert!(
        !rx.has_changed().unwrap(),
        "an unchanged posture must not notify"
    );
    assert!(
        !tls_rx.has_changed().unwrap(),
        "an unchanged identity must not notify"
    );

    // destroy tears the identity down → Authenticated→Open observed (a degrade
    // is as loud as the upgrade, ADR-020 §13).
    core.destroy().await.expect("destroy");
    assert!(rx.has_changed().unwrap(), "destroy must notify");
    assert!(!rx.borrow_and_update().posture.signed);
    assert!(
        roster_rx.has_changed().unwrap(),
        "destroy must clear roster"
    );
    assert!(roster_rx.borrow_and_update().active_members.is_empty());
    assert!(tls_rx.has_changed().unwrap(), "destroy must withdraw TLS");
    assert!(tls_rx.borrow_and_update().material.is_none());
    assert!(
        anchor_rx.has_changed().unwrap(),
        "destroy must withdraw the desired trust anchor before returning"
    );
    assert!(anchor_rx
        .borrow_and_update()
        .anchor()
        .expect("destroyed anchor must be observable")
        .is_none());
}

#[test]
fn ca_anchor_projection_distinguishes_unavailable_from_absent() {
    let paths = isolated_posture_paths("anchor-observation-state");
    let ca = ca::create_ca("test-pass", &[6_u8; 32], &paths).unwrap().0;
    let valid_pem = std::fs::read_to_string(paths.ca_cert_path()).unwrap();
    let core = CertmeshCore::new_with_paths(ca, Roster::empty(), None, paths.clone());
    let initial = core.ca_anchor();
    assert!(matches!(
        &initial.state,
        CertmeshCaAnchorState::Available(_)
    ));

    std::fs::write(paths.ca_cert_path(), b"invalid-anchor").unwrap();
    core.state.refresh_status_under_transition();
    let unavailable = core.ca_anchor();
    assert!(unavailable.revision > initial.revision);
    assert!(matches!(
        &unavailable.state,
        CertmeshCaAnchorState::Unavailable { reason } if reason.contains("invalid PEM")
    ));

    core.state.refresh_status_under_transition();
    assert!(Arc::ptr_eq(&unavailable, &core.ca_anchor()));

    std::fs::write(paths.ca_cert_path(), valid_pem).unwrap();
    core.state.refresh_status_under_transition();
    let recovered = core.ca_anchor();
    assert!(recovered.revision > unavailable.revision);
    assert!(matches!(
        &recovered.state,
        CertmeshCaAnchorState::Available(_)
    ));
}

#[tokio::test]
async fn destroy_preserves_slot_ledger_when_owned_label_is_invalid() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    let master_key = koi_crypto::unlock_slots::generate_master_key();
    let table =
        koi_crypto::unlock_slots::SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
    let slot_path = paths.slot_table_path();
    table.save(&slot_path).unwrap();

    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&slot_path).unwrap()).unwrap();
    json["pending_totp_credentials"] = serde_json::json!([{
        "version": 2,
        "credential_id": "../foreign",
        "secret": true,
        "fallback": true
    }]);
    std::fs::write(&slot_path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

    let core = CertmeshCore::uninitialized_with_paths(paths.clone());
    let error = core.destroy().await.unwrap_err();
    assert!(error
        .to_string()
        .contains("invalid TOTP credential ownership id"));
    assert!(
        slot_path.exists(),
        "destroy must retain the ownership ledger"
    );
    assert!(paths.certmesh_dir().exists());
}

#[test]
fn boot_retries_valid_credential_cleanup_and_reports_corrupt_ledgers() {
    let temp = tempfile::tempdir().unwrap();
    let clean_paths = CertmeshPaths::with_data_dir(temp.path().join("cleanup-retry"));
    std::fs::create_dir_all(clean_paths.credential_cleanup_dir()).unwrap();
    let master_key = koi_crypto::unlock_slots::generate_master_key();
    let table =
        koi_crypto::unlock_slots::SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
    let valid_ledger = clean_paths.credential_cleanup_dir().join("valid.json");
    let slot_path = clean_paths.data_dir().join("test-slot-table.json");
    table.save(&slot_path).unwrap();
    let mut slot_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&slot_path).unwrap()).unwrap();
    slot_json["pending_totp_credentials"] = serde_json::json!([{
        "version": 2,
        "credential_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "secret": false,
        "fallback": false
    }]);
    let ledger = CredentialCleanupLedger {
        version: CREDENTIAL_CLEANUP_LEDGER_VERSION,
        totp_slot_table: Some(serde_json::to_vec_pretty(&slot_json).unwrap()),
        delete_auto_unlock_vault: false,
        delete_ca_tpm: false,
    };
    std::fs::write(&valid_ledger, serde_json::to_vec_pretty(&ledger).unwrap()).unwrap();

    let clean = CertmeshCore::load_with_paths(clean_paths.clone(), "internal", TEST_LOCAL_HOSTNAME)
        .unwrap();
    assert!(!clean_paths.credential_cleanup_pending());
    assert!(!clean
        .status()
        .diagnosis
        .checks
        .iter()
        .any(|check| check.name == "credential_cleanup"));

    let corrupt_paths = CertmeshPaths::with_data_dir(temp.path().join("cleanup-corrupt"));
    std::fs::create_dir_all(corrupt_paths.credential_cleanup_dir()).unwrap();
    let corrupt_ledger = corrupt_paths.credential_cleanup_dir().join("corrupt.json");
    std::fs::write(&corrupt_ledger, b"{truncated").unwrap();
    let corrupt =
        CertmeshCore::load_with_paths(corrupt_paths.clone(), "internal", TEST_LOCAL_HOSTNAME)
            .unwrap();
    assert!(corrupt_paths.credential_cleanup_pending());
    let status = corrupt.status();
    let cleanup = status
        .diagnosis
        .checks
        .iter()
        .find(|check| check.name == "credential_cleanup")
        .expect("pending cleanup must be visible");
    assert_eq!(cleanup.status, koi_common::diagnosis::CheckStatus::Warn);
    assert!(
        corrupt_ledger.exists(),
        "corrupt evidence must be preserved"
    );
}

#[tokio::test]
async fn pending_credential_cleanup_fences_a_replacement_trust_generation() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    std::fs::create_dir_all(paths.credential_cleanup_dir()).unwrap();
    let ledger = paths.credential_cleanup_dir().join("unreadable.json");
    std::fs::write(&ledger, b"{truncated").unwrap();
    let core =
        CertmeshCore::load_with_paths(paths.clone(), "internal", TEST_LOCAL_HOSTNAME).unwrap();

    let error = core
        .create(create_request_for_membership_conflict())
        .await
        .expect_err("an older generation's cleanup must complete before replacement");

    assert!(matches!(error, CertmeshError::Conflict(_)));
    assert!(
        ledger.exists(),
        "failed cleanup evidence must remain durable"
    );
    assert!(!paths.ca_key_path().exists());
    assert_eq!(core.status().role, CertmeshRole::Open);
}

#[cfg(feature = "keyring")]
#[tokio::test]
async fn destroy_retires_real_store_totp_slot_before_removing_ledger() {
    struct Cleanup {
        slot_path: std::path::PathBuf,
        probe_label: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if self.slot_path.exists() {
                if let Ok(mut table) = koi_crypto::unlock_slots::SlotTable::load(&self.slot_path) {
                    let _ = table.remove_totp_slot(&self.slot_path);
                }
            }
            let _ = koi_crypto::tpm::delete_key_material(&self.probe_label);
            let _ = koi_crypto::tpm::delete_key_material("koi-certmesh-ca");
        }
    }

    let probe_label = format!("koi-certmesh-destroy-probe-{}", std::process::id());
    if koi_crypto::tpm::seal_key_material(&probe_label, b"probe").is_err() {
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    let (ca, master_key) = ca::create_ca("test-pass", &[17u8; 32], &paths).unwrap();
    let slot_path = paths.slot_table_path();
    let cleanup = Cleanup {
        slot_path: slot_path.clone(),
        probe_label,
    };
    let mut table = koi_crypto::unlock_slots::SlotTable::load(&slot_path).unwrap();
    let secret = koi_crypto::totp::generate_secret();
    table
        .add_totp_slot(&slot_path, &master_key, secret.as_bytes())
        .unwrap();

    let core = CertmeshCore::new_with_paths(ca, Roster::empty(), None, paths.clone());
    core.destroy().await.unwrap();

    assert!(!slot_path.exists());
    assert!(!paths.certmesh_dir().exists());
    drop(cleanup);
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

async fn valid_totp_response(core: &CertmeshCore) -> koi_crypto::auth::AuthResponse {
    let auth = core.state.auth.lock();
    let Some(koi_crypto::auth::AuthState::Totp(secret)) = auth.as_ref() else {
        panic!("test authority must have TOTP auth")
    };
    koi_crypto::auth::AuthResponse::Totp {
        code: koi_crypto::totp::current_code(secret).expect("current TOTP code"),
    }
}

fn promotion_request(
    auth: koi_crypto::auth::AuthResponse,
    ephemeral_public: [u8; 32],
) -> protocol::PromoteRequest {
    protocol::PromoteRequest {
        auth,
        ephemeral_public: Some(ephemeral_public),
    }
}

async fn backup_fixture(tag: &str) -> (CertmeshCore, CertmeshPaths, String) {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let paths = isolated_posture_paths(tag);
    let ca_passphrase = format!("{tag}-ca-passphrase");
    let ca = ca::create_ca(&ca_passphrase, &[31u8; 32], &paths)
        .expect("fixture CA")
        .0;
    let secret = koi_crypto::totp::generate_secret();
    let stored = koi_crypto::auth::store_totp(&secret, &ca_passphrase).expect("store auth");
    std::fs::write(
        paths.auth_path(),
        serde_json::to_vec_pretty(&stored).expect("serialize auth"),
    )
    .expect("write auth");
    let roster = make_test_roster_with_member("surviving-member", MemberRole::Member);
    crate::roster::save_roster(&roster, &paths.roster_path()).expect("persist roster");
    crate::audit::append_entry_to(&paths.audit_log_path(), "fixture_created", &[])
        .expect("write audit");
    let accounts = crate::acme::account::AccountStore::default();
    let prepared = accounts
        .prepare_registration(backup_fixture_account_jwk(), Vec::new())
        .expect("prepare fixture ACME account");
    std::fs::create_dir_all(paths.acme_dir()).expect("create ACME fixture directory");
    std::fs::write(
        paths.acme_accounts_path(),
        prepared.bytes.as_ref().expect("new account bytes"),
    )
    .expect("persist fixture ACME account");
    let core = CertmeshCore::new_with_paths(
        ca,
        roster,
        Some(koi_crypto::auth::AuthState::Totp(secret)),
        paths.clone(),
    );
    core.state.acme_accounts.commit_registration(&prepared);
    (core, paths, ca_passphrase)
}

fn backup_fixture_account_jwk() -> crate::acme::jws::Jwk {
    crate::acme::jws::Jwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "backup-account-x".into(),
        y: "backup-account-y".into(),
    }
}

#[tokio::test]
async fn failed_backup_preparation_writes_and_publishes_nothing() {
    let (core, paths, _ca_passphrase) = backup_fixture("backup-preparation-failure").await;
    let tracked = [
        paths.ca_key_path(),
        paths.slot_table_path(),
        paths.auth_path(),
        paths.roster_path(),
        paths.audit_log_path(),
    ];
    let before_files: Vec<_> = tracked
        .iter()
        .map(|path| std::fs::read(path).unwrap())
        .collect();
    let before_status = core.status();
    let before_roster = core.roster_snapshot();
    let before_tls = core.tls_identity();
    let mut events = core.subscribe();

    core.backup("wrong-ca-passphrase", "backup-passphrase")
        .await
        .expect_err("CA preparation must reject the wrong passphrase");

    for (path, before) in tracked.iter().zip(before_files) {
        assert_eq!(std::fs::read(path).unwrap(), before, "{}", path.display());
    }
    assert!(Arc::ptr_eq(&before_status, &core.status()));
    assert!(Arc::ptr_eq(&before_roster, &core.roster_snapshot()));
    assert!(Arc::ptr_eq(&before_tls, &core.tls_identity()));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn restore_prevalidates_mismatched_ca_before_writing() {
    let (source, _source_paths, ca_passphrase) = backup_fixture("restore-mismatch-source").await;
    let backup_passphrase = "restore-mismatch-backup";
    let bundle = source
        .backup(&ca_passphrase, backup_passphrase)
        .await
        .expect("create backup");
    let mut payload = crate::backup::decode_backup(&bundle, backup_passphrase).unwrap();
    let foreign_paths = isolated_posture_paths("restore-mismatch-foreign");
    let foreign = ca::create_ca("foreign-passphrase", &[32u8; 32], &foreign_paths)
        .unwrap()
        .0;
    payload.ca_cert_pem = foreign.cert_pem;
    let inconsistent = crate::backup::encode_backup(&payload, backup_passphrase).unwrap();

    let target_paths = isolated_posture_paths("restore-mismatch-target");
    let target = CertmeshCore::uninitialized_with_paths(target_paths.clone());
    let error = target
        .restore(&inconsistent, backup_passphrase, "new-passphrase")
        .await
        .expect_err("mismatched CA material must be rejected");

    assert!(error.to_string().contains("does not match"));
    assert!(
        !target_paths.is_ca_initialized(),
        "validation failure must happen before the first target write"
    );
    assert_eq!(target.posture(), koi_common::posture::Posture::OPEN);
}

#[tokio::test]
async fn restore_rebinds_activates_and_clears_member_only_state() {
    let (source, _source_paths, ca_passphrase) = backup_fixture("restore-clean-source").await;
    let source_fingerprint = source.ca_fingerprint().await.unwrap();
    let backup_passphrase = "restore-clean-backup";
    let bundle = source
        .backup(&ca_passphrase, backup_passphrase)
        .await
        .expect("create backup");

    let target_paths = isolated_posture_paths("restore-clean-target");
    crate::member::save(
        &target_paths.member_state_path(),
        &posture_member_state("former-member"),
    )
    .unwrap();
    std::fs::write(target_paths.invites_path(), b"stale invites").unwrap();
    std::fs::create_dir_all(target_paths.ca_dir()).unwrap();
    std::fs::write(target_paths.rate_limiter_path(), b"stale throttle").unwrap();
    std::fs::create_dir_all(target_paths.acme_dir()).unwrap();
    std::fs::write(target_paths.acme_accounts_path(), b"stale accounts").unwrap();
    CertmeshCore::save_auto_unlock_key_at(&target_paths, "stale-auto-unlock").unwrap();
    let target = CertmeshCore::uninitialized_with_paths(target_paths.clone());
    let mut status_rx = target.watch_status();
    assert!(!status_rx.borrow_and_update().posture.signed);

    target
        .restore(&bundle, backup_passphrase, "restored-passphrase")
        .await
        .expect("restore succeeds");

    assert!(
        status_rx.has_changed().unwrap(),
        "restore must publish posture"
    );
    assert!(status_rx.borrow_and_update().posture.signed);
    assert_eq!(target.ca_fingerprint().await.unwrap(), source_fingerprint);
    let identity = target
        .local_identity()
        .await
        .expect("restored self identity");
    assert!(crate::diagnosis::identity_material_is_usable(
        &identity.cert_pem,
        &identity.key_pem,
        &identity.ca_cert_pem
    ));
    assert!(target
        .status()
        .authority
        .as_ref()
        .unwrap()
        .members
        .iter()
        .any(|member| member.hostname == "surviving-member"));
    assert!(!target_paths.member_state_path().exists());
    assert!(!target_paths.invites_path().exists());
    assert!(!target_paths.rate_limiter_path().exists());
    let restored_account_id = crate::acme::jws::jwk_thumbprint(&backup_fixture_account_jwk());
    assert!(target_paths.acme_accounts_path().exists());
    assert!(target
        .state
        .acme_accounts
        .get(&restored_account_id)
        .is_some());
    assert!(ca::load_ca("restored-passphrase", &target_paths).is_ok());
    assert!(ca::load_ca(&ca_passphrase, &target_paths).is_err());
    assert!(machine_binding_ok(&target_paths));
    if koi_crypto::vault::machine_fingerprint().is_some() {
        assert!(target_paths.machine_bind_path().exists());
    }
    let audit = crate::audit::read_log_from(&target_paths.audit_log_path()).unwrap();
    assert!(audit.contains("fixture_created"));
    assert!(audit.contains("backup_restored"));
    assert!(CertmeshCore::read_auto_unlock_key(&target_paths)
        .unwrap()
        .is_none());
    let restarted =
        CertmeshCore::load_with_paths(target_paths, "internal", TEST_LOCAL_HOSTNAME).unwrap();
    assert!(restarted.status().authority.as_ref().unwrap().locked);
}

#[tokio::test]
async fn self_enroll_replaces_fresh_leaf_from_a_different_ca() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let paths = isolated_posture_paths("self-enroll-stale-ca");
    let current = ca::create_ca("current-pass", &[41u8; 32], &paths)
        .unwrap()
        .0;
    let foreign_paths = isolated_posture_paths("self-enroll-stale-ca-foreign");
    let foreign = ca::create_ca("foreign-pass", &[42u8; 32], &foreign_paths)
        .unwrap()
        .0;
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    let sans = vec![hostname.clone(), format!("{hostname}.internal")];
    let stale = ca::issue_certificate(&foreign, &hostname, &sans, 90).unwrap();
    crate::certfiles::write_cert_files_to(&paths.certs_dir().join(&hostname), &stale).unwrap();
    let stale_pem = stale.cert_pem;
    let core = CertmeshCore::new_with_paths(
        current,
        Roster::new(JUST_ME.0, JUST_ME.1, None),
        None,
        paths,
    );

    let repaired = core.self_enroll().await.expect("self-enroll repairs leaf");

    assert_ne!(repaired.cert_pem, stale_pem);
    assert!(crate::diagnosis::identity_material_is_usable(
        &repaired.cert_pem,
        &repaired.key_pem,
        &repaired.ca_cert_pem
    ));
}

#[tokio::test]
async fn member_csr_uses_the_core_configured_zone() {
    let paths = CertmeshPaths::with_data_dir(
        koi_common::test::ensure_data_dir("koi-certmesh-zone-tests").join("member-csr"),
    );
    let core = CertmeshCore::uninitialized_with_paths(paths)
        .with_dns_zone("Lab.Internal.")
        .unwrap();
    let csr = core
        .prepare_member_csr("Node-A", &[])
        .await
        .expect("member CSR");
    let names = csr::requested_sans(&csr).unwrap();
    assert!(names.contains(&"node-a".to_string()));
    assert!(names.contains(&"node-a.lab.internal".to_string()));
    assert!(!names.contains(&"node-a.local".to_string()));
    assert_eq!(core.dns_zone(), "lab.internal");
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
        .mint_invite("renew-host", 60, None)
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
            role: None,
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
            None,
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

    // Point the armed member state at the ephemeral test port.
    let mut st = member::load(&member_paths.member_state_path())
        .expect("read renewal state")
        .expect("renewal armed");
    assert_eq!(st.ca_host, "127.0.0.1");
    st.ca_mtls_port = port;
    #[cfg(unix)]
    let reload_sentinel = member_paths.data_dir().join("reload-completed");
    #[cfg(unix)]
    {
        let hook = member_paths.data_dir().join("reload-hook.sh");
        write_executable_script(&hook, &format!("touch '{}'", reload_sentinel.display()));
        st.reload_hook = Some(hook.display().to_string());
    }
    member::save(&member_paths.member_state_path(), &st).unwrap();

    let cert_dir = member_paths.certs_dir().join("renew-host");
    let old_key = std::fs::read_to_string(cert_dir.join("key.pem")).unwrap();
    let old_cert = std::fs::read_to_string(cert_dir.join("cert.pem")).unwrap();

    // A fresh leaf is not scheduled for renewal, but the operator can request an
    // immediate rotation through the same CSR-only mTLS transaction.
    let scheduled = member_core
        .renew_self_if_due()
        .await
        .expect("scheduled check ok");
    assert!(matches!(scheduled, RenewOutcome::NotDue { .. }));

    // ── Member pulls the operator-requested renewal over mTLS ──
    #[cfg(unix)]
    {
        member_core
            .state
            .repository
            .pause_next_commit_after_durable();
        let command = {
            let member_core = member_core.clone();
            tokio::spawn(async move { member_core.renew_self().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !member_core.state.repository.is_commit_paused() && !command.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("renewal must reach durable commit or settle");
        if command.is_finished() {
            let result = command.await;
            panic!("renewal exited before its durable commit barrier: {result:?}");
        }
        assert!(
            member_paths.reload_intent_path().exists(),
            "certificate activation must durably record reload intent"
        );
        assert!(
            member_core.status().reload.is_none(),
            "status cannot lead the durable commit tail"
        );
        command.abort();
        member_core.state.repository.release_commit();
        let _ = command.await;

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if reload_sentinel.exists()
                    && !member_paths.reload_intent_path().exists()
                    && member_core.status().reload.is_none()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained reload worker must execute and settle without a request retry");
    }
    #[cfg(not(unix))]
    {
        let outcome = member_core.renew_self().await.expect("renewal ok");
        assert!(
            matches!(outcome, RenewOutcome::Renewed { .. }),
            "expected Renewed, got {outcome:?}"
        );
    }

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
        let roster = ca_core.state.roster.lock();
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

#[cfg(unix)]
#[test]
fn startup_reconciles_a_durable_reload_intent_and_publishes_completion() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    let release = temp.path().join("release-hook");
    let sentinel = temp.path().join("reload-completed");
    let hook = temp.path().join("startup-reload.sh");
    write_executable_script(
        &hook,
        &format!(
            "while [ ! -f '{}' ]; do /bin/sleep 0.01; done\ntouch '{}'",
            release.display(),
            sentinel.display()
        ),
    );
    let intent = lifecycle::ReloadIntent::new(hook.display().to_string(), "new-leaf-fp".into());
    std::fs::write(
        paths.reload_intent_path(),
        lifecycle::render_intent(&intent).unwrap(),
    )
    .unwrap();

    let core =
        CertmeshCore::load_with_paths(paths.clone(), "internal", TEST_LOCAL_HOSTNAME).unwrap();
    let initial = core.status();
    assert_eq!(
        initial
            .reload
            .as_ref()
            .and_then(|reload| reload.certificate_fingerprint.as_deref()),
        Some("new-leaf-fp")
    );
    let mut events = core.subscribe();
    std::fs::write(&release, b"go").unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while (!sentinel.exists() || core.status().reload.is_some())
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(sentinel.exists());
    assert!(!paths.reload_intent_path().exists());
    assert!(core.status().reload.is_none());
    assert!(core.status().revision > initial.revision);
    assert!(matches!(
        events.try_recv().unwrap(),
        CertmeshEvent::ReloadHookCompleted { command } if command == hook.display().to_string()
    ));
}

#[cfg(unix)]
#[test]
fn failed_startup_reload_remains_durable_and_observable_for_retry() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    let release = temp.path().join("release-hook");
    let hook = temp.path().join("failing-reload.sh");
    write_executable_script(
        &hook,
        &format!(
            "while [ ! -f '{}' ]; do /bin/sleep 0.01; done\nexit 7",
            release.display()
        ),
    );
    let intent = lifecycle::ReloadIntent::new(hook.display().to_string(), "new-leaf-fp".into());
    std::fs::write(
        paths.reload_intent_path(),
        lifecycle::render_intent(&intent).unwrap(),
    )
    .unwrap();

    let core =
        CertmeshCore::load_with_paths(paths.clone(), "internal", TEST_LOCAL_HOSTNAME).unwrap();
    let initial = core.status();
    assert!(initial.reload.is_some());
    let mut events = core.subscribe();
    std::fs::write(&release, b"go").unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while core
        .status()
        .reload
        .as_ref()
        .is_none_or(|reload| reload.attempts == 0)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let status = core.status();
    let reload = status
        .reload
        .as_ref()
        .expect("failed intent remains pending");
    assert_eq!(reload.attempts, 1);
    assert!(reload
        .last_error
        .as_deref()
        .is_some_and(|error| error.contains("exit status")));
    assert!(paths.reload_intent_path().exists());
    assert!(status.revision > initial.revision);
    assert!(status
        .diagnosis
        .checks
        .iter()
        .any(|check| check.name == "certificate_reload"));
    assert!(matches!(
        events.try_recv().unwrap(),
        CertmeshEvent::ReloadHookFailed { command, .. } if command == hook.display().to_string()
    ));
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
    let invite = ca_core
        .mint_invite("bundle-host", 60, None)
        .await
        .unwrap()
        .token;
    ca_core
        .enroll(&protocol::JoinRequest {
            hostname: "bundle-host".to_string(),
            auth: None,
            invite_token: Some(invite),
            csr: Some(csr),
            sans: vec!["bundle-host".to_string()],
            role: None,
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
            last_bundle_digest: None,
            revoked_fingerprints: Vec::new(),
            self_revoked: false,
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
    let stored = member::load(&member_paths.member_state_path())
        .unwrap()
        .unwrap();
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

    // A freshly timestamped signature of the same semantic generation is an
    // exact no-op. Injecting a failure into the *next* commit proves this path
    // does not manufacture a repository write while returning NoChange.
    let same_generation = ca_core.signed_trust_bundle().await.unwrap();
    let member_bytes = std::fs::read(member_paths.member_state_path()).unwrap();
    let status_before = member_core.status();
    member_core.state.repository.fail_next_commit_after(0);
    assert!(matches!(
        member_core
            .apply_trust_bundle(&same_generation)
            .await
            .unwrap(),
        BundleOutcome::NoChange { .. }
    ));
    assert_eq!(
        std::fs::read(member_paths.member_state_path()).unwrap(),
        member_bytes
    );
    assert!(Arc::ptr_eq(&status_before, &member_core.status()));

    // The CA key can authenticate a document, but it cannot mutate one roster
    // generation under the same seq. The member's semantic digest rejects that
    // equivocation without changing persistence or its cheap status face.
    let mut equivocated_roster = ca_core.state.roster.lock().clone();
    equivocated_roster.metadata.policy.renew_threshold_days = equivocated_roster
        .metadata
        .policy
        .renew_threshold_days
        .saturating_add(1);
    let equivocated = {
        let ca = ca_core.state.ca.lock();
        bundle::sign(
            &equivocated_roster,
            ca.as_ref().unwrap(),
            chrono::Utc::now().to_rfc3339(),
        )
        .unwrap()
    };
    let error = member_core
        .apply_trust_bundle(&equivocated)
        .await
        .expect_err("same-sequence semantic equivocation must be rejected");
    assert!(error.to_string().contains("different semantic contents"));
    assert_eq!(
        std::fs::read(member_paths.member_state_path()).unwrap(),
        member_bytes
    );
    assert!(Arc::ptr_eq(&status_before, &member_core.status()));

    server.abort();
    let _ = std::fs::remove_dir_all(base.join("ca"));
    let _ = std::fs::remove_dir_all(base.join("member"));
}

/// ADR-023 §3: a member applies the bundle's **cross-member** revoked set, so its local
/// `verify`/`open` reject *other* revoked members — not just itself. The previous behavior
/// read the bundle's revoked set only to compute self-revocation and discarded the rest.
#[tokio::test]
async fn trust_bundle_applies_cross_member_revocation() {
    let base = koi_common::test::ensure_data_dir("koi-certmesh-xrevoke").join("xrevoke");
    let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
    let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
    let _ = std::fs::remove_dir_all(ca_paths.data_dir());
    let _ = std::fs::remove_dir_all(member_paths.data_dir());

    // CA with two enrolled hosts: the member M, and a peer P that will be revoked.
    let (ca_state, _m) = ca::create_ca("xrev", &[6u8; 32], &ca_paths).unwrap();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
    let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());
    for host in ["m-host", "p-host"] {
        let (_k, csr) = csr::generate_keypair_and_csr(host, &[host.to_string()]).unwrap();
        let invite = ca_core.mint_invite(host, 60, None).await.unwrap().token;
        ca_core
            .enroll(&protocol::JoinRequest {
                hostname: host.to_string(),
                auth: None,
                invite_token: Some(invite),
                csr: Some(csr),
                sans: vec![host.to_string()],
                role: None,
            })
            .await
            .unwrap();
    }
    let pin = ca::ca_fingerprint_from_disk(&ca_paths).unwrap();

    // Revoke the PEER (not the member).
    ca_core
        .revoke_member("p-host", Some("op".into()), Some("compromised".into()))
        .await
        .unwrap();
    // The peer's fingerprint as the CA holds it (what the bundle will carry).
    let p_fp = ca_core
        .status()
        .authority
        .as_ref()
        .unwrap()
        .members
        .iter()
        .find(|m| m.hostname == "p-host")
        .expect("peer in roster")
        .cert_fingerprint
        .clone();
    assert!(!p_fp.is_empty(), "peer has a recorded fingerprint");

    // Serve the certmesh routes (incl. GET /trust-bundle) over plain HTTP.
    let app = Router::new().nest("/v1/certmesh", crate::http::routes(ca_core.state.clone()));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    // Arm the member with a pin + fresh anti-rollback floor.
    member::save(
        &member_paths.member_state_path(),
        &member::MemberState {
            hostname: "m-host".to_string(),
            ca_host: "127.0.0.1".to_string(),
            ca_mtls_port: 5642,
            ca_http_port: port,
            ca_fingerprint: pin.clone(),
            sans: vec!["m-host".to_string()],
            policy: crate::roster::CertPolicy::default(),
            last_bundle_seq: 0,
            last_bundle_digest: None,
            revoked_fingerprints: Vec::new(),
            self_revoked: false,
            reload_hook: None,
        },
    )
    .unwrap();
    let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());

    // Pull → M is NOT self-revoked, but it applies the peer's revocation.
    match member_core.pull_trust_bundle().await.expect("pull ok") {
        BundleOutcome::Updated { self_revoked, .. } => {
            assert!(!self_revoked, "the member itself is not revoked")
        }
        other => panic!("expected Updated, got {other:?}"),
    }

    // The cross-member revoked fingerprint is persisted in member.json...
    let stored = member::load(&member_paths.member_state_path())
        .unwrap()
        .unwrap();
    assert!(
        stored.revoked_fingerprints.contains(&p_fp),
        "member persisted the peer's revoked fingerprint"
    );
    // ...and surfaces through revoked_fingerprints() — the exact slice verify()/open()
    // consume — so the member now rejects the peer's envelopes despite keeping no roster.
    let honored = member_core.revoked_fingerprints().await.unwrap();
    assert!(
        honored.contains(&p_fp),
        "verify()/open() now honor the peer's revocation on a pure member"
    );

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

/// A pre-zone roster remains renewable after an upgrade: the central policy
/// adds the configured FQDN to both CSR authorization and the committed roster
/// while retaining historical legitimate names.
#[tokio::test]
async fn renewal_migrates_legacy_names_to_the_configured_zone() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("legacy-host", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster)
        .with_dns_zone("lab.internal")
        .unwrap();
    let requested = [
        "legacy-host".to_string(),
        "legacy-host.lab.internal".to_string(),
        "legacy-host.local".to_string(),
    ];
    let (_key, csr) = csr::generate_keypair_and_csr("legacy-host", &requested).unwrap();

    core.renew_member("legacy-host", &csr)
        .await
        .expect("legacy member renews with configured-zone name");

    let roster = core.state.roster.lock();
    let member = roster.find_member("legacy-host").unwrap();
    assert!(member
        .cert_sans
        .contains(&"legacy-host.lab.internal".into()));
    assert!(member.cert_sans.contains(&"legacy-host.local".into()));
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
        let roster = core.state.roster.lock();
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

/// Once renewal has crossed the repository commit point, the retained Certmesh
/// worker — not the request future — owns the roster, status, and event tail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_renew_member_converges_after_durable_commit_without_retry() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    let ca = ca::create_ca("renew-cancel-pass", &[78_u8; 32], &paths)
        .unwrap()
        .0;
    let roster = make_test_roster_with_member("good-host", MemberRole::Primary);
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths.clone());
    let initial_revision = core.status().revision;
    let mut events = core.subscribe();
    let (_key, csr) = csr::generate_keypair_and_csr(
        "good-host",
        &["good-host".to_string(), "good-host.local".to_string()],
    )
    .unwrap();
    core.state.repository.pause_next_commit_after_durable();

    let command = {
        let core = core.clone();
        tokio::spawn(async move { core.renew_member("good-host", &csr).await })
    };
    while !core.state.repository.is_commit_paused() {
        tokio::task::yield_now().await;
    }

    let durable = roster::load_roster(&paths.roster_path()).unwrap();
    let durable_member = durable.find_member("good-host").unwrap();
    assert_ne!(durable_member.cert_fingerprint, "fp-test");
    command.abort();
    core.state.repository.release_commit();
    let _ = command.await;

    let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let status = core.status();
            let renewed = status
                .authority
                .as_ref()
                .and_then(|authority| {
                    authority
                        .members
                        .iter()
                        .find(|member| member.hostname == "good-host")
                })
                .is_some_and(|member| member.cert_fingerprint != "fp-test");
            if status.revision > initial_revision && renewed {
                break status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("renewal tail must publish model/status after caller cancellation");
    let model_fingerprint = core
        .state
        .roster
        .lock()
        .find_member("good-host")
        .unwrap()
        .cert_fingerprint
        .clone();
    assert_eq!(model_fingerprint, durable_member.cert_fingerprint);
    assert!(status.revision > initial_revision);
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap(),
        CertmeshEvent::CertRenewed { .. }
    ));
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
    let invite = ca_core.mint_invite("pin-host", 60, None).await.unwrap();
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
            role: None,
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
            None,
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
        member::load(&member_paths.member_state_path())
            .unwrap()
            .is_none(),
        "renewal must not be armed on pin mismatch"
    );

    // Correct pin (the one embedded in the invite) → installs + arms.
    let dir = member_core
        .install_member_cert(
            "pin-host",
            &join.service_cert,
            &join.ca_cert,
            Some("http://127.0.0.1:5641"),
            Some(16542),
            Some(&real_fp),
            &["pin-host".to_string()],
            Some(join.policy.clone()),
        )
        .await
        .unwrap();
    assert!(std::path::Path::new(&dir).join("cert.pem").exists());
    assert!(
        !std::path::Path::new(&dir).join("key.pending.pem").exists(),
        "successful install consumes the pending key"
    );
    let armed = member::load(&member_paths.member_state_path())
        .expect("read renewal state")
        .expect("correct pin arms renewal");
    assert_eq!(armed.ca_mtls_port, 16542);

    let _ = std::fs::remove_dir_all(base.join("ca"));
    let _ = std::fs::remove_dir_all(base.join("member"));
}

/// Joining is not an identity-replacement path. Once a durable member identity
/// exists, both CSR preparation and certificate installation fail closed until
/// an explicit destroy/leave, preserving all active artifacts byte-for-byte.
#[tokio::test]
async fn refused_rejoin_cannot_replace_active_member_identity() {
    let base =
        koi_common::test::ensure_data_dir("koi-certmesh-rejoin-custody").join("rejoin-custody");
    let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
    let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
    let _ = std::fs::remove_dir_all(ca_paths.data_dir());
    let _ = std::fs::remove_dir_all(member_paths.data_dir());

    let (ca_state, _m) = ca::create_ca("custody", &[13u8; 32], &ca_paths).unwrap();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
    let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());
    let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());

    let sans = ["custody-host".to_string()];
    let csr = member_core
        .prepare_member_csr("custody-host", &sans)
        .await
        .unwrap();
    let invite = ca_core.mint_invite("custody-host", 60, None).await.unwrap();
    let join = ca_core
        .enroll(&protocol::JoinRequest {
            hostname: "custody-host".to_string(),
            auth: None,
            invite_token: Some(invite::decode_code(&invite.token).0.to_string()),
            csr: Some(csr),
            sans: sans.to_vec(),
            role: None,
        })
        .await
        .unwrap();
    member_core
        .install_member_cert(
            "custody-host",
            &join.service_cert,
            &join.ca_cert,
            Some("http://127.0.0.1:5641"),
            None,
            Some(&join.ca_fingerprint),
            &sans,
            Some(join.policy.clone()),
        )
        .await
        .unwrap();

    let cert_dir = member_paths.certs_dir().join("custody-host");
    let active_key = std::fs::read(cert_dir.join("key.pem")).unwrap();
    let active_cert = std::fs::read(cert_dir.join("cert.pem")).unwrap();

    let prepare_error = member_core
        .prepare_member_csr("custody-host", &sans)
        .await
        .unwrap_err();
    assert!(matches!(prepare_error, CertmeshError::Conflict(_)));
    assert_eq!(std::fs::read(cert_dir.join("key.pem")).unwrap(), active_key);
    assert_eq!(
        std::fs::read(cert_dir.join("cert.pem")).unwrap(),
        active_cert
    );

    // Even a caller holding otherwise valid signed material cannot replace the
    // identity through the join command.
    let error = member_core
        .install_member_cert(
            "custody-host",
            &join.service_cert,
            &join.ca_cert,
            Some("http://127.0.0.1:5641"),
            None,
            Some(&join.ca_fingerprint),
            &sans,
            Some(join.policy),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, CertmeshError::Conflict(_)));
    assert_eq!(std::fs::read(cert_dir.join("key.pem")).unwrap(), active_key);
    assert_eq!(
        std::fs::read(cert_dir.join("cert.pem")).unwrap(),
        active_cert
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
    let invite = ca_core.mint_invite("heal-host", 60, None).await.unwrap();
    let (secret, fp) = invite::decode_code(&invite.token);
    let pin = fp.unwrap().to_string();
    let join = ca_core
        .enroll(&protocol::JoinRequest {
            hostname: "heal-host".to_string(),
            auth: None,
            invite_token: Some(secret.to_string()),
            csr: Some(csr),
            sans: vec!["heal-host".to_string()],
            role: None,
        })
        .await
        .unwrap();
    member_core
        .install_member_cert(
            "heal-host",
            &join.service_cert,
            &join.ca_cert,
            Some("http://127.0.0.1:5641"),
            None,
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
    let mut st = member::load(&member_paths.member_state_path())
        .unwrap()
        .unwrap();
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
    let roster = core.state.roster.lock();
    assert!(roster.members[0].last_seen.is_some());
}

// ── promote ──────────────────────────────────────────────────────

#[tokio::test]
async fn promote_returns_error_when_ca_locked() {
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_locked_core(roster);
    let dummy_pk = [0u8; 32];
    let request = promotion_request(
        koi_crypto::auth::AuthResponse::Totp {
            code: "000000".into(),
        },
        dummy_pk,
    );
    let result = core.promote("node-01", &request).await;
    assert!(matches!(result, Err(CertmeshError::CaLocked)));
}

#[tokio::test]
async fn promote_returns_encrypted_material() {
    let ca = make_test_ca();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let core = make_unlocked_core(ca, roster);

    let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
    let client_pub = client_kp.public_key_bytes();

    let request = promotion_request(valid_totp_response(&core).await, client_pub);
    let response = core.promote("node-01", &request).await.unwrap();
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

    let request = promotion_request(valid_totp_response(&core).await, client_pub);
    let response = core.promote("node-01", &request).await.unwrap();
    assert!(response.ephemeral_public.is_some());

    // Accept the promotion on the standby side using DH
    let (ca_key, accepted_auth, accepted_roster, _accepted_accounts) =
        failover::accept_promotion(&response, client_kp).unwrap();
    assert!(!ca_key.public_key_pem().unwrap().is_empty());
    assert_eq!(accepted_auth.method_name(), "totp");
    assert_eq!(accepted_roster.members.len(), 1);
}

#[tokio::test]
async fn accepted_promotion_is_atomic_and_cancellation_cannot_split_its_committed_tail() {
    let source_temp = tempfile::tempdir().unwrap();
    let target_temp = tempfile::tempdir().unwrap();
    let source_paths = CertmeshPaths::with_data_dir(source_temp.path().join("source"));
    let target_paths = CertmeshPaths::with_data_dir(target_temp.path().join("target"));
    let (source_ca, _) = ca::create_ca("source-pass", &[73u8; 32], &source_paths).unwrap();
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    let target_sans = vec![hostname.clone()];
    let target_identity = ca::issue_certificate(&source_ca, &hostname, &target_sans, 30).unwrap();
    crate::certfiles::write_cert_files_to(
        &target_paths.certs_dir().join(&hostname),
        &target_identity,
    )
    .unwrap();
    crate::member::save(
        &target_paths.member_state_path(),
        &crate::member::MemberState {
            hostname: hostname.clone(),
            ca_host: "source".into(),
            ca_mtls_port: crate::member::DEFAULT_CA_MTLS_PORT,
            ca_http_port: crate::member::DEFAULT_CA_HTTP_PORT,
            ca_fingerprint: ca::ca_fingerprint(&source_ca),
            sans: target_sans,
            policy: crate::roster::CertPolicy::default(),
            last_bundle_seq: 0,
            last_bundle_digest: None,
            revoked_fingerprints: Vec::new(),
            self_revoked: false,
            reload_hook: None,
        },
    )
    .unwrap();
    let source_roster = make_test_roster_with_member(&hostname, MemberRole::Primary);
    let source_secret = koi_crypto::totp::generate_secret();
    let source_code_secret =
        koi_crypto::totp::TotpSecret::from_bytes(source_secret.as_bytes().to_vec());
    let source = CertmeshCore::new_with_paths(
        source_ca,
        source_roster,
        Some(koi_crypto::auth::AuthState::Totp(source_secret)),
        source_paths,
    );
    let promotion_account_jwk = crate::acme::jws::Jwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "promotion-account-x".into(),
        y: "promotion-account-y".into(),
    };
    let promotion_account_id = crate::acme::jws::jwk_thumbprint(&promotion_account_jwk);
    let prepared_account = source
        .state
        .acme_accounts
        .prepare_registration(promotion_account_jwk, Vec::new())
        .unwrap();
    source
        .state
        .acme_accounts
        .commit_registration(&prepared_account);
    let target =
        CertmeshCore::load_with_paths(target_paths.clone(), "internal", TEST_LOCAL_HOSTNAME)
            .unwrap();
    assert_eq!(target.status().role, CertmeshRole::Member);
    assert_eq!(
        target.status().identity.condition,
        IdentityCondition::Healthy
    );
    let mut events = target.subscribe();
    let before = target.status();
    let before_tls = target.tls_identity();

    let session = target.begin_promotion_acceptance().await.unwrap();
    let client_public: [u8; 32] = koi_common::encoding::hex_decode(&session.ephemeral_public)
        .unwrap()
        .try_into()
        .unwrap();
    let prepare = promotion_request(
        koi_crypto::auth::AuthResponse::Totp {
            code: koi_crypto::totp::current_code(&source_code_secret).unwrap(),
        },
        client_public,
    );
    let promotion = source.promote(&hostname, &prepare).await.unwrap();
    target.state.repository.fail_next_commit_after(2);
    let error = target
        .accept_promotion(protocol::AcceptPromotionRequest {
            session_id: session.session_id,
            promotion,
            passphrase: "target-pass".into(),
        })
        .await
        .expect_err("injected artifact failure must reject promotion");
    assert!(matches!(
        error,
        CertmeshError::Io(_) | CertmeshError::Internal(_)
    ));
    assert!(Arc::ptr_eq(&before, &target.status()));
    assert!(Arc::ptr_eq(&before_tls, &target.tls_identity()));
    assert!(!target_paths.ca_key_path().exists());
    assert!(target
        .state
        .acme_accounts
        .get(&promotion_account_id)
        .is_none());
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let session = target.begin_promotion_acceptance().await.unwrap();
    let client_public: [u8; 32] = koi_common::encoding::hex_decode(&session.ephemeral_public)
        .unwrap()
        .try_into()
        .unwrap();
    let prepare = promotion_request(
        koi_crypto::auth::AuthResponse::Totp {
            code: koi_crypto::totp::current_code(&source_code_secret).unwrap(),
        },
        client_public,
    );
    let promotion = source.promote(&hostname, &prepare).await.unwrap();
    target.state.repository.pause_next_commit_after_durable();
    let command = {
        let target = target.clone();
        tokio::spawn(async move {
            target
                .accept_promotion(protocol::AcceptPromotionRequest {
                    session_id: session.session_id,
                    promotion,
                    passphrase: "target-pass".into(),
                })
                .await
        })
    };
    while !target.state.repository.is_commit_paused() {
        tokio::task::yield_now().await;
    }
    assert!(
        target_paths.ca_key_path().exists(),
        "the cancellation point must be after durable promotion"
    );
    command.abort();
    target.state.repository.release_commit();
    let _ = command.await;

    let promoted_status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let status = target.status();
            if status.role == CertmeshRole::Authority {
                break status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retained promotion must converge status without a retry");
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
        .await
        .expect("promotion event timeout")
        .expect("promotion event");
    assert!(matches!(
        event,
        CertmeshEvent::PromotedToAuthority {
            hostname: ref promoted,
        } if promoted == &hostname
    ));
    // An event observer can immediately read the committed projection and files.
    assert_eq!(promoted_status.role, CertmeshRole::Authority);
    assert!(target.tls_identity().material.is_some());
    assert!(Arc::ptr_eq(&before_tls, &target.tls_identity()));
    assert!(target_paths.ca_key_path().exists());
    assert!(target_paths.roster_path().exists());
    assert!(target_paths.acme_accounts_path().exists());
    assert!(target
        .state
        .acme_accounts
        .get(&promotion_account_id)
        .is_some());
}

// ── injected local hostname ──────────────────────────────────────

#[test]
fn unit_fixture_core_has_an_explicit_local_hostname() {
    let core = CertmeshCore::uninitialized_with_paths(isolated_posture_paths("fixture-host"));
    assert_eq!(
        core.configured_local_hostname().as_deref(),
        Some(TEST_LOCAL_HOSTNAME)
    );
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
    let mut rl = load_rate_limiter(&paths).unwrap();
    assert!(!rl.is_locked());

    // Drive it into lockout, then persist.
    for _ in 0..3 {
        let _ = rl.check_and_record(false);
    }
    assert!(rl.is_locked(), "limiter must lock after MAX_FAILURES");
    let mut transaction = crate::repository::ArtifactTransaction::new();
    transaction.write(
        paths.rate_limiter_path(),
        serde_json::to_vec(&rl).unwrap(),
        true,
    );
    crate::repository::CertmeshRepository::new(paths.data_dir().to_path_buf())
        .commit_durable(transaction)
        .unwrap();

    // A fresh load (simulating a daemon restart) must still be locked (F7).
    let reloaded = load_rate_limiter(&paths).unwrap();
    assert!(
        reloaded.is_locked(),
        "persisted lockout must survive a restart"
    );

    let _ = std::fs::remove_dir_all(paths.data_dir());
}

// ── build_status ─────────────────────────────────────────────────

#[test]
fn build_status_locked_ca() {
    let paths = isolated_posture_paths("status-locked");
    ca::create_ca("test-pass", &[51u8; 32], &paths).unwrap();
    let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
    let status = status::build(
        &paths,
        Some(TEST_LOCAL_HOSTNAME),
        false,
        None,
        &roster,
        None,
        0,
    );
    let authority = status.authority.unwrap();
    assert!(authority.locked);
    assert_eq!(authority.member_count, 1);
    assert_eq!(authority.members.len(), 1);
    assert_eq!(authority.members[0].hostname, "node-01");
    assert_eq!(authority.members[0].role, "primary");
}

#[test]
fn build_status_unlocked_ca() {
    let paths = isolated_posture_paths("status-unlocked");
    let ca = ca::create_ca("test-pass", &[52u8; 32], &paths).unwrap().0;
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let status = status::build(
        &paths,
        Some(TEST_LOCAL_HOSTNAME),
        true,
        Some(ca::ca_fingerprint(&ca)),
        &roster,
        None,
        0,
    );
    let authority = status.authority.unwrap();
    assert!(!authority.locked);
    assert_eq!(authority.member_count, 0);
}

#[test]
fn build_status_member_roles_lowercase() {
    let paths = isolated_posture_paths("status-member-roles");
    ca::create_ca("test-pass", &[53u8; 32], &paths).unwrap();
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
    let status = status::build(
        &paths,
        Some(TEST_LOCAL_HOSTNAME),
        false,
        None,
        &roster,
        None,
        0,
    );
    let member = &status.authority.unwrap().members[0];
    assert_eq!(member.role, "standby");
    assert_eq!(member.status, "active");
}

// ── Enrollment toggle facade tests ──────────────────────────────

#[tokio::test]
async fn open_enrollment_changes_state() {
    let ca = make_test_ca();
    let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".into()));
    let core = make_unlocked_core(ca, roster);

    // Initially closed (My Organization)
    let status = core.status();
    let authority = status.authority.as_ref().unwrap();
    assert_eq!(authority.enrollment_state, roster::EnrollmentState::Closed);
    assert!(!authority.enrollment_open);

    // Open
    core.open_enrollment().await.unwrap();
    let status = core.status();
    let authority = status.authority.as_ref().unwrap();
    assert_eq!(authority.enrollment_state, roster::EnrollmentState::Open);
    assert!(authority.enrollment_open);
}

#[tokio::test]
async fn close_enrollment_changes_state() {
    let ca = make_test_ca();
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = make_unlocked_core(ca, roster);

    // Initially open for Just Me
    let status = core.status();
    assert_eq!(
        status.authority.as_ref().unwrap().enrollment_state,
        roster::EnrollmentState::Open
    );

    // Close
    core.close_enrollment().await.unwrap();
    let status = core.status();
    let authority = status.authority.as_ref().unwrap();
    assert_eq!(authority.enrollment_state, roster::EnrollmentState::Closed);
    assert!(!authority.enrollment_open);
}

#[tokio::test]
async fn failed_roster_persist_rolls_back_memory_and_does_not_publish_status() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    let ca = ca::create_ca("test-pass", &[58_u8; 32], &paths).unwrap().0;
    let core = CertmeshCore::new_with_paths(ca, Roster::new(false, false, None), None, paths);
    let before = core.status();
    core.state.repository.fail_next_commit_after(0);

    core.open_enrollment()
        .await
        .expect_err("the injected roster commit must fail");

    assert!(!core.state.roster.lock().metadata.enrollment_open);
    assert!(Arc::ptr_eq(&before, &core.status()));
}

#[tokio::test]
async fn uncertain_roster_commit_accepts_visible_model_without_success_event_and_recovers() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    let ca = ca::create_ca("test-pass", &[60_u8; 32], &paths).unwrap().0;
    let roster = make_test_roster_with_member("node-02", MemberRole::Member);
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths.clone());
    let before = core.status();
    let mut events = core.subscribe();
    core.state
        .repository
        .make_next_marker_durability_uncertain();

    let error = core
        .revoke_member("node-02", Some("operator".into()), None)
        .await
        .expect_err("uncertain durability must not acknowledge revocation success");
    assert!(matches!(error, CertmeshError::DurabilityUncertain(_)));

    assert!(roster::load_roster(&paths.roster_path())
        .unwrap()
        .is_revoked("node-02"));
    assert!(core.state.roster.lock().is_revoked("node-02"));
    let unsettled = core.status();
    assert!(unsettled.revision > before.revision);
    assert!(unsettled.diagnosis.is_red());
    assert!(unsettled
        .diagnosis
        .checks
        .iter()
        .any(|check| check.name == "repository_durability"));
    let member = unsettled
        .authority
        .as_ref()
        .unwrap()
        .members
        .iter()
        .find(|member| member.hostname == "node-02")
        .unwrap();
    assert_eq!(member.status, "revoked");
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    drop(events);
    drop(core);
    let recovered =
        CertmeshCore::load_with_paths(paths.clone(), "mesh.internal", TEST_LOCAL_HOSTNAME)
            .expect("restart recovery accepts the visible committed generation");
    assert!(recovered.state.roster.lock().is_revoked("node-02"));
    assert!(!recovered
        .status()
        .diagnosis
        .checks
        .iter()
        .any(|check| check.name == "repository_durability"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_after_durable_commit_still_publishes_model_status_and_event() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
    let ca = ca::create_ca("test-pass", &[59_u8; 32], &paths).unwrap().0;
    let roster = make_test_roster_with_member("node-02", MemberRole::Member);
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths.clone());
    let initial_revision = core.status().revision;
    let mut events = core.subscribe();
    core.state.repository.pause_next_commit_after_durable();

    let command = {
        let core = core.clone();
        tokio::spawn(async move {
            core.revoke_member("node-02", Some("operator".into()), None)
                .await
        })
    };

    while !core.state.repository.is_commit_paused() {
        tokio::task::yield_now().await;
    }

    // The repository has crossed its durable commit point, while its caller is
    // deliberately still inside the synchronous aggregate invariant.
    let durable = roster::load_roster(&paths.roster_path()).unwrap();
    assert!(durable.is_revoked("node-02"));
    command.abort();
    core.state.repository.release_commit();
    let _ = command.await;

    // The caller no longer owns completion after admission. Wait on the cheap
    // authoritative face, not on a retry or the cancelled request future.
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let status = core.status();
            if status.revision > initial_revision {
                break status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the retained command must converge status without a retry");
    assert!(status.revision > initial_revision);
    let member = status
        .authority
        .as_ref()
        .unwrap()
        .members
        .iter()
        .find(|member| member.hostname == "node-02")
        .unwrap();
    assert_eq!(member.status, "revoked");
    assert!(core.state.roster.lock().is_revoked("node-02"));
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap(),
        CertmeshEvent::MemberRevoked { hostname } if hostname == "node-02"
    ));
}

#[tokio::test]
async fn rotate_auth_fails_when_ca_locked() {
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    let core = make_locked_core(roster);
    let result = core.rotate_auth("test-pass", None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn rotate_auth_commits_the_prepared_credential_to_disk_and_memory() {
    let paths = isolated_posture_paths("rotate-auth-happy-path");
    let passphrase = "rotate-auth-passphrase";
    let ca = ca::create_ca(passphrase, &[61u8; 32], &paths)
        .expect("fixture CA")
        .0;
    let old_secret = koi_crypto::totp::generate_secret();
    let old_bytes = old_secret.as_bytes().to_vec();
    let core = CertmeshCore::new_with_paths(
        ca,
        Roster::new(JUST_ME.0, JUST_ME.1, None),
        Some(koi_crypto::auth::AuthState::Totp(old_secret)),
        paths.clone(),
    );

    let setup = core
        .rotate_auth(passphrase, None)
        .await
        .expect("rotate auth");
    assert!(matches!(setup, koi_crypto::auth::AuthSetup::Totp { .. }));

    let in_memory = core.state.auth.lock();
    let Some(koi_crypto::auth::AuthState::Totp(in_memory_secret)) = in_memory.as_ref() else {
        panic!("rotated TOTP credential must be armed")
    };
    assert_ne!(in_memory_secret.as_bytes(), old_bytes);

    let stored: koi_crypto::auth::StoredAuth = serde_json::from_slice(
        &std::fs::read(paths.auth_path()).expect("read committed auth credential"),
    )
    .expect("parse committed auth credential");
    let koi_crypto::auth::AuthState::Totp(durable_secret) = stored
        .unlock(passphrase)
        .expect("unlock committed credential");
    assert_eq!(durable_secret.as_bytes(), in_memory_secret.as_bytes());
}

#[tokio::test]
async fn build_status_reports_posture_booleans() {
    let paths = isolated_posture_paths("status-posture-flags");
    let ca = ca::create_ca("test-pass", &[54u8; 32], &paths).unwrap().0;
    let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".into()));
    let status = status::build(
        &paths,
        Some(TEST_LOCAL_HOSTNAME),
        true,
        Some(ca::ca_fingerprint(&ca)),
        &roster,
        None,
        0,
    );
    let authority = status.authority.unwrap();
    assert!(!authority.enrollment_open);
    assert!(authority.requires_approval);
    assert_eq!(authority.enrollment_state, roster::EnrollmentState::Closed);
}

// ── CertmeshCore::uninitialized_with_paths(test_paths()) state ─────────────────────────

#[tokio::test]
async fn uninitialized_core_status_shows_empty_roster() {
    let core = CertmeshCore::uninitialized_with_paths(isolated_posture_paths("empty-status"));
    let status = core.status();
    assert_eq!(status.role, CertmeshRole::Open);
    assert!(status.authority.is_none());
    assert_eq!(status.identity.condition, IdentityCondition::Absent);
}

#[tokio::test]
async fn corrupt_member_marker_remains_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("corrupt-member"));
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    std::fs::write(paths.member_state_path(), b"{not-json").unwrap();

    let core = CertmeshCore::load_with_paths(paths, "internal", TEST_LOCAL_HOSTNAME).unwrap();
    let status = core.status();
    assert_eq!(status.role, CertmeshRole::Member);
    assert!(status.role.requires_authentication());
    assert_eq!(status.identity.condition, IdentityCondition::Invalid);
    assert!(status.diagnosis.is_red());
}

#[tokio::test]
async fn corrupt_member_state_is_never_reported_as_a_not_applicable_member_command() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("corrupt-member-commands"));
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    std::fs::write(paths.member_state_path(), b"{not-json").unwrap();
    let core = CertmeshCore::load_with_paths(paths, "internal", TEST_LOCAL_HOSTNAME).unwrap();

    for error in [
        core.renew_self().await.unwrap_err(),
        core.pull_trust_bundle().await.unwrap_err(),
    ] {
        assert!(
            matches!(error, CertmeshError::Internal(ref message) if message.contains("persisted member state")),
            "unexpected command result: {error}"
        );
    }

    let signed = bundle::SignedBundle {
        bundle: bundle::TrustBundle {
            seq: 0,
            issued_at: chrono::Utc::now().to_rfc3339(),
            ca_fingerprint: String::new(),
            ca_cert_pem: String::new(),
            policy: roster::CertPolicy::default(),
            members: Vec::new(),
            revoked: Vec::new(),
        },
        signature: String::new(),
    };
    let error = core.apply_trust_bundle(&signed).await.unwrap_err();
    assert!(
        matches!(error, CertmeshError::Internal(ref message) if message.contains("persisted member state")),
        "unexpected apply result: {error}"
    );
}

#[tokio::test]
async fn corrupt_invite_store_is_not_manufactured_into_invalid_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("corrupt-invites"));
    let ca = ca::create_ca("invite-corruption-pass", &[88_u8; 32], &paths)
        .unwrap()
        .0;
    let core =
        CertmeshCore::new_with_paths(ca, Roster::new(true, false, None), None, paths.clone());
    std::fs::write(paths.invites_path(), b"{not-json").unwrap();
    let (_key, csr) = csr::generate_keypair_and_csr("candidate", &["candidate".into()]).unwrap();

    let error = core
        .enroll(&protocol::JoinRequest {
            hostname: "candidate".into(),
            auth: None,
            invite_token: Some("not-a-real-token".into()),
            csr: Some(csr),
            sans: vec!["candidate".into()],
            role: None,
        })
        .await
        .unwrap_err();

    assert!(
        matches!(error, CertmeshError::Io(ref source) if source.kind() == std::io::ErrorKind::InvalidData),
        "durable invite damage must surface distinctly, got {error}"
    );
    assert!(core.state.roster.lock().members.is_empty());
    assert_eq!(std::fs::read(paths.invites_path()).unwrap(), b"{not-json");
}

#[test]
fn persisted_acme_account_corruption_fails_aggregate_bootstrap() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("corrupt-acme-accounts"));
    std::fs::create_dir_all(paths.acme_dir()).unwrap();
    std::fs::write(paths.acme_accounts_path(), b"{not-json").unwrap();

    // Explicit-material constructors describe a new aggregate and therefore do
    // not inspect unrelated old account persistence at all.
    let fresh = CertmeshCore::uninitialized_with_paths(paths.clone());
    assert_eq!(fresh.status().role, CertmeshRole::Open);
    drop(fresh);

    let error = match CertmeshCore::load_with_paths(paths, "internal", TEST_LOCAL_HOSTNAME) {
        Ok(_) => panic!("damaged durable ACME state must fail startup"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CertmeshError::Internal(ref message) if message.contains("persisted ACME account registry")),
        "unexpected startup error: {error}"
    );
}

#[test]
fn persisted_rate_limiter_corruption_fails_aggregate_bootstrap() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("corrupt-rate-limiter"));
    std::fs::create_dir_all(paths.ca_dir()).unwrap();
    std::fs::write(paths.rate_limiter_path(), b"{not-json").unwrap();

    let error = match CertmeshCore::load_with_paths(paths, "internal", TEST_LOCAL_HOSTNAME) {
        Ok(_) => panic!("damaged durable rate-limiter state must fail startup"),
        Err(error) => error,
    };
    assert!(
        matches!(error, CertmeshError::Internal(ref message) if message.contains("persisted enrollment rate limiter")),
        "unexpected startup error: {error}"
    );
}

#[tokio::test]
async fn corrupt_member_cannot_materialize_an_authority_roster() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("corrupt-member-roster-write"));
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    let marker = b"{not-json";
    std::fs::write(paths.member_state_path(), marker).unwrap();
    let core =
        CertmeshCore::load_with_paths(paths.clone(), "internal", TEST_LOCAL_HOSTNAME).unwrap();

    let error = core
        .open_enrollment()
        .await
        .expect_err("a member cannot mutate authority-owned roster state");

    assert!(matches!(error, CertmeshError::Conflict(_)));
    assert_eq!(std::fs::read(paths.member_state_path()).unwrap(), marker);
    assert!(!paths.roster_path().exists());
    assert_eq!(core.status().role, CertmeshRole::Member);
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
        role: None,
    };
    let result = core.enroll(&request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn uninitialized_core_promote_returns_error() {
    let core = CertmeshCore::uninitialized_with_paths(test_paths());
    let dummy_pk = [0u8; 32];
    let request = promotion_request(
        koi_crypto::auth::AuthResponse::Totp {
            code: "000000".into(),
        },
        dummy_pk,
    );
    let result = core.promote("node-01", &request).await;
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
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
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
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    let mut roster = make_test_roster_with_member(&hostname, MemberRole::Primary);
    roster.members[0].pinned_ca_fingerprint = Some("test-pinned-fp".to_string());
    let core = make_unlocked_core(ca, roster);
    let fp = core.pinned_ca_fingerprint().await;
    assert_eq!(fp.as_deref(), Some("test-pinned-fp"));
}

// ── Capability::status() ───────────────────────────────────────────

// ── synchronous status facade ──────────────────────────────────────

#[tokio::test]
async fn certmesh_status_reports_posture() {
    let ca = make_test_ca();
    let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("ops".to_string()));
    let totp = koi_crypto::totp::generate_secret();
    let auth = koi_crypto::auth::AuthState::Totp(totp);
    let core = CertmeshCore::new_with_paths(ca, roster, Some(auth), test_paths());
    let status = core.status();
    // My Organization posture: closed enrollment, approval required.
    let authority = status.authority.as_ref().unwrap();
    assert!(!authority.enrollment_open);
    assert!(authority.requires_approval);
}

#[tokio::test]
async fn primary_status_revision_advances_only_for_semantic_change() {
    let paths = isolated_posture_paths("status-semantic-revision");
    let ca = ca::create_ca("test-pass", &[81_u8; 32], &paths).unwrap().0;
    let core = CertmeshCore::new_with_paths(ca, Roster::new(false, false, None), None, paths);
    let initial = core.status();

    let unchanged = core.state.refresh_status().await;
    assert!(Arc::ptr_eq(&initial, &unchanged));
    assert_eq!(unchanged.revision, initial.revision);

    core.open_enrollment().await.unwrap();
    let changed = core.status();
    assert_eq!(changed.revision, initial.revision + 1);
    assert!(!Arc::ptr_eq(&initial, &changed));

    let unchanged_again = core.state.refresh_status().await;
    assert!(Arc::ptr_eq(&changed, &unchanged_again));
    assert_eq!(unchanged_again.revision, changed.revision);
}

#[test]
fn status_wire_round_trips_tolerates_additions_and_bootstrap_has_exact_keys() {
    let paths = isolated_posture_paths("status-wire");
    let ca = ca::create_ca("test-pass", &[82_u8; 32], &paths).unwrap().0;
    let core = CertmeshCore::new_with_paths(ca, Roster::new(false, true, None), None, paths);
    let status = core.status();

    let status_value = serde_json::to_value(status.as_ref()).unwrap();
    let round_trip: CertmeshStatus = serde_json::from_value(status_value.clone()).unwrap();
    assert_eq!(round_trip, *status);
    let mut additive_status = status_value;
    additive_status["future_status_field"] = serde_json::json!({"ignored": true});
    let additive_round_trip: CertmeshStatus = serde_json::from_value(additive_status).unwrap();
    assert_eq!(additive_round_trip, *status);

    let bootstrap = status.bootstrap();
    let bootstrap_value = serde_json::to_value(&bootstrap).unwrap();
    let keys = bootstrap_value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "authority_available",
            "ca_fingerprint",
            "enrollment_open",
            "requires_approval",
            "revision",
        ]
        .into_iter()
        .collect()
    );
    let round_trip: CertmeshBootstrapStatus =
        serde_json::from_value(bootstrap_value.clone()).unwrap();
    assert_eq!(round_trip, bootstrap);
    let mut additive_bootstrap = bootstrap_value;
    additive_bootstrap["future_bootstrap_field"] = serde_json::json!("ignored");
    let additive_round_trip: CertmeshBootstrapStatus =
        serde_json::from_value(additive_bootstrap).unwrap();
    assert_eq!(additive_round_trip, bootstrap);
}

#[test]
fn expired_member_identity_is_authoritative_and_fails_closed() {
    let source_paths = isolated_posture_paths("expired-source");
    let ca = ca::create_ca("test-pass", &[83_u8; 32], &source_paths)
        .unwrap()
        .0;
    let paths = isolated_posture_paths("expired-member");
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    let issued = ca::issue_expired_certificate(&ca, &hostname, std::slice::from_ref(&hostname))
        .expect("issue already-expired member identity");
    crate::certfiles::write_cert_files_to(&paths.certs_dir().join(&hostname), &issued).unwrap();
    let mut member = posture_member_state(&hostname);
    member.ca_fingerprint = ca::ca_fingerprint(&ca);
    crate::member::save(&paths.member_state_path(), &member).unwrap();

    let core = CertmeshCore::uninitialized_with_paths(paths);
    let status = core.status();
    assert_eq!(status.role, CertmeshRole::Member);
    assert!(status.role.requires_authentication());
    assert_eq!(status.identity.condition, IdentityCondition::Expired);
    assert!(!status.posture.signed);
    assert!(status.authority.is_none());
    assert!(core.tls_identity().material.is_none());
}

#[tokio::test]
async fn self_revocation_is_authoritative_before_the_event_is_observed() {
    let paths = isolated_posture_paths("self-revoked-status");
    let ca = ca::create_ca("test-pass", &[84_u8; 32], &paths).unwrap().0;
    let core = CertmeshCore::new_with_paths(ca, Roster::new(true, false, None), None, paths);
    core.self_enroll().await.unwrap();
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    let mut events = core.subscribe();

    core.revoke_member(&hostname, Some("operator".into()), None)
        .await
        .unwrap();
    let status = core.status();
    assert_eq!(status.identity.condition, IdentityCondition::Revoked);
    assert!(!status.posture.signed);
    assert!(status.role.requires_authentication());
    assert!(core.tls_identity().material.is_none());
    assert!(matches!(
        events.recv().await.unwrap(),
        CertmeshEvent::MemberRevoked { hostname: event_hostname } if event_hostname == hostname
    ));
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
    let roster = core.state.roster.lock();
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
    let roster = core.state.roster.lock();
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
    let status = core.status();
    assert_eq!(status.role, CertmeshRole::Authority);
    let authority = status.authority.as_ref().unwrap();
    assert!(!authority.locked, "CA should be unlocked after create");

    // The CA node self-enrolled as the primary member.
    assert_eq!(authority.member_count, 1, "CA node should self-enroll");
    assert_eq!(authority.members.len(), 1);
    assert_eq!(authority.members[0].role, "primary");
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_create_preparation_keeps_current_thread_responsive_and_has_no_effect() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("cancelled-create-preparation"));
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());
    let before = core.status();
    let mut events = core.subscribe();
    core.state.blocking.pause_next_work();
    let command = tokio::spawn({
        let core = core.clone();
        async move {
            core.create(protocol::CreateCaRequest {
                passphrase: "preparation-passphrase".into(),
                entropy_hex: koi_common::encoding::hex_encode(&[70u8; 32]),
                operator: None,
                enrollment_open: true,
                requires_approval: false,
                auto_unlock: false,
                totp_secret_hex: None,
            })
            .await
        }
    });
    while !core.state.blocking.is_work_paused() {
        tokio::task::yield_now().await;
    }
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio::time::sleep(std::time::Duration::from_millis(5)),
    )
    .await
    .expect("CA preparation must not block a current-thread runtime");
    command.abort();
    let _ = command.await;
    core.state.blocking.release_work();

    assert!(!paths.is_ca_initialized());
    assert!(Arc::ptr_eq(&before, &core.status()));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    // Aggregate release deterministically drains and joins every accepted
    // preparation. Keep that potentially expensive join off this single-thread
    // executor; returning proves the abandoned KDF did not detach.
    tokio::task::spawn_blocking(move || drop(core))
        .await
        .expect("Certmesh worker owner must drain and join on release");
    assert!(!paths.is_ca_initialized());
}

#[tokio::test]
async fn requested_auto_unlock_is_required_and_survives_restart() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("create-auto-unlock"));
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());
    core.create(protocol::CreateCaRequest {
        passphrase: "auto-unlock-passphrase".into(),
        entropy_hex: koi_common::encoding::hex_encode(&[71u8; 32]),
        operator: Some("ops".into()),
        enrollment_open: true,
        requires_approval: false,
        auto_unlock: true,
        totp_secret_hex: None,
    })
    .await
    .expect("auto-unlock creation must not report success without its credential");

    assert!(ca::load_slot_table(&paths.slot_table_path())
        .unwrap()
        .unwrap()
        .has_auto_unlock());
    assert_eq!(
        CertmeshCore::read_auto_unlock_key(&paths)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("auto-unlock-passphrase")
    );
    drop(core);
    let restarted = CertmeshCore::load_with_paths(paths, "internal", TEST_LOCAL_HOSTNAME).unwrap();
    assert!(!restarted.status().authority.as_ref().unwrap().locked);
}

#[tokio::test]
async fn requested_auto_unlock_rejects_an_empty_passphrase_without_effects() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("empty-auto-unlock-passphrase"));
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());
    let before = core.status();
    let mut events = core.subscribe();

    let error = core
        .create(protocol::CreateCaRequest {
            passphrase: String::new(),
            entropy_hex: koi_common::encoding::hex_encode(&[85_u8; 32]),
            operator: Some("ops".into()),
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: true,
            totp_secret_hex: None,
        })
        .await
        .expect_err("auto-unlock cannot succeed without a credential");

    assert!(matches!(error, CertmeshError::InvalidPayload(_)));
    assert!(!paths.is_ca_initialized());
    assert!(Arc::ptr_eq(&before, &core.status()));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn requested_auto_unlock_vault_failure_commits_and_publishes_nothing() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("create-vault-failure"));
    std::fs::create_dir_all(paths.data_dir()).unwrap();
    std::fs::write(paths.data_dir().join("vault"), b"not-a-directory").unwrap();
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());
    let before = core.status();
    let mut events = core.subscribe();
    let error = core
        .create(protocol::CreateCaRequest {
            passphrase: "auto-unlock-passphrase".into(),
            entropy_hex: koi_common::encoding::hex_encode(&[72u8; 32]),
            operator: Some("ops".into()),
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: true,
            totp_secret_hex: None,
        })
        .await
        .expect_err("required vault persistence must fail the command");

    assert!(matches!(error, CertmeshError::Internal(_)));
    assert!(!paths.is_ca_initialized());
    assert!(Arc::ptr_eq(&before, &core.status()));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_create_finishes_auto_unlock_model_status_event_and_restart() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("cancelled-create"));
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());
    let mut events = core.subscribe();
    core.state.repository.pause_next_commit_after_durable();
    let command = tokio::spawn({
        let core = core.clone();
        async move {
            core.create(protocol::CreateCaRequest {
                passphrase: "cancelled-create-passphrase".into(),
                entropy_hex: koi_common::encoding::hex_encode(&[73u8; 32]),
                operator: Some("ops".into()),
                enrollment_open: true,
                requires_approval: false,
                auto_unlock: true,
                totp_secret_hex: None,
            })
            .await
        }
    });
    while !core.state.repository.is_commit_paused() {
        tokio::task::yield_now().await;
    }
    assert!(
        paths.is_ca_initialized(),
        "repository crossed its commit point"
    );
    command.abort();
    let _ = command.await;
    core.state.repository.release_commit();

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while core.status().role != CertmeshRole::Authority {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retained create must publish its completed generation");
    assert!(matches!(
        events.recv().await.unwrap(),
        CertmeshEvent::MemberJoined { .. }
    ));
    assert!(ca::load_slot_table(&paths.slot_table_path())
        .unwrap()
        .unwrap()
        .has_auto_unlock());
    assert_eq!(
        CertmeshCore::read_auto_unlock_key(&paths)
            .unwrap()
            .as_deref()
            .map(String::as_str),
        Some("cancelled-create-passphrase")
    );
    let restarted = CertmeshCore::load_with_paths(paths, "internal", TEST_LOCAL_HOSTNAME).unwrap();
    assert!(!restarted.status().authority.as_ref().unwrap().locked);
}

#[test]
fn boot_never_uses_and_safely_retires_an_unmarked_vault_credential() {
    std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("stale-auto-unlock"));
    let _ = ca::create_ca("stale-passphrase", &[74u8; 32], &paths).unwrap();
    crate::roster::save_roster(
        &Roster::new(JUST_ME.0, JUST_ME.1, None),
        &paths.roster_path(),
    )
    .unwrap();
    CertmeshCore::save_auto_unlock_key_at(&paths, "stale-passphrase").unwrap();
    assert!(!ca::load_slot_table(&paths.slot_table_path())
        .unwrap()
        .unwrap()
        .has_auto_unlock());

    let booted =
        CertmeshCore::load_with_paths(paths.clone(), "internal", TEST_LOCAL_HOSTNAME).unwrap();
    assert!(booted.status().authority.as_ref().unwrap().locked);
    assert!(CertmeshCore::read_auto_unlock_key(&paths)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn failed_create_restores_every_artifact_and_publishes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("failed-create"));
    let core = CertmeshCore::uninitialized_with_paths(paths.clone());
    let before = core.status();
    let before_tls = core.tls_identity();
    let mut events = core.subscribe();
    core.state.repository.fail_next_commit_after(4);

    let error = core
        .create(protocol::CreateCaRequest {
            passphrase: "test-pass-strong".to_string(),
            entropy_hex: koi_common::encoding::hex_encode(&[17u8; 32]),
            operator: Some("ops".to_string()),
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: false,
            totp_secret_hex: None,
        })
        .await
        .expect_err("injected aggregate failure must abort create");
    assert!(matches!(
        error,
        CertmeshError::Io(_) | CertmeshError::Internal(_)
    ));
    assert!(Arc::ptr_eq(&before, &core.status()));
    assert!(Arc::ptr_eq(&before_tls, &core.tls_identity()));
    assert!(!paths.ca_key_path().exists());
    assert!(!paths.ca_cert_path().exists());
    assert!(!paths.roster_path().exists());
    assert!(!paths.certs_dir().exists());
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn failed_destroy_restores_every_artifact_and_publishes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("failed-destroy"));
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    std::fs::create_dir_all(paths.certs_dir().join("member")).unwrap();
    std::fs::create_dir_all(paths.log_dir()).unwrap();
    let member = b"{corrupt-member-marker";
    let cert = b"existing-certificate";
    let audit = b"existing-audit\n";
    std::fs::write(paths.member_state_path(), member).unwrap();
    std::fs::write(paths.certs_dir().join("member/cert.pem"), cert).unwrap();
    std::fs::write(paths.audit_log_path(), audit).unwrap();
    let master_key = koi_crypto::unlock_slots::generate_master_key();
    let slot_table =
        koi_crypto::unlock_slots::SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
    slot_table.save(&paths.slot_table_path()).unwrap();
    let mut slot_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(paths.slot_table_path()).unwrap()).unwrap();
    slot_json["pending_totp_credentials"] = serde_json::json!([{
        "version": 2,
        "credential_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "secret": true,
        "fallback": false
    }]);
    std::fs::write(
        paths.slot_table_path(),
        serde_json::to_vec_pretty(&slot_json).unwrap(),
    )
    .unwrap();
    let slots = std::fs::read(paths.slot_table_path()).unwrap();

    let core =
        CertmeshCore::load_with_paths(paths.clone(), "internal", TEST_LOCAL_HOSTNAME).unwrap();
    let before = core.status();
    let before_roster = core.roster_snapshot();
    let before_tls = core.tls_identity();
    let mut events = core.subscribe();
    core.state.repository.fail_next_commit_after(1);

    let error = core
        .destroy()
        .await
        .expect_err("injected aggregate failure must abort destroy");
    assert!(matches!(
        error,
        CertmeshError::Io(_) | CertmeshError::Internal(_)
    ));
    assert_eq!(std::fs::read(paths.member_state_path()).unwrap(), member);
    assert_eq!(
        std::fs::read(paths.certs_dir().join("member/cert.pem")).unwrap(),
        cert
    );
    assert_eq!(std::fs::read(paths.audit_log_path()).unwrap(), audit);
    assert_eq!(std::fs::read(paths.slot_table_path()).unwrap(), slots);
    assert!(
        !paths.credential_cleanup_pending(),
        "rollback must remove the not-yet-actionable cleanup ledger"
    );
    assert!(Arc::ptr_eq(&before, &core.status()));
    assert!(Arc::ptr_eq(&before_roster, &core.roster_snapshot()));
    assert!(Arc::ptr_eq(&before_tls, &core.tls_identity()));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_destroy_finishes_disk_model_status_and_event_without_retry() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("cancelled-destroy"));
    let ca = ca::create_ca("destroy-passphrase", &[77u8; 32], &paths)
        .unwrap()
        .0;
    let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
    crate::roster::save_roster(&roster, &paths.roster_path()).unwrap();
    let core = CertmeshCore::new_with_paths(ca, roster, None, paths.clone());
    let mut events = core.subscribe();
    core.state.repository.pause_next_commit_after_durable();
    let command = tokio::spawn({
        let core = core.clone();
        async move { core.destroy().await }
    });
    while !core.state.repository.is_commit_paused() {
        tokio::task::yield_now().await;
    }
    assert!(
        !paths.is_ca_initialized(),
        "durable delete is already visible"
    );
    command.abort();
    let _ = command.await;
    core.state.repository.release_commit();

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while core.status().role != CertmeshRole::Open {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retained destroy must publish the empty generation");
    assert!(core.state.ca.lock().is_none());
    assert!(core.roster_snapshot().active_members.is_empty());
    assert!(core.tls_identity().material.is_none());
    assert!(matches!(
        events.recv().await.unwrap(),
        CertmeshEvent::Destroyed
    ));
    let restarted = CertmeshCore::load_with_paths(paths, "internal", TEST_LOCAL_HOSTNAME).unwrap();
    assert_eq!(restarted.status().role, CertmeshRole::Open);
}

fn create_request_for_membership_conflict() -> protocol::CreateCaRequest {
    protocol::CreateCaRequest {
        passphrase: "replacement-pass".to_string(),
        entropy_hex: koi_common::encoding::hex_encode(&[29u8; 32]),
        operator: None,
        enrollment_open: true,
        requires_approval: false,
        auto_unlock: false,
        totp_secret_hex: None,
    }
}

#[tokio::test]
async fn create_refuses_a_joined_member_and_preserves_its_identity() {
    let temp = tempfile::tempdir().unwrap();
    let source_paths = CertmeshPaths::with_data_dir(temp.path().join("source-ca"));
    let member_paths = CertmeshPaths::with_data_dir(temp.path().join("member"));
    let (source_ca, _) = ca::create_ca("source-pass", &[31u8; 32], &source_paths).unwrap();
    let hostname = TEST_LOCAL_HOSTNAME.to_string();
    let sans = vec![hostname.clone()];
    let issued = ca::issue_certificate(&source_ca, &hostname, &sans, 30).unwrap();
    crate::certfiles::write_cert_files_to(&member_paths.certs_dir().join(&hostname), &issued)
        .unwrap();
    let member_state = crate::member::MemberState {
        hostname,
        ca_host: "source-ca".into(),
        ca_mtls_port: crate::member::DEFAULT_CA_MTLS_PORT,
        ca_http_port: crate::member::DEFAULT_CA_HTTP_PORT,
        ca_fingerprint: ca::ca_fingerprint(&source_ca),
        sans,
        policy: crate::roster::CertPolicy::default(),
        last_bundle_seq: 0,
        last_bundle_digest: None,
        revoked_fingerprints: Vec::new(),
        self_revoked: false,
        reload_hook: None,
    };
    crate::member::save(&member_paths.member_state_path(), &member_state).unwrap();
    let marker_before = std::fs::read(member_paths.member_state_path()).unwrap();
    let cert_before = std::fs::read(
        member_paths
            .certs_dir()
            .join(&member_state.hostname)
            .join("cert.pem"),
    )
    .unwrap();
    let core = CertmeshCore::load_with_paths(member_paths.clone(), "internal", TEST_LOCAL_HOSTNAME)
        .unwrap();
    assert_eq!(core.status().role, CertmeshRole::Member);
    assert_eq!(core.status().identity.condition, IdentityCondition::Healthy);

    let error = core
        .create(create_request_for_membership_conflict())
        .await
        .expect_err("joined members cannot silently replace their mesh");
    assert!(matches!(error, CertmeshError::Conflict(_)));
    assert_eq!(
        std::fs::read(member_paths.member_state_path()).unwrap(),
        marker_before
    );
    assert_eq!(
        std::fs::read(
            member_paths
                .certs_dir()
                .join(&member_state.hostname)
                .join("cert.pem")
        )
        .unwrap(),
        cert_before
    );
    assert!(!member_paths.ca_key_path().exists());
}

#[tokio::test]
async fn create_refuses_a_corrupt_member_marker_and_preserves_it() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("corrupt-member"));
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    let marker = b"{not-valid-member-json";
    std::fs::write(paths.member_state_path(), marker).unwrap();
    let core =
        CertmeshCore::load_with_paths(paths.clone(), "internal", TEST_LOCAL_HOSTNAME).unwrap();
    assert_eq!(core.status().role, CertmeshRole::Member);

    let error = core
        .create(create_request_for_membership_conflict())
        .await
        .expect_err("corrupt durable membership must fail closed");
    assert!(matches!(error, CertmeshError::Conflict(_)));
    assert_eq!(std::fs::read(paths.member_state_path()).unwrap(), marker);
    assert!(!paths.ca_key_path().exists());
}

#[tokio::test]
async fn join_commands_refuse_a_corrupt_member_marker() {
    let temp = tempfile::tempdir().unwrap();
    let paths = CertmeshPaths::with_data_dir(temp.path().join("corrupt-rejoin"));
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    let marker = b"{not-valid-member-json";
    std::fs::write(paths.member_state_path(), marker).unwrap();
    let core =
        CertmeshCore::load_with_paths(paths.clone(), "internal", TEST_LOCAL_HOSTNAME).unwrap();

    let prepare = core
        .prepare_member_csr("candidate", &["candidate".to_string()])
        .await
        .expect_err("corrupt durable membership must block a new join");
    assert!(matches!(prepare, CertmeshError::Conflict(_)));
    assert!(!paths.certs_dir().join("candidate/key.pending.pem").exists());

    let install = core
        .install_member_cert(
            "candidate",
            "invalid-cert",
            "invalid-ca",
            None,
            None,
            None,
            &[],
            None,
        )
        .await
        .expect_err("corrupt durable membership must block identity replacement");
    assert!(matches!(install, CertmeshError::Conflict(_)));
    assert_eq!(std::fs::read(paths.member_state_path()).unwrap(), marker);
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

#[test]
fn load_with_paths_keeps_durable_authority_fail_closed_when_roster_is_corrupt() {
    let paths = isolated_posture_paths("load-corrupt-roster");
    std::fs::create_dir_all(paths.ca_dir()).unwrap();
    std::fs::write(paths.ca_key_path(), b"durable-authority-marker").unwrap();
    std::fs::create_dir_all(paths.certmesh_dir()).unwrap();
    std::fs::write(paths.roster_path(), b"not-json").unwrap();

    let core =
        CertmeshCore::load_with_paths(paths.clone(), "mesh.internal", TEST_LOCAL_HOSTNAME).unwrap();
    let status = core.status();
    assert_eq!(status.role, crate::CertmeshRole::Authority);
    assert!(status.role.requires_authentication());
    assert!(status.authority.as_ref().unwrap().locked);
    assert_eq!(core.dns_zone(), "mesh.internal");

    let _ = std::fs::remove_dir_all(paths.data_dir());
}
