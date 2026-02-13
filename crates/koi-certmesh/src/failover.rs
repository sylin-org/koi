//! Promotion, roster sync, and failover detection.
//!
//! - **Promotion**: transfers the encrypted CA key + auth credential to a standby.
//! - **Roster sync**: standby periodically pulls a signed roster manifest.
//! - **Failover detection**: monitors mDNS presence; after grace period,
//!   standby with the lowest hostname takes over.

use std::time::{Duration, Instant};

use koi_crypto::auth::AuthState;
use koi_crypto::keys::{self, CaKeyPair};
use koi_crypto::signing;

use crate::ca::CaState;
use crate::error::CertmeshError;
use crate::protocol::{PromoteResponse, RosterManifest};
use crate::roster::Roster;

/// Grace period before a standby considers the primary dead.
pub const FAILOVER_GRACE_SECS: u64 = 60;

/// How often the standby syncs the roster from the primary.
pub const ROSTER_SYNC_INTERVAL_SECS: u64 = 300; // 5 minutes

// ── Promotion ──────────────────────────────────────────────────────

/// Package the CA key, auth credential, roster, and CA cert for transfer to a standby.
///
/// The CA key is encrypted with the provided passphrase so the standby
/// can decrypt it locally. Auth data is serialized as a JSON value.
/// The passphrase is never sent over the wire.
pub fn prepare_promotion(
    ca: &CaState,
    auth_state: &AuthState,
    roster: &Roster,
    passphrase: &str,
) -> Result<PromoteResponse, CertmeshError> {
    let encrypted_ca_key = keys::encrypt_key(&ca.key, passphrase)?;

    // Serialize auth state for transfer
    let auth_data = match auth_state {
        AuthState::Totp(secret) => {
            let encrypted_totp = koi_crypto::totp::encrypt_secret(secret, passphrase)?;
            serde_json::to_value(&koi_crypto::auth::StoredAuth::Totp {
                encrypted_secret: encrypted_totp,
            })
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?
        }
        AuthState::Fido2(cred) => {
            serde_json::to_value(koi_crypto::auth::store_fido2(cred.clone()))
                .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?
        }
    };

    let roster_json = serde_json::to_string(roster)
        .map_err(|e| CertmeshError::Internal(format!("roster serialization failed: {e}")))?;

    Ok(PromoteResponse {
        encrypted_ca_key,
        auth_data,
        roster_json,
        ca_cert_pem: ca.cert_pem.clone(),
    })
}

/// Accept a promotion response and decrypt the CA key and auth credential.
///
/// The standby calls this after receiving the `PromoteResponse` from the primary.
/// Returns the decrypted CA key pair, auth state, and roster.
pub fn accept_promotion(
    response: &PromoteResponse,
    passphrase: &str,
) -> Result<(CaKeyPair, AuthState, Roster), CertmeshError> {
    let ca_key = keys::decrypt_key(&response.encrypted_ca_key, passphrase)
        .map_err(|e| CertmeshError::PromotionFailed(format!("CA key decryption: {e}")))?;

    let stored: koi_crypto::auth::StoredAuth = serde_json::from_value(response.auth_data.clone())
        .map_err(|e| {
        CertmeshError::PromotionFailed(format!("auth data deserialization: {e}"))
    })?;
    let auth_state = stored
        .unlock(passphrase)
        .map_err(|e| CertmeshError::PromotionFailed(format!("auth unlock: {e}")))?;

    let roster: Roster = serde_json::from_str(&response.roster_json)
        .map_err(|e| CertmeshError::PromotionFailed(format!("roster deserialization: {e}")))?;

    Ok((ca_key, auth_state, roster))
}

// ── Roster Sync ────────────────────────────────────────────────────

/// Build a signed roster manifest for standby sync.
///
/// The primary serializes the roster to JSON, signs it with the CA's
/// ECDSA key, and packages the signature + public key for verification.
pub fn build_signed_manifest(
    ca: &CaState,
    roster: &Roster,
) -> Result<RosterManifest, CertmeshError> {
    let roster_json = serde_json::to_string(roster)
        .map_err(|e| CertmeshError::Internal(format!("roster serialization failed: {e}")))?;

    let signature = signing::sign_bytes(&ca.key, roster_json.as_bytes());
    let ca_public_key = ca.key.public_key_pem();

    Ok(RosterManifest {
        roster_json,
        signature,
        ca_public_key,
    })
}

/// Verify a roster manifest's signature and deserialize the roster.
///
/// The standby calls this after receiving a `RosterManifest` from the primary.
/// Returns the verified roster if the signature is valid.
pub fn verify_manifest(manifest: &RosterManifest) -> Result<Roster, CertmeshError> {
    let valid = signing::verify_signature(
        &manifest.ca_public_key,
        manifest.roster_json.as_bytes(),
        &manifest.signature,
    );

    if !valid {
        return Err(CertmeshError::InvalidManifest);
    }

    serde_json::from_str(&manifest.roster_json)
        .map_err(|e| CertmeshError::Internal(format!("roster deserialization: {e}")))
}

// ── Failover Detection ─────────────────────────────────────────────

/// Determine whether the primary has been absent long enough to trigger failover.
///
/// `primary_absent_since` is `Some(instant)` when the primary was last seen
/// disappearing from mDNS. Returns `true` if the grace period has elapsed.
pub fn should_promote(primary_absent_since: Option<Instant>, grace: Duration) -> bool {
    match primary_absent_since {
        Some(since) => since.elapsed() >= grace,
        None => false,
    }
}

/// Deterministic tiebreaker: lower hostname wins.
///
/// When two standbys detect the same failover condition, the one with
/// the lexicographically lower hostname takes over. This prevents
/// split-brain scenarios without needing distributed consensus.
pub fn tiebreaker_wins(my_hostname: &str, other_hostname: &str) -> bool {
    my_hostname < other_hostname
}

/// Check mDNS service records for an active primary with the expected CA fingerprint.
///
/// Scans the TXT records of `_certmesh._tcp` services for a `role=primary`
/// entry whose `fingerprint` matches our pinned CA fingerprint.
/// Returns the endpoint (host:port) of the matching primary, if found.
pub fn find_active_primary(
    ca_fingerprint: &str,
    services: &[(String, u16, std::collections::HashMap<String, String>)],
) -> Option<String> {
    for (host, port, txt) in services {
        let is_primary = txt.get("role").map(|r| r == "primary").unwrap_or(false);
        let fp_matches = txt
            .get("fingerprint")
            .map(|fp| koi_crypto::pinning::fingerprints_match(fp, ca_fingerprint))
            .unwrap_or(false);

        if is_primary && fp_matches {
            return Some(format!("{host}:{port}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca;
    use crate::profiles::TrustProfile;
    use crate::roster::{MemberRole, MemberStatus, Roster, RosterMember};
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_test_ca() -> CaState {
        let _ = koi_common::test::ensure_data_dir("koi-certmesh-failover-tests");
        ca::create_ca("test-pass", &[42u8; 32]).unwrap()
    }

    fn make_test_roster() -> Roster {
        let mut r = Roster::new(TrustProfile::JustMe, None);
        r.members.push(RosterMember {
            hostname: "stone-01".to_string(),
            role: MemberRole::Primary,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp-abc".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec!["stone-01".to_string()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        r
    }

    // ── Promotion tests ────────────────────────────────────────────

    #[test]
    fn promotion_round_trip() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth_state = AuthState::Totp(totp);
        let roster = make_test_roster();
        let passphrase = "standby-pass-123";

        let response = prepare_promotion(&ca, &auth_state, &roster, passphrase).unwrap();

        // Verify encrypted material is non-empty
        assert!(!response.encrypted_ca_key.ciphertext.is_empty());
        assert!(!response.auth_data.is_null());
        assert!(!response.roster_json.is_empty());
        assert!(response.ca_cert_pem.contains("BEGIN CERTIFICATE"));

        // Accept on the standby side
        let (ca_key, accepted_auth, accepted_roster) =
            accept_promotion(&response, passphrase).unwrap();

        // Verify the decrypted key produces the same public key
        assert_eq!(ca_key.public_key_pem(), ca.key.public_key_pem());
        // Verify auth state survived the round-trip
        assert_eq!(accepted_auth.method_name(), "totp");
        // Verify roster survived
        assert_eq!(accepted_roster.members.len(), 1);
        assert_eq!(accepted_roster.members[0].hostname, "stone-01");
    }

    #[test]
    fn promotion_wrong_passphrase_fails() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth_state = AuthState::Totp(totp);
        let roster = make_test_roster();

        let response = prepare_promotion(&ca, &auth_state, &roster, "correct-pass").unwrap();
        let result = accept_promotion(&response, "wrong-pass");
        assert!(matches!(result, Err(CertmeshError::PromotionFailed(_))));
    }

    // ── Roster sync tests ──────────────────────────────────────────

    #[test]
    fn manifest_sign_verify_round_trip() {
        let ca = make_test_ca();
        let roster = make_test_roster();

        let manifest = build_signed_manifest(&ca, &roster).unwrap();
        assert!(!manifest.signature.is_empty());
        assert!(!manifest.ca_public_key.is_empty());

        let verified_roster = verify_manifest(&manifest).unwrap();
        assert_eq!(verified_roster.members.len(), 1);
        assert_eq!(verified_roster.members[0].hostname, "stone-01");
    }

    #[test]
    fn tampered_manifest_fails_verification() {
        let ca = make_test_ca();
        let roster = make_test_roster();

        let mut manifest = build_signed_manifest(&ca, &roster).unwrap();
        // Tamper with the roster JSON
        manifest.roster_json = manifest.roster_json.replace("stone-01", "evil-host");

        let result = verify_manifest(&manifest);
        assert!(matches!(result, Err(CertmeshError::InvalidManifest)));
    }

    #[test]
    fn wrong_key_manifest_fails_verification() {
        let ca1 = make_test_ca();
        let ca2 = ca::create_ca("other-pass", &[99u8; 32]).unwrap();
        let roster = make_test_roster();

        let mut manifest = build_signed_manifest(&ca1, &roster).unwrap();
        // Replace the public key with a different CA's key
        manifest.ca_public_key = ca2.key.public_key_pem();

        let result = verify_manifest(&manifest);
        assert!(matches!(result, Err(CertmeshError::InvalidManifest)));
    }

    // ── Failover detection tests ───────────────────────────────────

    #[test]
    fn should_promote_false_when_no_absence() {
        assert!(!should_promote(None, Duration::from_secs(60)));
    }

    #[test]
    fn should_promote_false_within_grace() {
        let since = Instant::now();
        assert!(!should_promote(Some(since), Duration::from_secs(60)));
    }

    #[test]
    fn should_promote_true_after_grace() {
        // Use a zero grace period so the check passes immediately
        let since = Instant::now() - Duration::from_secs(1);
        assert!(should_promote(Some(since), Duration::from_secs(0)));
    }

    #[test]
    fn tiebreaker_lower_hostname_wins() {
        assert!(tiebreaker_wins("alpha", "bravo"));
        assert!(!tiebreaker_wins("bravo", "alpha"));
        assert!(!tiebreaker_wins("alpha", "alpha")); // tie = neither wins
    }

    #[test]
    fn tiebreaker_is_case_sensitive() {
        // Uppercase sorts before lowercase in ASCII
        assert!(tiebreaker_wins("Alpha", "alpha"));
    }

    // ── find_active_primary tests ──────────────────────────────────

    #[test]
    fn find_active_primary_matches_fingerprint() {
        let fp = "abc123";
        let mut txt = HashMap::new();
        txt.insert("role".to_string(), "primary".to_string());
        txt.insert("fingerprint".to_string(), fp.to_string());

        let services = vec![("stone-01.local".to_string(), 5641u16, txt)];
        let result = find_active_primary(fp, &services);
        assert_eq!(result.as_deref(), Some("stone-01.local:5641"));
    }

    #[test]
    fn find_active_primary_skips_standby() {
        let fp = "abc123";
        let mut txt = HashMap::new();
        txt.insert("role".to_string(), "standby".to_string());
        txt.insert("fingerprint".to_string(), fp.to_string());

        let services = vec![("stone-02.local".to_string(), 5641u16, txt)];
        let result = find_active_primary(fp, &services);
        assert!(result.is_none());
    }

    #[test]
    fn find_active_primary_wrong_fingerprint() {
        let mut txt = HashMap::new();
        txt.insert("role".to_string(), "primary".to_string());
        txt.insert("fingerprint".to_string(), "wrong-fp".to_string());

        let services = vec![("stone-01.local".to_string(), 5641u16, txt)];
        let result = find_active_primary("correct-fp", &services);
        assert!(result.is_none());
    }

    #[test]
    fn find_active_primary_empty_services() {
        let result = find_active_primary("abc123", &[]);
        assert!(result.is_none());
    }

    // ── Promotion edge cases ────────────────────────────────────────

    #[test]
    fn promotion_with_empty_passphrase() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth = koi_crypto::auth::AuthState::Totp(totp);
        let roster = make_test_roster();

        // Empty passphrase should still work (encryption doesn't require length)
        let response = prepare_promotion(&ca, &auth, &roster, "").unwrap();
        let (ca_key, _auth, accepted_roster) = accept_promotion(&response, "").unwrap();
        assert_eq!(ca_key.public_key_pem(), ca.key.public_key_pem());
        assert_eq!(accepted_roster.members.len(), 1);
    }

    #[test]
    fn promotion_with_unicode_passphrase() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth = koi_crypto::auth::AuthState::Totp(totp);
        let roster = make_test_roster();
        let passphrase = "café-naïve-résumé-日本語";

        let response = prepare_promotion(&ca, &auth, &roster, passphrase).unwrap();
        let (ca_key, _, _) = accept_promotion(&response, passphrase).unwrap();
        assert_eq!(ca_key.public_key_pem(), ca.key.public_key_pem());
    }

    #[test]
    fn promotion_preserves_roster_metadata() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth = koi_crypto::auth::AuthState::Totp(totp);
        let mut roster = make_test_roster();
        roster.metadata.operator = Some("ops-team".to_string());

        let response = prepare_promotion(&ca, &auth, &roster, "pass").unwrap();
        let (_, _, accepted_roster) = accept_promotion(&response, "pass").unwrap();
        assert_eq!(
            accepted_roster.metadata.operator.as_deref(),
            Some("ops-team")
        );
        assert_eq!(
            accepted_roster.metadata.trust_profile,
            roster.metadata.trust_profile
        );
    }

    #[test]
    fn promotion_with_empty_roster() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth = koi_crypto::auth::AuthState::Totp(totp);
        let roster = Roster::new(TrustProfile::JustMe, None);
        assert!(roster.members.is_empty());

        let response = prepare_promotion(&ca, &auth, &roster, "pass").unwrap();
        let (_, _, accepted_roster) = accept_promotion(&response, "pass").unwrap();
        assert!(accepted_roster.members.is_empty());
    }

    // ── Manifest edge cases ─────────────────────────────────────────

    #[test]
    fn manifest_with_empty_roster() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);

        let manifest = build_signed_manifest(&ca, &roster).unwrap();
        let verified = verify_manifest(&manifest).unwrap();
        assert!(verified.members.is_empty());
    }

    #[test]
    fn manifest_with_multiple_members() {
        let ca = make_test_ca();
        let mut roster = make_test_roster();
        roster.members.push(RosterMember {
            hostname: "stone-02".to_string(),
            role: MemberRole::Standby,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp-def".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec!["stone-02".to_string()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        roster.members.push(RosterMember {
            hostname: "stone-03".to_string(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp-ghi".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec!["stone-03".to_string()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });

        let manifest = build_signed_manifest(&ca, &roster).unwrap();
        let verified = verify_manifest(&manifest).unwrap();
        assert_eq!(verified.members.len(), 3);
    }

    #[test]
    fn manifest_tampered_signature_fails() {
        let ca = make_test_ca();
        let roster = make_test_roster();

        let mut manifest = build_signed_manifest(&ca, &roster).unwrap();
        // Flip a byte in the signature
        if let Some(byte) = manifest.signature.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(matches!(
            verify_manifest(&manifest),
            Err(CertmeshError::InvalidManifest)
        ));
    }

    #[test]
    fn manifest_empty_signature_fails() {
        let ca = make_test_ca();
        let roster = make_test_roster();

        let mut manifest = build_signed_manifest(&ca, &roster).unwrap();
        manifest.signature = vec![];
        assert!(matches!(
            verify_manifest(&manifest),
            Err(CertmeshError::InvalidManifest)
        ));
    }

    #[test]
    fn manifest_empty_public_key_fails() {
        let ca = make_test_ca();
        let roster = make_test_roster();

        let mut manifest = build_signed_manifest(&ca, &roster).unwrap();
        manifest.ca_public_key = String::new();
        assert!(matches!(
            verify_manifest(&manifest),
            Err(CertmeshError::InvalidManifest)
        ));
    }

    // ── Failover detection edge cases ───────────────────────────────

    #[test]
    fn should_promote_at_exact_boundary() {
        // Test with a grace period that just barely elapsed
        let grace = Duration::from_millis(50);
        let since = Instant::now() - Duration::from_millis(60);
        assert!(should_promote(Some(since), grace));
    }

    #[test]
    fn should_promote_with_zero_grace() {
        // Zero grace = instant promotion
        let since = Instant::now();
        // Even though "now", with zero grace it should be true (elapsed >= 0)
        assert!(should_promote(Some(since), Duration::ZERO));
    }

    // ── Tiebreaker edge cases ───────────────────────────────────────

    #[test]
    fn tiebreaker_with_numeric_hostnames() {
        // Lexicographic: "1" < "2" < "10" (string, not numeric)
        assert!(tiebreaker_wins("1", "2"));
        // "10" < "2" lexicographically
        assert!(tiebreaker_wins("10", "2"));
    }

    #[test]
    fn tiebreaker_with_empty_hostname() {
        // Empty string sorts before anything
        assert!(tiebreaker_wins("", "any"));
        assert!(!tiebreaker_wins("any", ""));
    }

    #[test]
    fn tiebreaker_with_common_prefixes() {
        assert!(tiebreaker_wins("node-01", "node-02"));
        assert!(!tiebreaker_wins("node-02", "node-01"));
    }

    // ── find_active_primary edge cases ──────────────────────────────

    #[test]
    fn find_active_primary_multiple_primaries_returns_first() {
        let fp = "abc123";
        let mut txt1 = HashMap::new();
        txt1.insert("role".to_string(), "primary".to_string());
        txt1.insert("fingerprint".to_string(), fp.to_string());

        let mut txt2 = HashMap::new();
        txt2.insert("role".to_string(), "primary".to_string());
        txt2.insert("fingerprint".to_string(), fp.to_string());

        let services = vec![
            ("stone-01.local".to_string(), 5641u16, txt1),
            ("stone-02.local".to_string(), 5642u16, txt2),
        ];
        let result = find_active_primary(fp, &services);
        // Should return the first match
        assert_eq!(result.as_deref(), Some("stone-01.local:5641"));
    }

    #[test]
    fn find_active_primary_missing_role_key() {
        let fp = "abc123";
        let mut txt = HashMap::new();
        // No "role" key at all
        txt.insert("fingerprint".to_string(), fp.to_string());

        let services = vec![("stone-01.local".to_string(), 5641u16, txt)];
        assert!(find_active_primary(fp, &services).is_none());
    }

    #[test]
    fn find_active_primary_missing_fingerprint_key() {
        let mut txt = HashMap::new();
        txt.insert("role".to_string(), "primary".to_string());
        // No "fingerprint" key at all

        let services = vec![("stone-01.local".to_string(), 5641u16, txt)];
        assert!(find_active_primary("abc123", &services).is_none());
    }

    #[test]
    fn find_active_primary_mixed_roles() {
        let fp = "abc123";

        let mut txt_standby = HashMap::new();
        txt_standby.insert("role".to_string(), "standby".to_string());
        txt_standby.insert("fingerprint".to_string(), fp.to_string());

        let mut txt_member = HashMap::new();
        txt_member.insert("role".to_string(), "member".to_string());
        txt_member.insert("fingerprint".to_string(), fp.to_string());

        let mut txt_primary = HashMap::new();
        txt_primary.insert("role".to_string(), "primary".to_string());
        txt_primary.insert("fingerprint".to_string(), fp.to_string());

        let services = vec![
            ("standby.local".to_string(), 5641u16, txt_standby),
            ("member.local".to_string(), 5641u16, txt_member),
            ("primary.local".to_string(), 5641u16, txt_primary),
        ];
        // Should skip standby and member, find primary
        let result = find_active_primary(fp, &services);
        assert_eq!(result.as_deref(), Some("primary.local:5641"));
    }
}
