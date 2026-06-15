//! Manual CA promotion — the encrypted CA-key transfer to a standby.
//!
//! Promotion is **operator-driven** (`koi certmesh promote`): there is no automatic
//! failover. With 30-day certificates a dead CA pauses renewals but does not cause an
//! outage, so absence-watching, lexicographic tiebreakers, and background roster sync are
//! not justified.
//!
//! [`prepare_promotion`] packages the CA key + auth credential, encrypted under an X25519
//! Diffie-Hellman shared key, so the passphrase never crosses the wire; [`accept_promotion`]
//! reverses it on the standby.

use koi_crypto::auth::AuthState;
use koi_crypto::key_agreement::EphemeralKeyPair;
use koi_crypto::keys::{self, CaKeyPair};
use zeroize::Zeroize;

use crate::ca::CaState;
use crate::error::CertmeshError;
use crate::protocol::PromoteResponse;
use crate::roster::Roster;

// ── Promotion ──────────────────────────────────────────────────────

/// Package the CA key, auth credential, roster, and CA cert for transfer to a standby.
///
/// When `client_public_key` is provided, the server generates its own
/// ephemeral X25519 key pair, derives a shared key via Diffie-Hellman,
/// and encrypts the CA key material with that shared key. The standby
/// combines its own ephemeral secret with the server's public key to
/// derive the same shared key locally -- the passphrase never crosses
/// the wire.
///
/// The `client_public_key` is required — promotion without DH key
/// agreement is not supported.
pub fn prepare_promotion(
    ca: &CaState,
    auth_state: &AuthState,
    roster: &Roster,
    client_public_key: &[u8; 32],
) -> Result<PromoteResponse, CertmeshError> {
    let server_kp = EphemeralKeyPair::generate();
    let server_pub = server_kp.public_key_bytes();
    let mut shared_key = server_kp
        .derive_shared_key(client_public_key)
        .map_err(|e| CertmeshError::PromotionFailed(format!("key derivation: {e}")))?;
    let shared_key_hex =
        koi_crypto::secret::SecretString::new(koi_common::encoding::hex_encode(&shared_key));
    shared_key.zeroize();
    let encrypted_ca_key = keys::encrypt_key(&ca.key, shared_key_hex.as_ref())?;

    // Serialize auth state for transfer.
    //
    // Auth data is encrypted with the DH-derived shared key (same key
    // that protects the CA key). The standby derives the same shared key
    // from the DH exchange and decrypts both CA key and auth state.
    let auth_data = {
        let AuthState::Totp(secret) = auth_state;
        let encrypted_totp = koi_crypto::totp::encrypt_secret(secret, shared_key_hex.as_ref())?;
        serde_json::to_value(&koi_crypto::auth::StoredAuth::Totp {
            encrypted_secret: encrypted_totp,
        })
        .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?
    };

    let roster_json = serde_json::to_string(roster)
        .map_err(|e| CertmeshError::Internal(format!("roster serialization failed: {e}")))?;

    Ok(PromoteResponse {
        encrypted_ca_key,
        auth_data,
        roster_json,
        ca_cert_pem: ca.cert_pem.clone(),
        ephemeral_public: Some(server_pub),
    })
}

/// Accept a promotion response and decrypt the CA key and auth credential.
///
/// The CA key is decrypted using the DH-derived shared key from the
/// ephemeral key pair exchange. Auth data is decrypted with an empty
/// passphrase (the server encrypts it that way for wire transfer).
pub fn accept_promotion(
    response: &PromoteResponse,
    our_keypair: EphemeralKeyPair,
) -> Result<(CaKeyPair, AuthState, Roster), CertmeshError> {
    let server_pub = response.ephemeral_public.as_ref().ok_or_else(|| {
        CertmeshError::PromotionFailed("server did not provide ephemeral public key".into())
    })?;
    let mut shared_key = our_keypair
        .derive_shared_key(server_pub)
        .map_err(|e| CertmeshError::PromotionFailed(format!("key derivation: {e}")))?;
    let shared_key_hex =
        koi_crypto::secret::SecretString::new(koi_common::encoding::hex_encode(&shared_key));
    shared_key.zeroize();
    let ca_key = keys::decrypt_key(&response.encrypted_ca_key, shared_key_hex.as_ref())
        .map_err(|e| CertmeshError::PromotionFailed(format!("CA key DH decryption: {e}")))?;

    // Auth data is encrypted with the same DH-derived shared key
    let stored: koi_crypto::auth::StoredAuth = serde_json::from_value(response.auth_data.clone())
        .map_err(|e| {
        CertmeshError::PromotionFailed(format!("auth data deserialization: {e}"))
    })?;
    let auth_state = stored
        .unlock(shared_key_hex.as_ref())
        .map_err(|e| CertmeshError::PromotionFailed(format!("auth unlock: {e}")))?;

    let roster: Roster = serde_json::from_str(&response.roster_json)
        .map_err(|e| CertmeshError::PromotionFailed(format!("roster deserialization: {e}")))?;

    Ok((ca_key, auth_state, roster))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca;
    use crate::profiles::TrustProfile;
    use crate::roster::{MemberRole, MemberStatus, Roster, RosterMember};
    use chrono::Utc;

    fn test_paths() -> crate::CertmeshPaths {
        crate::CertmeshPaths::with_data_dir(koi_common::test::ensure_data_dir(
            "koi-certmesh-failover-tests",
        ))
    }

    fn make_test_ca() -> CaState {
        ca::create_ca("test-pass", &[42u8; 32], &test_paths())
            .unwrap()
            .0
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
    fn promotion_round_trip_with_dh() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth_state = AuthState::Totp(totp);
        let roster = make_test_roster();

        // Client generates ephemeral keypair
        let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let client_pub = client_kp.public_key_bytes();

        let response = prepare_promotion(&ca, &auth_state, &roster, &client_pub).unwrap();

        // Verify encrypted material is non-empty
        assert!(!response.encrypted_ca_key.ciphertext.is_empty());
        assert!(!response.auth_data.is_null());
        assert!(!response.roster_json.is_empty());
        assert!(response.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(response.ephemeral_public.is_some());

        // Accept on the standby side using DH
        let (ca_key, accepted_auth, accepted_roster) =
            accept_promotion(&response, client_kp).unwrap();

        // Verify the decrypted key produces the same public key
        assert_eq!(
            ca_key.public_key_pem().unwrap(),
            ca.key.public_key_pem().unwrap()
        );
        // Verify auth state survived the round-trip
        assert_eq!(accepted_auth.method_name(), "totp");
        // Verify roster survived
        assert_eq!(accepted_roster.members.len(), 1);
        assert_eq!(accepted_roster.members[0].hostname, "stone-01");
    }

    #[test]
    fn promotion_missing_server_ephemeral_key_fails() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth_state = AuthState::Totp(totp);
        let roster = make_test_roster();

        let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let client_pub = client_kp.public_key_bytes();
        let mut response = prepare_promotion(&ca, &auth_state, &roster, &client_pub).unwrap();

        // Remove the server's ephemeral key — acceptance must fail
        response.ephemeral_public = None;
        let result = accept_promotion(&response, client_kp);
        assert!(matches!(result, Err(CertmeshError::PromotionFailed(_))));
    }

    #[test]
    fn promotion_dh_wrong_keypair_fails() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth_state = AuthState::Totp(totp);
        let roster = make_test_roster();

        let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let client_pub = client_kp.public_key_bytes();

        let response = prepare_promotion(&ca, &auth_state, &roster, &client_pub).unwrap();

        // Try to accept with a DIFFERENT keypair -- should fail
        let wrong_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let result = accept_promotion(&response, wrong_kp);
        assert!(matches!(result, Err(CertmeshError::PromotionFailed(_))));
    }

    // ── Promotion edge cases ────────────────────────────────────────

    #[test]
    fn promotion_dh_preserves_roster_metadata() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth = koi_crypto::auth::AuthState::Totp(totp);
        let mut roster = make_test_roster();
        roster.metadata.operator = Some("ops-team".to_string());

        let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let client_pub = client_kp.public_key_bytes();

        let response = prepare_promotion(&ca, &auth, &roster, &client_pub).unwrap();
        let (_, _, accepted_roster) = accept_promotion(&response, client_kp).unwrap();
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
    fn promotion_dh_with_empty_roster() {
        let ca = make_test_ca();
        let totp = koi_crypto::totp::generate_secret();
        let auth = koi_crypto::auth::AuthState::Totp(totp);
        let roster = Roster::new(TrustProfile::JustMe, None);
        assert!(roster.members.is_empty());

        let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let client_pub = client_kp.public_key_bytes();

        let response = prepare_promotion(&ca, &auth, &roster, &client_pub).unwrap();
        let (_, _, accepted_roster) = accept_promotion(&response, client_kp).unwrap();
        assert!(accepted_roster.members.is_empty());
    }
}
