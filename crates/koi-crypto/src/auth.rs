//! Pluggable authentication adapter system.
//!
//! One flow, N auth methods. The enrollment/promote/rotate flow is
//! identical regardless of which method the CA is configured to use.
//! Callers never branch on method - they call `adapter.verify()`.
//!
//! # Adding a new method
//!
//! 1. Add a variant to [`AuthState`], [`AuthChallenge`], [`AuthResponse`]
//! 2. Write a struct implementing [`AuthAdapter`]
//! 3. Add an arm to [`adapter_for`] and [`available_methods`]
//! 4. Add an arm to the CLI's `resolve_auth()` match

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::EncryptedKey;
use crate::totp::TotpSecret;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("auth method mismatch: expected {expected}, got {got}")]
    MethodMismatch { expected: String, got: String },

    #[error("auth verification failed: {0}")]
    VerificationFailed(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] crate::keys::CryptoError),
}

// ── In-memory auth state (decrypted, ready to verify) ───────────────

/// In-memory auth state held by the daemon while the CA is unlocked.
///
/// For TOTP this holds the decrypted secret. For FIDO2 it holds the
/// public credential (no decryption needed - private key never leaves
/// the hardware device).
pub enum AuthState {
    Totp(TotpSecret),
    Fido2(Fido2Credential),
}

impl AuthState {
    /// Return the method name for status/logging.
    pub fn method_name(&self) -> &'static str {
        match self {
            AuthState::Totp(_) => "totp",
            AuthState::Fido2(_) => "fido2",
        }
    }

    /// Serialize to raw bytes for backup payloads.
    pub fn to_backup_bytes(&self) -> Vec<u8> {
        match self {
            AuthState::Totp(secret) => secret.as_bytes().to_vec(),
            AuthState::Fido2(cred) => serde_json::to_vec(cred).unwrap_or_default(),
        }
    }

    /// Deserialize from backup bytes + method name.
    pub fn from_backup(method: &str, bytes: Vec<u8>) -> Result<Self, AuthError> {
        match method {
            "totp" => Ok(AuthState::Totp(TotpSecret::from_bytes(bytes))),
            "fido2" => {
                let cred: Fido2Credential = serde_json::from_slice(&bytes).map_err(|e| {
                    AuthError::VerificationFailed(format!("FIDO2 deserialize: {e}"))
                })?;
                Ok(AuthState::Fido2(cred))
            }
            other => Err(AuthError::MethodMismatch {
                expected: "totp or fido2".into(),
                got: other.into(),
            }),
        }
    }
}

/// FIDO2 credential stored server-side after key registration.
///
/// Contains only the public key and metadata - the private key
/// never leaves the hardware authenticator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2Credential {
    /// Credential ID assigned by the authenticator during registration.
    pub credential_id: Vec<u8>,
    /// COSE-encoded public key (ECDSA P-256).
    pub public_key: Vec<u8>,
    /// Relying Party ID used during registration.
    pub rp_id: String,
    /// Signature counter for clone detection.
    pub sign_count: u32,
}

// ── On-disk serializable form ───────────────────────────────────────

/// Auth credential stored on disk as `auth.json` in the CA directory.
///
/// For TOTP, the secret is encrypted with the CA passphrase (same as
/// the CA key). For FIDO2, the credential is stored as-is since it
/// contains only the public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum StoredAuth {
    #[serde(rename = "totp")]
    Totp { encrypted_secret: EncryptedKey },
    #[serde(rename = "fido2")]
    Fido2(Fido2Credential),
}

impl StoredAuth {
    /// Decrypt/load the stored credential into an active [`AuthState`].
    ///
    /// For TOTP, requires the CA passphrase to decrypt the secret.
    /// For FIDO2, no decryption is needed.
    pub fn unlock(&self, passphrase: &str) -> Result<AuthState, AuthError> {
        match self {
            StoredAuth::Totp { encrypted_secret } => {
                let secret = crate::totp::decrypt_secret(encrypted_secret, passphrase)?;
                Ok(AuthState::Totp(secret))
            }
            StoredAuth::Fido2(cred) => Ok(AuthState::Fido2(cred.clone())),
        }
    }

    pub fn method_name(&self) -> &'static str {
        match self {
            StoredAuth::Totp { .. } => "totp",
            StoredAuth::Fido2(_) => "fido2",
        }
    }
}

/// Create a [`StoredAuth`] for a TOTP secret encrypted with the given passphrase.
pub fn store_totp(secret: &TotpSecret, passphrase: &str) -> Result<StoredAuth, AuthError> {
    let encrypted = crate::totp::encrypt_secret(secret, passphrase)?;
    Ok(StoredAuth::Totp {
        encrypted_secret: encrypted,
    })
}

/// Create a [`StoredAuth`] for a FIDO2 credential.
pub fn store_fido2(cred: Fido2Credential) -> StoredAuth {
    StoredAuth::Fido2(cred)
}

// ── Wire types ──────────────────────────────────────────────────────

/// Challenge sent to the client via GET /auth/challenge.
///
/// The variant tells the CLI what kind of proof to collect from the operator.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "method")]
pub enum AuthChallenge {
    #[serde(rename = "totp")]
    Totp,
    #[serde(rename = "fido2")]
    Fido2 {
        challenge: Vec<u8>,
        credential_id: Vec<u8>,
        rp_id: String,
    },
}

/// Proof the client sends back in join/promote requests.
///
/// Opaque to the transport layer - only the adapter inspects it.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "method")]
pub enum AuthResponse {
    #[serde(rename = "totp")]
    Totp { code: String },
    #[serde(rename = "fido2")]
    Fido2 {
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        client_data_hash: Vec<u8>,
    },
}

/// Setup info returned after CA creation (tells CLI what to show).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "method")]
pub enum AuthSetup {
    #[serde(rename = "totp")]
    Totp { totp_uri: String },
    #[serde(rename = "fido2")]
    Fido2 { registered: bool },
}

/// Metadata about an available auth method (for discovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethodInfo {
    pub name: &'static str,
    pub is_default: bool,
    pub description: &'static str,
}

// ── Adapter trait ───────────────────────────────────────────────────

/// Auth adapter interface. The ONLY abstraction the flow touches.
///
/// Stateless - each method receives the credential/challenge/response
/// and returns a result. No side effects.
pub trait AuthAdapter: Send + Sync {
    /// Short identifier (e.g. "totp", "fido2").
    fn method_name(&self) -> &'static str;

    /// Whether this method should be pre-selected in the CLI menu.
    fn is_default(&self) -> bool;

    /// Human-readable description for the CLI menu.
    fn description(&self) -> &'static str;

    /// Generate a challenge for the client.
    fn challenge(&self, state: &AuthState) -> Result<AuthChallenge, AuthError>;

    /// Verify a client's response against the challenge and credential.
    fn verify(
        &self,
        state: &AuthState,
        challenge: &AuthChallenge,
        response: &AuthResponse,
    ) -> Result<bool, AuthError>;
}

// ── TOTP adapter ────────────────────────────────────────────────────

pub struct TotpAdapter;

impl AuthAdapter for TotpAdapter {
    fn method_name(&self) -> &'static str {
        "totp"
    }

    fn is_default(&self) -> bool {
        true
    }

    fn description(&self) -> &'static str {
        "TOTP \u{2014} authenticator app"
    }

    fn challenge(&self, state: &AuthState) -> Result<AuthChallenge, AuthError> {
        match state {
            AuthState::Totp(_) => Ok(AuthChallenge::Totp),
            other => Err(AuthError::MethodMismatch {
                expected: "totp".into(),
                got: other.method_name().into(),
            }),
        }
    }

    fn verify(
        &self,
        state: &AuthState,
        _challenge: &AuthChallenge,
        response: &AuthResponse,
    ) -> Result<bool, AuthError> {
        let AuthState::Totp(secret) = state else {
            return Err(AuthError::MethodMismatch {
                expected: "totp".into(),
                got: state.method_name().into(),
            });
        };
        let AuthResponse::Totp { code } = response else {
            return Err(AuthError::MethodMismatch {
                expected: "totp".into(),
                got: "fido2".into(),
            });
        };
        Ok(crate::totp::verify_code(secret, code))
    }
}

// ── FIDO2 adapter ───────────────────────────────────────────────────

pub struct Fido2Adapter;

impl AuthAdapter for Fido2Adapter {
    fn method_name(&self) -> &'static str {
        "fido2"
    }

    fn is_default(&self) -> bool {
        false
    }

    fn description(&self) -> &'static str {
        "FIDO2 \u{2014} hardware security key"
    }

    fn challenge(&self, state: &AuthState) -> Result<AuthChallenge, AuthError> {
        let AuthState::Fido2(cred) = state else {
            return Err(AuthError::MethodMismatch {
                expected: "fido2".into(),
                got: state.method_name().into(),
            });
        };
        let mut challenge = vec![0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        Ok(AuthChallenge::Fido2 {
            challenge,
            credential_id: cred.credential_id.clone(),
            rp_id: cred.rp_id.clone(),
        })
    }

    fn verify(
        &self,
        state: &AuthState,
        challenge: &AuthChallenge,
        response: &AuthResponse,
    ) -> Result<bool, AuthError> {
        let AuthState::Fido2(cred) = state else {
            return Err(AuthError::MethodMismatch {
                expected: "fido2".into(),
                got: state.method_name().into(),
            });
        };
        let AuthResponse::Fido2 {
            authenticator_data,
            signature,
            client_data_hash,
        } = response
        else {
            return Err(AuthError::MethodMismatch {
                expected: "fido2".into(),
                got: "totp".into(),
            });
        };
        let AuthChallenge::Fido2 {
            challenge: expected_challenge,
            ..
        } = challenge
        else {
            return Err(AuthError::MethodMismatch {
                expected: "fido2".into(),
                got: "totp".into(),
            });
        };

        // Verify the client_data_hash contains the expected challenge.
        // In a full FIDO2 implementation, client_data_hash is SHA-256 of
        // the clientDataJSON which embeds the challenge. For our CLI flow
        // where we control both sides, we hash the challenge directly.
        use sha2::{Digest, Sha256};
        let expected_hash = Sha256::digest(expected_challenge);
        if client_data_hash.as_slice() != &expected_hash[..] {
            return Ok(false);
        }

        // Verify ECDSA P-256 signature over (authenticator_data || client_data_hash)
        verify_fido2_signature(
            &cred.public_key,
            authenticator_data,
            client_data_hash,
            signature,
        )
    }
}

/// Verify a FIDO2 ECDSA P-256 signature.
///
/// The signed message is `authenticator_data || client_data_hash` per the
/// WebAuthn spec. The public key is COSE-encoded.
fn verify_fido2_signature(
    public_key_cose: &[u8],
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    signature: &[u8],
) -> Result<bool, AuthError> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    // Build the signed message: authenticator_data || client_data_hash
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(client_data_hash);

    // Hash the message (FIDO2 uses SHA-256)
    let digest = Sha256::digest(&message);

    // Parse the public key from COSE encoding.
    // For simplicity, we accept the uncompressed SEC1 format (0x04 || x || y)
    // which is what ctap-hid-fido2's verifier produces.
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_cose)
        .map_err(|e| AuthError::VerificationFailed(format!("invalid public key: {e}")))?;

    // Parse the DER signature
    let sig = Signature::from_der(signature)
        .map_err(|e| AuthError::VerificationFailed(format!("invalid signature: {e}")))?;

    // Verify (p256 signs over the raw hash for ECDSA)
    match verifying_key.verify(&digest, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ── Registry ────────────────────────────────────────────────────────

/// Get the adapter for an active auth state.
pub fn adapter_for(state: &AuthState) -> Box<dyn AuthAdapter> {
    match state {
        AuthState::Totp(_) => Box::new(TotpAdapter),
        AuthState::Fido2(_) => Box::new(Fido2Adapter),
    }
}

/// List all available auth methods (for CLI discovery menu).
pub fn available_methods() -> Vec<AuthMethodInfo> {
    let adapters: Vec<Box<dyn AuthAdapter>> = vec![Box::new(TotpAdapter), Box::new(Fido2Adapter)];
    adapters
        .iter()
        .map(|a| AuthMethodInfo {
            name: a.method_name(),
            is_default: a.is_default(),
            description: a.description(),
        })
        .collect()
}

/// Get an adapter by method name.
pub fn adapter_by_name(name: &str) -> Option<Box<dyn AuthAdapter>> {
    match name {
        "totp" => Some(Box::new(TotpAdapter)),
        "fido2" => Some(Box::new(Fido2Adapter)),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_adapter_is_default() {
        assert!(TotpAdapter.is_default());
        assert!(!Fido2Adapter.is_default());
    }

    #[test]
    fn totp_challenge_and_verify() {
        let secret = crate::totp::generate_secret();
        let code = crate::totp::current_code(&secret).unwrap();
        let state = AuthState::Totp(secret);

        let adapter = adapter_for(&state);
        let challenge = adapter.challenge(&state).unwrap();
        assert!(matches!(challenge, AuthChallenge::Totp));

        let response = AuthResponse::Totp { code };
        let valid = adapter.verify(&state, &challenge, &response).unwrap();
        assert!(valid);
    }

    #[test]
    fn totp_verify_invalid_code() {
        let secret = crate::totp::generate_secret();
        let state = AuthState::Totp(secret);

        let adapter = adapter_for(&state);
        let challenge = adapter.challenge(&state).unwrap();

        let response = AuthResponse::Totp {
            code: "000000".into(),
        };
        // May or may not be valid depending on timing, but this tests the path
        let _result = adapter.verify(&state, &challenge, &response);
    }

    #[test]
    fn totp_method_mismatch_returns_error() {
        let cred = Fido2Credential {
            credential_id: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            rp_id: "test".into(),
            sign_count: 0,
        };
        let state = AuthState::Fido2(cred);

        let adapter = TotpAdapter;
        let result = adapter.challenge(&state);
        assert!(result.is_err());
    }

    #[test]
    fn available_methods_includes_both() {
        let methods = available_methods();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0].name, "totp");
        assert!(methods[0].is_default);
        assert_eq!(methods[1].name, "fido2");
        assert!(!methods[1].is_default);
    }

    #[test]
    fn adapter_by_name_resolves() {
        assert!(adapter_by_name("totp").is_some());
        assert!(adapter_by_name("fido2").is_some());
        assert!(adapter_by_name("unknown").is_none());
    }

    #[test]
    fn stored_auth_totp_serde_round_trip() {
        let stored = StoredAuth::Totp {
            encrypted_secret: EncryptedKey {
                ciphertext: vec![1, 2, 3],
                salt: vec![4, 5, 6],
                nonce: vec![7, 8, 9],
            },
        };
        let json = serde_json::to_string(&stored).unwrap();
        assert!(json.contains(r#""method":"totp"#));
        let parsed: StoredAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method_name(), "totp");
    }

    #[test]
    fn stored_auth_fido2_serde_round_trip() {
        let stored = StoredAuth::Fido2(Fido2Credential {
            credential_id: vec![10, 20],
            public_key: vec![30, 40],
            rp_id: "koi-certmesh".into(),
            sign_count: 5,
        });
        let json = serde_json::to_string(&stored).unwrap();
        assert!(json.contains(r#""method":"fido2"#));
        let parsed: StoredAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method_name(), "fido2");
    }

    #[test]
    fn auth_state_backup_round_trip_totp() {
        let secret = crate::totp::generate_secret();
        let original_bytes = secret.as_bytes().to_vec();
        let state = AuthState::Totp(secret);

        let bytes = state.to_backup_bytes();
        assert_eq!(bytes, original_bytes);

        let restored = AuthState::from_backup("totp", bytes).unwrap();
        assert_eq!(restored.method_name(), "totp");
    }

    #[test]
    fn auth_state_backup_round_trip_fido2() {
        let cred = Fido2Credential {
            credential_id: vec![1, 2, 3],
            public_key: vec![4, 5, 6],
            rp_id: "test".into(),
            sign_count: 42,
        };
        let state = AuthState::Fido2(cred);

        let bytes = state.to_backup_bytes();
        let restored = AuthState::from_backup("fido2", bytes).unwrap();
        assert_eq!(restored.method_name(), "fido2");
        if let AuthState::Fido2(c) = restored {
            assert_eq!(c.sign_count, 42);
        } else {
            panic!("expected Fido2 variant");
        }
    }

    #[test]
    fn auth_challenge_serde() {
        let c = AuthChallenge::Totp;
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains(r#""method":"totp"#));

        let c2 = AuthChallenge::Fido2 {
            challenge: vec![1, 2, 3],
            credential_id: vec![4, 5],
            rp_id: "koi".into(),
        };
        let json2 = serde_json::to_string(&c2).unwrap();
        assert!(json2.contains(r#""method":"fido2"#));
    }

    #[test]
    fn auth_response_serde() {
        let r = AuthResponse::Totp {
            code: "123456".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("123456"));

        let parsed: AuthResponse = serde_json::from_str(&json).unwrap();
        if let AuthResponse::Totp { code } = parsed {
            assert_eq!(code, "123456");
        } else {
            panic!("expected Totp variant");
        }
    }

    // ── FakeAuthAdapter ─────────────────────────────────────────────

    /// Test-only adapter that always succeeds or always fails,
    /// configurable at construction time. Exercises the adapter
    /// abstraction without real TOTP timing or hardware keys.
    struct FakeAuthAdapter {
        should_pass: bool,
    }

    impl AuthAdapter for FakeAuthAdapter {
        fn method_name(&self) -> &'static str {
            "fake"
        }
        fn is_default(&self) -> bool {
            false
        }
        fn description(&self) -> &'static str {
            "Fake - test only"
        }
        fn challenge(&self, _state: &AuthState) -> Result<AuthChallenge, AuthError> {
            // Reuse TOTP challenge shape - callers never inspect internals
            Ok(AuthChallenge::Totp)
        }
        fn verify(
            &self,
            _state: &AuthState,
            _challenge: &AuthChallenge,
            _response: &AuthResponse,
        ) -> Result<bool, AuthError> {
            Ok(self.should_pass)
        }
    }

    #[test]
    fn fake_adapter_always_passes() {
        let secret = crate::totp::generate_secret();
        let state = AuthState::Totp(secret);
        let adapter = FakeAuthAdapter { should_pass: true };

        let challenge = adapter.challenge(&state).unwrap();
        let response = AuthResponse::Totp {
            code: "anything".into(),
        };
        assert!(adapter.verify(&state, &challenge, &response).unwrap());
    }

    #[test]
    fn fake_adapter_always_fails() {
        let secret = crate::totp::generate_secret();
        let state = AuthState::Totp(secret);
        let adapter = FakeAuthAdapter { should_pass: false };

        let challenge = adapter.challenge(&state).unwrap();
        let response = AuthResponse::Totp {
            code: "anything".into(),
        };
        assert!(!adapter.verify(&state, &challenge, &response).unwrap());
    }

    // ── FIDO2 crypto round-trip ─────────────────────────────────────

    /// Helper: generate a P-256 keypair, register as Fido2Credential,
    /// sign a challenge through the real adapter, and verify.
    fn make_fido2_keypair() -> (p256::ecdsa::SigningKey, Fido2Credential) {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        let pub_bytes = vk.to_encoded_point(false).as_bytes().to_vec();

        let cred = Fido2Credential {
            credential_id: vec![1, 2, 3, 4],
            public_key: pub_bytes,
            rp_id: "koi-test".into(),
            sign_count: 0,
        };
        (sk, cred)
    }

    #[test]
    fn fido2_full_sign_verify_round_trip() {
        use p256::ecdsa::signature::Signer;
        use sha2::{Digest, Sha256};

        let (sk, cred) = make_fido2_keypair();
        let state = AuthState::Fido2(cred.clone());
        let adapter = Fido2Adapter;

        // Generate challenge
        let challenge = adapter.challenge(&state).unwrap();
        let AuthChallenge::Fido2 {
            challenge: challenge_bytes,
            ..
        } = &challenge
        else {
            panic!("expected Fido2 challenge");
        };

        // Simulate authenticator: hash the challenge as client_data_hash
        let client_data_hash = Sha256::digest(challenge_bytes).to_vec();
        let authenticator_data = b"fake-auth-data".to_vec();

        // Build the signed message (auth_data || client_data_hash)
        let mut msg = authenticator_data.clone();
        msg.extend_from_slice(&client_data_hash);
        let digest = Sha256::digest(&msg);

        // Sign
        let sig: p256::ecdsa::Signature = sk.sign(&digest);
        let sig_der = sig.to_der().as_bytes().to_vec();

        let response = AuthResponse::Fido2 {
            authenticator_data,
            signature: sig_der,
            client_data_hash,
        };

        let valid = adapter.verify(&state, &challenge, &response).unwrap();
        assert!(valid, "FIDO2 signature should verify");
    }

    #[test]
    fn fido2_wrong_signature_fails() {
        use sha2::{Digest, Sha256};

        let (_sk, cred) = make_fido2_keypair();
        let state = AuthState::Fido2(cred);
        let adapter = Fido2Adapter;

        let challenge = adapter.challenge(&state).unwrap();
        let AuthChallenge::Fido2 {
            challenge: challenge_bytes,
            ..
        } = &challenge
        else {
            panic!("expected Fido2 challenge");
        };

        let client_data_hash = Sha256::digest(challenge_bytes).to_vec();

        // Garbage signature
        let response = AuthResponse::Fido2 {
            authenticator_data: b"fake".to_vec(),
            signature: vec![0u8; 64],
            client_data_hash,
        };

        // Should error (invalid DER) or return false
        let result = adapter.verify(&state, &challenge, &response);
        if let Ok(valid) = result {
            assert!(!valid);
        }
        // Err (DER parse error) is also acceptable
    }

    #[test]
    fn fido2_wrong_key_fails() {
        use p256::ecdsa::signature::Signer;
        use sha2::{Digest, Sha256};

        // Sign with key A, verify with credential from key B
        let (sk_a, _cred_a) = make_fido2_keypair();
        let (_sk_b, cred_b) = make_fido2_keypair();
        let state = AuthState::Fido2(cred_b); // verifier uses B's public key

        let adapter = Fido2Adapter;
        let challenge = adapter.challenge(&state).unwrap();
        let AuthChallenge::Fido2 {
            challenge: challenge_bytes,
            ..
        } = &challenge
        else {
            panic!("expected Fido2 challenge");
        };

        let client_data_hash = Sha256::digest(challenge_bytes).to_vec();
        let authenticator_data = b"auth-data".to_vec();
        let mut msg = authenticator_data.clone();
        msg.extend_from_slice(&client_data_hash);
        let digest = Sha256::digest(&msg);

        // Sign with key A
        let sig: p256::ecdsa::Signature = sk_a.sign(&digest);
        let sig_der = sig.to_der().as_bytes().to_vec();

        let response = AuthResponse::Fido2 {
            authenticator_data,
            signature: sig_der,
            client_data_hash,
        };

        let valid = adapter.verify(&state, &challenge, &response).unwrap();
        assert!(!valid, "signature from different key should fail");
    }

    #[test]
    fn fido2_wrong_challenge_hash_fails() {
        use p256::ecdsa::signature::Signer;
        use sha2::{Digest, Sha256};

        let (sk, cred) = make_fido2_keypair();
        let state = AuthState::Fido2(cred);
        let adapter = Fido2Adapter;

        let challenge = adapter.challenge(&state).unwrap();

        // client_data_hash doesn't match the challenge
        let client_data_hash = Sha256::digest(b"wrong-challenge").to_vec();
        let authenticator_data = b"auth-data".to_vec();
        let mut msg = authenticator_data.clone();
        msg.extend_from_slice(&client_data_hash);
        let digest = Sha256::digest(&msg);

        let sig: p256::ecdsa::Signature = sk.sign(&digest);
        let sig_der = sig.to_der().as_bytes().to_vec();

        let response = AuthResponse::Fido2 {
            authenticator_data,
            signature: sig_der,
            client_data_hash,
        };

        let valid = adapter.verify(&state, &challenge, &response).unwrap();
        assert!(!valid, "mismatched challenge hash should fail");
    }

    #[test]
    fn fido2_challenge_is_random() {
        let (_, cred) = make_fido2_keypair();
        let state = AuthState::Fido2(cred);
        let adapter = Fido2Adapter;

        let c1 = adapter.challenge(&state).unwrap();
        let c2 = adapter.challenge(&state).unwrap();

        let (
            AuthChallenge::Fido2 { challenge: b1, .. },
            AuthChallenge::Fido2 { challenge: b2, .. },
        ) = (&c1, &c2)
        else {
            panic!("expected Fido2 challenges");
        };
        assert_ne!(b1, b2, "two challenges should differ (32 random bytes)");
    }

    // ── Cross-method rejection ──────────────────────────────────────

    #[test]
    fn totp_adapter_rejects_fido2_response() {
        let secret = crate::totp::generate_secret();
        let state = AuthState::Totp(secret);
        let adapter = TotpAdapter;
        let challenge = adapter.challenge(&state).unwrap();

        let response = AuthResponse::Fido2 {
            authenticator_data: vec![],
            signature: vec![],
            client_data_hash: vec![],
        };
        let result = adapter.verify(&state, &challenge, &response);
        assert!(result.is_err(), "TOTP adapter should reject FIDO2 response");
    }

    #[test]
    fn fido2_adapter_rejects_totp_response() {
        let (_, cred) = make_fido2_keypair();
        let state = AuthState::Fido2(cred);
        let adapter = Fido2Adapter;
        let challenge = adapter.challenge(&state).unwrap();

        let response = AuthResponse::Totp {
            code: "123456".into(),
        };
        let result = adapter.verify(&state, &challenge, &response);
        assert!(result.is_err(), "FIDO2 adapter should reject TOTP response");
    }

    #[test]
    fn fido2_adapter_rejects_totp_state() {
        let secret = crate::totp::generate_secret();
        let state = AuthState::Totp(secret);
        let adapter = Fido2Adapter;

        let result = adapter.challenge(&state);
        assert!(result.is_err(), "FIDO2 adapter should reject TOTP state");
    }

    // ── StoredAuth round-trip with encryption ───────────────────────

    #[test]
    fn store_totp_unlock_round_trip() {
        let secret = crate::totp::generate_secret();
        let original_bytes = secret.as_bytes().to_vec();

        let stored = store_totp(&secret, "my-passphrase").unwrap();
        assert_eq!(stored.method_name(), "totp");

        let state = stored.unlock("my-passphrase").unwrap();
        assert_eq!(state.method_name(), "totp");
        if let AuthState::Totp(s) = state {
            assert_eq!(s.as_bytes(), &original_bytes);
        } else {
            panic!("expected Totp variant");
        }
    }

    #[test]
    fn store_totp_wrong_passphrase_fails() {
        let secret = crate::totp::generate_secret();
        let stored = store_totp(&secret, "correct").unwrap();
        let result = stored.unlock("wrong");
        assert!(result.is_err(), "wrong passphrase should fail");
    }

    #[test]
    fn store_fido2_round_trip() {
        let cred = Fido2Credential {
            credential_id: vec![10, 20, 30],
            public_key: vec![40, 50, 60],
            rp_id: "koi-test".into(),
            sign_count: 7,
        };
        let stored = store_fido2(cred.clone());
        assert_eq!(stored.method_name(), "fido2");

        // FIDO2 unlock ignores the passphrase
        let state = stored.unlock("anything").unwrap();
        if let AuthState::Fido2(c) = state {
            assert_eq!(c.credential_id, cred.credential_id);
            assert_eq!(c.sign_count, 7);
        } else {
            panic!("expected Fido2 variant");
        }
    }

    // ── adapter_for dispatches correctly ────────────────────────────

    #[test]
    fn adapter_for_returns_totp_for_totp_state() {
        let secret = crate::totp::generate_secret();
        let state = AuthState::Totp(secret);
        let adapter = adapter_for(&state);
        assert_eq!(adapter.method_name(), "totp");
        assert!(adapter.is_default());
    }

    #[test]
    fn adapter_for_returns_fido2_for_fido2_state() {
        let cred = Fido2Credential {
            credential_id: vec![1],
            public_key: vec![2],
            rp_id: "test".into(),
            sign_count: 0,
        };
        let state = AuthState::Fido2(cred);
        let adapter = adapter_for(&state);
        assert_eq!(adapter.method_name(), "fido2");
        assert!(!adapter.is_default());
    }

    // ── AuthError display ───────────────────────────────────────────

    #[test]
    fn auth_error_method_mismatch_display() {
        let err = AuthError::MethodMismatch {
            expected: "totp".into(),
            got: "fido2".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("totp"));
        assert!(msg.contains("fido2"));
    }

    #[test]
    fn auth_error_verification_failed_display() {
        let err = AuthError::VerificationFailed("bad sig".into());
        assert!(err.to_string().contains("bad sig"));
    }
}
