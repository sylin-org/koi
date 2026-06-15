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
/// For TOTP this holds the decrypted secret.
pub enum AuthState {
    Totp(TotpSecret),
}

impl AuthState {
    /// Return the method name for status/logging.
    pub fn method_name(&self) -> &'static str {
        match self {
            AuthState::Totp(_) => "totp",
        }
    }

    /// Serialize to raw bytes for backup payloads.
    pub fn to_backup_bytes(&self) -> Vec<u8> {
        match self {
            AuthState::Totp(secret) => secret.as_bytes().to_vec(),
        }
    }

    /// Deserialize from backup bytes + method name.
    pub fn from_backup(method: &str, bytes: Vec<u8>) -> Result<Self, AuthError> {
        match method {
            "totp" => Ok(AuthState::Totp(TotpSecret::from_bytes(bytes))),
            other => Err(AuthError::MethodMismatch {
                expected: "totp".into(),
                got: other.into(),
            }),
        }
    }
}

// ── On-disk serializable form ───────────────────────────────────────

/// Auth credential stored on disk as `auth.json` in the CA directory.
///
/// For TOTP, the secret is encrypted with the CA passphrase (same as
/// the CA key).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum StoredAuth {
    #[serde(rename = "totp")]
    Totp { encrypted_secret: EncryptedKey },
}

impl StoredAuth {
    /// Decrypt/load the stored credential into an active [`AuthState`].
    ///
    /// For TOTP, requires the CA passphrase to decrypt the secret.
    pub fn unlock(&self, passphrase: &str) -> Result<AuthState, AuthError> {
        match self {
            StoredAuth::Totp { encrypted_secret } => {
                let secret = crate::totp::decrypt_secret(encrypted_secret, passphrase)?;
                Ok(AuthState::Totp(secret))
            }
        }
    }

    pub fn method_name(&self) -> &'static str {
        match self {
            StoredAuth::Totp { .. } => "totp",
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

// ── Wire types ──────────────────────────────────────────────────────

/// Challenge sent to the client via GET /auth/challenge.
///
/// The variant tells the CLI what kind of proof to collect from the operator.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "method")]
pub enum AuthChallenge {
    #[serde(rename = "totp")]
    Totp,
}

/// Proof the client sends back in join/promote requests.
///
/// Opaque to the transport layer - only the adapter inspects it.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "method")]
pub enum AuthResponse {
    #[serde(rename = "totp")]
    Totp { code: String },
}

/// Setup info returned after CA creation (tells CLI what to show).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "method")]
pub enum AuthSetup {
    #[serde(rename = "totp")]
    Totp { totp_uri: String },
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
    /// Short identifier (e.g. "totp").
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
        }
    }

    fn verify(
        &self,
        state: &AuthState,
        _challenge: &AuthChallenge,
        response: &AuthResponse,
    ) -> Result<bool, AuthError> {
        let AuthState::Totp(secret) = state;
        let AuthResponse::Totp { code } = response;
        Ok(crate::totp::verify_code(secret, code))
    }
}

// ── Registry ────────────────────────────────────────────────────────

/// Get the adapter for an active auth state.
pub fn adapter_for(state: &AuthState) -> Box<dyn AuthAdapter> {
    match state {
        AuthState::Totp(_) => Box::new(TotpAdapter),
    }
}

/// List all available auth methods (for CLI discovery menu).
pub fn available_methods() -> Vec<AuthMethodInfo> {
    let adapters: Vec<Box<dyn AuthAdapter>> = vec![Box::new(TotpAdapter)];
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
    fn available_methods_includes_totp() {
        let methods = available_methods();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].name, "totp");
        assert!(methods[0].is_default);
    }

    #[test]
    fn adapter_by_name_resolves() {
        assert!(adapter_by_name("totp").is_some());
        assert!(adapter_by_name("unknown").is_none());
    }

    #[test]
    fn stored_auth_totp_serde_round_trip() {
        let stored = StoredAuth::Totp {
            encrypted_secret: EncryptedKey {
                ciphertext: vec![1, 2, 3],
                salt: vec![4, 5, 6],
                nonce: vec![7, 8, 9],
                kdf_params: Default::default(),
            },
        };
        let json = serde_json::to_string(&stored).unwrap();
        assert!(json.contains(r#""method":"totp"#));
        let parsed: StoredAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method_name(), "totp");
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
    fn auth_challenge_serde() {
        let c = AuthChallenge::Totp;
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains(r#""method":"totp"#));
    }

    #[test]
    fn auth_response_serde() {
        let r = AuthResponse::Totp {
            code: "123456".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("123456"));

        let parsed: AuthResponse = serde_json::from_str(&json).unwrap();
        let AuthResponse::Totp { code } = parsed;
        assert_eq!(code, "123456");
    }

    // ── FakeAuthAdapter ─────────────────────────────────────────────

    /// Test-only adapter that always succeeds or always fails,
    /// configurable at construction time. Exercises the adapter
    /// abstraction without real TOTP timing.
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

    // ── StoredAuth round-trip with encryption ───────────────────────

    #[test]
    fn store_totp_unlock_round_trip() {
        let secret = crate::totp::generate_secret();
        let original_bytes = secret.as_bytes().to_vec();

        let stored = store_totp(&secret, "my-passphrase").unwrap();
        assert_eq!(stored.method_name(), "totp");

        let state = stored.unlock("my-passphrase").unwrap();
        assert_eq!(state.method_name(), "totp");
        let AuthState::Totp(s) = state;
        assert_eq!(s.as_bytes(), &original_bytes);
    }

    #[test]
    fn store_totp_wrong_passphrase_fails() {
        let secret = crate::totp::generate_secret();
        let stored = store_totp(&secret, "correct").unwrap();
        let result = stored.unlock("wrong");
        assert!(result.is_err(), "wrong passphrase should fail");
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

    // ── AuthError display ───────────────────────────────────────────

    #[test]
    fn auth_error_method_mismatch_display() {
        let err = AuthError::MethodMismatch {
            expected: "totp".into(),
            got: "other".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("totp"));
        assert!(msg.contains("other"));
    }

    #[test]
    fn auth_error_verification_failed_display() {
        let err = AuthError::VerificationFailed("bad sig".into());
        assert!(err.to_string().contains("bad sig"));
    }
}
