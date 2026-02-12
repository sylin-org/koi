//! TOTP generation, QR code rendering, verification, and rate limiting.
//!
//! Uses RFC 6238 TOTP with SHA-1 (industry standard for authenticator apps),
//! 6-digit codes, 30-second time steps. Verification uses constant-time
//! comparison via the `subtle` crate.

use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::keys::{decrypt_bytes, encrypt_bytes, CryptoError, EncryptedKey};

/// TOTP secret length in bytes (256 bits).
const SECRET_LEN: usize = 32;

/// Maximum failed verification attempts before lockout.
const MAX_FAILURES: u32 = 3;

/// Duration of lockout after max failures.
const LOCKOUT_DURATION: Duration = Duration::from_secs(300); // 5 minutes

/// TOTP secret material with zeroize-on-drop.
pub struct TotpSecret {
    secret: Vec<u8>,
}

impl TotpSecret {
    /// Create from raw bytes (for decryption path).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { secret: bytes }
    }

    /// Access the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl Drop for TotpSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Generate a fresh TOTP secret from the OS CSPRNG.
pub fn generate_secret() -> TotpSecret {
    let mut secret = vec![0u8; SECRET_LEN];
    OsRng.fill_bytes(&mut secret);
    TotpSecret { secret }
}

/// Render a QR code as a Unicode string for terminal display.
///
/// The QR code encodes a `otpauth://` URI that authenticator apps
/// (Google Authenticator, Authy, etc.) can scan.
pub fn qr_code_unicode(secret: &TotpSecret, issuer: &str, account: &str) -> String {
    use qrcode::render::unicode;
    use qrcode::QrCode;

    let uri = build_totp_uri(secret, issuer, account);

    match QrCode::new(uri.as_bytes()) {
        Ok(code) => code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build(),
        Err(e) => {
            tracing::warn!(error = %e, "QR code generation failed");
            format!("(QR code unavailable: {e})")
        }
    }
}

/// Verify a 6-digit TOTP code against the secret using constant-time comparison.
///
/// Allows a window of +/- 1 time step (30 seconds) to account for clock skew.
pub fn verify_code(secret: &TotpSecret, code: &str) -> bool {
    let Ok(totp) = build_totp(secret) else {
        return false;
    };

    // Check current time step and +/- 1 step for clock skew tolerance
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let step = 30u64;
    for offset in [0i64, -1, 1] {
        let time = (now as i64 + offset * step as i64) as u64;
        let expected = totp.generate(time);
        let code_bytes = code.as_bytes();
        let expected_bytes = expected.as_bytes();

        if code_bytes.len() == expected_bytes.len() && code_bytes.ct_eq(expected_bytes).into() {
            return true;
        }
    }
    false
}

/// Encrypt a TOTP secret for storage at rest.
pub fn encrypt_secret(secret: &TotpSecret, passphrase: &str) -> Result<EncryptedKey, CryptoError> {
    encrypt_bytes(&secret.secret, passphrase)
}

/// Decrypt a TOTP secret from encrypted storage.
pub fn decrypt_secret(
    encrypted: &EncryptedKey,
    passphrase: &str,
) -> Result<TotpSecret, CryptoError> {
    let bytes = decrypt_bytes(encrypted, passphrase)?;
    Ok(TotpSecret::from_bytes(bytes))
}

/// Rate limiter for TOTP verification attempts.
///
/// After `MAX_FAILURES` consecutive failures, locks out for
/// `LOCKOUT_DURATION` (5 minutes). Resets on successful verification.
pub struct RateLimiter {
    failures: u32,
    locked_until: Option<Instant>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            failures: 0,
            locked_until: None,
        }
    }

    /// Check if currently locked out.
    pub fn is_locked(&self) -> bool {
        self.locked_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    /// Record a verification attempt result. Returns an error if
    /// the attempt is rate-limited or triggers a new lockout.
    pub fn check_and_record(&mut self, valid: bool) -> Result<(), RateLimitError> {
        // Check existing lockout
        if self.is_locked() {
            let remaining = self
                .locked_until
                .unwrap()
                .saturating_duration_since(Instant::now());
            return Err(RateLimitError::LockedOut {
                remaining_secs: remaining.as_secs(),
            });
        }

        // Clear expired lockout
        if self.locked_until.is_some() && !self.is_locked() {
            self.locked_until = None;
            self.failures = 0;
        }

        if valid {
            self.failures = 0;
            self.locked_until = None;
            Ok(())
        } else {
            self.failures += 1;
            if self.failures >= MAX_FAILURES {
                self.locked_until = Some(Instant::now() + LOCKOUT_DURATION);
                Err(RateLimitError::LockedOut {
                    remaining_secs: LOCKOUT_DURATION.as_secs(),
                })
            } else {
                Err(RateLimitError::InvalidCode {
                    attempts_remaining: MAX_FAILURES - self.failures,
                })
            }
        }
    }

    /// Get the number of remaining attempts before lockout.
    pub fn attempts_remaining(&self) -> u32 {
        MAX_FAILURES.saturating_sub(self.failures)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("invalid code ({attempts_remaining} attempts remaining)")]
    InvalidCode { attempts_remaining: u32 },
    #[error("locked out for {remaining_secs} seconds")]
    LockedOut { remaining_secs: u64 },
}

/// Build the `otpauth://` URI for authenticator apps.
pub fn build_totp_uri(secret: &TotpSecret, issuer: &str, account: &str) -> String {
    use totp_rs::Secret;

    let encoded = Secret::Raw(secret.secret.clone()).to_encoded().to_string();
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        issuer, account, encoded, issuer
    )
}

/// Build a totp-rs TOTP instance from our secret.
fn build_totp(secret: &TotpSecret) -> Result<totp_rs::TOTP, totp_rs::TotpUrlError> {
    use totp_rs::{Algorithm, Secret, TOTP};

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(secret.secret.clone()).to_bytes().unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_secret_produces_correct_length() {
        let secret = generate_secret();
        assert_eq!(secret.as_bytes().len(), SECRET_LEN);
    }

    #[test]
    fn qr_code_contains_unicode() {
        let secret = generate_secret();
        let qr = qr_code_unicode(&secret, "Koi", "test@example.com");
        // QR code should produce multi-line unicode output
        assert!(qr.contains('\n'));
        assert!(!qr.is_empty());
    }

    #[test]
    fn verify_valid_code() {
        let secret = generate_secret();
        let totp = build_totp(&secret).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = totp.generate(now);
        assert!(verify_code(&secret, &code));
    }

    #[test]
    fn verify_invalid_code() {
        let secret = generate_secret();
        assert!(!verify_code(&secret, "000000"));
    }

    #[test]
    fn rate_limiter_allows_initial_attempts() {
        let rl = RateLimiter::new();
        assert!(!rl.is_locked());
        assert_eq!(rl.attempts_remaining(), 3);
    }

    #[test]
    fn rate_limiter_tracks_failures() {
        let mut rl = RateLimiter::new();
        let r = rl.check_and_record(false);
        assert!(r.is_err());
        assert_eq!(rl.attempts_remaining(), 2);

        let r = rl.check_and_record(false);
        assert!(r.is_err());
        assert_eq!(rl.attempts_remaining(), 1);
    }

    #[test]
    fn rate_limiter_locks_after_max_failures() {
        let mut rl = RateLimiter::new();
        let _ = rl.check_and_record(false);
        let _ = rl.check_and_record(false);
        let r = rl.check_and_record(false);

        assert!(r.is_err());
        assert!(rl.is_locked());
        assert!(matches!(r, Err(RateLimitError::LockedOut { .. })));
    }

    #[test]
    fn rate_limiter_resets_on_success() {
        let mut rl = RateLimiter::new();
        let _ = rl.check_and_record(false);
        let _ = rl.check_and_record(false);

        // Success resets
        let r = rl.check_and_record(true);
        assert!(r.is_ok());
        assert!(!rl.is_locked());
        assert_eq!(rl.attempts_remaining(), 3);
    }

    #[test]
    fn rate_limiter_rejects_during_lockout() {
        let mut rl = RateLimiter::new();
        let _ = rl.check_and_record(false);
        let _ = rl.check_and_record(false);
        let _ = rl.check_and_record(false);
        assert!(rl.is_locked());

        // Even valid attempts are rejected during lockout
        let r = rl.check_and_record(true);
        assert!(r.is_err());
    }

    #[test]
    fn encrypt_decrypt_secret_round_trip() {
        let secret = generate_secret();
        let original_bytes = secret.as_bytes().to_vec();

        let encrypted = encrypt_secret(&secret, "test-pass").unwrap();
        let decrypted = decrypt_secret(&encrypted, "test-pass").unwrap();

        assert_eq!(decrypted.as_bytes(), &original_bytes);
    }

    #[test]
    fn totp_uri_format() {
        let secret = generate_secret();
        let uri = build_totp_uri(&secret, "Koi Certmesh", "admin@stone-01");
        assert!(uri.starts_with("otpauth://totp/Koi Certmesh:admin@stone-01?secret="));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }
}
