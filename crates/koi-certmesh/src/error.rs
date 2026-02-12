//! Certmesh domain error types.

use koi_common::error::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum CertmeshError {
    #[error("CA not initialized — run `koi certmesh create` first")]
    CaNotInitialized,

    #[error("CA is locked — run `koi certmesh unlock`")]
    CaLocked,

    #[error("invalid TOTP code")]
    InvalidTotp,

    #[error("rate limited — try again in {remaining_secs} seconds")]
    RateLimited { remaining_secs: u64 },

    #[error("enrollment is closed")]
    EnrollmentClosed,

    #[error("already enrolled: {0}")]
    AlreadyEnrolled(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("revoked: {0}")]
    Revoked(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Internal(String),

    #[error("invalid backup: {0}")]
    BackupInvalid(String),

    // Phase 3 — Failover + Lifecycle
    #[error("not a standby: {0}")]
    NotStandby(String),

    #[error("promotion failed: {0}")]
    PromotionFailed(String),

    #[error("renewal failed for {hostname}: {reason}")]
    RenewalFailed { hostname: String, reason: String },

    #[error("invalid roster manifest signature")]
    InvalidManifest,

    // Phase 4 — Enrollment Policy
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    #[error("enrollment denied by operator")]
    ApprovalDenied,

    #[error("enrollment approval timed out")]
    ApprovalTimeout,

    #[error("enrollment approval unavailable")]
    ApprovalUnavailable,
}

impl From<koi_crypto::keys::CryptoError> for CertmeshError {
    fn from(e: koi_crypto::keys::CryptoError) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<&CertmeshError> for ErrorCode {
    fn from(e: &CertmeshError) -> Self {
        match e {
            CertmeshError::CaNotInitialized => ErrorCode::CaNotInitialized,
            CertmeshError::CaLocked => ErrorCode::CaLocked,
            CertmeshError::InvalidTotp => ErrorCode::InvalidTotp,
            CertmeshError::RateLimited { .. } => ErrorCode::RateLimited,
            CertmeshError::EnrollmentClosed => ErrorCode::EnrollmentClosed,
            CertmeshError::AlreadyEnrolled(_) => ErrorCode::Conflict,
            CertmeshError::NotFound(_) => ErrorCode::NotFound,
            CertmeshError::Revoked(_) => ErrorCode::Revoked,
            CertmeshError::Crypto(_) | CertmeshError::Certificate(_) => ErrorCode::Internal,
            CertmeshError::Io(_) => ErrorCode::IoError,
            CertmeshError::Internal(_) => ErrorCode::Internal,
            CertmeshError::BackupInvalid(_) => ErrorCode::InvalidPayload,
            CertmeshError::NotStandby(_) => ErrorCode::NotStandby,
            CertmeshError::PromotionFailed(_) => ErrorCode::PromotionFailed,
            CertmeshError::RenewalFailed { .. } => ErrorCode::RenewalFailed,
            CertmeshError::InvalidManifest => ErrorCode::InvalidManifest,
            CertmeshError::ScopeViolation(_) => ErrorCode::ScopeViolation,
            CertmeshError::ApprovalDenied => ErrorCode::ApprovalDenied,
            CertmeshError::ApprovalTimeout => ErrorCode::ApprovalTimeout,
            CertmeshError::ApprovalUnavailable => ErrorCode::ApprovalUnavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive test: every CertmeshError variant maps to the expected
    /// ErrorCode and HTTP status. Adding a new variant forces a compile
    /// error until explicitly mapped.
    #[test]
    fn all_certmesh_error_variants_map_to_expected_error_code_and_http_status() {
        let cases: Vec<(CertmeshError, ErrorCode, u16)> = vec![
            (
                CertmeshError::CaNotInitialized,
                ErrorCode::CaNotInitialized,
                503,
            ),
            (CertmeshError::CaLocked, ErrorCode::CaLocked, 503),
            (CertmeshError::InvalidTotp, ErrorCode::InvalidTotp, 401),
            (
                CertmeshError::RateLimited { remaining_secs: 60 },
                ErrorCode::RateLimited,
                429,
            ),
            (
                CertmeshError::EnrollmentClosed,
                ErrorCode::EnrollmentClosed,
                403,
            ),
            (
                CertmeshError::AlreadyEnrolled("host-01".into()),
                ErrorCode::Conflict,
                409,
            ),
            (
                CertmeshError::NotFound("missing".into()),
                ErrorCode::NotFound,
                404,
            ),
            (
                CertmeshError::Revoked("stone-01".into()),
                ErrorCode::Revoked,
                403,
            ),
            (
                CertmeshError::Crypto("bad key".into()),
                ErrorCode::Internal,
                500,
            ),
            (
                CertmeshError::Certificate("bad cert".into()),
                ErrorCode::Internal,
                500,
            ),
            (
                CertmeshError::Io(std::io::Error::other("test")),
                ErrorCode::IoError,
                500,
            ),
            (
                CertmeshError::Internal("unexpected".into()),
                ErrorCode::Internal,
                500,
            ),
            (
                CertmeshError::BackupInvalid("bad magic".into()),
                ErrorCode::InvalidPayload,
                400,
            ),
            // Phase 3
            (
                CertmeshError::NotStandby("stone-01".into()),
                ErrorCode::NotStandby,
                403,
            ),
            (
                CertmeshError::PromotionFailed("transfer error".into()),
                ErrorCode::PromotionFailed,
                500,
            ),
            (
                CertmeshError::RenewalFailed {
                    hostname: "stone-05".into(),
                    reason: "cert expired".into(),
                },
                ErrorCode::RenewalFailed,
                500,
            ),
            (
                CertmeshError::InvalidManifest,
                ErrorCode::InvalidManifest,
                400,
            ),
            // Phase 4
            (
                CertmeshError::ScopeViolation("hostname outside domain".into()),
                ErrorCode::ScopeViolation,
                403,
            ),
            (CertmeshError::ApprovalDenied, ErrorCode::ApprovalDenied, 403),
            (CertmeshError::ApprovalTimeout, ErrorCode::ApprovalTimeout, 504),
            (
                CertmeshError::ApprovalUnavailable,
                ErrorCode::ApprovalUnavailable,
                503,
            ),
        ];
        for (error, expected_code, expected_status) in &cases {
            let code = ErrorCode::from(error);
            assert_eq!(
                &code, expected_code,
                "{error:?} should map to {expected_code:?}"
            );
            assert_eq!(
                code.http_status(),
                *expected_status,
                "{error:?} → {expected_code:?} should have HTTP {expected_status}"
            );
        }
    }

    #[test]
    fn crypto_error_converts_to_certmesh_error() {
        let crypto_err =
            koi_crypto::keys::CryptoError::Encryption("test failure".into());
        let certmesh_err: CertmeshError = crypto_err.into();
        assert!(matches!(certmesh_err, CertmeshError::Crypto(_)));
        assert!(certmesh_err.to_string().contains("test failure"));
    }

    #[test]
    fn rate_limited_error_includes_remaining_secs_in_message() {
        let e = CertmeshError::RateLimited { remaining_secs: 42 };
        assert!(e.to_string().contains("42"));
    }
}
