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

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Internal(String),
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
            CertmeshError::Crypto(_) | CertmeshError::Certificate(_) => ErrorCode::Internal,
            CertmeshError::Io(_) => ErrorCode::IoError,
            CertmeshError::Internal(_) => ErrorCode::Internal,
        }
    }
}
