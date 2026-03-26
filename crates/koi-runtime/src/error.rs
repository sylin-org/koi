//! Runtime adapter errors.

use koi_common::error::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("runtime backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("runtime connection failed: {0}")]
    Connection(String),

    #[error("runtime event stream error: {0}")]
    EventStream(String),

    #[error("instance not found: {0}")]
    NotFound(String),

    #[error("runtime I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("runtime internal error: {0}")]
    Internal(String),
}

impl From<&RuntimeError> for ErrorCode {
    fn from(e: &RuntimeError) -> Self {
        match e {
            RuntimeError::BackendUnavailable(_) => ErrorCode::CapabilityDisabled,
            RuntimeError::NotFound(_) => ErrorCode::NotFound,
            _ => ErrorCode::Internal,
        }
    }
}
