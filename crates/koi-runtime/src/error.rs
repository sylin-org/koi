//! Runtime adapter errors.

use koi_common::error::ErrorCode;

#[derive(Debug, Clone, thiserror::Error)]
pub enum RuntimeError {
    #[error("runtime backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("runtime connection failed: {0}")]
    Connection(String),

    #[error("runtime event stream error: {0}")]
    EventStream(String),

    #[error("instance not found: {0}")]
    NotFound(String),

    #[error("runtime domain is shut down")]
    ShutDown,

    #[error("runtime lifecycle worker failed: {0}")]
    Worker(String),

    #[error("runtime I/O error: {0}")]
    Io(#[source] std::sync::Arc<std::io::Error>),

    #[error("runtime internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for RuntimeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(std::sync::Arc::new(error))
    }
}

impl From<&RuntimeError> for ErrorCode {
    fn from(e: &RuntimeError) -> Self {
        match e {
            RuntimeError::BackendUnavailable(_) => ErrorCode::CapabilityDisabled,
            RuntimeError::ShutDown => ErrorCode::ShuttingDown,
            RuntimeError::NotFound(_) => ErrorCode::NotFound,
            _ => ErrorCode::Internal,
        }
    }
}
