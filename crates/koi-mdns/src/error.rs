use koi_common::error::ErrorCode;
use thiserror::Error;

/// Domain-specific errors for the mDNS capability.
#[derive(Debug, Error)]
pub enum MdnsError {
    #[error("Invalid service type: {0}")]
    InvalidServiceType(String),

    #[error("Registration not found: {0}")]
    RegistrationNotFound(String),

    #[error("Resolve timeout: {0}")]
    ResolveTimeout(String),

    #[error("mDNS daemon error: {0}")]
    Daemon(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Already draining: {0}")]
    AlreadyDraining(String),

    #[error("Not draining: {0}")]
    NotDraining(String),

    #[error("Ambiguous ID prefix: {0}")]
    AmbiguousId(String),
}

pub type Result<T> = std::result::Result<T, MdnsError>;

impl From<koi_common::types::ServiceTypeError> for MdnsError {
    fn from(e: koi_common::types::ServiceTypeError) -> Self {
        MdnsError::InvalidServiceType(e.to_string())
    }
}

impl From<&MdnsError> for ErrorCode {
    fn from(e: &MdnsError) -> Self {
        match e {
            MdnsError::InvalidServiceType(_) => Self::InvalidType,
            MdnsError::RegistrationNotFound(_) => Self::NotFound,
            MdnsError::ResolveTimeout(_) => Self::ResolveTimeout,
            MdnsError::Daemon(_) => Self::DaemonError,
            MdnsError::Io(_) => Self::IoError,
            MdnsError::AlreadyDraining(_) => Self::AlreadyDraining,
            MdnsError::NotDraining(_) => Self::NotDraining,
            MdnsError::AmbiguousId(_) => Self::AmbiguousId,
        }
    }
}
