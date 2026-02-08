use serde::{Deserialize, Serialize};

use crate::core::KoiError;

/// Machine-readable error codes for the wire protocol.
/// Shared by all transports — HTTP, pipe, CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidType,
    NotFound,
    ResolveTimeout,
    DaemonError,
    IoError,
    AlreadyDraining,
    NotDraining,
    AmbiguousId,
    ParseError,
}

impl ErrorCode {
    /// Suggested HTTP status code for this error.
    /// Transport-agnostic (returns u16, not an axum type).
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidType | Self::AmbiguousId | Self::ParseError => 400,
            Self::NotFound => 404,
            Self::AlreadyDraining | Self::NotDraining => 409,
            Self::ResolveTimeout => 504,
            Self::DaemonError | Self::IoError => 500,
        }
    }
}

impl From<&KoiError> for ErrorCode {
    fn from(e: &KoiError) -> Self {
        match e {
            KoiError::InvalidServiceType(_) => Self::InvalidType,
            KoiError::RegistrationNotFound(_) => Self::NotFound,
            KoiError::ResolveTimeout(_) => Self::ResolveTimeout,
            KoiError::Daemon(_) => Self::DaemonError,
            KoiError::Io(_) => Self::IoError,
            KoiError::AlreadyDraining(_) => Self::AlreadyDraining,
            KoiError::NotDraining(_) => Self::NotDraining,
            KoiError::AmbiguousId(_) => Self::AmbiguousId,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_value(ErrorCode::InvalidType).unwrap(),
            "invalid_type"
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::NotFound).unwrap(),
            "not_found"
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::AlreadyDraining).unwrap(),
            "already_draining"
        );
    }

    #[test]
    fn error_code_from_koi_error() {
        let e = KoiError::RegistrationNotFound("xyz".into());
        assert_eq!(ErrorCode::from(&e), ErrorCode::NotFound);
    }

    #[test]
    fn http_status_codes_are_correct() {
        assert_eq!(ErrorCode::InvalidType.http_status(), 400);
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::AlreadyDraining.http_status(), 409);
        assert_eq!(ErrorCode::ResolveTimeout.http_status(), 504);
        assert_eq!(ErrorCode::DaemonError.http_status(), 500);
    }
}
