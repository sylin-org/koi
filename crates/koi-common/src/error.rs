use serde::{Deserialize, Serialize};

/// Machine-readable error codes for the wire protocol.
/// Shared by all transports and domains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidType,
    InvalidName,
    InvalidPayload,
    NotFound,
    Conflict,
    SessionMismatch,
    ResolveTimeout,
    DaemonError,
    IoError,
    AlreadyDraining,
    NotDraining,
    AmbiguousId,
    ParseError,
    ShuttingDown,
    Internal,
}

impl ErrorCode {
    /// Suggested HTTP status code for this error.
    /// Transport-agnostic (returns u16, not an axum type).
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidType | Self::InvalidName | Self::InvalidPayload
            | Self::AmbiguousId | Self::ParseError => 400,
            Self::SessionMismatch => 403,
            Self::NotFound => 404,
            Self::Conflict | Self::AlreadyDraining | Self::NotDraining => 409,
            Self::ResolveTimeout => 504,
            Self::ShuttingDown => 503,
            Self::DaemonError | Self::IoError | Self::Internal => 500,
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
    fn http_status_codes_are_correct() {
        assert_eq!(ErrorCode::InvalidType.http_status(), 400);
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::AlreadyDraining.http_status(), 409);
        assert_eq!(ErrorCode::ResolveTimeout.http_status(), 504);
        assert_eq!(ErrorCode::DaemonError.http_status(), 500);
    }
}
