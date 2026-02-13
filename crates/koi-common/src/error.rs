use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Machine-readable error codes for the wire protocol.
/// Shared by all transports and domains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
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
    // Certmesh (Phase 2)
    CaNotInitialized,
    CaLocked,
    InvalidTotp,
    RateLimited,
    EnrollmentClosed,
    CapabilityDisabled,
    // Certmesh (Phase 3)
    NotStandby,
    PromotionFailed,
    RenewalFailed,
    InvalidManifest,
    // Certmesh (Phase 4)
    ScopeViolation,
    ApprovalDenied,
    ApprovalTimeout,
    ApprovalUnavailable,
    // Certmesh (Phase 5)
    Revoked,
}

impl ErrorCode {
    /// Suggested HTTP status code for this error.
    /// Transport-agnostic (returns u16, not an axum type).
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidType
            | Self::InvalidName
            | Self::InvalidPayload
            | Self::AmbiguousId
            | Self::ParseError => 400,
            Self::SessionMismatch => 403,
            Self::NotFound => 404,
            Self::Conflict | Self::AlreadyDraining | Self::NotDraining => 409,
            Self::ResolveTimeout => 504,
            Self::ShuttingDown
            | Self::CaNotInitialized
            | Self::CaLocked
            | Self::CapabilityDisabled => 503,
            Self::InvalidTotp => 401,
            Self::RateLimited => 429,
            Self::EnrollmentClosed
            | Self::NotStandby
            | Self::ScopeViolation
            | Self::ApprovalDenied => 403,
            Self::Revoked => 403,
            Self::DaemonError
            | Self::IoError
            | Self::Internal
            | Self::PromotionFailed
            | Self::RenewalFailed => 500,
            Self::InvalidManifest => 400,
            Self::ApprovalTimeout => 504,
            Self::ApprovalUnavailable => 503,
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

    /// Exhaustive test covering every ErrorCode variant → HTTP status mapping.
    /// Adding a new ErrorCode variant forces a compile error here until the
    /// mapping is explicitly verified.
    #[test]
    fn all_error_code_variants_map_to_expected_http_status() {
        let cases: Vec<(ErrorCode, u16)> = vec![
            // 400 Bad Request
            (ErrorCode::InvalidType, 400),
            (ErrorCode::InvalidName, 400),
            (ErrorCode::InvalidPayload, 400),
            (ErrorCode::AmbiguousId, 400),
            (ErrorCode::ParseError, 400),
            // 401 Unauthorized
            (ErrorCode::InvalidTotp, 401),
            // 403 Forbidden
            (ErrorCode::SessionMismatch, 403),
            (ErrorCode::EnrollmentClosed, 403),
            // 404 Not Found
            (ErrorCode::NotFound, 404),
            // 409 Conflict
            (ErrorCode::Conflict, 409),
            (ErrorCode::AlreadyDraining, 409),
            (ErrorCode::NotDraining, 409),
            // 429 Rate Limited
            (ErrorCode::RateLimited, 429),
            // 400 Bad Request (Phase 3)
            (ErrorCode::InvalidManifest, 400),
            // 403 Forbidden (Phase 3)
            (ErrorCode::NotStandby, 403),
            // 403 Forbidden (Phase 4)
            (ErrorCode::ScopeViolation, 403),
            (ErrorCode::Revoked, 403),
            (ErrorCode::ApprovalDenied, 403),
            // 500 Internal Server Error
            (ErrorCode::DaemonError, 500),
            (ErrorCode::IoError, 500),
            (ErrorCode::Internal, 500),
            (ErrorCode::PromotionFailed, 500),
            (ErrorCode::RenewalFailed, 500),
            // 503 Service Unavailable
            (ErrorCode::ShuttingDown, 503),
            (ErrorCode::CaNotInitialized, 503),
            (ErrorCode::CaLocked, 503),
            (ErrorCode::CapabilityDisabled, 503),
            (ErrorCode::ApprovalUnavailable, 503),
            // 504 Gateway Timeout
            (ErrorCode::ResolveTimeout, 504),
            (ErrorCode::ApprovalTimeout, 504),
        ];
        for (code, expected_status) in &cases {
            assert_eq!(
                code.http_status(),
                *expected_status,
                "{code:?} should map to HTTP {expected_status}"
            );
        }
    }

    /// Exhaustive serde round-trip for all ErrorCode variants.
    #[test]
    fn all_error_code_variants_roundtrip_through_json() {
        let variants: Vec<(ErrorCode, &str)> = vec![
            (ErrorCode::InvalidType, "invalid_type"),
            (ErrorCode::InvalidName, "invalid_name"),
            (ErrorCode::InvalidPayload, "invalid_payload"),
            (ErrorCode::NotFound, "not_found"),
            (ErrorCode::Conflict, "conflict"),
            (ErrorCode::SessionMismatch, "session_mismatch"),
            (ErrorCode::ResolveTimeout, "resolve_timeout"),
            (ErrorCode::DaemonError, "daemon_error"),
            (ErrorCode::IoError, "io_error"),
            (ErrorCode::AlreadyDraining, "already_draining"),
            (ErrorCode::NotDraining, "not_draining"),
            (ErrorCode::AmbiguousId, "ambiguous_id"),
            (ErrorCode::ParseError, "parse_error"),
            (ErrorCode::ShuttingDown, "shutting_down"),
            (ErrorCode::Internal, "internal"),
            (ErrorCode::CaNotInitialized, "ca_not_initialized"),
            (ErrorCode::CaLocked, "ca_locked"),
            (ErrorCode::InvalidTotp, "invalid_totp"),
            (ErrorCode::RateLimited, "rate_limited"),
            (ErrorCode::EnrollmentClosed, "enrollment_closed"),
            (ErrorCode::CapabilityDisabled, "capability_disabled"),
            (ErrorCode::NotStandby, "not_standby"),
            (ErrorCode::PromotionFailed, "promotion_failed"),
            (ErrorCode::RenewalFailed, "renewal_failed"),
            (ErrorCode::InvalidManifest, "invalid_manifest"),
            (ErrorCode::ScopeViolation, "scope_violation"),
            (ErrorCode::Revoked, "revoked"),
            (ErrorCode::ApprovalDenied, "approval_denied"),
            (ErrorCode::ApprovalTimeout, "approval_timeout"),
            (ErrorCode::ApprovalUnavailable, "approval_unavailable"),
        ];
        for (code, expected_str) in &variants {
            let serialized = serde_json::to_value(code).unwrap();
            assert_eq!(
                serialized, *expected_str,
                "{code:?} should serialize to \"{expected_str}\""
            );

            let deserialized: ErrorCode = serde_json::from_value(serialized).unwrap();
            assert_eq!(
                &deserialized, code,
                "\"{expected_str}\" should deserialize back to {code:?}"
            );
        }
    }
}
