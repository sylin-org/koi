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

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive test: every MdnsError variant maps to the expected ErrorCode
    /// and HTTP status. Adding a new variant forces a compile error until
    /// explicitly mapped.
    #[test]
    fn all_mdns_error_variants_map_to_expected_error_code_and_http_status() {
        let cases: Vec<(MdnsError, ErrorCode, u16)> = vec![
            (
                MdnsError::InvalidServiceType("bad".into()),
                ErrorCode::InvalidType,
                400,
            ),
            (
                MdnsError::RegistrationNotFound("abc".into()),
                ErrorCode::NotFound,
                404,
            ),
            (
                MdnsError::ResolveTimeout("srv".into()),
                ErrorCode::ResolveTimeout,
                504,
            ),
            (
                MdnsError::Daemon("engine crash".into()),
                ErrorCode::DaemonError,
                500,
            ),
            (
                MdnsError::Io(std::io::Error::other("test")),
                ErrorCode::IoError,
                500,
            ),
            (
                MdnsError::AlreadyDraining("abc".into()),
                ErrorCode::AlreadyDraining,
                409,
            ),
            (
                MdnsError::NotDraining("abc".into()),
                ErrorCode::NotDraining,
                409,
            ),
            (
                MdnsError::AmbiguousId("a1".into()),
                ErrorCode::AmbiguousId,
                400,
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
    fn service_type_error_converts_to_mdns_error() {
        let st_err = koi_common::types::ServiceTypeError::Invalid("bad_proto".into());
        let mdns_err: MdnsError = st_err.into();
        assert!(matches!(mdns_err, MdnsError::InvalidServiceType(_)));
        assert!(mdns_err.to_string().contains("bad_proto"));
    }

    #[test]
    fn error_display_messages_contain_context() {
        let e = MdnsError::InvalidServiceType("_bad._xyz".into());
        assert!(e.to_string().contains("_bad._xyz"));

        let e = MdnsError::RegistrationNotFound("deadbeef".into());
        assert!(e.to_string().contains("deadbeef"));
    }
}
