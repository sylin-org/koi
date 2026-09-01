//! Versioned wire contract for Koi's trusted, machine-local control plane.
//!
//! This protocol deliberately travels only over an authenticated Unix socket or
//! Windows named pipe. It is the safe hand-off for the daemon endpoint and DAT
//! when the caller cannot read the owner-private breadcrumb directly.

use serde::{Deserialize, Serialize};

/// Current local-control wire version.
pub const LOCAL_CONTROL_VERSION: u16 = 1;

/// One newline-delimited request sent to the local daemon.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum LocalControlRequest {
    /// Return credentials for the currently running local daemon.
    Access { version: u16 },
}

impl LocalControlRequest {
    pub fn access() -> Self {
        Self::Access {
            version: LOCAL_CONTROL_VERSION,
        }
    }
}

/// Successful local daemon access hand-off.
///
/// Intentionally does not implement `Debug`: the value contains the DAT.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDaemonAccess {
    pub version: u16,
    pub endpoint: String,
    pub token: String,
}

/// One newline-delimited response from the local daemon.
///
/// Intentionally does not implement `Debug`: the `Access` variant contains the DAT.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum LocalControlResponse {
    Access(LocalDaemonAccess),
    Error { code: String, message: String },
}

impl LocalControlResponse {
    pub fn unsupported_version(version: u16) -> Self {
        Self::Error {
            code: "unsupported_version".to_string(),
            message: format!(
                "local-control version {version} is unsupported; expected {LOCAL_CONTROL_VERSION}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_request_has_a_stable_versioned_wire_shape() {
        let json = serde_json::to_string(&LocalControlRequest::access()).unwrap();
        assert_eq!(json, r#"{"request":"access","version":1}"#);
        assert!(
            serde_json::from_str::<LocalControlRequest>(&json).unwrap()
                == LocalControlRequest::access()
        );
    }

    #[test]
    fn access_response_round_trips() {
        let response = LocalControlResponse::Access(LocalDaemonAccess {
            version: LOCAL_CONTROL_VERSION,
            endpoint: "http://127.0.0.1:5641".to_string(),
            token: "secret".to_string(),
        });
        let json = serde_json::to_string(&response).unwrap();
        assert!(serde_json::from_str::<LocalControlResponse>(&json).unwrap() == response);
    }
}
