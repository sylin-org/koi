//! Wire types for certmesh HTTP endpoints.
//!
//! These types define the JSON shapes for join requests/responses
//! and status queries. They are the public API contract.

use serde::{Deserialize, Serialize};

use crate::profiles::TrustProfile;
use crate::roster::EnrollmentState;

/// Client request to join the mesh.
#[derive(Debug, Serialize, Deserialize)]
pub struct JoinRequest {
    /// TOTP code for enrollment authentication.
    pub totp_code: String,
}

/// Server response after successful enrollment.
#[derive(Debug, Serialize, Deserialize)]
pub struct JoinResponse {
    pub hostname: String,
    pub ca_cert: String,
    pub service_cert: String,
    pub service_key: String,
    pub ca_fingerprint: String,
    pub cert_path: String,
}

/// Certmesh status overview (returned by GET /status).
#[derive(Debug, Serialize)]
pub struct CertmeshStatus {
    pub ca_initialized: bool,
    pub ca_locked: bool,
    pub profile: TrustProfile,
    pub enrollment_state: EnrollmentState,
    pub member_count: usize,
    pub members: Vec<MemberSummary>,
}

/// Compact member summary for status display.
#[derive(Debug, Serialize)]
pub struct MemberSummary {
    pub hostname: String,
    pub role: String,
    pub status: String,
    pub cert_fingerprint: String,
    pub cert_expires: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_request_serde_round_trip() {
        let req = JoinRequest {
            totp_code: "123456".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: JoinRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.totp_code, "123456");
    }

    #[test]
    fn join_response_serializes() {
        let resp = JoinResponse {
            hostname: "stone-05".to_string(),
            ca_cert: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n".to_string(),
            service_cert: "-----BEGIN CERTIFICATE-----\nsvc\n-----END CERTIFICATE-----\n"
                .to_string(),
            service_key: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
                .to_string(),
            ca_fingerprint: "abc123".to_string(),
            cert_path: "/home/koi/.koi/certs/stone-05".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("stone-05"));
        assert!(json.contains("ca_fingerprint"));
    }

    #[test]
    fn certmesh_status_serializes() {
        let status = CertmeshStatus {
            ca_initialized: true,
            ca_locked: false,
            profile: TrustProfile::JustMe,
            enrollment_state: EnrollmentState::Open,
            member_count: 1,
            members: vec![MemberSummary {
                hostname: "stone-01".to_string(),
                role: "primary".to_string(),
                status: "active".to_string(),
                cert_fingerprint: "abc".to_string(),
                cert_expires: "2026-03-13T00:00:00Z".to_string(),
            }],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"ca_initialized\":true"));
        assert!(json.contains("\"member_count\":1"));
    }
}
