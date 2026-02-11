//! Wire types for certmesh HTTP endpoints.
//!
//! These types define the JSON shapes for join requests/responses
//! and status queries. They are the public API contract.

use std::collections::HashMap;

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

/// Descriptor for mDNS self-announcement of the CA.
///
/// Produced by CertmeshCore, consumed by the binary crate to
/// create an mDNS registration via MdnsCore. This avoids a
/// direct dependency between koi-certmesh and koi-mdns.
#[derive(Debug, Clone)]
pub struct CaAnnouncement {
    /// mDNS instance name (e.g. "koi-ca-stone-01").
    pub name: String,
    /// Port the CA is listening on.
    pub port: u16,
    /// TXT record key/value pairs (role, fingerprint, profile).
    pub txt: HashMap<String, String>,
}

/// Request to set a post-renewal reload hook for this host.
#[derive(Debug, Serialize, Deserialize)]
pub struct SetHookRequest {
    /// Hostname of the member setting the hook.
    pub hostname: String,
    /// Shell command to run after certificate renewal.
    pub reload: String,
}

/// Response after setting a reload hook.
#[derive(Debug, Serialize)]
pub struct SetHookResponse {
    pub hostname: String,
    pub reload: String,
}

// ── Phase 3 — Failover + Lifecycle ──────────────────────────────────

/// POST /promote request — TOTP-verified CA key transfer.
#[derive(Debug, Serialize, Deserialize)]
pub struct PromoteRequest {
    pub totp_code: String,
}

/// POST /promote response — encrypted CA key, TOTP secret, and roster.
///
/// The standby decrypts the CA key with the passphrase provided during
/// the `koi certmesh promote` flow. The passphrase is never sent over
/// the wire — only the already-encrypted material is transferred.
#[derive(Debug, Serialize, Deserialize)]
pub struct PromoteResponse {
    pub encrypted_ca_key: koi_crypto::keys::EncryptedKey,
    pub encrypted_totp_secret: koi_crypto::keys::EncryptedKey,
    pub roster_json: String,
    pub ca_cert_pem: String,
}

/// POST /renew request — CA pushes renewed cert to a member.
#[derive(Debug, Serialize, Deserialize)]
pub struct RenewRequest {
    pub hostname: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
    pub fullchain_pem: String,
    pub fingerprint: String,
    pub expires: String,
}

/// POST /renew response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RenewResponse {
    pub hostname: String,
    pub renewed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_result: Option<HookResult>,
}

/// Result of executing a reload hook after cert renewal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
    pub success: bool,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

/// GET /roster response — signed manifest for standby sync.
#[derive(Debug, Serialize, Deserialize)]
pub struct RosterManifest {
    pub roster_json: String,
    pub signature: Vec<u8>,
    pub ca_public_key: String,
}

/// POST /health request — member heartbeat.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthRequest {
    pub hostname: String,
    pub pinned_ca_fingerprint: String,
}

/// POST /health response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub valid: bool,
    pub ca_fingerprint: String,
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
    fn set_hook_request_serde_round_trip() {
        let req = SetHookRequest {
            hostname: "stone-01".to_string(),
            reload: "systemctl restart nginx".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: SetHookRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hostname, "stone-01");
        assert_eq!(parsed.reload, "systemctl restart nginx");
    }

    #[test]
    fn set_hook_response_serializes() {
        let resp = SetHookResponse {
            hostname: "stone-01".to_string(),
            reload: "systemctl restart nginx".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("stone-01"));
        assert!(json.contains("systemctl restart nginx"));
    }

    #[test]
    fn ca_announcement_has_correct_fields() {
        use std::collections::HashMap;
        let mut txt = HashMap::new();
        txt.insert("role".to_string(), "primary".to_string());
        txt.insert("profile".to_string(), "just_me".to_string());

        let ann = CaAnnouncement {
            name: "koi-ca-stone-01".to_string(),
            port: 5641,
            txt,
        };
        assert_eq!(ann.name, "koi-ca-stone-01");
        assert_eq!(ann.port, 5641);
        assert_eq!(ann.txt.get("role").unwrap(), "primary");
    }

    // ── Phase 3 serde tests ──────────────────────────────────────────

    #[test]
    fn promote_request_serde_round_trip() {
        let req = PromoteRequest {
            totp_code: "654321".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: PromoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.totp_code, "654321");
    }

    #[test]
    fn promote_response_serde_round_trip() {
        let resp = PromoteResponse {
            encrypted_ca_key: koi_crypto::keys::EncryptedKey {
                ciphertext: vec![1, 2, 3],
                salt: vec![4, 5, 6],
                nonce: vec![7, 8, 9],
            },
            encrypted_totp_secret: koi_crypto::keys::EncryptedKey {
                ciphertext: vec![10, 11],
                salt: vec![12, 13],
                nonce: vec![14, 15],
            },
            roster_json: r#"{"metadata":{}}"#.to_string(),
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: PromoteResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.encrypted_ca_key.ciphertext, vec![1, 2, 3]);
        assert_eq!(parsed.ca_cert_pem.len(), resp.ca_cert_pem.len());
    }

    #[test]
    fn renew_request_serde_round_trip() {
        let req = RenewRequest {
            hostname: "stone-05".to_string(),
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            ca_pem: "ca".to_string(),
            fullchain_pem: "chain".to_string(),
            fingerprint: "abc123".to_string(),
            expires: "2026-03-15T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: RenewRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hostname, "stone-05");
        assert_eq!(parsed.fingerprint, "abc123");
    }

    #[test]
    fn renew_response_serde_round_trip() {
        let resp = RenewResponse {
            hostname: "stone-05".to_string(),
            renewed: true,
            hook_result: Some(HookResult {
                success: true,
                command: "systemctl reload nginx".to_string(),
                output: Some("OK".to_string()),
            }),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: RenewResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.renewed);
        assert!(parsed.hook_result.unwrap().success);
    }

    #[test]
    fn renew_response_omits_none_hook_result() {
        let resp = RenewResponse {
            hostname: "stone-05".to_string(),
            renewed: true,
            hook_result: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("hook_result"));
    }

    #[test]
    fn hook_result_omits_none_output() {
        let hr = HookResult {
            success: false,
            command: "bad-cmd".to_string(),
            output: None,
        };
        let json = serde_json::to_string(&hr).unwrap();
        assert!(!json.contains("output"));
    }

    #[test]
    fn roster_manifest_serde_round_trip() {
        let manifest = RosterManifest {
            roster_json: r#"{"members":[]}"#.to_string(),
            signature: vec![1, 2, 3, 4, 5],
            ca_public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n".to_string(),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: RosterManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signature, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn health_request_serde_round_trip() {
        let req = HealthRequest {
            hostname: "stone-05".to_string(),
            pinned_ca_fingerprint: "abcdef".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HealthRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hostname, "stone-05");
        assert_eq!(parsed.pinned_ca_fingerprint, "abcdef");
    }

    #[test]
    fn health_response_serde_round_trip() {
        let resp = HealthResponse {
            valid: true,
            ca_fingerprint: "cafp123".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HealthResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.valid);
        assert_eq!(parsed.ca_fingerprint, "cafp123");
    }

    // ── Phase 2 tests ──────────────────────────────────────────────────

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
