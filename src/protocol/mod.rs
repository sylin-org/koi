pub mod error;
pub mod request;
pub mod response;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A service instance as seen on the network.
/// Used in browse results, resolve results, register confirmations,
/// and event payloads. This is THE service representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub txt: HashMap<String, String>,
}

/// Payload for registering a new service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegisterPayload {
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub port: u16,
    /// Pin the A/AAAA record to a specific IP address.
    /// When absent, all machine IPs are advertised (auto-detect).
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u64>,
    #[serde(default)]
    pub txt: HashMap<String, String>,
}

/// Result of a successful registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistrationResult {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub port: u16,
    pub mode: LeaseMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u64>,
}

/// Result of a successful lease renewal (heartbeat).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RenewalResult {
    pub id: String,
    pub lease_secs: u64,
}

/// Service event kinds for subscribe streams.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Found,
    Resolved,
    Removed,
}

/// How a registration stays alive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LeaseMode {
    Session,
    Heartbeat,
    Permanent,
}

/// Wire-level registration state (domain `RegistrationState` carries
/// temporal data; this is the display-only projection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LeaseState {
    Alive,
    Draining,
}

/// Full registration state as exposed to admin queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRegistration {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub port: u16,
    pub mode: LeaseMode,
    pub state: LeaseState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_secs: Option<u64>,
    pub grace_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub registered_at: String,
    pub last_seen: String,
    #[serde(default)]
    pub txt: HashMap<String, String>,
}

/// Daemon status overview for admin queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
    pub uptime_secs: u64,
    pub platform: String,
    pub registrations: RegistrationCounts,
}

/// Registration counts by state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationCounts {
    pub alive: usize,
    pub draining: usize,
    pub permanent: usize,
    pub total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_record_omits_none_fields() {
        let record = ServiceRecord {
            name: "Test".into(),
            service_type: "_http._tcp".into(),
            host: None,
            ip: None,
            port: None,
            txt: HashMap::new(),
        };
        let json = serde_json::to_value(&record).unwrap();
        assert!(!json.as_object().unwrap().contains_key("host"));
        assert!(!json.as_object().unwrap().contains_key("ip"));
        assert!(!json.as_object().unwrap().contains_key("port"));
    }

    #[test]
    fn service_record_includes_present_fields() {
        let record = ServiceRecord {
            name: "Test".into(),
            service_type: "_http._tcp".into(),
            host: Some("server.local".into()),
            ip: Some("192.168.1.42".into()),
            port: Some(8080),
            txt: HashMap::from([("version".into(), "1.0".into())]),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"host\":\"server.local\""));
        assert!(json.contains("\"ip\":\"192.168.1.42\""));
    }

    #[test]
    fn service_record_uses_type_not_service_type_in_json() {
        let record = ServiceRecord {
            name: "Test".into(),
            service_type: "_http._tcp".into(),
            host: None,
            ip: None,
            port: Some(80),
            txt: HashMap::new(),
        };
        let json = serde_json::to_value(&record).unwrap();
        assert!(json.get("type").is_some());
        assert!(json.get("service_type").is_none());
    }

    #[test]
    fn register_payload_deserializes_from_json() {
        let json =
            r#"{"name": "My App", "type": "_http._tcp", "port": 8080, "txt": {"version": "1.0"}}"#;
        let payload: RegisterPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name, "My App");
        assert_eq!(payload.service_type, "_http._tcp");
        assert_eq!(payload.port, 8080);
        assert_eq!(payload.txt.get("version").unwrap(), "1.0");
    }

    #[test]
    fn register_payload_defaults_txt_to_empty() {
        let json = r#"{"name": "Bare", "type": "_http._tcp", "port": 80}"#;
        let payload: RegisterPayload = serde_json::from_str(json).unwrap();
        assert!(payload.txt.is_empty());
    }

    #[test]
    fn register_payload_defaults_lease_to_none() {
        let json = r#"{"name": "Bare", "type": "_http._tcp", "port": 80}"#;
        let payload: RegisterPayload = serde_json::from_str(json).unwrap();
        assert!(payload.lease_secs.is_none());
    }

    #[test]
    fn register_payload_accepts_lease_secs() {
        let json = r#"{"name": "Bare", "type": "_http._tcp", "port": 80, "lease_secs": 300}"#;
        let payload: RegisterPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.lease_secs, Some(300));
    }

    #[test]
    fn lease_mode_serializes_to_lowercase() {
        assert_eq!(serde_json::to_value(LeaseMode::Session).unwrap(), "session");
        assert_eq!(
            serde_json::to_value(LeaseMode::Heartbeat).unwrap(),
            "heartbeat"
        );
        assert_eq!(
            serde_json::to_value(LeaseMode::Permanent).unwrap(),
            "permanent"
        );
    }

    #[test]
    fn lease_state_serializes_to_lowercase() {
        assert_eq!(serde_json::to_value(LeaseState::Alive).unwrap(), "alive");
        assert_eq!(
            serde_json::to_value(LeaseState::Draining).unwrap(),
            "draining"
        );
    }

    #[test]
    fn renewal_result_roundtrips() {
        let r = RenewalResult {
            id: "abc".into(),
            lease_secs: 300,
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: RenewalResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, r2);
    }
}
