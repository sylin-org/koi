use std::collections::HashMap;

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use utoipa::ToSchema;

use koi_common::api::{error_body, ErrorBody};
use koi_common::error::ErrorCode;
use koi_common::types::{EventKind, ServiceRecord};

use crate::error::MdnsError;
use crate::events::MdnsEvent;

// ── mDNS-specific wire types ─────────────────────────────────────────

/// Payload for registering a new service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct RenewalResult {
    pub id: String,
    pub lease_secs: u64,
}

/// How a registration stays alive (wire representation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LeaseMode {
    Session,
    Heartbeat,
    Permanent,
}

/// Wire-level registration state (display-only projection).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LeaseState {
    Alive,
    Draining,
}

/// Full registration state as exposed to admin queries.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DaemonStatus {
    pub version: String,
    pub uptime_secs: u64,
    pub platform: String,
    pub registrations: RegistrationCounts,
}

/// Registration counts by state.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegistrationCounts {
    pub alive: usize,
    pub draining: usize,
    pub permanent: usize,
    pub total: usize,
}

// ── Request ──────────────────────────────────────────────────────────

/// All possible inbound operations for mDNS.
/// The top-level JSON key determines the variant.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Request {
    Browse(String),
    Register(RegisterPayload),
    Unregister(String),
    Resolve(String),
    Subscribe(String),
    Heartbeat(String),
}

// ── Response ─────────────────────────────────────────────────────────

/// All possible outbound messages for the mDNS domain.
/// Custom Serialize ensures the correct JSON shape for each variant:
/// - Found/Registered/Unregistered/Resolved: `{"found": {...}}`
/// - Error: `{"error": "code", "message": "..."}`  (flat)
/// - Event: `{"event": "kind", "service": {...}}`   (flat)
#[derive(Debug, Clone)]
pub enum Response {
    Found(ServiceRecord),
    Registered(RegistrationResult),
    Unregistered(String),
    Resolved(ServiceRecord),
    Event {
        event: EventKind,
        service: ServiceRecord,
    },
    Renewed(RenewalResult),
    Error(ErrorBody),
}

impl Serialize for Response {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Response::Found(record) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("found", record)?;
                map.end()
            }
            Response::Registered(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("registered", result)?;
                map.end()
            }
            Response::Unregistered(id) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("unregistered", id)?;
                map.end()
            }
            Response::Resolved(record) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("resolved", record)?;
                map.end()
            }
            Response::Event { event, service } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("event", event)?;
                map.serialize_entry("service", service)?;
                map.end()
            }
            Response::Renewed(result) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("renewed", result)?;
                map.end()
            }
            Response::Error(body) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("error", &body.error)?;
                map.serialize_entry("message", &body.message)?;
                map.end()
            }
        }
    }
}

// ── Pipeline helpers ─────────────────────────────────────────────────

use koi_common::pipeline::PipelineResponse;

/// Type alias for mDNS pipeline responses.
pub type MdnsPipelineResponse = PipelineResponse<Response>;

/// Convert a browse event into a pipeline response.
pub fn browse_event_to_pipeline(event: MdnsEvent) -> MdnsPipelineResponse {
    match event {
        MdnsEvent::Resolved(record) | MdnsEvent::Found(record) => {
            PipelineResponse::clean(Response::Found(record))
        }
        MdnsEvent::Removed { name, service_type } => PipelineResponse::clean(Response::Event {
            event: EventKind::Removed,
            service: ServiceRecord {
                name,
                service_type,
                host: None,
                ip: None,
                port: None,
                txt: Default::default(),
            },
        }),
    }
}

/// Convert a subscribe event into a pipeline response.
pub fn subscribe_event_to_pipeline(event: MdnsEvent) -> MdnsPipelineResponse {
    let (kind, record) = match event {
        MdnsEvent::Found(record) => (EventKind::Found, record),
        MdnsEvent::Resolved(record) => (EventKind::Resolved, record),
        MdnsEvent::Removed { name, service_type } => (
            EventKind::Removed,
            ServiceRecord {
                name,
                service_type,
                host: None,
                ip: None,
                port: None,
                txt: Default::default(),
            },
        ),
    };
    PipelineResponse::clean(Response::Event {
        event: kind,
        service: record,
    })
}

/// Convert an MdnsError into a pipeline error response.
pub fn error_to_pipeline(e: &MdnsError) -> MdnsPipelineResponse {
    PipelineResponse::clean(Response::Error(error_body(
        ErrorCode::from(e),
        e.to_string(),
    )))
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_record() -> ServiceRecord {
        ServiceRecord {
            name: "Server A".into(),
            service_type: "_http._tcp".into(),
            host: Some("server.local".into()),
            ip: Some("192.168.1.42".into()),
            port: Some(8080),
            txt: HashMap::from([("version".into(), "2.1".into())]),
        }
    }

    // ── RegisterPayload tests ────────────────────────────────────────

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

    // ── Request tests ────────────────────────────────────────────────

    #[test]
    fn browse_request_parses() {
        let json = r#"{"browse": "_http._tcp"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Browse(ref s) if s == "_http._tcp"));
    }

    #[test]
    fn register_request_parses() {
        let json = r#"{"register": {"name": "My App", "type": "_http._tcp", "port": 8080}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Register(ref p) if p.name == "My App"));
    }

    #[test]
    fn unregister_request_parses() {
        let json = r#"{"unregister": "abc123"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Unregister(ref id) if id == "abc123"));
    }

    #[test]
    fn resolve_request_parses() {
        let json = r#"{"resolve": "My App._http._tcp.local."}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Resolve(ref s) if s == "My App._http._tcp.local."));
    }

    #[test]
    fn subscribe_request_parses() {
        let json = r#"{"subscribe": "_http._tcp"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Subscribe(ref s) if s == "_http._tcp"));
    }

    #[test]
    fn heartbeat_request_parses() {
        let json = r#"{"heartbeat": "a1b2c3d4"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(matches!(req, Request::Heartbeat(ref id) if id == "a1b2c3d4"));
    }

    #[test]
    fn unknown_verb_fails() {
        let json = r#"{"explode": "boom"}"#;
        let result = serde_json::from_str::<Request>(json);
        assert!(result.is_err());
    }

    // ── Response tests ───────────────────────────────────────────────

    #[test]
    fn clean_response_has_no_pipeline_properties() {
        let resp = MdnsPipelineResponse::clean(Response::Found(test_record()));
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("status"));
        assert!(!obj.contains_key("warning"));
        assert!(obj.contains_key("found"));
    }

    #[test]
    fn ongoing_response_includes_status() {
        let resp = MdnsPipelineResponse::ongoing(Response::Found(test_record()));
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.get("status").unwrap(), "ongoing");
        assert!(obj.contains_key("found"));
    }

    #[test]
    fn finished_response_includes_status() {
        let resp = MdnsPipelineResponse::finished(Response::Found(test_record()));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("status").unwrap(), "finished");
    }

    #[test]
    fn warning_attaches_to_response() {
        let resp = MdnsPipelineResponse::finished(Response::Found(test_record()))
            .with_warning("TXT empty");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("warning").unwrap(), "TXT empty");
        assert_eq!(json.get("status").unwrap(), "finished");
    }

    #[test]
    fn flatten_produces_flat_json_not_nested() {
        let resp = MdnsPipelineResponse::clean(Response::Found(test_record()));
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("found").is_some());
        assert!(json.get("body").is_none());
    }

    #[test]
    fn renewed_response_serializes_correctly() {
        let resp = MdnsPipelineResponse::clean(Response::Renewed(RenewalResult {
            id: "a1b2c3".into(),
            lease_secs: 300,
        }));
        let json = serde_json::to_value(&resp).unwrap();
        let renewed = json.get("renewed").unwrap();
        assert_eq!(renewed.get("id").unwrap(), "a1b2c3");
        assert_eq!(renewed.get("lease_secs").unwrap(), 300);
    }

    #[test]
    fn error_response_serializes_correctly() {
        let resp = MdnsPipelineResponse::clean(Response::Error(error_body(
            ErrorCode::NotFound,
            "No registration with id 'xyz'",
        )));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("error").unwrap(), "not_found");
        assert_eq!(
            json.get("message").unwrap(),
            "No registration with id 'xyz'"
        );
    }

    #[test]
    fn registered_response_serializes_correctly() {
        let resp = MdnsPipelineResponse::clean(Response::Registered(RegistrationResult {
            id: "a1b2c3".into(),
            name: "My App".into(),
            service_type: "_http._tcp".into(),
            port: 8080,
            mode: LeaseMode::Permanent,
            lease_secs: None,
        }));
        let json = serde_json::to_value(&resp).unwrap();
        let reg = json.get("registered").unwrap();
        assert_eq!(reg.get("id").unwrap(), "a1b2c3");
        assert_eq!(reg.get("name").unwrap(), "My App");
    }

    #[test]
    fn unregistered_response_serializes_correctly() {
        let resp = MdnsPipelineResponse::clean(Response::Unregistered("a1b2c3".into()));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("unregistered").unwrap(), "a1b2c3");
    }

    #[test]
    fn event_response_serializes_correctly() {
        let resp = MdnsPipelineResponse::clean(Response::Event {
            event: EventKind::Found,
            service: test_record(),
        });
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("event").unwrap(), "found");
        assert!(json.get("service").is_some());
    }

    // ── Pipeline helper free function tests ─────────────────────────

    #[test]
    fn browse_event_resolved_produces_found() {
        let event = MdnsEvent::Resolved(test_record());
        let resp = browse_event_to_pipeline(event);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("found").is_some(), "should have 'found' key");
        assert_eq!(json.get("found").unwrap().get("name").unwrap(), "Server A");
    }

    #[test]
    fn browse_event_removed_produces_event_removed() {
        let event = MdnsEvent::Removed {
            name: "Gone._http._tcp.local.".into(),
            service_type: "_http._tcp".into(),
        };
        let resp = browse_event_to_pipeline(event);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("event").unwrap(), "removed");
        assert_eq!(
            json.get("service").unwrap().get("name").unwrap(),
            "Gone._http._tcp.local."
        );
    }

    #[test]
    fn subscribe_event_found_produces_event_found() {
        let event = MdnsEvent::Found(test_record());
        let resp = subscribe_event_to_pipeline(event);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("event").unwrap(), "found");
        assert!(json.get("service").is_some());
    }

    #[test]
    fn subscribe_event_resolved_produces_event_resolved() {
        let event = MdnsEvent::Resolved(test_record());
        let resp = subscribe_event_to_pipeline(event);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("event").unwrap(), "resolved");
        assert_eq!(
            json.get("service").unwrap().get("name").unwrap(),
            "Server A"
        );
    }

    #[test]
    fn error_to_pipeline_not_found() {
        let err = MdnsError::RegistrationNotFound("xyz".into());
        let resp = error_to_pipeline(&err);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("error").unwrap(), "not_found");
        let msg = json.get("message").unwrap().as_str().unwrap();
        assert!(msg.contains("xyz"), "message should contain id: {msg}");
    }
}
