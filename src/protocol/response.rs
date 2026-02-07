use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use super::{EventKind, RegistrationResult, ServiceRecord};

/// All possible outbound messages.
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
    Error {
        error: String,
        message: String,
    },
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
            Response::Error { error, message } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("error", error)?;
                map.serialize_entry("message", message)?;
                map.end()
            }
        }
    }
}

/// Pipeline status for streaming responses.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PipelineStatus {
    Ongoing,
    Finished,
}

/// A response with optional pipeline metadata.
/// `#[serde(flatten)]` on body produces flat JSON output.
/// `skip_serializing_if` on status/warning means clean responses have no extra keys.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineResponse {
    #[serde(flatten)]
    pub body: Response,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<PipelineStatus>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

impl PipelineResponse {
    /// Wrap a response with no pipeline metadata (the happy path).
    pub fn clean(body: Response) -> Self {
        Self {
            body,
            status: None,
            warning: None,
        }
    }

    /// Wrap a response with an ongoing status.
    pub fn ongoing(body: Response) -> Self {
        Self {
            body,
            status: Some(PipelineStatus::Ongoing),
            warning: None,
        }
    }

    /// Wrap a response with a finished status.
    pub fn finished(body: Response) -> Self {
        Self {
            body,
            status: Some(PipelineStatus::Finished),
            warning: None,
        }
    }

    /// Attach a warning to this response.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warning = Some(warning.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_record() -> ServiceRecord {
        ServiceRecord {
            name: "Server A".into(),
            service_type: "_http._tcp".into(),
            host: Some("server.local".into()),
            ip: Some("192.168.1.42".into()),
            port: 8080,
            txt: HashMap::from([("version".into(), "2.1".into())]),
        }
    }

    #[test]
    fn clean_response_has_no_pipeline_properties() {
        let resp = PipelineResponse::clean(Response::Found(test_record()));
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("status"));
        assert!(!obj.contains_key("warning"));
        assert!(obj.contains_key("found"));
    }

    #[test]
    fn ongoing_response_includes_status() {
        let resp = PipelineResponse::ongoing(Response::Found(test_record()));
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.get("status").unwrap(), "ongoing");
        assert!(obj.contains_key("found"));
    }

    #[test]
    fn finished_response_includes_status() {
        let resp = PipelineResponse::finished(Response::Found(test_record()));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("status").unwrap(), "finished");
    }

    #[test]
    fn warning_attaches_to_response() {
        let resp =
            PipelineResponse::finished(Response::Found(test_record())).with_warning("TXT empty");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("warning").unwrap(), "TXT empty");
        assert_eq!(json.get("status").unwrap(), "finished");
    }

    #[test]
    fn flatten_produces_flat_json_not_nested() {
        let resp = PipelineResponse::clean(Response::Found(test_record()));
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("found").is_some());
        assert!(json.get("body").is_none());
    }

    #[test]
    fn error_response_serializes_correctly() {
        let resp = PipelineResponse::clean(Response::Error {
            error: "not_found".into(),
            message: "No registration with id 'xyz'".into(),
        });
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("error").unwrap(), "not_found");
        assert_eq!(
            json.get("message").unwrap(),
            "No registration with id 'xyz'"
        );
    }

    #[test]
    fn registered_response_serializes_correctly() {
        let resp = PipelineResponse::clean(Response::Registered(RegistrationResult {
            id: "a1b2c3".into(),
            name: "My App".into(),
            service_type: "_http._tcp".into(),
            port: 8080,
        }));
        let json = serde_json::to_value(&resp).unwrap();
        let reg = json.get("registered").unwrap();
        assert_eq!(reg.get("id").unwrap(), "a1b2c3");
        assert_eq!(reg.get("name").unwrap(), "My App");
    }

    #[test]
    fn unregistered_response_serializes_correctly() {
        let resp = PipelineResponse::clean(Response::Unregistered("a1b2c3".into()));
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("unregistered").unwrap(), "a1b2c3");
    }

    #[test]
    fn event_response_serializes_correctly() {
        let resp = PipelineResponse::clean(Response::Event {
            event: EventKind::Found,
            service: test_record(),
        });
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json.get("event").unwrap(), "found");
        assert!(json.get("service").is_some());
    }
}
