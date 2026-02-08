use serde::Deserialize;

use super::RegisterPayload;

/// All possible inbound operations.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
