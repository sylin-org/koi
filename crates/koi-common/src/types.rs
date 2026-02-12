use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A service instance as seen on the network.
/// Used in browse results, resolve results, register confirmations,
/// and event payloads. This is THE service representation across all domains.
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

/// Service event kinds for subscribe streams.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Found,
    Resolved,
    Removed,
}

/// Unique identifier for a connection/session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

/// DNS-SD meta-query type for discovering all service types on the network.
pub const META_QUERY: &str = "_services._dns-sd._udp.local.";

/// Maximum allowed length for DNS-SD service names (RFC 6763).
const SERVICE_NAME_MAX_LEN: usize = 15;

/// Validated DNS-SD service type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceType(String);

impl ServiceType {
    /// Parse and normalize a service type string.
    /// Accepts liberal input: "http", "_http", "_http._tcp", "_http._tcp.local."
    /// Always produces the canonical form: "_name._tcp.local."
    pub fn parse(s: &str) -> Result<Self, ServiceTypeError> {
        let s = s.trim().trim_end_matches('.');
        let s = s.trim_end_matches(".local");

        let parts: Vec<&str> = s.split('.').collect();

        let (name, proto) = match parts.len() {
            1 => {
                let name = parts[0].strip_prefix('_').unwrap_or(parts[0]);
                (name, "tcp")
            }
            2 => {
                let name = parts[0].strip_prefix('_').unwrap_or(parts[0]);
                let proto = parts[1].strip_prefix('_').unwrap_or(parts[1]);
                (name, proto)
            }
            _ => return Err(ServiceTypeError::Invalid(s.to_string())),
        };

        if proto != "tcp" && proto != "udp" {
            return Err(ServiceTypeError::Invalid(format!(
                "protocol must be tcp or udp, got '{proto}'"
            )));
        }

        if name.is_empty() || name.len() > SERVICE_NAME_MAX_LEN {
            return Err(ServiceTypeError::Invalid(format!(
                "service name must be 1-15 characters, got '{name}'"
            )));
        }

        let canonical = format!("_{name}._{proto}.local.");
        tracing::debug!("Normalized service type: \"{s}\" → \"{canonical}\"");
        Ok(ServiceType(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The short form without ".local." for user-facing output.
    pub fn short(&self) -> &str {
        self.0.trim_end_matches(".local.").trim_end_matches('.')
    }
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.short())
    }
}

/// Error parsing a DNS-SD service type string.
#[derive(Debug, thiserror::Error)]
pub enum ServiceTypeError {
    #[error("Invalid service type: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_type_parse_bare_name() {
        let st = ServiceType::parse("http").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
        assert_eq!(st.short(), "_http._tcp");
    }

    #[test]
    fn service_type_parse_with_underscore() {
        let st = ServiceType::parse("_http").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
    }

    #[test]
    fn service_type_parse_full_form() {
        let st = ServiceType::parse("_http._tcp").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
    }

    #[test]
    fn service_type_parse_with_trailing_dot() {
        let st = ServiceType::parse("_http._tcp.").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
    }

    #[test]
    fn service_type_parse_with_local_dot() {
        let st = ServiceType::parse("_http._tcp.local.").unwrap();
        assert_eq!(st.as_str(), "_http._tcp.local.");
    }

    #[test]
    fn service_type_parse_udp() {
        let st = ServiceType::parse("_dns._udp").unwrap();
        assert_eq!(st.as_str(), "_dns._udp.local.");
    }

    #[test]
    fn service_type_rejects_invalid_protocol() {
        assert!(ServiceType::parse("_http._xyz").is_err());
    }

    #[test]
    fn service_type_rejects_empty_name() {
        assert!(ServiceType::parse("").is_err());
    }

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
}
