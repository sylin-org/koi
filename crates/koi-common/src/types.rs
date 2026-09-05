use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A service instance as seen on the network.
/// Used in browse results, resolve results, register confirmations,
/// and event payloads. This is THE service representation across all domains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
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

/// Supported health service-check kinds (wire contract). Lives in the kernel so a
/// client can request a check without depending on the `koi-health` engine;
/// `koi-health` re-exports it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ServiceCheckKind {
    Http,
    Tcp,
}

/// Unique identifier for a connection/session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl SessionId {
    /// Create a new session identifier.
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
        Self::parse_inner(s, false)
    }

    /// Parse and normalize a type used for service browsing.
    ///
    /// In addition to the liberal base forms accepted by [`Self::parse`], this
    /// accepts the DNS-SD selective-enumeration form
    /// `<subtype>._sub._service._tcp.local.`. Registration intentionally keeps
    /// using [`Self::parse`]: a subtype is a browse selector, not a distinct
    /// service-instance namespace.
    pub fn parse_browse(s: &str) -> Result<Self, ServiceTypeError> {
        Self::parse_inner(s, true)
    }

    fn parse_inner(input: &str, allow_subtype: bool) -> Result<Self, ServiceTypeError> {
        let trimmed = input.trim().trim_end_matches('.');
        let mut parts = split_presentation_labels(trimmed)
            .ok_or_else(|| ServiceTypeError::Invalid(input.to_string()))?;
        if parts
            .last()
            .is_some_and(|label| label.eq_ignore_ascii_case("local"))
        {
            parts.pop();
        }

        let (subtype, name, proto) = match parts.as_slice() {
            [single] => {
                let name = single.strip_prefix('_').unwrap_or(single);
                (None, name, "tcp")
            }
            [name, proto] => {
                let name = name.strip_prefix('_').unwrap_or(name);
                let proto = proto.strip_prefix('_').unwrap_or(proto);
                (None, name, proto)
            }
            [subtype, marker, name, proto]
                if allow_subtype && marker.eq_ignore_ascii_case("_sub") =>
            {
                let name = name.strip_prefix('_').unwrap_or(name);
                let proto = proto.strip_prefix('_').unwrap_or(proto);
                (Some(*subtype), name, proto)
            }
            _ => return Err(ServiceTypeError::Invalid(input.to_string())),
        };

        if !proto.eq_ignore_ascii_case("tcp") && !proto.eq_ignore_ascii_case("udp") {
            return Err(ServiceTypeError::Invalid(format!(
                "protocol must be tcp or udp, got '{proto}'"
            )));
        }

        if name.is_empty() || name.len() > SERVICE_NAME_MAX_LEN {
            return Err(ServiceTypeError::Invalid(format!(
                "service name must be 1-15 characters, got '{name}'"
            )));
        }
        if subtype.is_some_and(|value| value.is_empty() || value.len() > 63) {
            return Err(ServiceTypeError::Invalid(
                "DNS-SD subtype must contain 1-63 bytes".to_string(),
            ));
        }

        let mut name = name.to_string();
        name.make_ascii_lowercase();
        let mut proto = proto.to_string();
        proto.make_ascii_lowercase();
        let canonical = match subtype {
            Some(subtype) => {
                let mut subtype = subtype.to_string();
                subtype.make_ascii_lowercase();
                format!("{subtype}._sub._{name}._{proto}.local.")
            }
            None => format!("_{name}._{proto}.local."),
        };
        tracing::debug!("Normalized service type: \"{input}\" → \"{canonical}\"");
        Ok(ServiceType(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The short form without ".local." for user-facing output.
    pub fn short(&self) -> &str {
        self.0.trim_end_matches(".local.").trim_end_matches('.')
    }

    /// Canonical base type for either a base browse or a subtype browse.
    pub fn base_type(&self) -> String {
        let labels = self.0.split('.').collect::<Vec<_>>();
        if labels.get(1).is_some_and(|label| *label == "_sub") {
            format!("{}.{}.local.", labels[2], labels[3])
        } else {
            self.0.clone()
        }
    }

    pub fn is_subtype(&self) -> bool {
        self.0.split('.').nth(1) == Some("_sub")
    }
}

/// Split a DNS presentation name without treating an escaped dot as a label
/// separator. The returned slices retain their presentation escaping.
fn split_presentation_labels(value: &str) -> Option<Vec<&str>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    let bytes = value.as_bytes();
    let mut labels = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                cursor += 1;
                if cursor >= bytes.len() {
                    return None;
                }
                cursor += 1;
            }
            b'.' => {
                if cursor == start {
                    return None;
                }
                labels.push(&value[start..cursor]);
                cursor += 1;
                start = cursor;
            }
            _ => cursor += 1,
        }
    }
    if start == bytes.len() {
        return None;
    }
    labels.push(&value[start..]);
    Some(labels)
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
    fn service_type_browse_accepts_subtypes_without_making_them_registrable() {
        let subtype = ServiceType::parse_browse("_Printer._SUB._HTTP._TCP.LOCAL.").unwrap();
        assert_eq!(subtype.as_str(), "_printer._sub._http._tcp.local.");
        assert_eq!(subtype.base_type(), "_http._tcp.local.");
        assert!(subtype.is_subtype());
        assert!(ServiceType::parse(subtype.as_str()).is_err());
    }

    #[test]
    fn service_type_parse_is_ascii_case_and_trailing_dot_insensitive() {
        assert_eq!(
            ServiceType::parse("_CuStOm._UdP.LoCaL.").unwrap().as_str(),
            "_custom._udp.local."
        );
    }

    #[test]
    fn subtype_label_may_use_dns_presentation_escaping() {
        let subtype = ServiceType::parse_browse(r"Printer\.Color._sub._ipp._tcp.local.").unwrap();
        assert_eq!(subtype.as_str(), r"printer\.color._sub._ipp._tcp.local.");
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
