//! Normalized instance and metadata types.
//!
//! Every runtime backend converts its native types into these
//! runtime-agnostic representations.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A runtime-managed instance (container, VM, or service unit).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Instance {
    /// Unique identifier from the runtime (container ID, pod UID, unit name).
    pub id: String,
    /// Human-readable name (container name, pod name, unit description).
    pub name: String,
    /// Resolved host-side port mappings.
    pub ports: Vec<PortMapping>,
    /// IP addresses reachable from the host network (as strings for serde/OpenAPI).
    pub ips: Vec<String>,
    /// Koi-specific metadata extracted from labels/annotations/config.
    pub metadata: KoiMetadata,
    /// Runtime backend that discovered this instance.
    pub backend: String,
    /// Current lifecycle state.
    pub state: InstanceState,
    /// When the instance was first observed.
    pub discovered_at: DateTime<Utc>,
    /// Image or unit source (e.g., "grafana/grafana:latest").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// A host-side port mapping.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PortMapping {
    /// Host port (the one reachable from the network).
    pub host_port: u16,
    /// Container/internal port.
    pub container_port: u16,
    /// Protocol (tcp or udp).
    pub protocol: PortProtocol,
    /// Host IP the port is bound to (0.0.0.0, 127.0.0.1, etc.).
    pub host_ip: String,
}

/// Port protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    Tcp,
    Udp,
}

/// Lifecycle state of a runtime instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum InstanceState {
    Running,
    Stopped,
    Paused,
    Restarting,
    Unknown,
}

/// Koi-specific metadata extracted from runtime labels/annotations.
///
/// All fields are optional — when absent, the adapter uses heuristics
/// or skips the corresponding Koi capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct KoiMetadata {
    /// Opt-in flag. When `Some(false)`, the instance is ignored.
    /// When `None`, the adapter uses its default policy (opt-in or opt-out).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,

    /// mDNS service type override (e.g., `_http._tcp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,

    /// Service name override for mDNS/DNS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// DNS name override (without zone suffix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_name: Option<String>,

    /// TXT record key-value pairs for mDNS.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub txt: HashMap<String, String>,

    /// Health check HTTP path (e.g., `/healthz`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_path: Option<String>,

    /// Health check kind override (`http` or `tcp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_kind: Option<String>,

    /// Health check interval in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_interval: Option<u64>,

    /// Health check timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_timeout: Option<u64>,

    /// TLS proxy listen port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,

    /// Allow remote proxy connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_remote: Option<bool>,

    /// Enable certmesh cert injection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certmesh: Option<bool>,
}

impl KoiMetadata {
    /// Parse from a flat key-value map (Docker labels, Incus user.* config).
    ///
    /// Keys use the `koi.` prefix: `koi.type`, `koi.name`, `koi.dns.name`,
    /// `koi.txt.key`, `koi.health.path`, etc.
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        let mut meta = Self::default();

        for (key, value) in labels {
            match key.as_str() {
                "koi.enable" => meta.enable = value.parse().ok(),
                "koi.type" => meta.service_type = Some(value.clone()),
                "koi.name" => meta.name = Some(value.clone()),
                "koi.dns.name" => meta.dns_name = Some(value.clone()),
                "koi.health.path" => meta.health_path = Some(value.clone()),
                "koi.health.kind" => meta.health_kind = Some(value.clone()),
                "koi.health.interval" => meta.health_interval = value.parse().ok(),
                "koi.health.timeout" => meta.health_timeout = value.parse().ok(),
                "koi.proxy.port" => meta.proxy_port = value.parse().ok(),
                "koi.proxy.remote" => meta.proxy_remote = value.parse().ok(),
                "koi.certmesh" => meta.certmesh = value.parse().ok(),
                k if k.starts_with("koi.txt.") => {
                    if let Some(txt_key) = k.strip_prefix("koi.txt.") {
                        meta.txt.insert(txt_key.to_string(), value.clone());
                    }
                }
                _ => {}
            }
        }

        meta
    }

    /// Whether this instance is explicitly opted out.
    pub fn is_disabled(&self) -> bool {
        self.enable == Some(false)
    }
}

/// Compose metadata extracted from Docker Compose labels.
#[derive(Debug, Clone, Default)]
pub struct ComposeInfo {
    pub project: Option<String>,
    pub service: Option<String>,
}

impl ComposeInfo {
    /// Extract from Docker labels.
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
        Self {
            project: labels.get("com.docker.compose.project").cloned(),
            service: labels.get("com.docker.compose.service").cloned(),
        }
    }

    /// Best available service name: Compose service > container name.
    pub fn effective_name<'a>(&'a self, container_name: &'a str) -> &'a str {
        self.service.as_deref().unwrap_or(container_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_labels_extracts_all_fields() {
        let mut labels = HashMap::new();
        labels.insert("koi.enable".into(), "true".into());
        labels.insert("koi.type".into(), "_http._tcp".into());
        labels.insert("koi.name".into(), "My App".into());
        labels.insert("koi.dns.name".into(), "myapp".into());
        labels.insert("koi.txt.version".into(), "1.0".into());
        labels.insert("koi.txt.env".into(), "production".into());
        labels.insert("koi.health.path".into(), "/healthz".into());
        labels.insert("koi.health.kind".into(), "http".into());
        labels.insert("koi.health.interval".into(), "30".into());
        labels.insert("koi.health.timeout".into(), "5".into());
        labels.insert("koi.proxy.port".into(), "443".into());
        labels.insert("koi.proxy.remote".into(), "true".into());
        labels.insert("koi.certmesh".into(), "true".into());

        let meta = KoiMetadata::from_labels(&labels);

        assert_eq!(meta.enable, Some(true));
        assert_eq!(meta.service_type.as_deref(), Some("_http._tcp"));
        assert_eq!(meta.name.as_deref(), Some("My App"));
        assert_eq!(meta.dns_name.as_deref(), Some("myapp"));
        assert_eq!(meta.txt.get("version").map(|s| s.as_str()), Some("1.0"));
        assert_eq!(meta.txt.get("env").map(|s| s.as_str()), Some("production"));
        assert_eq!(meta.health_path.as_deref(), Some("/healthz"));
        assert_eq!(meta.health_kind.as_deref(), Some("http"));
        assert_eq!(meta.health_interval, Some(30));
        assert_eq!(meta.health_timeout, Some(5));
        assert_eq!(meta.proxy_port, Some(443));
        assert_eq!(meta.proxy_remote, Some(true));
        assert_eq!(meta.certmesh, Some(true));
    }

    #[test]
    fn empty_labels_produce_defaults() {
        let meta = KoiMetadata::from_labels(&HashMap::new());
        assert!(meta.enable.is_none());
        assert!(meta.service_type.is_none());
        assert!(meta.txt.is_empty());
    }

    #[test]
    fn is_disabled_when_enable_false() {
        let mut labels = HashMap::new();
        labels.insert("koi.enable".into(), "false".into());
        let meta = KoiMetadata::from_labels(&labels);
        assert!(meta.is_disabled());
    }

    #[test]
    fn compose_info_prefers_service_over_container_name() {
        let mut labels = HashMap::new();
        labels.insert("com.docker.compose.service".into(), "grafana".into());
        labels.insert("com.docker.compose.project".into(), "monitoring".into());
        let info = ComposeInfo::from_labels(&labels);
        assert_eq!(info.effective_name("random-container-name"), "grafana");
    }

    #[test]
    fn compose_info_falls_back_to_container_name() {
        let info = ComposeInfo::from_labels(&HashMap::new());
        assert_eq!(info.effective_name("my-container"), "my-container");
    }
}
