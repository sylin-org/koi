//! Privacy-preserving status projection for Pond's unauthenticated LAN surface.
//!
//! The product aggregate intentionally retains exact operational detail for trusted
//! in-process consumers. Pond exposes only this closed, coarse read model: adding an
//! internal status field cannot accidentally expand the public wire contract.

use koi_compose::status::KoiStatus;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Coarse capability state safe for Pond's unauthenticated LAN status endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondPublicCapabilityStatus {
    pub name: String,
    pub enabled: bool,
    pub healthy: bool,
}

/// Allowlisted product status safe for Pond's unauthenticated LAN surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PondPublicStatus {
    pub version: String,
    pub platform: String,
    pub uptime_secs: u64,
    pub revision: u64,
    pub daemon: bool,
    pub surface: String,
    pub capabilities: Vec<PondPublicCapabilityStatus>,
}

/// Project one already-accepted product snapshot into Pond's public read model.
///
/// This is deliberately an allowlist rather than a redaction pass. Capability
/// summaries and exact domain projections never enter the output value.
pub fn project(status: &KoiStatus, uptime_secs: u64) -> PondPublicStatus {
    PondPublicStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        uptime_secs,
        revision: status.revision,
        daemon: true,
        surface: "pond".to_string(),
        capabilities: status
            .capabilities
            .iter()
            .filter_map(|capability| {
                let name = public_capability_name(&capability.status.name)?;
                Some(PondPublicCapabilityStatus {
                    name: name.to_string(),
                    enabled: capability.enabled,
                    healthy: capability.status.healthy,
                })
            })
            .collect(),
    }
}

fn public_capability_name(name: &str) -> Option<&'static str> {
    match name {
        "mdns" => Some("mdns"),
        "certmesh" => Some("certmesh"),
        "trust" => Some("trust"),
        "dns" => Some("dns"),
        "health" => Some("health"),
        "proxy" => Some("proxy"),
        "udp" => Some("udp"),
        "runtime" => Some("runtime"),
        "ipc" => Some("ipc"),
        "pond" => Some("pond"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::capability::CapabilityStatus;
    use koi_compose::status::{CapabilityReport, DomainStatuses};
    use serde_json::json;

    fn sensitive_aggregate() -> KoiStatus {
        let mut domains = DomainStatuses::default();
        let mut pond = koi_common::pond::PondStatus::awaiting_reconciliation(56_444);
        pond.urls = vec!["http://10.23.4.5:56444/".to_string()];
        pond.url = pond.urls.first().cloned();
        pond.reason = Some("bind failed: permission denied at /secret/path".to_string());
        pond.firewall.detail = "blocked by private rule on eth-secret".to_string();
        domains.pond = Some(pond.into());

        KoiStatus {
            revision: 42,
            catalog: std::sync::Arc::new(koi_common::service::CatalogSnapshot::default()),
            capabilities: vec![
                CapabilityReport {
                    status: CapabilityStatus {
                        name: "dns".to_string(),
                        summary: "listening on 10.23.4.5:5353".to_string(),
                        healthy: true,
                    },
                    enabled: true,
                },
                CapabilityReport {
                    status: CapabilityStatus {
                        name: "pond".to_string(),
                        summary: "unavailable: permission denied at /secret/path".to_string(),
                        healthy: false,
                    },
                    enabled: false,
                },
                CapabilityReport {
                    status: CapabilityStatus {
                        name: "private endpoint 10.23.4.5:9999".to_string(),
                        summary: "internal extension error".to_string(),
                        healthy: false,
                    },
                    enabled: true,
                },
            ],
            domains,
        }
    }

    #[test]
    fn projection_serializes_only_the_public_allowlist() {
        let value = serde_json::to_value(project(&sensitive_aggregate(), 17)).unwrap();

        assert_eq!(
            value,
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "platform": std::env::consts::OS,
                "uptime_secs": 17,
                "revision": 42,
                "daemon": true,
                "surface": "pond",
                "capabilities": [
                    { "name": "dns", "enabled": true, "healthy": true },
                    { "name": "pond", "enabled": false, "healthy": false },
                ],
            })
        );
    }

    #[test]
    fn operational_summaries_endpoints_and_errors_cannot_cross_the_boundary() {
        let encoded = serde_json::to_string(&project(&sensitive_aggregate(), 17)).unwrap();

        for private_fragment in [
            "summary",
            "domains",
            "urls",
            "url",
            "reason",
            "detail",
            "10.23.4.5",
            "5353",
            "56444",
            "permission denied",
            "/secret/path",
            "eth-secret",
        ] {
            assert!(
                !encoded.contains(private_fragment),
                "public Pond status leaked {private_fragment:?}: {encoded}"
            );
        }
    }

    #[test]
    fn public_status_wire_round_trips() {
        let projected = project(&sensitive_aggregate(), 17);
        let encoded = serde_json::to_string(&projected).unwrap();
        assert_eq!(
            serde_json::from_str::<PondPublicStatus>(&encoded).unwrap(),
            projected
        );
    }
}
