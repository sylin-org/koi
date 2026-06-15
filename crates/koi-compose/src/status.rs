//! Unified capability-status assembly — the one capability ladder that the daemon's
//! `/v1/status`, the dashboard snapshot, and the embedded snapshot all share.
//!
//! Before P07 this 7-rung ladder (mdns, certmesh, dns, health, proxy, udp, runtime — each
//! with present / stopped / disabled branches) was hand-written three times and could
//! silently drift between the HTTP API, the dashboard, and embedded. [`assemble_capabilities`]
//! is now the one source; each consumer projects the result into its own output shape.

use koi_common::capability::{Capability, CapabilityStatus};

use crate::cores::Cores;

/// One capability's report: its status summary plus whether it is configured on at all.
///
/// `/v1/status` emits just the [`CapabilityStatus`]; the dashboard and embedded snapshots
/// additionally surface `enabled` (false only when the capability is disabled entirely — a
/// stopped-but-enabled runtime still reports `enabled = true`).
pub struct CapabilityReport {
    pub status: CapabilityStatus,
    pub enabled: bool,
}

impl CapabilityReport {
    fn present(status: CapabilityStatus) -> Self {
        Self {
            status,
            enabled: true,
        }
    }

    fn disabled(name: &str) -> Self {
        Self {
            status: CapabilityStatus {
                name: name.to_string(),
                summary: "disabled".to_string(),
                healthy: false,
            },
            enabled: false,
        }
    }

    fn stopped(name: &str) -> Self {
        Self {
            status: CapabilityStatus {
                name: name.to_string(),
                summary: "stopped".to_string(),
                healthy: false,
            },
            enabled: true,
        }
    }
}

/// Assemble the capability ladder in the canonical order:
/// mdns, certmesh, dns, health, proxy, udp, runtime.
///
/// DNS and health distinguish running / stopped / disabled; proxy is always healthy when
/// present (its summary is the listener count); the rest are present-or-disabled.
pub async fn assemble_capabilities(cores: &Cores) -> Vec<CapabilityReport> {
    let mut caps = Vec::with_capacity(7);

    // mDNS
    caps.push(match &cores.mdns {
        Some(core) => CapabilityReport::present(core.status()),
        None => CapabilityReport::disabled("mdns"),
    });

    // Certmesh
    caps.push(match &cores.certmesh {
        Some(core) => CapabilityReport::present(core.status()),
        None => CapabilityReport::disabled("certmesh"),
    });

    // DNS
    caps.push(match &cores.dns {
        Some(rt) if rt.status().await.running => CapabilityReport::present(rt.core().status()),
        Some(_) => CapabilityReport::stopped("dns"),
        None => CapabilityReport::disabled("dns"),
    });

    // Health
    caps.push(match &cores.health {
        Some(rt) if rt.status().await.running => CapabilityReport::present(rt.core().status()),
        Some(_) => CapabilityReport::stopped("health"),
        None => CapabilityReport::disabled("health"),
    });

    // Proxy (always healthy when present; summary = listener count)
    caps.push(match &cores.proxy {
        Some(rt) => {
            let listeners = rt.status().await;
            let summary = if listeners.is_empty() {
                "no listeners".to_string()
            } else {
                format!("{} listeners", listeners.len())
            };
            CapabilityReport::present(CapabilityStatus {
                name: "proxy".to_string(),
                summary,
                healthy: true,
            })
        }
        None => CapabilityReport::disabled("proxy"),
    });

    // UDP (disambiguate the Capability trait method from UdpRuntime's own status())
    caps.push(match &cores.udp {
        Some(rt) => CapabilityReport::present(Capability::status(rt.as_ref())),
        None => CapabilityReport::disabled("udp"),
    });

    // Runtime
    caps.push(match &cores.runtime {
        Some(rt) => CapabilityReport::present(rt.capability_status().await),
        None => CapabilityReport::disabled("runtime"),
    });

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn all_disabled_ladder_is_the_canonical_seven_rungs() {
        // Golden contract: with no cores, the ladder is exactly these seven rungs, in this
        // order, each disabled. This is the shape /v1/status, the dashboard, and embedded
        // all serialize — locking the three projections to one source.
        let caps = assemble_capabilities(&Cores::default()).await;
        let rungs: Vec<(&str, &str, bool, bool)> = caps
            .iter()
            .map(|c| {
                (
                    c.status.name.as_str(),
                    c.status.summary.as_str(),
                    c.status.healthy,
                    c.enabled,
                )
            })
            .collect();
        assert_eq!(
            rungs,
            vec![
                ("mdns", "disabled", false, false),
                ("certmesh", "disabled", false, false),
                ("dns", "disabled", false, false),
                ("health", "disabled", false, false),
                ("proxy", "disabled", false, false),
                ("udp", "disabled", false, false),
                ("runtime", "disabled", false, false),
            ]
        );
    }

    #[tokio::test]
    async fn capability_status_projection_matches_v1_status_shape() {
        // The `/v1/status` projection drops `enabled` and serializes {name, summary, healthy}.
        let caps = assemble_capabilities(&Cores::default()).await;
        let statuses: Vec<CapabilityStatus> = caps.into_iter().map(|c| c.status).collect();
        let json = serde_json::to_value(&statuses).unwrap();
        let first = &json[0];
        assert_eq!(first["name"], "mdns");
        assert_eq!(first["summary"], "disabled");
        assert_eq!(first["healthy"], false);
        assert!(first.get("enabled").is_none(), "/v1/status omits `enabled`");
    }
}
