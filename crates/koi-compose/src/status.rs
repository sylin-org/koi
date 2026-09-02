//! Unified capability-status assembly — the one capability ladder that the daemon's
//! `/v1/status`, the dashboard snapshot, and the embedded snapshot all share.
//!
//! Before P07 this 7-rung ladder (mdns, certmesh, dns, health, proxy, udp, runtime — each
//! with present / stopped / disabled branches) was hand-written three times and could
//! silently drift between the HTTP API, the dashboard, and embedded.
//! [`crate::status::assemble_capabilities`]
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
    /// Project this report into the dashboard/embedded capability card shape:
    /// `{name, enabled, healthy, summary}`. The single source both the daemon's
    /// dashboard snapshot and the embedded snapshot serialize, so the four-field card
    /// cannot drift between the two presentations.
    pub fn into_card(self) -> serde_json::Value {
        serde_json::json!({
            "name": self.status.name,
            "enabled": self.enabled,
            "healthy": self.status.healthy,
            "summary": self.status.summary,
        })
    }

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
/// mdns, certmesh, dns, health, proxy, udp, runtime, ipc, pond.
///
/// DNS and health distinguish running / stopped / disabled; proxy is always healthy when
/// present (its summary is the listener count); the rest are present-or-disabled.
pub async fn assemble_capabilities(cores: &Cores) -> Vec<CapabilityReport> {
    let mut caps = Vec::with_capacity(9);

    // mDNS
    caps.push(match &cores.mdns {
        Some(core) => CapabilityReport::present(core.status().await),
        None => CapabilityReport::disabled("mdns"),
    });

    // Certmesh
    caps.push(match &cores.certmesh {
        Some(core) => CapabilityReport::present(core.status().await),
        None => CapabilityReport::disabled("certmesh"),
    });

    // DNS
    caps.push(match &cores.dns {
        Some(rt) => {
            let runtime = rt.status().await;
            if runtime.running {
                let mut status = rt.core().status().await;
                status.summary = format!(
                    "{}; listening on {}{}",
                    status.summary,
                    runtime.endpoints.join(", "),
                    runtime
                        .reason
                        .as_deref()
                        .map(|reason| format!(" ({reason})"))
                        .unwrap_or_default()
                );
                CapabilityReport::present(status)
            } else if runtime.desired {
                CapabilityReport::present(CapabilityStatus {
                    name: "dns".to_string(),
                    summary: format!(
                        "waiting: {}",
                        runtime
                            .reason
                            .as_deref()
                            .unwrap_or("listener reconciliation")
                    ),
                    healthy: false,
                })
            } else {
                CapabilityReport::stopped("dns")
            }
        }
        None => CapabilityReport::disabled("dns"),
    });

    // Health
    caps.push(match &cores.health {
        Some(rt) if rt.status().await.running => {
            CapabilityReport::present(rt.core().status().await)
        }
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
        Some(rt) => CapabilityReport::present(Capability::status(rt.as_ref()).await),
        None => CapabilityReport::disabled("udp"),
    });

    // Runtime (RuntimeCore's Capability::status; was the bespoke capability_status())
    caps.push(match &cores.runtime {
        Some(rt) => CapabilityReport::present(Capability::status(rt.as_ref()).await),
        None => CapabilityReport::disabled("runtime"),
    });

    // IPC is the independent trusted local-control plane. It also carries mDNS
    // session requests when that domain is present, but never depends on it.
    let notes = koi_common::capability::notes_snapshot();
    let ipc_note = notes.iter().rev().find(|note| note.capability == "ipc");
    let ipc = match ipc_note {
        Some(note) if note.state == "mounted" => CapabilityReport {
            status: CapabilityStatus {
                name: "ipc".to_string(),
                summary: note.reason.clone(),
                healthy: true,
            },
            enabled: true,
        },
        Some(note) => CapabilityReport {
            status: CapabilityStatus {
                name: "ipc".to_string(),
                summary: format!("{}: {}", note.state, note.reason),
                healthy: false,
            },
            enabled: note.state != "disabled",
        },
        None => CapabilityReport::disabled("ipc"),
    };
    caps.push(ipc);

    // Pond is a serving adapter rather than a domain core. Its desired-state
    // controller publishes live observation into the shared note registry.
    let pond_note = notes.iter().rev().find(|note| note.capability == "pond");
    let pond = match pond_note {
        Some(note) => CapabilityReport {
            status: CapabilityStatus {
                name: "pond".to_string(),
                summary: if note.state == "running" {
                    note.reason.clone()
                } else {
                    format!("{}: {}", note.state, note.reason)
                },
                healthy: note.state == "running",
            },
            enabled: note.state != "disabled",
        },
        None => CapabilityReport::disabled("pond"),
    };
    caps.push(pond);

    // Merge assembly notes into the rungs they describe: a capability that
    // carries a note wears the note's reason as its summary (ADR-035).
    for cap in caps.iter_mut() {
        if cap.status.name == "pond" {
            continue;
        }
        if let Some(note) = notes
            .iter()
            .find(|note| note.capability == cap.status.name && note.state != "mounted")
        {
            cap.status.summary = format!("{}: {}", note.state, note.reason);
        }
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    static NOTES_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn all_disabled_ladder_is_the_canonical_nine_rungs() {
        let _notes_guard = NOTES_TEST_LOCK.lock().await;
        koi_common::capability::clear_notes();

        // Golden contract: with no cores, the ladder is exactly these nine rungs, in this
        // order, each disabled. This is the shape /v1/status, the dashboard, and embedded
        // all serialize — locking the three projections to one source. (The ipc rung joined
        // in ADR-035: it bridges the mDNS core and reports its own skip state.)
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
                ("ipc", "disabled", false, false),
                ("pond", "disabled", false, false),
            ]
        );
    }

    #[tokio::test]
    async fn pond_live_note_becomes_a_healthy_adapter_rung() {
        let _notes_guard = NOTES_TEST_LOCK.lock().await;
        koi_common::capability::clear_notes();
        koi_common::capability::set_note(koi_common::capability::CapabilityNote {
            capability: "pond".to_string(),
            state: "running".to_string(),
            reason: "read-only listener at http://192.168.1.2:5644/".to_string(),
            depends_on: vec!["http".to_string()],
        });

        let caps = assemble_capabilities(&Cores::default()).await;
        koi_common::capability::clear_notes();
        let pond = caps
            .iter()
            .find(|capability| capability.status.name == "pond")
            .expect("pond rung");
        assert!(pond.enabled);
        assert!(pond.status.healthy);
        assert!(pond.status.summary.contains("192.168.1.2:5644"));
    }

    #[tokio::test]
    async fn mdns_skip_does_not_disable_the_independent_local_control_plane() {
        let _notes_guard = NOTES_TEST_LOCK.lock().await;
        koi_common::capability::clear_notes();

        // ADR-035 "yield, but declare": an mDNS coexistence skip must be visible
        // in the ladder with its reason, and the IPC rung must name the mDNS
        // dependency it inherited the skip from.
        koi_common::capability::record_notes(vec![
            koi_common::capability::CapabilityNote {
                capability: "mdns".to_string(),
                state: "skipped".to_string(),
                reason: "UDP 5353 held by systemd-resolved".to_string(),
                depends_on: Vec::new(),
            },
            koi_common::capability::CapabilityNote {
                capability: "ipc".to_string(),
                state: "mounted".to_string(),
                reason: "trusted local-control transport".to_string(),
                depends_on: vec![],
            },
        ]);
        let caps = assemble_capabilities(&Cores::default()).await;
        koi_common::capability::clear_notes();

        let mdns = caps
            .iter()
            .find(|c| c.status.name == "mdns")
            .expect("mdns rung");
        assert!(mdns
            .status
            .summary
            .contains("UDP 5353 held by systemd-resolved"));
        let ipc = caps
            .iter()
            .find(|c| c.status.name == "ipc")
            .expect("ipc rung");
        assert!(ipc.status.healthy);
        assert!(ipc.status.summary.contains("trusted local-control"));
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
