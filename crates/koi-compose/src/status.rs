//! Reactive whole-product status assembly shared by `/v1/status`, the dashboard,
//! MCP, Pond, and embedded consumers.
//!
//! [`KoiStatus`](crate::status::KoiStatus) is the one cached ten-rung aggregate:
//! mDNS, Certmesh, Trust, DNS, Health, Proxy, UDP, Runtime, IPC, and Pond. Domain
//! feeds contribute their already-decided `Arc` snapshots; composition adds only
//! its own IPC/Pond facts. Consumers read one revision instead of re-querying
//! domains or rebuilding a potentially torn view.

use std::collections::BTreeMap;
use std::future::pending;
use std::sync::{Arc, Mutex};

use koi_common::capability::CapabilityStatus;
use koi_common::status::StatusFeed;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::cores::Cores;

/// Stable product capability order shared by every whole-Koi presentation.
///
/// This belongs to composition rather than `koi-common`: it names the domains
/// and adapters assembled into one Koi process, not vocabulary owned by an
/// individual domain. Presentations may describe a rung as unobserved, but must
/// not invent a shorter product shape when the daemon is unavailable.
pub const CAPABILITY_LADDER: [&str; 10] = [
    "mdns", "certmesh", "trust", "dns", "health", "proxy", "udp", "runtime", "ipc", "pond",
];

/// One capability's report: its status summary plus whether it is configured on at all.
///
/// `/v1/status` emits just the [`CapabilityStatus`]; the dashboard and embedded snapshots
/// additionally surface `enabled` (false only when the capability is disabled entirely — a
/// stopped-but-enabled runtime still reports `enabled = true`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub status: CapabilityStatus,
    pub enabled: bool,
}

/// Observable composition-level projection consumed by the daemon, embedded
/// facade, dashboard, and MCP adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KoiStatus {
    /// Monotonic process-local revision, advanced when any capability or exact
    /// domain projection in this aggregate changes semantically.
    pub revision: u64,
    pub capabilities: Vec<CapabilityReport>,
    /// Exact domain snapshots captured alongside `capabilities`. Presentations
    /// use these values rather than rereading individual cores and creating a
    /// torn product view.
    pub domains: DomainStatuses,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainStatuses {
    pub mdns: Option<Arc<koi_mdns::MdnsStatus>>,
    /// Exact specialized mDNS discovery projection. `MdnsStatus` deliberately
    /// retains only bounded counts; presentations needing resolved records read
    /// this value from the same composition snapshot instead of consulting the
    /// mDNS core independently.
    pub mdns_discovery: Option<Arc<koi_common::integration::MdnsDiscoverySnapshot>>,
    pub certmesh: Option<Arc<koi_certmesh::CertmeshStatus>>,
    pub trust: Option<Arc<koi_trust::TrustStatus>>,
    /// Certmesh-owned active roster projection for cross-domain consumers and
    /// presentations. Keeping the domain's already-decided membership semantics
    /// here avoids downstream filtering of the full operational status.
    pub certmesh_roster: Option<Arc<koi_common::integration::CertmeshRosterSnapshot>>,
    pub dns: Option<Arc<koi_dns::DnsRuntimeStatus>>,
    /// DNS-owned presentation catalog for consumers that need effective names
    /// or static entries, but not resolver internals.
    pub dns_catalog: Option<Arc<koi_dns::DnsCatalogSnapshot>>,
    pub health: Option<Arc<koi_health::HealthSnapshot>>,
    pub proxy: Option<Arc<koi_proxy::ProxyRuntimeStatus>>,
    pub udp: Option<Arc<koi_udp::UdpRuntimeStatus>>,
    pub runtime: Option<Arc<koi_runtime::RuntimeStatus>>,
    /// Exact desired and observed state of the optional Pond serving component.
    pub pond: Option<Arc<koi_common::pond::PondStatus>>,
}

#[derive(Debug, Default)]
struct CompositionInputs {
    overrides: BTreeMap<String, CapabilityReport>,
    pond: Option<Arc<koi_common::pond::PondStatus>>,
}

/// Owner of the composition-level status feed.
#[derive(Debug)]
pub struct KoiStatusRuntime {
    feed: StatusFeed<KoiStatus>,
    inputs: Mutex<CompositionInputs>,
}

impl Default for KoiStatusRuntime {
    fn default() -> Self {
        Self {
            feed: StatusFeed::new(KoiStatus {
                revision: 0,
                capabilities: disabled_ladder(),
                domains: DomainStatuses::default(),
            }),
            inputs: Mutex::new(CompositionInputs::default()),
        }
    }
}

impl KoiStatusRuntime {
    pub fn status(&self) -> Arc<KoiStatus> {
        self.feed.current()
    }

    pub fn watch_status(&self) -> tokio::sync::watch::Receiver<Arc<KoiStatus>> {
        self.feed.subscribe()
    }

    /// Publish a composition-owned capability projection, then refresh the
    /// aggregate. Domain-owned status must never be supplied through this path.
    pub(crate) fn publish_composition_status(
        &self,
        cores: &Cores,
        report: CapabilityReport,
    ) -> Arc<KoiStatus> {
        let mut inputs = self.inputs.lock().expect("composition status lock");
        inputs.overrides.insert(report.status.name.clone(), report);
        self.reconcile_with(cores, &inputs)
    }

    /// Accept the latest typed state from the optional Pond serving component.
    ///
    /// Pond lives above composition in `koi-serve`, so it is explicitly projected
    /// here rather than hidden in `Cores` or reduced to a human summary.
    pub(crate) fn publish_pond_status(
        &self,
        cores: &Cores,
        status: Arc<koi_common::pond::PondStatus>,
    ) -> Arc<KoiStatus> {
        let mut inputs = self.inputs.lock().expect("composition status lock");
        inputs.overrides.remove("pond");
        inputs.pond = Some(status);
        self.reconcile_with(cores, &inputs)
    }

    pub(crate) fn install_initial_statuses(&self, reports: Vec<CapabilityReport>) {
        let mut inputs = self.inputs.lock().expect("composition status lock");
        for report in reports {
            inputs.overrides.insert(report.status.name.clone(), report);
        }
    }

    /// Refresh exclusively from cheap domain projections and composition facts.
    pub fn reconcile(&self, cores: &Cores) -> Arc<KoiStatus> {
        let inputs = self.inputs.lock().expect("composition status lock");
        self.reconcile_with(cores, &inputs)
    }

    fn reconcile_with(&self, cores: &Cores, inputs: &CompositionInputs) -> Arc<KoiStatus> {
        let domains = capture_domains(cores, inputs.pond.clone());
        let capabilities = project_capabilities(&domains, &inputs.overrides);
        self.feed.update(|current| {
            if current.capabilities == capabilities && current.domains == domains {
                None
            } else {
                Some(KoiStatus {
                    revision: current.revision.saturating_add(1),
                    capabilities,
                    domains,
                })
            }
        })
    }
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

    pub fn available(name: impl Into<String>, summary: impl Into<String>, healthy: bool) -> Self {
        Self {
            status: CapabilityStatus {
                name: name.into(),
                summary: summary.into(),
                healthy,
            },
            enabled: true,
        }
    }

    fn present(status: CapabilityStatus) -> Self {
        Self {
            status,
            enabled: true,
        }
    }

    pub fn disabled(name: impl Into<String>, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            status: CapabilityStatus {
                name: name.into(),
                summary: if reason.is_empty() {
                    "disabled".to_string()
                } else {
                    format!("disabled: {reason}")
                },
                healthy: false,
            },
            enabled: false,
        }
    }

    pub fn unavailable(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::available(name, format!("unavailable: {}", reason.into()), false)
    }

    fn stopped(name: &str) -> Self {
        Self::available(name, "stopped", false)
    }
}

fn disabled_ladder() -> Vec<CapabilityReport> {
    CAPABILITY_LADDER
        .into_iter()
        .map(|name| CapabilityReport::disabled(name, ""))
        .collect()
}

/// Assemble the capability ladder in the canonical order:
/// mdns, certmesh, trust, dns, health, proxy, udp, runtime, ipc, pond.
///
/// DNS, health, and proxy distinguish real observed readiness from mere presence;
/// the remaining domains project their own bounded state below.
fn capture_domains(
    cores: &Cores,
    pond: Option<Arc<koi_common::pond::PondStatus>>,
) -> DomainStatuses {
    let (mdns, mdns_discovery) = match &cores.mdns {
        Some(core) => {
            let (status, discovery) = core.status_with_discovery();
            (Some(status), Some(discovery))
        }
        None => (None, None),
    };
    let (certmesh, certmesh_roster) = match &cores.certmesh {
        Some(core) => {
            let (status, roster) = core.status_with_roster();
            (Some(status), Some(roster))
        }
        None => (None, None),
    };
    let (dns, dns_catalog) = match &cores.dns {
        Some(runtime) => {
            let (status, catalog) = runtime.status_with_catalog();
            (Some(status), Some(catalog))
        }
        None => (None, None),
    };

    DomainStatuses {
        mdns,
        mdns_discovery,
        certmesh,
        trust: cores.trust.as_ref().map(|core| core.status()),
        certmesh_roster,
        dns,
        dns_catalog,
        health: cores.health.as_ref().map(|runtime| runtime.status()),
        proxy: cores.proxy.as_ref().map(|runtime| runtime.status()),
        udp: cores.udp.as_ref().map(|runtime| runtime.status()),
        runtime: cores.runtime.as_ref().map(|core| core.status()),
        pond,
    }
}

fn project_capabilities(
    domains: &DomainStatuses,
    overrides: &BTreeMap<String, CapabilityReport>,
) -> Vec<CapabilityReport> {
    let mut caps = Vec::with_capacity(10);

    // mDNS
    caps.push(match &domains.mdns {
        Some(status) => {
            let control = &status.control_plane;
            let routes = &control.routes;
            let healthy = matches!(
                control.state,
                koi_common::mdns_protocol::ControlPlaneState::Ready
                    | koi_common::mdns_protocol::ControlPlaneState::Reconciling
            ) && routes.publish.is_some()
                && routes.browse.is_some()
                && control.publications.failed == 0;
            CapabilityReport::present(CapabilityStatus {
                name: "mdns".to_string(),
                summary: format!(
                    "control plane {}; publish {}, browse {}, resolve {}; {} established / {} desired; {} discovered",
                    control.state,
                    routes.publish.as_deref().unwrap_or("none"),
                    routes.browse.as_deref().unwrap_or("none"),
                    routes.resolve.as_deref().unwrap_or("browse fallback"),
                    control.publications.established,
                    control.publications.desired,
                    status.discovery.record_count,
                ),
                healthy,
            })
        }
        None => CapabilityReport::disabled("mdns", ""),
    });

    // Certmesh
    caps.push(match &domains.certmesh {
        Some(status) => {
            let (summary, healthy) = match status.role {
                koi_certmesh::CertmeshRole::Open => {
                    ("ready — run certmesh create".to_string(), true)
                }
                koi_certmesh::CertmeshRole::Member => (
                    format!("member identity {:?}", status.identity.condition).to_lowercase(),
                    !status.diagnosis.is_red(),
                ),
                koi_certmesh::CertmeshRole::Authority => {
                    let authority = status.authority.as_ref().expect("authority status");
                    if authority.locked {
                        ("CA locked".to_string(), false)
                    } else {
                        (
                            format!(
                                "active ({} member{})",
                                authority.member_count,
                                if authority.member_count == 1 { "" } else { "s" }
                            ),
                            !status.diagnosis.is_red(),
                        )
                    }
                }
            };
            CapabilityReport::present(CapabilityStatus {
                name: "certmesh".to_string(),
                summary,
                healthy,
            })
        }
        None => CapabilityReport::disabled("certmesh", ""),
    });

    // OS trust store
    caps.push(match &domains.trust {
        Some(status) => trust_capability(status),
        None => CapabilityReport::disabled("trust", ""),
    });

    // DNS
    caps.push(match &domains.dns {
        Some(runtime) => {
            if runtime.running {
                CapabilityReport::present(CapabilityStatus {
                    name: "dns".to_string(),
                    summary: format!(
                        "listening on {}{}",
                        runtime.endpoints.join(", "),
                        runtime
                            .reason
                            .as_deref()
                            .map(|reason| format!(" ({reason})"))
                            .unwrap_or_default()
                    ),
                    healthy: true,
                })
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
        None => CapabilityReport::disabled("dns", ""),
    });

    // Health
    caps.push(match &domains.health {
        Some(status) => {
            if status.running {
                let up = status
                    .services
                    .iter()
                    .filter(|service| matches!(service.status, koi_health::ServiceStatus::Up))
                    .count();
                CapabilityReport::present(CapabilityStatus {
                    name: "health".to_string(),
                    summary: format!("{} services up ({} total)", up, status.services.len()),
                    healthy: true,
                })
            } else {
                CapabilityReport::stopped("health")
            }
        }
        None => CapabilityReport::disabled("health", ""),
    });

    // Proxy
    caps.push(match &domains.proxy {
        Some(status) => proxy_capability(status),
        None => CapabilityReport::disabled("proxy", ""),
    });

    caps.push(match &domains.udp {
        Some(status) => {
            let count = status.bindings.len();
            CapabilityReport::present(CapabilityStatus {
                name: "udp".to_string(),
                summary: if count == 0 {
                    "no bindings".to_string()
                } else {
                    format!("{count} binding{}", if count == 1 { "" } else { "s" })
                },
                healthy: status.running,
            })
        }
        None => CapabilityReport::disabled("udp", ""),
    });

    caps.push(match &domains.runtime {
        Some(status) => CapabilityReport::present(CapabilityStatus {
            name: "runtime".to_string(),
            summary: if status.active {
                format!(
                    "{}: {} instances",
                    status.backend.as_deref().unwrap_or("none"),
                    status.instance_count
                )
            } else if let Some(error) = status.backend_error.as_deref() {
                format!("inactive: {error}")
            } else {
                "inactive".to_string()
            },
            healthy: status.active,
        }),
        None => CapabilityReport::disabled("runtime", ""),
    });

    // IPC is a composition-owned transport fact. Pond supplies an exact typed
    // serving-component snapshot, from which composition derives its card.
    caps.push(CapabilityReport::disabled("ipc", ""));
    caps.push(match &domains.pond {
        Some(status) => pond_capability(status),
        None => CapabilityReport::disabled("pond", ""),
    });

    // Composition facts win only for their named rung. They never alter a
    // domain snapshot; they explain an absent core or represent an adapter.
    for cap in &mut caps {
        if cap.status.name != "pond" || domains.pond.is_none() {
            if let Some(replacement) = overrides.get(&cap.status.name) {
                *cap = replacement.clone();
            }
        }
    }

    caps
}

fn trust_capability(status: &koi_trust::TrustStatus) -> CapabilityReport {
    if let Some(error) = status.last_error.as_deref() {
        return CapabilityReport::available("trust", format!("error: {error}"), false);
    }
    if let Some(pending) = &status.pending {
        let operation = match pending.operation {
            koi_trust::TrustOperation::Install => "install",
            koi_trust::TrustOperation::Uninstall => "uninstall",
            koi_trust::TrustOperation::Ensure => "ensure",
        };
        return CapabilityReport::available(
            "trust",
            format!("{operation} pending for {}", pending.name),
            false,
        );
    }
    if status.roots.is_empty() {
        return CapabilityReport::available("trust", "no managed roots", true);
    }

    let present = status
        .roots
        .iter()
        .filter(|root| root.presence == koi_trust::TrustPresence::Present && root.warning.is_none())
        .count();
    let total = status.roots.len();
    CapabilityReport::available(
        "trust",
        if present == total {
            format!("{total} root{} present", if total == 1 { "" } else { "s" })
        } else {
            format!("{present}/{total} roots present")
        },
        present == total,
    )
}

fn proxy_capability(status: &koi_proxy::ProxyRuntimeStatus) -> CapabilityReport {
    if status.proxies.is_empty() {
        return CapabilityReport::available("proxy", "no listeners", true);
    }

    let mut running = 0;
    let mut starting = 0;
    let mut stopped = 0;
    let mut failed = 0;
    let mut unknown = 0;
    for listener in &status.proxies {
        match listener.state.as_str() {
            "running" => running += 1,
            "starting" => starting += 1,
            "stopped" => stopped += 1,
            "error" => failed += 1,
            _ => unknown += 1,
        }
    }
    let total = status.proxies.len();
    let healthy = running == total;
    let summary = if healthy {
        format!(
            "{running} listener{} running",
            if running == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "{running}/{total} listeners running; {starting} starting, {stopped} stopped, \
             {failed} failed, {unknown} unknown"
        )
    };
    CapabilityReport::available("proxy", summary, healthy)
}

fn pond_capability(status: &koi_common::pond::PondStatus) -> CapabilityReport {
    use koi_common::pond::{PondFirewallState, PondState};

    match status.state {
        PondState::Disabled => {
            CapabilityReport::disabled("pond", status.reason.as_deref().unwrap_or("not published"))
        }
        PondState::Running => {
            let blocked = status.firewall.state == PondFirewallState::Blocked;
            let mut summary = status
                .url
                .clone()
                .unwrap_or_else(|| format!("listening on port {}", status.port));
            if blocked {
                summary.push_str(&format!("; firewall blocked: {}", status.firewall.detail));
            }
            CapabilityReport::available("pond", summary, !blocked)
        }
        PondState::Reconciling => CapabilityReport::available("pond", "reconciling", false),
        PondState::Waiting => CapabilityReport::available(
            "pond",
            format!(
                "waiting: {}",
                status.reason.as_deref().unwrap_or("listener retry")
            ),
            false,
        ),
        PondState::Error => CapabilityReport::unavailable(
            "pond",
            status.reason.as_deref().unwrap_or("listener failed"),
        ),
    }
}

/// Subscribe once to every enabled domain and keep the composition aggregate current.
/// Coalescing is intentional: `KoiStatus` is current truth, not event history.
pub(crate) fn spawn_status_observer(
    cores: Cores,
    cancel: CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    let mut mdns = cores.mdns.as_ref().map(|core| core.watch_status());
    let mut certmesh = cores.certmesh.as_ref().map(|core| core.watch_status());
    let mut trust = cores.trust.as_ref().map(|core| core.watch_status());
    let mut dns = cores.dns.as_ref().map(|runtime| runtime.watch_status());
    let mut health = cores.health.as_ref().map(|runtime| runtime.watch_status());
    let mut proxy = cores.proxy.as_ref().map(|runtime| runtime.watch_status());
    let mut udp = cores.udp.as_ref().map(|runtime| runtime.watch_status());
    let mut runtime = cores.runtime.as_ref().map(|core| core.watch_status());
    let aggregate = Arc::clone(&cores.system_status);

    // Subscribe before the initial reconciliation. A transition racing with
    // observer startup is then either included in this read or remains pending
    // on its watch receiver; there is no reconcile-then-subscribe blind spot.
    aggregate.reconcile(&cores);

    tasks.push(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = watch_next(&mut mdns) => {},
                _ = watch_next(&mut certmesh) => {},
                _ = watch_next(&mut trust) => {},
                _ = watch_next(&mut dns) => {},
                _ = watch_next(&mut health) => {},
                _ = watch_next(&mut proxy) => {},
                _ = watch_next(&mut udp) => {},
                _ = watch_next(&mut runtime) => {},
            }
            aggregate.reconcile(&cores);
        }
    }));
}

async fn watch_next<T>(receiver: &mut Option<tokio::sync::watch::Receiver<Arc<T>>>) {
    let closed = match receiver.as_mut() {
        Some(receiver) => receiver.changed().await.is_err(),
        None => pending().await,
    };
    if closed {
        *receiver = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_listener(name: &str, state: &str) -> koi_proxy::ProxyStatus {
        koi_proxy::ProxyStatus {
            name: name.to_string(),
            listen_port: 443,
            backend: "http://127.0.0.1:8080".to_string(),
            allow_remote: false,
            cert_source: "self-signed".to_string(),
            cert_revision: 1,
            state: state.to_string(),
            error: (state == "error").then(|| "bind failed".to_string()),
        }
    }

    #[test]
    fn all_disabled_ladder_is_the_canonical_ten_rungs() {
        let cores = Cores::default();
        let caps = &cores.system_status.status().capabilities;
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
                ("trust", "disabled", false, false),
                ("dns", "disabled", false, false),
                ("health", "disabled", false, false),
                ("proxy", "disabled", false, false),
                ("udp", "disabled", false, false),
                ("runtime", "disabled", false, false),
                ("ipc", "disabled", false, false),
                ("pond", "disabled", false, false),
            ]
        );
        assert_eq!(
            caps.iter()
                .map(|capability| capability.status.name.as_str())
                .collect::<Vec<_>>(),
            CAPABILITY_LADDER
        );
    }

    #[test]
    fn proxy_capability_reports_observed_listener_readiness() {
        let empty = proxy_capability(&koi_proxy::ProxyRuntimeStatus::default());
        assert!(empty.enabled);
        assert!(empty.status.healthy);
        assert_eq!(empty.status.summary, "no listeners");

        let running = proxy_capability(&koi_proxy::ProxyRuntimeStatus {
            revision: 1,
            entries_revision: 0,
            proxies: vec![proxy_listener("api", "running")],
        });
        assert!(running.status.healthy);
        assert_eq!(running.status.summary, "1 listener running");

        let degraded = proxy_capability(&koi_proxy::ProxyRuntimeStatus {
            revision: 2,
            entries_revision: 0,
            proxies: vec![
                proxy_listener("api", "running"),
                proxy_listener("admin", "starting"),
                proxy_listener("old", "stopped"),
                proxy_listener("broken", "error"),
                proxy_listener("future", "unexpected"),
            ],
        });
        assert!(degraded.enabled);
        assert!(!degraded.status.healthy);
        assert_eq!(
            degraded.status.summary,
            "1/5 listeners running; 1 starting, 1 stopped, 1 failed, 1 unknown"
        );
    }

    #[test]
    fn trust_capability_reports_exact_observed_store_state() {
        let root = koi_trust::TrustRootStatus {
            name: "mesh".to_string(),
            installed_at: "now".to_string(),
            fingerprint: "abcd".to_string(),
            source: "certmesh".to_string(),
            presence: koi_trust::TrustPresence::Present,
            warning: None,
        };
        let present = trust_capability(&koi_trust::TrustStatus {
            revision: 1,
            roots: vec![root.clone()],
            pending: None,
            last_error: None,
        });
        assert!(present.status.healthy);
        assert_eq!(present.status.summary, "1 root present");

        let uncertain = trust_capability(&koi_trust::TrustStatus {
            roots: vec![koi_trust::TrustRootStatus {
                warning: Some("application trust could not be confirmed".to_string()),
                ..root
            }],
            ..Default::default()
        });
        assert!(!uncertain.status.healthy);
        assert_eq!(uncertain.status.summary, "0/1 roots present");

        let pending = trust_capability(&koi_trust::TrustStatus {
            pending: Some(koi_trust::TrustPendingStatus {
                operation: koi_trust::TrustOperation::Ensure,
                name: "mesh".to_string(),
                fingerprint: "ef01".to_string(),
            }),
            ..Default::default()
        });
        assert!(!pending.status.healthy);
        assert_eq!(pending.status.summary, "ensure pending for mesh");
    }

    #[test]
    fn typed_pond_update_is_immediate_revisioned_and_suppresses_noops() {
        let cores = Cores::default();
        let before = cores.system_status.status();
        let status = koi_common::pond::PondStatus {
            revision: 4,
            generation: 2,
            accepting_commands: true,
            desired: true,
            running: true,
            state: koi_common::pond::PondState::Running,
            port: 5644,
            urls: vec!["http://192.168.1.2:5644/".to_string()],
            url: Some("http://192.168.1.2:5644/".to_string()),
            firewall: koi_common::pond::PondFirewallStatus {
                state: koi_common::pond::PondFirewallState::Open,
                detail: "open".to_string(),
            },
            ui: koi_common::pond::PondUiStatus::default(),
            reason: None,
        };
        let source = Arc::new(status.clone());
        let changed = cores
            .system_status
            .publish_pond_status(&cores, Arc::clone(&source));
        assert_eq!(changed.revision, before.revision + 1);
        assert!(Arc::ptr_eq(
            changed.domains.pond.as_ref().expect("Pond snapshot"),
            &source
        ));
        let unchanged = cores
            .system_status
            .publish_pond_status(&cores, Arc::clone(&source));
        assert!(Arc::ptr_eq(&changed, &unchanged));
        assert_eq!(changed.domains.pond.as_deref(), Some(&status));

        let pond = changed
            .capabilities
            .iter()
            .find(|capability| capability.status.name == "pond")
            .expect("pond rung");
        assert!(pond.enabled);
        assert!(pond.status.healthy);
        assert!(pond.status.summary.contains("192.168.1.2:5644"));

        let waiting = koi_common::pond::PondStatus {
            state: koi_common::pond::PondState::Waiting,
            firewall: koi_common::pond::PondFirewallStatus {
                state: koi_common::pond::PondFirewallState::Blocked,
                detail: "host firewall blocks TCP 5644".to_string(),
            },
            reason: Some("host firewall blocks TCP 5644".to_string()),
            ..status
        };
        let changed = cores
            .system_status
            .publish_pond_status(&cores, Arc::new(waiting));
        let pond = changed
            .capabilities
            .iter()
            .find(|capability| capability.status.name == "pond")
            .expect("pond rung");
        assert!(changed.domains.pond.as_ref().unwrap().running);
        assert!(!pond.status.healthy);
        assert!(pond.status.summary.contains("waiting"));
    }

    #[test]
    fn capability_status_projection_matches_v1_status_shape() {
        // The `/v1/status` projection drops `enabled` and serializes {name, summary, healthy}.
        let cores = Cores::default();
        let statuses: Vec<CapabilityStatus> = cores
            .system_status
            .status()
            .capabilities
            .iter()
            .map(|c| c.status.clone())
            .collect();
        let json = serde_json::to_value(&statuses).unwrap();
        let first = &json[0];
        assert_eq!(first["name"], "mdns");
        assert_eq!(first["summary"], "disabled");
        assert_eq!(first["healthy"], false);
        assert!(first.get("enabled").is_none(), "/v1/status omits `enabled`");
    }

    #[test]
    fn product_status_round_trips_exact_specialized_domain_projections() {
        let expected = KoiStatus {
            revision: 11,
            capabilities: Vec::new(),
            domains: DomainStatuses {
                mdns_discovery: Some(Arc::new(koi_common::integration::MdnsDiscoverySnapshot {
                    revision: 9,
                    service_types: vec!["_http._tcp".to_string()],
                    records: vec![koi_common::types::ServiceRecord {
                        name: "console".to_string(),
                        service_type: "_http._tcp".to_string(),
                        host: Some("console.local.".to_string()),
                        ip: Some("192.0.2.10".to_string()),
                        port: Some(9464),
                        txt: std::collections::HashMap::new(),
                    }],
                    sources: Vec::new(),
                    observations: Vec::new(),
                })),
                certmesh_roster: Some(Arc::new(koi_common::integration::CertmeshRosterSnapshot {
                    revision: 4,
                    active_members: Vec::new(),
                })),
                dns_catalog: Some(Arc::new(koi_dns::DnsCatalogSnapshot {
                    revision: 3,
                    names: vec!["node.internal.".to_string()],
                    entries: Vec::new(),
                })),
                ..DomainStatuses::default()
            },
        };

        let encoded = serde_json::to_string(&expected).expect("serialize KoiStatus");
        let decoded: KoiStatus = serde_json::from_str(&encoded).expect("deserialize KoiStatus");
        assert_eq!(decoded, expected);
    }

    #[tokio::test]
    async fn aggregate_retains_the_domain_snapshot_arc_without_a_deep_clone() {
        let health = Arc::new(koi_health::HealthRuntime::new(Arc::new(
            koi_health::HealthCore::open(
                koi_health::HealthPaths::new(
                    std::env::temp_dir().join(format!(
                        "koi-compose-health-status-{}.json",
                        koi_common::id::generate_short_id()
                    )),
                    std::env::temp_dir().join(format!(
                        "koi-compose-health-status-{}.log",
                        koi_common::id::generate_short_id()
                    )),
                ),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("health core"),
        )));
        let source = health.status();
        let cores = Cores {
            health: Some(health),
            ..Cores::default()
        };

        let aggregate = cores.system_status.reconcile(&cores);
        assert!(Arc::ptr_eq(
            aggregate.domains.health.as_ref().expect("health snapshot"),
            &source
        ));
    }

    #[tokio::test]
    async fn domain_status_change_reconciles_the_product_status() {
        let cancel = CancellationToken::new();
        let health = Arc::new(koi_health::HealthRuntime::new(Arc::new(
            koi_health::HealthCore::open(
                koi_health::HealthPaths::new(
                    std::env::temp_dir().join(format!(
                        "koi-compose-health-observer-{}.json",
                        koi_common::id::generate_short_id()
                    )),
                    std::env::temp_dir().join(format!(
                        "koi-compose-health-observer-{}.log",
                        koi_common::id::generate_short_id()
                    )),
                ),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("health core"),
        )));
        let cores = Cores {
            health: Some(Arc::clone(&health)),
            ..Cores::default()
        };
        cores.system_status.reconcile(&cores);
        let mut aggregate = cores.system_status.watch_status();
        let before = aggregate.borrow().revision;
        let mut tasks = Vec::new();
        spawn_status_observer(cores.clone(), cancel.clone(), &mut tasks);

        health.start().await.expect("start health runtime");
        tokio::time::timeout(std::time::Duration::from_secs(2), aggregate.changed())
            .await
            .expect("aggregate update timeout")
            .expect("aggregate feed closed");
        let current = aggregate.borrow().clone();
        assert!(current.revision > before);
        let health = current
            .capabilities
            .iter()
            .find(|capability| capability.status.name == "health")
            .expect("health rung");
        assert!(health.status.healthy);

        cancel.cancel();
        for task in tasks {
            task.await.expect("observer task");
        }
    }

    #[tokio::test]
    async fn dns_primary_status_fences_its_specialized_catalog_projection() {
        let cancel = CancellationToken::new();
        let state_path = std::env::temp_dir().join(format!(
            "koi-compose-dns-status-{}.json",
            koi_common::id::generate_short_id()
        ));
        let dns = Arc::new(koi_dns::DnsRuntime::new(
            koi_dns::DnsCore::open(
                state_path.clone(),
                koi_dns::DnsConfig::default(),
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        let cores = Cores {
            dns: Some(Arc::clone(&dns)),
            ..Cores::default()
        };
        cores.system_status.reconcile(&cores);
        let mut aggregate = cores.system_status.watch_status();
        aggregate.borrow_and_update();
        let mut tasks = Vec::new();
        spawn_status_observer(cores.clone(), cancel.clone(), &mut tasks);

        dns.add_entry(koi_dns::DnsEntry {
            name: "api.internal.".to_string(),
            ip: "10.0.0.11".to_string(),
            ttl: None,
        })
        .expect("add DNS entry");
        tokio::time::timeout(std::time::Duration::from_secs(2), aggregate.changed())
            .await
            .expect("aggregate update timeout")
            .expect("aggregate feed closed");
        let current = aggregate.borrow_and_update().clone();
        assert_eq!(
            current.domains.dns.as_ref().unwrap().records.static_entries,
            1
        );
        assert_eq!(
            current.domains.dns_catalog.as_ref().unwrap().names,
            ["api.internal."]
        );

        cancel.cancel();
        for task in tasks {
            task.await.expect("observer task");
        }
        let _ = std::fs::remove_file(state_path);
    }
}
