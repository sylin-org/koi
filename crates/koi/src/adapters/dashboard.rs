//! Dashboard wiring — connects domain cores to the shared dashboard
//! infrastructure in `koi_common::dashboard`.
//!
//! This module provides:
//! - A snapshot closure that queries all domain cores
//! - An event forwarding loop that maps domain events → `DashboardSseEvent`
//! - A builder that produces the `DashboardState` consumed by koi-common

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use koi_common::capability::Capability;
use koi_common::dashboard::{DashboardIdentity, DashboardSseEvent, DashboardState};

// ── Snapshot detail types (private — serialized into opaque JSON) ────

use serde::Serialize;

#[derive(Debug, Serialize)]
struct CapabilityCard {
    name: String,
    enabled: bool,
    healthy: bool,
    summary: String,
}

#[derive(Debug, Serialize)]
struct HealthDetail {
    machines: Vec<koi_health::MachineHealth>,
    services: Vec<koi_health::ServiceHealth>,
}

#[derive(Debug, Serialize)]
struct DnsDetail {
    running: bool,
    zone: String,
    port: u16,
    static_count: usize,
    certmesh_count: usize,
    mdns_count: usize,
}

#[derive(Debug, Serialize)]
struct CertmeshDetail {
    ca_initialized: bool,
    ca_locked: bool,
    auth_method: Option<String>,
    profile: String,
    member_count: usize,
    enrollment_state: String,
}

#[derive(Debug, Serialize)]
struct ProxyDetail {
    entries: Vec<ProxyEntryDetail>,
    listeners: Vec<ProxyListenerDetail>,
}

#[derive(Debug, Serialize)]
struct ProxyEntryDetail {
    name: String,
    listen_port: u16,
    backend: String,
}

#[derive(Debug, Serialize)]
struct ProxyListenerDetail {
    name: String,
    listen_port: u16,
    running: bool,
}

#[derive(Debug, Serialize)]
struct UdpDetail {
    bindings: Vec<UdpBindingDetail>,
}

#[derive(Debug, Serialize)]
struct UdpBindingDetail {
    id: String,
    local_addr: String,
}

// ── Domain core references (cloned into the snapshot closure) ────────

#[derive(Clone)]
struct DomainCores {
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
}

// ── Build snapshot (domain-specific) ────────────────────────────────

async fn build_snapshot_value(cores: &DomainCores) -> serde_json::Value {
    let mut capabilities = Vec::with_capacity(6);

    // mDNS
    if let Some(ref core) = cores.mdns {
        let s = core.status();
        capabilities.push(CapabilityCard {
            name: s.name,
            enabled: true,
            healthy: s.healthy,
            summary: s.summary,
        });
    } else {
        capabilities.push(CapabilityCard {
            name: "mdns".to_string(),
            enabled: false,
            healthy: false,
            summary: "disabled".to_string(),
        });
    }

    // Certmesh
    if let Some(ref core) = cores.certmesh {
        let s = core.status();
        capabilities.push(CapabilityCard {
            name: s.name,
            enabled: true,
            healthy: s.healthy,
            summary: s.summary,
        });
    } else {
        capabilities.push(CapabilityCard {
            name: "certmesh".to_string(),
            enabled: false,
            healthy: false,
            summary: "disabled".to_string(),
        });
    }

    // DNS
    if let Some(ref runtime) = cores.dns {
        let running = runtime.status().await.running;
        if running {
            let s = runtime.core().status();
            capabilities.push(CapabilityCard {
                name: s.name,
                enabled: true,
                healthy: s.healthy,
                summary: s.summary,
            });
        } else {
            capabilities.push(CapabilityCard {
                name: "dns".to_string(),
                enabled: true,
                healthy: false,
                summary: "stopped".to_string(),
            });
        }
    } else {
        capabilities.push(CapabilityCard {
            name: "dns".to_string(),
            enabled: false,
            healthy: false,
            summary: "disabled".to_string(),
        });
    }

    // Health
    if let Some(ref runtime) = cores.health {
        let running = runtime.status().await.running;
        if running {
            let s = runtime.core().status();
            capabilities.push(CapabilityCard {
                name: s.name,
                enabled: true,
                healthy: s.healthy,
                summary: s.summary,
            });
        } else {
            capabilities.push(CapabilityCard {
                name: "health".to_string(),
                enabled: true,
                healthy: false,
                summary: "stopped".to_string(),
            });
        }
    } else {
        capabilities.push(CapabilityCard {
            name: "health".to_string(),
            enabled: false,
            healthy: false,
            summary: "disabled".to_string(),
        });
    }

    // Proxy
    if let Some(ref runtime) = cores.proxy {
        let status = runtime.status().await;
        capabilities.push(CapabilityCard {
            name: "proxy".to_string(),
            enabled: true,
            healthy: true,
            summary: if status.is_empty() {
                "no listeners".to_string()
            } else {
                format!("{} listeners", status.len())
            },
        });
    } else {
        capabilities.push(CapabilityCard {
            name: "proxy".to_string(),
            enabled: false,
            healthy: false,
            summary: "disabled".to_string(),
        });
    }

    // UDP
    if let Some(ref runtime) = cores.udp {
        let s = Capability::status(runtime.as_ref());
        capabilities.push(CapabilityCard {
            name: s.name,
            enabled: true,
            healthy: s.healthy,
            summary: s.summary,
        });
    } else {
        capabilities.push(CapabilityCard {
            name: "udp".to_string(),
            enabled: false,
            healthy: false,
            summary: "disabled".to_string(),
        });
    }

    // Domain details
    let health = if let Some(ref runtime) = cores.health {
        let snap = runtime.core().snapshot().await;
        Some(HealthDetail {
            machines: snap.machines,
            services: snap.services,
        })
    } else {
        None
    };

    let dns = if let Some(ref runtime) = cores.dns {
        let core = runtime.core();
        let snap = core.snapshot();
        let cfg = core.config();
        Some(DnsDetail {
            running: runtime.status().await.running,
            zone: cfg.zone.clone(),
            port: cfg.port,
            static_count: snap.static_entries.len(),
            certmesh_count: snap.certmesh_entries.len(),
            mdns_count: snap.mdns_entries.len(),
        })
    } else {
        None
    };

    let certmesh = if let Some(ref core) = cores.certmesh {
        let status = core.certmesh_status().await;
        Some(CertmeshDetail {
            ca_initialized: status.ca_initialized,
            ca_locked: status.ca_locked,
            auth_method: status.auth_method,
            profile: format!("{:?}", status.profile),
            member_count: status.member_count,
            enrollment_state: format!("{:?}", status.enrollment_state),
        })
    } else {
        None
    };

    let proxy = if let Some(ref runtime) = cores.proxy {
        let entries = runtime.core().entries().await;
        let status = runtime.status().await;
        Some(ProxyDetail {
            entries: entries
                .into_iter()
                .map(|e| ProxyEntryDetail {
                    name: e.name,
                    listen_port: e.listen_port,
                    backend: e.backend,
                })
                .collect(),
            listeners: status
                .into_iter()
                .map(|s| ProxyListenerDetail {
                    name: s.name,
                    listen_port: s.listen_port,
                    running: s.running,
                })
                .collect(),
        })
    } else {
        None
    };

    let udp = if let Some(ref runtime) = cores.udp {
        let bindings = runtime.status().await;
        Some(UdpDetail {
            bindings: bindings
                .into_iter()
                .map(|b| UdpBindingDetail {
                    id: b.id,
                    local_addr: b.local_addr,
                })
                .collect(),
        })
    } else {
        None
    };

    serde_json::json!({
        "capabilities": capabilities,
        "health": health,
        "dns": dns,
        "certmesh": certmesh,
        "proxy": proxy,
        "udp": udp,
    })
}

// ── Event forwarding ────────────────────────────────────────────────

/// Spawn a task that subscribes to all domain broadcast channels and
/// forwards events into the unified `DashboardSseEvent` channel.
pub(crate) fn spawn_event_forwarder(
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    event_tx: broadcast::Sender<DashboardSseEvent>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut mdns_rx = mdns.as_ref().map(|c| c.subscribe());
        let mut health_rx = health.as_ref().map(|r| r.core().subscribe());
        let mut dns_rx = dns.as_ref().map(|r| r.core().subscribe());
        let mut certmesh_rx = certmesh.as_ref().map(|c| c.subscribe());
        let mut proxy_rx = proxy.as_ref().map(|r| r.core().subscribe());

        loop {
            let sse_event: Option<DashboardSseEvent> = tokio::select! {
                _ = cancel.cancelled() => break,

                Some(Ok(ev)) = async { match mdns_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    let id = uuid::Uuid::now_v7().to_string();
                    match ev {
                        koi_mdns::MdnsEvent::Found(record) => Some(DashboardSseEvent {
                            event_type: "mdns.found".to_string(), id,
                            data: serde_json::to_value(record).unwrap_or_default(),
                        }),
                        koi_mdns::MdnsEvent::Resolved(record) => Some(DashboardSseEvent {
                            event_type: "mdns.resolved".to_string(), id,
                            data: serde_json::to_value(record).unwrap_or_default(),
                        }),
                        koi_mdns::MdnsEvent::Removed { name, service_type } => Some(DashboardSseEvent {
                            event_type: "mdns.removed".to_string(), id,
                            data: serde_json::json!({ "name": name, "service_type": service_type }),
                        }),
                    }
                },

                Some(Ok(ev)) = async { match health_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    let id = uuid::Uuid::now_v7().to_string();
                    match ev {
                        koi_health::HealthEvent::StatusChanged { name, status } => Some(DashboardSseEvent {
                            event_type: "health.changed".to_string(), id,
                            data: serde_json::json!({ "name": name, "status": status }),
                        }),
                    }
                },

                Some(Ok(ev)) = async { match dns_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    let id = uuid::Uuid::now_v7().to_string();
                    match ev {
                        koi_dns::DnsEvent::EntryUpdated { name, ip } => Some(DashboardSseEvent {
                            event_type: "dns.updated".to_string(), id,
                            data: serde_json::json!({ "name": name, "ip": ip }),
                        }),
                        koi_dns::DnsEvent::EntryRemoved { name } => Some(DashboardSseEvent {
                            event_type: "dns.removed".to_string(), id,
                            data: serde_json::json!({ "name": name }),
                        }),
                    }
                },

                Some(Ok(ev)) = async { match certmesh_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    let id = uuid::Uuid::now_v7().to_string();
                    match ev {
                        koi_certmesh::CertmeshEvent::MemberJoined { hostname, fingerprint } => Some(DashboardSseEvent {
                            event_type: "certmesh.joined".to_string(), id,
                            data: serde_json::json!({ "hostname": hostname, "fingerprint": fingerprint }),
                        }),
                        koi_certmesh::CertmeshEvent::MemberRevoked { hostname } => Some(DashboardSseEvent {
                            event_type: "certmesh.revoked".to_string(), id,
                            data: serde_json::json!({ "hostname": hostname }),
                        }),
                        koi_certmesh::CertmeshEvent::Destroyed => Some(DashboardSseEvent {
                            event_type: "certmesh.destroyed".to_string(), id,
                            data: serde_json::json!({}),
                        }),
                    }
                },

                Some(Ok(ev)) = async { match proxy_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    let id = uuid::Uuid::now_v7().to_string();
                    match ev {
                        koi_proxy::ProxyEvent::EntryUpdated { entry } => Some(DashboardSseEvent {
                            event_type: "proxy.updated".to_string(), id,
                            data: serde_json::to_value(entry).unwrap_or_default(),
                        }),
                        koi_proxy::ProxyEvent::EntryRemoved { name } => Some(DashboardSseEvent {
                            event_type: "proxy.removed".to_string(), id,
                            data: serde_json::json!({ "name": name }),
                        }),
                    }
                },
            };

            if let Some(ev) = sse_event {
                let _ = event_tx.send(ev);
            }
        }
    })
}

// ── Build dashboard state ───────────────────────────────────────────

/// Construct the `DashboardState` for the daemon.
pub(crate) fn build_dashboard_state(
    cores: &crate::DaemonCores,
    started_at: Instant,
    mode: &'static str,
) -> DashboardState {
    let domain = DomainCores {
        mdns: cores.mdns.clone(),
        certmesh: cores.certmesh.clone(),
        dns: cores.dns.clone(),
        health: cores.health.clone(),
        proxy: cores.proxy.clone(),
        udp: cores.udp.clone(),
    };

    let snapshot_fn: koi_common::dashboard::SnapshotFn = Arc::new(move || {
        let d = domain.clone();
        Box::pin(async move { build_snapshot_value(&d).await })
    });

    let (event_tx, _) = broadcast::channel(256);

    DashboardState {
        identity: DashboardIdentity {
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: std::env::consts::OS.to_string(),
        },
        mode,
        snapshot_fn,
        event_tx,
        started_at,
    }
}
