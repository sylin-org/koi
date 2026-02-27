//! Dashboard adapter — system-level operational overview.
//!
//! Assembles a unified JSON snapshot from all domain cores,
//! serves a single-page HTML dashboard, and provides an SSE
//! event stream merging all domain broadcast channels.
//!
//! This is a **presentation adapter** — it owns zero domain logic.
//! All data comes from existing `Capability::status()` calls,
//! domain query methods, and broadcast channels.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::Extension;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, Json};
use serde::Serialize;
use tokio_stream::Stream;

use koi_common::capability::Capability;

// ── HTML asset ──────────────────────────────────────────────────────

const DASHBOARD_HTML: &str = include_str!("../../assets/dashboard.html");

// ── Snapshot types ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct DashboardSnapshot {
    version: String,
    platform: String,
    hostname: String,
    hostname_fqdn: String,
    uptime_secs: u64,
    mode: &'static str,
    capabilities: Vec<CapabilityCard>,
    health: Option<HealthDetail>,
    dns: Option<DnsDetail>,
    certmesh: Option<CertmeshDetail>,
    proxy: Option<ProxyDetail>,
    udp: Option<UdpDetail>,
}

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

// ── Shared state (injected via Extension) ────────────────────────────

#[derive(Clone)]
pub(crate) struct DashboardState {
    pub(crate) mdns: Option<Arc<koi_mdns::MdnsCore>>,
    pub(crate) certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    pub(crate) dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub(crate) health: Option<Arc<koi_health::HealthRuntime>>,
    pub(crate) proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    pub(crate) udp: Option<Arc<koi_udp::UdpRuntime>>,
    pub(crate) started_at: Instant,
}

// ── Snapshot builder ─────────────────────────────────────────────────

async fn build_snapshot(state: &DashboardState) -> DashboardSnapshot {
    let hostname = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let hostname_fqdn = format!("{hostname}.local");

    let mut capabilities = Vec::with_capacity(6);

    // mDNS
    if let Some(ref core) = state.mdns {
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
    if let Some(ref core) = state.certmesh {
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
    if let Some(ref runtime) = state.dns {
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
    if let Some(ref runtime) = state.health {
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
    if let Some(ref runtime) = state.proxy {
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
    if let Some(ref runtime) = state.udp {
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

    // ── Domain details ──
    let health = if let Some(ref runtime) = state.health {
        let snap = runtime.core().snapshot().await;
        Some(HealthDetail {
            machines: snap.machines,
            services: snap.services,
        })
    } else {
        None
    };

    let dns = if let Some(ref runtime) = state.dns {
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

    let certmesh = if let Some(ref core) = state.certmesh {
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

    let proxy = if let Some(ref runtime) = state.proxy {
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

    let udp = if let Some(ref runtime) = state.udp {
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

    DashboardSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        hostname,
        hostname_fqdn,
        uptime_secs: state.started_at.elapsed().as_secs(),
        mode: "daemon",
        capabilities,
        health,
        dns,
        certmesh,
        proxy,
        udp,
    }
}

// ── SSE stream builder ───────────────────────────────────────────────

fn dashboard_event_stream(
    state: DashboardState,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        // Subscribe to all available domain channels
        let mut mdns_rx = state.mdns.as_ref().map(|c| c.subscribe());
        let mut health_rx = state.health.as_ref().map(|r| r.core().subscribe());
        let mut dns_rx = state.dns.as_ref().map(|r| r.core().subscribe());
        let mut certmesh_rx = state.certmesh.as_ref().map(|c| c.subscribe());
        let mut proxy_rx = state.proxy.as_ref().map(|r| r.core().subscribe());

        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat.tick().await; // skip immediate tick

        loop {
            let event = tokio::select! {
                Some(Ok(ev)) = async { match mdns_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    match ev {
                        koi_mdns::MdnsEvent::Found(record) => {
                            Event::default()
                                .event("mdns.found")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(record).ok()
                        }
                        koi_mdns::MdnsEvent::Resolved(record) => {
                            Event::default()
                                .event("mdns.resolved")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(record).ok()
                        }
                        koi_mdns::MdnsEvent::Removed { name, service_type } => {
                            Event::default()
                                .event("mdns.removed")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({ "name": name, "service_type": service_type })).ok()
                        }
                    }
                },
                Some(Ok(ev)) = async { match health_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    match ev {
                        koi_health::HealthEvent::StatusChanged { name, status } => {
                            Event::default()
                                .event("health.changed")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({ "name": name, "status": status })).ok()
                        }
                    }
                },
                Some(Ok(ev)) = async { match dns_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    match ev {
                        koi_dns::DnsEvent::EntryUpdated { name, ip } => {
                            Event::default()
                                .event("dns.updated")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({ "name": name, "ip": ip })).ok()
                        }
                        koi_dns::DnsEvent::EntryRemoved { name } => {
                            Event::default()
                                .event("dns.removed")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({ "name": name })).ok()
                        }
                    }
                },
                Some(Ok(ev)) = async { match certmesh_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    match ev {
                        koi_certmesh::CertmeshEvent::MemberJoined { hostname, fingerprint } => {
                            Event::default()
                                .event("certmesh.joined")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({ "hostname": hostname, "fingerprint": fingerprint })).ok()
                        }
                        koi_certmesh::CertmeshEvent::MemberRevoked { hostname } => {
                            Event::default()
                                .event("certmesh.revoked")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({ "hostname": hostname })).ok()
                        }
                        koi_certmesh::CertmeshEvent::Destroyed => {
                            Event::default()
                                .event("certmesh.destroyed")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({})).ok()
                        }
                    }
                },
                Some(Ok(ev)) = async { match proxy_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                    match ev {
                        koi_proxy::ProxyEvent::EntryUpdated { entry } => {
                            Event::default()
                                .event("proxy.updated")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(entry).ok()
                        }
                        koi_proxy::ProxyEvent::EntryRemoved { name } => {
                            Event::default()
                                .event("proxy.removed")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({ "name": name })).ok()
                        }
                    }
                },
                _ = heartbeat.tick() => {
                    Event::default()
                        .event("heartbeat")
                        .json_data(serde_json::json!({
                            "uptime_secs": state.started_at.elapsed().as_secs()
                        })).ok()
                },
            };

            if let Some(ev) = event {
                yield Ok(ev);
            }
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────

/// `GET /` — Serve the dashboard SPA.
pub(crate) async fn get_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

/// `GET /v1/dashboard/snapshot` — System-level JSON snapshot.
pub(crate) async fn get_snapshot(
    Extension(state): Extension<DashboardState>,
) -> Json<DashboardSnapshot> {
    Json(build_snapshot(&state).await)
}

/// `GET /v1/dashboard/events` — Unified SSE event stream.
pub(crate) async fn get_events(
    Extension(state): Extension<DashboardState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    Sse::new(dashboard_event_stream(state)).keep_alive(KeepAlive::default())
}
