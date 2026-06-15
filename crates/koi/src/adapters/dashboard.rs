//! Dashboard wiring — connects the daemon's domain cores to the shared dashboard
//! infrastructure in `koi_dashboard::dashboard`.
//!
//! This module provides:
//! - A snapshot closure that queries all domain cores (the injected `SnapshotFn`)
//! - A builder that produces the `DashboardState` consumed by `koi-dashboard`
//!
//! The event forwarder lives in `koi_dashboard::forward` (the single, deduplicated
//! superset shared with koi-embedded).

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::broadcast;

use koi_dashboard::dashboard::{DashboardIdentity, DashboardState};

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
    enrollment_open: bool,
    requires_approval: bool,
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
    state: String,
    cert_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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
    runtime: Option<Arc<koi_runtime::RuntimeCore>>,
}

// ── Build snapshot (domain-specific) ────────────────────────────────

async fn build_snapshot_value(cores: &DomainCores) -> serde_json::Value {
    // The capability ladder is assembled once in koi-compose, shared with `/v1/status` and
    // the embedded snapshot. The dashboard card adds `enabled` (false only when disabled).
    let domain_cores = koi_compose::cores::Cores {
        mdns: cores.mdns.clone(),
        certmesh: cores.certmesh.clone(),
        dns: cores.dns.clone(),
        health: cores.health.clone(),
        proxy: cores.proxy.clone(),
        udp: cores.udp.clone(),
        runtime: cores.runtime.clone(),
    };
    let capabilities: Vec<CapabilityCard> =
        koi_compose::status::assemble_capabilities(&domain_cores)
            .await
            .into_iter()
            .map(|c| CapabilityCard {
                name: c.status.name,
                enabled: c.enabled,
                healthy: c.status.healthy,
                summary: c.status.summary,
            })
            .collect();

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
            enrollment_open: status.enrollment_open,
            requires_approval: status.requires_approval,
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
                    state: s.state,
                    cert_source: s.cert_source,
                    error: s.error,
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

// ── Build dashboard state ───────────────────────────────────────────
//
// The event forwarder lives in `koi_dashboard::forward` (the single, deduplicated
// superset). Only the snapshot builder (the injected `SnapshotFn`) stays here, since it
// is the binary's own domain-detail projection.

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
        runtime: cores.runtime.clone(),
    };

    let snapshot_fn: koi_dashboard::dashboard::SnapshotFn = Arc::new(move || {
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
