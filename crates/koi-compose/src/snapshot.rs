//! The rich dashboard snapshot — the one detail projection of the live domain cores.
//!
//! Both the daemon's dashboard adapter and `koi-embedded` serve their dashboard JSON through
//! an injected `SnapshotFn`; both now call [`build_dashboard_snapshot`] so the embedded
//! snapshot is no longer a `{capabilities}`-only stub but carries the same health / DNS /
//! certmesh / proxy / UDP detail the daemon dashboard renders. The capability ladder itself
//! comes from [`crate::status::assemble_capabilities`] (shared with `/v1/status`), projected
//! into the four-field card via [`crate::status::CapabilityReport::into_card`].

use serde::Serialize;

use crate::cores::Cores;

// ── Snapshot detail types (private — serialized into opaque JSON) ────

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

/// Build the dashboard snapshot JSON from the live domain cores: the capability ladder plus
/// the per-domain detail (health, DNS, certmesh, proxy, UDP). Each detail is `null` when its
/// capability is disabled.
pub async fn build_dashboard_snapshot(cores: &Cores) -> serde_json::Value {
    // The capability ladder is assembled once in koi-compose, shared with `/v1/status`.
    // The dashboard card adds `enabled` (false only when disabled).
    let capabilities: Vec<serde_json::Value> = crate::status::assemble_capabilities(cores)
        .await
        .into_iter()
        .map(|c| c.into_card())
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
