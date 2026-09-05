//! The rich dashboard snapshot — the one detail projection of [`KoiStatus`](crate::status::KoiStatus).
//!
//! Both the daemon's dashboard adapter and `koi-embedded` serve their dashboard JSON through
//! an injected `SnapshotFn`; both now call [`crate::snapshot::build_dashboard_snapshot`] so the embedded
//! snapshot is no longer a `{capabilities}`-only stub but carries the same health / DNS /
//! certmesh / proxy / UDP detail the daemon dashboard renders. The capability ladder itself
//! comes from the cached [`crate::status::KoiStatus`] (shared with `/v1/status`), projected
//! into the four-field card via [`crate::status::CapabilityReport::into_card`].

use serde::Serialize;

use crate::status::KoiStatus;

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
    cert_revision: u64,
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

fn project_proxy(status: &koi_proxy::ProxyRuntimeStatus) -> ProxyDetail {
    ProxyDetail {
        entries: status
            .proxies
            .iter()
            .map(|entry| ProxyEntryDetail {
                name: entry.name.clone(),
                listen_port: entry.listen_port,
                backend: entry.backend.clone(),
            })
            .collect(),
        listeners: status
            .proxies
            .iter()
            .map(|listener| ProxyListenerDetail {
                name: listener.name.clone(),
                listen_port: listener.listen_port,
                state: listener.state.clone(),
                cert_source: listener.cert_source.clone(),
                cert_revision: listener.cert_revision,
                error: listener.error.clone(),
            })
            .collect(),
    }
}

/// Build dashboard JSON from one already-captured product snapshot: the capability ladder
/// plus per-domain detail (health, DNS, certmesh, proxy, UDP). Each detail is `null` when its
/// capability is disabled. This projector has no access to cores, so it cannot create a torn
/// view with request-time domain reads.
pub fn build_dashboard_snapshot(status: &KoiStatus) -> serde_json::Value {
    let capabilities: Vec<serde_json::Value> = status
        .capabilities
        .iter()
        .cloned()
        .map(|c| c.into_card())
        .collect();

    // Domain details
    let health = status.domains.health.as_ref().map(|snap| HealthDetail {
        machines: snap.machines.clone(),
        services: snap.services.clone(),
    });

    let dns = status.domains.dns.as_ref().map(|dns_status| DnsDetail {
        running: dns_status.running,
        zone: dns_status.zone.clone(),
        port: dns_status.port,
        static_count: dns_status.records.static_entries,
        certmesh_count: dns_status.records.certmesh_entries,
        mdns_count: dns_status.records.mdns_entries,
    });

    let certmesh = status.domains.certmesh.clone();

    let proxy = status.domains.proxy.as_deref().map(project_proxy);

    let udp = status.domains.udp.as_ref().map(|udp_status| UdpDetail {
        bindings: udp_status
            .bindings
            .iter()
            .map(|b| UdpBindingDetail {
                id: b.id.clone(),
                local_addr: b.local_addr.clone(),
            })
            .collect(),
    });

    serde_json::json!({
        "revision": status.revision,
        "catalog": &status.catalog,
        "capabilities": capabilities,
        "health": health,
        "dns": dns,
        "certmesh": certmesh,
        "proxy": proxy,
        "udp": udp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_detail_preserves_the_selected_certificate_revision() {
        let status = KoiStatus {
            revision: 21,
            capabilities: Vec::new(),
            catalog: std::sync::Arc::new(koi_common::service::CatalogSnapshot {
                revision: 9,
                ..koi_common::service::CatalogSnapshot::default()
            }),
            domains: crate::status::DomainStatuses {
                proxy: Some(std::sync::Arc::new(koi_proxy::ProxyRuntimeStatus {
                    revision: 8,
                    entries_revision: 0,
                    proxies: vec![koi_proxy::ProxyStatus {
                        name: "api".to_string(),
                        listen_port: 9443,
                        backend: "http://127.0.0.1:8080".to_string(),
                        allow_remote: false,
                        cert_source: "certmesh".to_string(),
                        cert_revision: 17,
                        state: "running".to_string(),
                        error: None,
                    }],
                })),
                ..crate::status::DomainStatuses::default()
            },
        };

        let json = build_dashboard_snapshot(&status);
        assert_eq!(json["revision"], 21);
        assert_eq!(json["catalog"]["revision"], 9);
        assert_eq!(json["proxy"]["listeners"][0]["cert_source"], "certmesh");
        assert_eq!(json["proxy"]["listeners"][0]["cert_revision"], 17);
    }
}
