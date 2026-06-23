//! Unified domain-event forwarder for the dashboard SSE feed.
//!
//! This is the **single** forwarder: it subscribes to every event-bearing domain's
//! broadcast channel and maps each event into a [`DashboardSseEvent`]. It replaces the
//! two diverged copies that previously lived in the binary crate (5 domains) and in
//! koi-embedded (6 domains, with runtime). The superset — mdns, health, dns, certmesh,
//! proxy, **runtime** — is the union of both.
//!
//! UDP exposes no lifecycle-event broadcast (only per-binding datagram streams), so
//! there is nothing to forward for it.

use std::sync::Arc;

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::dashboard::DashboardSseEvent;

/// Domain cores whose events feed the dashboard activity stream. Each is optional —
/// disabled capabilities simply contribute nothing.
#[derive(Clone, Default)]
pub struct ForwarderCores {
    pub mdns: Option<Arc<koi_mdns::MdnsCore>>,
    pub certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    pub dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub health: Option<Arc<koi_health::HealthRuntime>>,
    pub proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    pub runtime: Option<Arc<koi_runtime::RuntimeCore>>,
}

/// Spawn the forwarder task. It subscribes to each present core and relays mapped
/// events into `event_tx` until `cancel` fires.
pub fn spawn_event_forwarder(
    cores: ForwarderCores,
    event_tx: broadcast::Sender<DashboardSseEvent>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut mdns_rx = cores.mdns.as_ref().map(|c| c.subscribe());
        let mut health_rx = cores.health.as_ref().map(|r| r.core().subscribe());
        let mut dns_rx = cores.dns.as_ref().map(|r| r.core().subscribe());
        let mut certmesh_rx = cores.certmesh.as_ref().map(|c| c.subscribe());
        let mut proxy_rx = cores.proxy.as_ref().map(|r| r.core().subscribe());
        let mut runtime_rx = cores.runtime.as_ref().map(|r| r.subscribe());

        loop {
            let sse_event: Option<DashboardSseEvent> = tokio::select! {
                _ = cancel.cancelled() => break,

                Some(Ok(ev)) = recv_opt(&mut mdns_rx) => Some(map_mdns(ev)),
                Some(Ok(ev)) = recv_opt(&mut health_rx) => Some(map_health(ev)),
                Some(Ok(ev)) = recv_opt(&mut dns_rx) => Some(map_dns(ev)),
                Some(Ok(ev)) = recv_opt(&mut certmesh_rx) => Some(map_certmesh(ev)),
                Some(Ok(ev)) = recv_opt(&mut proxy_rx) => Some(map_proxy(ev)),
                Some(Ok(ev)) = recv_opt(&mut runtime_rx) => Some(map_runtime(ev)),
            };

            if let Some(ev) = sse_event {
                let _ = event_tx.send(ev);
            }
        }
    })
}

/// Await an optional broadcast receiver; `None` when the channel is absent (capability
/// disabled), so its select arm stays disabled.
async fn recv_opt<T: Clone>(
    rx: &mut Option<broadcast::Receiver<T>>,
) -> Option<Result<T, broadcast::error::RecvError>> {
    match rx.as_mut() {
        Some(rx) => Some(rx.recv().await),
        None => None,
    }
}

fn ev(event_type: &str, data: serde_json::Value) -> DashboardSseEvent {
    DashboardSseEvent {
        event_type: event_type.to_string(),
        id: uuid::Uuid::now_v7().to_string(),
        data,
    }
}

// ── Pure per-domain mappers (unit-tested) ───────────────────────────

fn map_mdns(event: koi_mdns::MdnsEvent) -> DashboardSseEvent {
    match event {
        koi_mdns::MdnsEvent::Found(record) => ev(
            "mdns.found",
            serde_json::to_value(record).unwrap_or_default(),
        ),
        koi_mdns::MdnsEvent::Resolved(record) => ev(
            "mdns.resolved",
            serde_json::to_value(record).unwrap_or_default(),
        ),
        koi_mdns::MdnsEvent::Removed { name, service_type } => ev(
            "mdns.removed",
            serde_json::json!({ "name": name, "service_type": service_type }),
        ),
    }
}

fn map_health(event: koi_health::HealthEvent) -> DashboardSseEvent {
    match event {
        koi_health::HealthEvent::StatusChanged { name, status } => ev(
            "health.changed",
            serde_json::json!({ "name": name, "status": status }),
        ),
    }
}

fn map_dns(event: koi_dns::DnsEvent) -> DashboardSseEvent {
    match event {
        koi_dns::DnsEvent::EntryUpdated { name, ip } => {
            ev("dns.updated", serde_json::json!({ "name": name, "ip": ip }))
        }
        koi_dns::DnsEvent::EntryRemoved { name } => {
            ev("dns.removed", serde_json::json!({ "name": name }))
        }
    }
}

fn map_certmesh(event: koi_certmesh::CertmeshEvent) -> DashboardSseEvent {
    match event {
        koi_certmesh::CertmeshEvent::MemberJoined {
            hostname,
            fingerprint,
        } => ev(
            "certmesh.joined",
            serde_json::json!({ "hostname": hostname, "fingerprint": fingerprint }),
        ),
        koi_certmesh::CertmeshEvent::MemberRevoked { hostname } => ev(
            "certmesh.revoked",
            serde_json::json!({ "hostname": hostname }),
        ),
        koi_certmesh::CertmeshEvent::Destroyed => ev("certmesh.destroyed", serde_json::json!({})),
        koi_certmesh::CertmeshEvent::CertRenewed { expires_at } => ev(
            "certmesh.cert_renewed",
            serde_json::json!({ "expires_at": expires_at }),
        ),
        koi_certmesh::CertmeshEvent::CertExpiringSoon { days_left } => ev(
            "certmesh.cert_expiring_soon",
            serde_json::json!({ "days_left": days_left }),
        ),
        koi_certmesh::CertmeshEvent::CertRenewalFailed {
            reason,
            consecutive_failures,
        } => ev(
            "certmesh.cert_renewal_failed",
            serde_json::json!({ "reason": reason, "consecutive_failures": consecutive_failures }),
        ),
        koi_certmesh::CertmeshEvent::BundleUpdated { self_revoked } => ev(
            "certmesh.bundle_updated",
            serde_json::json!({ "self_revoked": self_revoked }),
        ),
    }
}

fn map_proxy(event: koi_proxy::ProxyEvent) -> DashboardSseEvent {
    match event {
        koi_proxy::ProxyEvent::EntryUpdated { entry } => ev(
            "proxy.updated",
            serde_json::to_value(entry).unwrap_or_default(),
        ),
        koi_proxy::ProxyEvent::EntryRemoved { name } => {
            ev("proxy.removed", serde_json::json!({ "name": name }))
        }
    }
}

fn map_runtime(event: koi_runtime::RuntimeEvent) -> DashboardSseEvent {
    match event {
        koi_runtime::RuntimeEvent::Started(instance) => ev(
            "runtime.started",
            serde_json::to_value(instance).unwrap_or_default(),
        ),
        koi_runtime::RuntimeEvent::Stopped { id, name } => ev(
            "runtime.stopped",
            serde_json::json!({ "id": id, "name": name }),
        ),
        koi_runtime::RuntimeEvent::Updated(instance) => ev(
            "runtime.updated",
            serde_json::to_value(instance).unwrap_or_default(),
        ),
        koi_runtime::RuntimeEvent::BackendDisconnected { backend, reason } => ev(
            "runtime.disconnected",
            serde_json::json!({ "backend": backend, "reason": reason }),
        ),
        koi_runtime::RuntimeEvent::BackendReconnected { backend } => ev(
            "runtime.reconnected",
            serde_json::json!({ "backend": backend }),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_event_maps_to_superset_event() {
        // The runtime arm is the daemon/embedded divergence — assert the unified
        // forwarder includes it.
        let mapped = map_runtime(koi_runtime::RuntimeEvent::BackendReconnected {
            backend: "docker".to_string(),
        });
        assert_eq!(mapped.event_type, "runtime.reconnected");
        assert_eq!(mapped.data["backend"], "docker");
        assert!(!mapped.id.is_empty());
    }

    #[test]
    fn dns_removed_maps_to_named_event() {
        let mapped = map_dns(koi_dns::DnsEvent::EntryRemoved {
            name: "grafana".to_string(),
        });
        assert_eq!(mapped.event_type, "dns.removed");
        assert_eq!(mapped.data["name"], "grafana");
    }

    #[test]
    fn certmesh_destroyed_maps_without_payload() {
        let mapped = map_certmesh(koi_certmesh::CertmeshEvent::Destroyed);
        assert_eq!(mapped.event_type, "certmesh.destroyed");
    }
}
