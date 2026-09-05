//! Unified domain-event forwarder for the dashboard SSE feed.
//!
//! This is the **single** forwarder: it subscribes to every event-bearing domain's
//! broadcast channel and maps each event into a [`DashboardSseEvent`]. It replaces the
//! two diverged copies that previously lived in the binary and embedded crates. Its
//! complete set is mDNS, health, DNS, certmesh, Trust, proxy, runtime, and UDP.

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
    pub trust: Option<Arc<koi_trust::TrustCore>>,
    pub dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub health: Option<Arc<koi_health::HealthRuntime>>,
    pub proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    pub runtime: Option<Arc<koi_runtime::RuntimeCore>>,
    pub udp: Option<Arc<koi_udp::UdpRuntime>>,
}

/// Spawn the forwarder task. It subscribes to each present core and relays mapped
/// events into `event_tx` until `cancel` fires.
pub fn spawn_event_forwarder(
    cores: ForwarderCores,
    event_tx: broadcast::Sender<DashboardSseEvent>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    // Arm every domain subscription before returning the owned task. Broadcast
    // channels retain values only for existing receivers, so subscribing inside
    // the spawned future left a deterministic window in which the composition
    // could accept its first command but the dashboard/webhook boundary would
    // never observe the resulting event.
    let mut mdns_rx = cores.mdns.as_ref().map(|c| c.subscribe());
    let mut health_rx = cores.health.as_ref().map(|r| r.subscribe());
    let mut dns_rx = cores.dns.as_ref().map(|r| r.subscribe());
    let mut certmesh_rx = cores.certmesh.as_ref().map(|c| c.subscribe());
    let mut trust_rx = cores.trust.as_ref().map(|c| c.subscribe());
    let mut proxy_rx = cores.proxy.as_ref().map(|r| r.subscribe());
    let mut runtime_rx = cores.runtime.as_ref().map(|r| r.subscribe());
    let mut udp_rx = cores.udp.as_ref().map(|r| r.subscribe());

    tokio::spawn(async move {
        loop {
            let sse_event: Option<DashboardSseEvent> = tokio::select! {
                _ = cancel.cancelled() => break,

                result = recv_opt(&mut mdns_rx) => {
                    let (event, closed) = map_delivery("mdns", result, map_mdns);
                    if closed { mdns_rx = None; }
                    event
                },
                result = recv_opt(&mut health_rx) => {
                    let (event, closed) = map_delivery("health", result, map_health);
                    if closed { health_rx = None; }
                    event
                },
                result = recv_opt(&mut dns_rx) => {
                    let (event, closed) = map_delivery("dns", result, map_dns);
                    if closed { dns_rx = None; }
                    event
                },
                result = recv_opt(&mut certmesh_rx) => {
                    let (event, closed) = map_delivery("certmesh", result, map_certmesh);
                    if closed { certmesh_rx = None; }
                    event
                },
                result = recv_opt(&mut trust_rx) => {
                    let (event, closed) = map_delivery("trust", result, map_trust);
                    if closed { trust_rx = None; }
                    event
                },
                result = recv_opt(&mut proxy_rx) => {
                    let (event, closed) = map_delivery("proxy", result, map_proxy);
                    if closed { proxy_rx = None; }
                    event
                },
                result = recv_opt(&mut runtime_rx) => {
                    let (event, closed) = map_delivery("runtime", result, map_runtime);
                    if closed { runtime_rx = None; }
                    event
                },
                result = recv_opt(&mut udp_rx) => {
                    let (event, closed) = map_delivery("udp", result, map_udp);
                    if closed { udp_rx = None; }
                    event
                },
            };

            if let Some(ev) = sse_event {
                let _ = event_tx.send(ev);
            }
        }
    })
}

/// Await an optional broadcast receiver. An absent or retired receiver remains pending,
/// so disabled capabilities cannot turn the forwarding loop into a busy spin.
async fn recv_opt<T: Clone>(
    rx: &mut Option<broadcast::Receiver<T>>,
) -> Result<T, broadcast::error::RecvError> {
    match rx.as_mut() {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

fn map_delivery<T>(
    domain: &'static str,
    result: Result<T, broadcast::error::RecvError>,
    map: fn(T) -> DashboardSseEvent,
) -> (Option<DashboardSseEvent>, bool) {
    match result {
        Ok(event) => (Some(map(event)), false),
        Err(broadcast::error::RecvError::Lagged(dropped)) => {
            tracing::warn!(
                domain,
                dropped,
                "Dashboard forwarder lagged; requesting snapshot resync"
            );
            (
                Some(ev(
                    "system.resync_required",
                    serde_json::json!({ "domain": domain, "dropped": dropped }),
                )),
                false,
            )
        }
        Err(broadcast::error::RecvError::Closed) => {
            tracing::debug!(domain, "Dashboard domain event source closed");
            (None, true)
        }
    }
}

fn ev(event_type: &str, data: serde_json::Value) -> DashboardSseEvent {
    DashboardSseEvent {
        event_type: event_type.to_string(),
        id: uuid::Uuid::now_v7().to_string(),
        data,
    }
}

fn serialized_ev(event_type: &'static str, data: impl serde::Serialize) -> DashboardSseEvent {
    match serde_json::to_value(data) {
        Ok(data) => ev(event_type, data),
        Err(error) => ev(
            "system.serialization_failed",
            serde_json::json!({
                "source_event": event_type,
                "error": error.to_string(),
            }),
        ),
    }
}

// ── Pure per-domain mappers (unit-tested) ───────────────────────────

fn map_mdns(event: koi_mdns::MdnsEvent) -> DashboardSseEvent {
    match event {
        koi_mdns::MdnsEvent::Found(record) => serialized_ev("mdns.found", record),
        koi_mdns::MdnsEvent::Resolved(record) => serialized_ev("mdns.resolved", record),
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
        koi_dns::DnsEvent::TxtUpdated { name } => {
            ev("dns.txt_updated", serde_json::json!({ "name": name }))
        }
        koi_dns::DnsEvent::TxtRemoved { name } => {
            ev("dns.txt_removed", serde_json::json!({ "name": name }))
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
        koi_certmesh::CertmeshEvent::ServiceCertificateIssued {
            service_id,
            dns_name,
            expires_at,
            renewed,
        } => ev(
            "certmesh.service_certificate_issued",
            serde_json::json!({
                "service_id": service_id,
                "dns_name": dns_name,
                "expires_at": expires_at,
                "renewed": renewed,
            }),
        ),
        koi_certmesh::CertmeshEvent::ServiceNameRevoked {
            service_id,
            dns_name,
        } => ev(
            "certmesh.service_name_revoked",
            serde_json::json!({ "service_id": service_id, "dns_name": dns_name }),
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
        koi_certmesh::CertmeshEvent::PromotedToAuthority { hostname } => ev(
            "certmesh.promoted_to_authority",
            serde_json::json!({ "hostname": hostname }),
        ),
        koi_certmesh::CertmeshEvent::ReloadHookCompleted { command } => ev(
            "certmesh.reload_hook_completed",
            serde_json::json!({ "command": command }),
        ),
        koi_certmesh::CertmeshEvent::ReloadHookFailed { command, reason } => ev(
            "certmesh.reload_hook_failed",
            serde_json::json!({ "command": command, "reason": reason }),
        ),
    }
}

fn map_trust(event: koi_trust::TrustEvent) -> DashboardSseEvent {
    match event {
        koi_trust::TrustEvent::RootInstalled { name, fingerprint } => ev(
            "trust.root_installed",
            serde_json::json!({ "name": name, "fingerprint": fingerprint }),
        ),
        koi_trust::TrustEvent::RootRemoved { name, fingerprint } => ev(
            "trust.root_removed",
            serde_json::json!({ "name": name, "fingerprint": fingerprint }),
        ),
        koi_trust::TrustEvent::TransitionRecovered {
            operation,
            name,
            fingerprint,
        } => ev(
            "trust.transition_recovered",
            serde_json::json!({
                "operation": operation,
                "name": name,
                "fingerprint": fingerprint,
            }),
        ),
        koi_trust::TrustEvent::PresenceChanged {
            name,
            fingerprint,
            presence,
        } => ev(
            "trust.presence_changed",
            serde_json::json!({
                "name": name,
                "fingerprint": fingerprint,
                "presence": presence,
            }),
        ),
    }
}

fn map_proxy(event: koi_proxy::ProxyEvent) -> DashboardSseEvent {
    match event {
        koi_proxy::ProxyEvent::EntryUpdated { entry } => serialized_ev("proxy.updated", entry),
        koi_proxy::ProxyEvent::EntryRemoved { name } => {
            ev("proxy.removed", serde_json::json!({ "name": name }))
        }
        koi_proxy::ProxyEvent::ScopedEntriesReplaced { scope, entries } => ev(
            "proxy.scope_replaced",
            serde_json::json!({
                "scope": match scope {
                    koi_proxy::ProxyEntryScope::Runtime => "runtime",
                },
                "entries": entries,
            }),
        ),
    }
}

fn map_runtime(event: koi_runtime::RuntimeEvent) -> DashboardSseEvent {
    match event {
        koi_runtime::RuntimeEvent::Started(instance) => serialized_ev("runtime.started", instance),
        koi_runtime::RuntimeEvent::Stopped { id, name } => ev(
            "runtime.stopped",
            serde_json::json!({ "id": id, "name": name }),
        ),
        koi_runtime::RuntimeEvent::Updated(instance) => serialized_ev("runtime.updated", instance),
        koi_runtime::RuntimeEvent::BackendDisconnected { backend, reason } => ev(
            "runtime.disconnected",
            serde_json::json!({ "backend": backend, "reason": reason }),
        ),
        koi_runtime::RuntimeEvent::BackendReconnected { backend } => ev(
            "runtime.reconnected",
            serde_json::json!({ "backend": backend }),
        ),
        koi_runtime::RuntimeEvent::BackendStopped { backend } => ev(
            "runtime.backend_stopped",
            serde_json::json!({ "backend": backend }),
        ),
    }
}

fn map_udp(event: koi_udp::UdpEvent) -> DashboardSseEvent {
    match event {
        koi_udp::UdpEvent::Bound(binding) => serialized_ev("udp.bound", binding),
        koi_udp::UdpEvent::Renewed { id, last_heartbeat } => ev(
            "udp.renewed",
            serde_json::json!({ "id": id, "last_heartbeat": last_heartbeat }),
        ),
        koi_udp::UdpEvent::Unbound { id, reason } => ev(
            "udp.unbound",
            serde_json::json!({ "id": id, "reason": reason }),
        ),
        koi_udp::UdpEvent::Stopped => ev("udp.stopped", serde_json::json!({})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscriptions_are_armed_before_the_owned_task_is_polled() {
        let state_path = std::env::temp_dir().join(format!(
            "koi-dashboard-forwarder-{}.json",
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
            .expect("open DNS domain"),
        ));
        let (event_tx, mut event_rx) = broadcast::channel(16);
        let cancel = CancellationToken::new();
        let task = spawn_event_forwarder(
            ForwarderCores {
                dns: Some(Arc::clone(&dns)),
                ..ForwarderCores::default()
            },
            event_tx,
            cancel.clone(),
        );

        // Do not yield between spawning and committing the command. This is the
        // startup edge that used to lose the first event deterministically.
        dns.add_entry(koi_dns::DnsEntry {
            name: "ready.internal".to_string(),
            ip: "192.0.2.17".to_string(),
            ttl: None,
        })
        .expect("commit DNS entry");

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), event_rx.recv())
            .await
            .expect("forwarding task should observe the already-admitted event")
            .expect("dashboard event channel should remain open");
        assert_eq!(event.event_type, "dns.updated");
        assert_eq!(event.data["name"], "ready.internal");

        cancel.cancel();
        task.await.expect("forwarder shutdown");
        dns.shutdown().await;
        let _ = std::fs::remove_file(state_path);
    }

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
    fn serialization_failure_is_an_explicit_event_not_empty_data() {
        struct Broken;

        impl serde::Serialize for Broken {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("broken event payload"))
            }
        }

        let mapped = serialized_ev("runtime.updated", Broken);
        assert_eq!(mapped.event_type, "system.serialization_failed");
        assert_eq!(mapped.data["source_event"], "runtime.updated");
        assert!(mapped.data["error"]
            .as_str()
            .is_some_and(|detail| detail.contains("broken event payload")));
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

    #[test]
    fn service_certificate_events_expose_only_public_identity_facts() {
        let service_id = koi_common::service::ServiceId::new("svc_dashboard").unwrap();
        let mapped = map_certmesh(koi_certmesh::CertmeshEvent::ServiceCertificateIssued {
            service_id,
            dns_name: "dashboard.internal".into(),
            expires_at: chrono::DateTime::UNIX_EPOCH,
            renewed: false,
        });
        assert_eq!(mapped.event_type, "certmesh.service_certificate_issued");
        assert_eq!(mapped.data["service_id"], "svc_dashboard");
        assert_eq!(mapped.data["dns_name"], "dashboard.internal");
        assert!(mapped.data.get("key_pem").is_none());
        assert!(mapped.data.get("cert_pem").is_none());
    }

    #[test]
    fn certmesh_reload_failure_preserves_actionable_detail() {
        let mapped = map_certmesh(koi_certmesh::CertmeshEvent::ReloadHookFailed {
            command: "reload-consumer".to_string(),
            reason: "exit status 1".to_string(),
        });
        assert_eq!(mapped.event_type, "certmesh.reload_hook_failed");
        assert_eq!(mapped.data["command"], "reload-consumer");
        assert_eq!(mapped.data["reason"], "exit status 1");
    }

    #[test]
    fn trust_events_are_coarse_and_never_carry_certificate_material() {
        let mapped = map_trust(koi_trust::TrustEvent::RootInstalled {
            name: "koi-certmesh-ca".into(),
            fingerprint: "abcdef".into(),
        });
        assert_eq!(mapped.event_type, "trust.root_installed");
        assert_eq!(mapped.data["name"], "koi-certmesh-ca");
        assert!(mapped.data.get("certificate_pem").is_none());
    }

    #[test]
    fn udp_unbound_preserves_the_domain_reason() {
        let mapped = map_udp(koi_udp::UdpEvent::Unbound {
            id: "binding-1".to_string(),
            reason: koi_udp::UdpUnbindReason::LeaseExpired,
        });
        assert_eq!(mapped.event_type, "udp.unbound");
        assert_eq!(mapped.data["id"], "binding-1");
        assert_eq!(mapped.data["reason"], "lease_expired");
    }

    #[test]
    fn lag_requests_authoritative_resync_and_closed_source_retires() {
        let (event, closed) = map_delivery::<koi_udp::UdpEvent>(
            "udp",
            Err(broadcast::error::RecvError::Lagged(7)),
            map_udp,
        );
        let event = event.expect("lag is visible to consumers");
        assert!(!closed);
        assert_eq!(event.event_type, "system.resync_required");
        assert_eq!(event.data["domain"], "udp");
        assert_eq!(event.data["dropped"], 7);

        let (event, closed) = map_delivery::<koi_udp::UdpEvent>(
            "udp",
            Err(broadcast::error::RecvError::Closed),
            map_udp,
        );
        assert!(event.is_none());
        assert!(closed);
    }
}
