//! Runtime lifecycle orchestrator.
//!
//! Subscribes to [`RuntimeEvent`] from `koi-runtime` and translates
//! container/service lifecycle events into Koi domain operations:
//! mDNS announce, DNS entry, health check, proxy entry — and their
//! reverses on stop.
//!
//! This is the single place where runtime detection meets domain action.
//! Domain crates know nothing about containers; koi-runtime knows nothing
//! about mDNS. The orchestrator bridges the two.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use koi_runtime::heuristics;
use koi_runtime::instance::{Instance, PortProtocol};
use koi_runtime::{RuntimeCore, RuntimeEvent};

// ── Resource tracking ───────────────────────────────────────────────

/// Resources created by the orchestrator for a single runtime instance.
///
/// When the instance stops, each non-None resource is cleaned up.
#[derive(Debug, Default)]
struct OrchestratedResources {
    /// mDNS registration IDs (one per published port).
    mdns_ids: Vec<String>,
    /// DNS entry name (without zone suffix).
    dns_name: Option<String>,
    /// Health check name.
    health_name: Option<String>,
    /// Proxy entry name.
    proxy_name: Option<String>,
}

// ── Domain handles ──────────────────────────────────────────────────

/// Optional references to domain cores. Each may be `None` if the
/// capability is disabled via `--no-*` flags.
pub struct OrchestrationTargets {
    pub mdns: Option<Arc<koi_mdns::MdnsCore>>,
    pub dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub health: Option<Arc<koi_health::HealthRuntime>>,
    pub proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
}

// ── Orchestrator loop ───────────────────────────────────────────────

/// Spawn the runtime lifecycle orchestrator.
///
/// Returns a `JoinHandle` that runs until the cancellation token fires.
/// On cancellation, all orchestrated resources are cleaned up before exit.
pub fn spawn_orchestrator(
    runtime: &Arc<RuntimeCore>,
    targets: OrchestrationTargets,
    scope: Option<String>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let mut rx = runtime.subscribe();
    let runtime = Arc::clone(runtime);
    let resources: Arc<Mutex<HashMap<String, OrchestratedResources>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let resources_clone = Arc::clone(&resources);
    let targets = Arc::new(targets);
    let scope = scope.as_deref().map(str::to_owned);

    tokio::spawn(async move {
        // The runtime connects and inventories existing instances before the
        // composition root starts this subscriber. Reconcile that snapshot here
        // so a Koi restart reconstructs every derived resource for containers
        // that never stopped. Subscribing before the snapshot closes the race:
        // concurrent events queue and are handled idempotently below.
        match runtime.list_instances().await {
            Ok(instances) => {
                for instance in instances {
                    handle_start(&instance, &resources_clone, &targets, scope.as_deref()).await;
                }
            }
            Err(error) => {
                tracing::warn!(%error, "Orchestrator could not reconcile runtime inventory");
            }
        }

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("Orchestrator shutting down, cleaning up resources");
                    cleanup_all(&resources_clone, &targets).await;
                    break;
                }
                event = rx.recv() => {
                    match event {
                        Ok(RuntimeEvent::Started(instance)) => {
                            handle_start(&instance, &resources_clone, &targets, scope.as_deref())
                                .await;
                        }
                        Ok(RuntimeEvent::Stopped { id, name }) => {
                            handle_stop(&id, &name, &resources_clone, &targets).await;
                        }
                        Ok(RuntimeEvent::Updated(instance)) => {
                            // Re-register: stop then start
                            handle_stop(&instance.id, &instance.name, &resources_clone, &targets).await;
                            handle_start(&instance, &resources_clone, &targets, scope.as_deref())
                                .await;
                        }
                        Ok(RuntimeEvent::BackendDisconnected { backend, reason }) => {
                            tracing::warn!(
                                backend,
                                reason,
                                "Runtime backend disconnected — keeping registrations alive"
                            );
                        }
                        Ok(RuntimeEvent::BackendReconnected { backend }) => {
                            tracing::info!(backend, "Runtime backend reconnected");
                            // The backend emits exact Stopped/Started/Updated reconciliation
                            // events before this marker. They traverse the normal handlers above;
                            // no parallel reconnect policy is needed here.
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(missed = n, "Orchestrator lagged behind runtime events");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            tracing::info!("Runtime event channel closed");
                            break;
                        }
                    }
                }
            }
        }
    })
}

// ── Event handlers ──────────────────────────────────────────────────

async fn handle_start(
    instance: &Instance,
    resources: &Arc<Mutex<HashMap<String, OrchestratedResources>>>,
    targets: &Arc<OrchestrationTargets>,
    scope: Option<&str>,
) {
    // Only orchestrate containers that opted in
    if !should_orchestrate(instance, scope) {
        return;
    }

    // If already tracked (reconnection/duplicate), remove first
    {
        let map = resources.lock().await;
        if map.contains_key(&instance.id) {
            drop(map);
            handle_stop(&instance.id, &instance.name, resources, targets).await;
        }
    }

    let mut res = OrchestratedResources::default();
    let service_name = effective_name(instance);

    // ── mDNS: one registration per published TCP port ───────────
    if let Some(ref mdns) = targets.mdns {
        for port in &instance.ports {
            if port.protocol != PortProtocol::Tcp {
                continue;
            }

            let service_type = heuristics::resolve_service_type(
                port.container_port,
                false,
                instance.metadata.service_type.as_deref(),
            );

            let payload = koi_mdns::protocol::RegisterPayload {
                name: service_name.clone(),
                service_type: service_type.to_string(),
                port: port.host_port,
                ip: non_loopback_ip(instance, port),
                lease_secs: None,
                txt: instance.metadata.txt.clone(),
            };

            match mdns.register(payload).await {
                Ok(result) => {
                    tracing::info!(
                        name = %service_name,
                        service_type,
                        port = port.host_port,
                        id = %result.id,
                        "Orchestrator: mDNS announced"
                    );
                    res.mdns_ids.push(result.id);
                }
                Err(e) => {
                    tracing::warn!(
                        name = %service_name,
                        port = port.host_port,
                        error = %e,
                        "Orchestrator: mDNS announce failed"
                    );
                }
            }
        }
    }

    // ── DNS: one entry for the service ──────────────────────────
    if let Some(ref dns) = targets.dns {
        let dns_name = instance
            .metadata
            .dns_name
            .as_deref()
            .unwrap_or(&service_name);

        // Use the first non-loopback host IP, or fall back to 127.0.0.1
        let ip = resolve_host_ip(instance);

        let entry = koi_config::state::DnsEntry {
            name: dns_name.to_string(),
            ip,
            ttl: None,
        };

        match dns.core().add_entry(entry) {
            Ok(_) => {
                tracing::info!(name = dns_name, "Orchestrator: DNS entry added");
                res.dns_name = Some(dns_name.to_string());
            }
            Err(e) => {
                tracing::warn!(name = dns_name, error = %e, "Orchestrator: DNS add failed");
            }
        }
    }

    // ── Health check ────────────────────────────────────────────
    if let Some(ref health) = targets.health {
        if let Some(check) = build_health_check(instance, &service_name) {
            let check_name = check.name.clone();
            // Remove existing check with same name (idempotent restart)
            let _ = health.core().remove_check(&check_name).await;
            match health.core().add_check(check).await {
                Ok(()) => {
                    tracing::info!(name = %check_name, "Orchestrator: health check added");
                    res.health_name = Some(check_name);
                }
                Err(e) => {
                    tracing::warn!(
                        name = %check_name,
                        error = %e,
                        "Orchestrator: health check add failed"
                    );
                }
            }
        }
    }

    // ── Proxy (only if explicitly requested via label) ──────────
    if let Some(ref proxy) = targets.proxy {
        if let Some(entry) = build_proxy_entry(instance, &service_name) {
            let proxy_name = entry.name.clone();
            match proxy.upsert(entry).await {
                Ok(()) => {
                    tracing::info!(name = %proxy_name, "Orchestrator: proxy entry added");
                    res.proxy_name = Some(proxy_name);
                }
                Err(e) => {
                    tracing::warn!(
                        name = %proxy_name,
                        error = %e,
                        "Orchestrator: proxy upsert failed"
                    );
                }
            }
        }
    }

    resources.lock().await.insert(instance.id.clone(), res);
}

async fn handle_stop(
    id: &str,
    name: &str,
    resources: &Arc<Mutex<HashMap<String, OrchestratedResources>>>,
    targets: &Arc<OrchestrationTargets>,
) {
    let res = resources.lock().await.remove(id);
    let Some(res) = res else { return };

    // ── mDNS unregister ─────────────────────────────────────────
    if let Some(ref mdns) = targets.mdns {
        for mdns_id in &res.mdns_ids {
            if let Err(e) = mdns.unregister(mdns_id).await {
                tracing::warn!(id = mdns_id, error = %e, "Orchestrator: mDNS unregister failed");
            } else {
                tracing::info!(id = mdns_id, name, "Orchestrator: mDNS unregistered");
            }
        }
    }

    // ── DNS remove ──────────────────────────────────────────────
    if let Some(ref dns) = targets.dns {
        if let Some(ref dns_name) = res.dns_name {
            if let Err(e) = dns.core().remove_entry(dns_name) {
                tracing::warn!(name = dns_name, error = %e, "Orchestrator: DNS remove failed");
            } else {
                tracing::info!(name = dns_name, "Orchestrator: DNS entry removed");
            }
        }
    }

    // ── Health check remove ─────────────────────────────────────
    if let Some(ref health) = targets.health {
        if let Some(ref check_name) = res.health_name {
            if let Err(e) = health.core().remove_check(check_name).await {
                tracing::warn!(name = check_name, error = %e, "Orchestrator: health remove failed");
            } else {
                tracing::info!(name = check_name, "Orchestrator: health check removed");
            }
        }
    }

    // ── Proxy remove ────────────────────────────────────────────
    if let Some(ref proxy) = targets.proxy {
        if let Some(ref proxy_name) = res.proxy_name {
            if let Err(e) = proxy.remove(proxy_name).await {
                tracing::warn!(name = proxy_name, error = %e, "Orchestrator: proxy remove failed");
            } else {
                tracing::info!(name = proxy_name, "Orchestrator: proxy entry removed");
            }
        }
    }
}

/// Clean up all orchestrated resources (called on shutdown).
async fn cleanup_all(
    resources: &Arc<Mutex<HashMap<String, OrchestratedResources>>>,
    targets: &Arc<OrchestrationTargets>,
) {
    let entries: Vec<(String, OrchestratedResources)> = resources.lock().await.drain().collect();

    for (id, res) in entries {
        tracing::debug!(id, "Cleaning up orchestrated resources");

        if let Some(ref mdns) = targets.mdns {
            for mdns_id in &res.mdns_ids {
                let _ = mdns.unregister(mdns_id).await;
            }
        }
        if let Some(ref dns) = targets.dns {
            if let Some(ref dns_name) = res.dns_name {
                let _ = dns.core().remove_entry(dns_name);
            }
        }
        if let Some(ref health) = targets.health {
            if let Some(ref check_name) = res.health_name {
                let _ = health.core().remove_check(check_name).await;
            }
        }
        if let Some(ref proxy) = targets.proxy {
            if let Some(ref proxy_name) = res.proxy_name {
                let _ = proxy.remove(proxy_name).await;
            }
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Determine whether an instance should be orchestrated (opt-in policy).
fn should_orchestrate(instance: &Instance, scope: Option<&str>) -> bool {
    // Explicit disable always wins
    if instance.metadata.is_disabled() {
        return false;
    }
    // Scope membership (ADR-035): a base-scope daemon derives unlabeled
    // containers only; a scoped daemon derives exactly its own scope. Two
    // daemons sharing one Docker socket therefore never derive the same
    // container, and never race for the same derived surfaces.
    let scope_matches = match (instance.metadata.scope.as_deref(), scope) {
        (Some(container_scope), Some(daemon_scope)) => container_scope == daemon_scope,
        (None, None) => true,
        _ => false,
    };
    scope_matches && instance.metadata.enable == Some(true)
}

/// Derive the effective service name for an instance.
fn effective_name(instance: &Instance) -> String {
    instance
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| instance.name.clone())
}

/// Find the best host IP to advertise for a container.
///
/// Prefers non-loopback IPs from port bindings, falls back to instance IPs,
/// then to 127.0.0.1.
fn resolve_host_ip(instance: &Instance) -> String {
    // Check port binding host IPs (prefer 0.0.0.0 which means "all interfaces")
    for port in &instance.ports {
        if port.host_ip != "127.0.0.1" && port.host_ip != "::1" && !port.host_ip.is_empty() {
            // 0.0.0.0 means all interfaces — the host's LAN IP will be used by mDNS
            // For DNS we need a concrete IP; return the first non-loopback instance IP
            if port.host_ip == "0.0.0.0" || port.host_ip == "::" {
                for ip in &instance.ips {
                    if ip != "127.0.0.1" && ip != "::1" {
                        return ip.clone();
                    }
                }
            }
            return port.host_ip.clone();
        }
    }

    // Fall back to instance IPs
    for ip in &instance.ips {
        if ip != "127.0.0.1" && ip != "::1" {
            return ip.clone();
        }
    }

    "127.0.0.1".to_string()
}

/// Get a non-loopback IP for mDNS registration, or None to let mDNS auto-detect.
fn non_loopback_ip(_instance: &Instance, port: &koi_runtime::PortMapping) -> Option<String> {
    let ip = &port.host_ip;
    if ip.is_empty() || ip == "0.0.0.0" || ip == "::" || ip == "127.0.0.1" || ip == "::1" {
        None // wildcard or loopback — let mDNS advertise all host interfaces
    } else {
        Some(ip.clone())
    }
}

/// Build a health check configuration from instance metadata.
fn build_health_check(instance: &Instance, service_name: &str) -> Option<koi_health::HealthCheck> {
    // Need at least one published port to check
    let first_tcp_port = instance
        .ports
        .iter()
        .find(|p| p.protocol == PortProtocol::Tcp)?;

    let check_name = format!("runtime:{}", service_name);
    let host_ip = resolve_host_ip(instance);
    let port = first_tcp_port.host_port;
    let health_path = instance.metadata.health_path.as_deref();

    // `koi.health.kind` (http|tcp) is an explicit operator override; when absent,
    // infer from whether a health path was given (path → HTTP probe, else TCP).
    let kind = instance
        .metadata
        .health_kind
        .as_deref()
        .map(|k| k.trim().to_ascii_lowercase());
    let (check_kind, target) = match kind.as_deref() {
        Some("tcp") => (
            koi_health::ServiceCheckKind::Tcp,
            format!("{host_ip}:{port}"),
        ),
        Some("http") => (
            koi_health::ServiceCheckKind::Http,
            format!("http://{host_ip}:{port}{}", health_path.unwrap_or("/")),
        ),
        Some(other) => {
            tracing::warn!(
                kind = other,
                service = service_name,
                "ignoring unknown koi.health.kind (expected http|tcp); inferring from health path"
            );
            infer_check_kind(&host_ip, port, health_path)
        }
        None => infer_check_kind(&host_ip, port, health_path),
    };

    Some(koi_health::HealthCheck {
        name: check_name,
        kind: check_kind,
        target,
        interval_secs: instance.metadata.health_interval.unwrap_or(30),
        timeout_secs: instance.metadata.health_timeout.unwrap_or(5),
    })
}

/// Infer a health probe from path-presence: a health path → HTTP GET, else a
/// bare TCP connect. Used when `koi.health.kind` is unset (or unrecognized).
fn infer_check_kind(
    host_ip: &str,
    port: u16,
    health_path: Option<&str>,
) -> (koi_health::ServiceCheckKind, String) {
    match health_path {
        Some(path) => (
            koi_health::ServiceCheckKind::Http,
            format!("http://{host_ip}:{port}{path}"),
        ),
        None => (
            koi_health::ServiceCheckKind::Tcp,
            format!("{host_ip}:{port}"),
        ),
    }
}

/// Build a proxy entry if explicitly requested via metadata.
fn build_proxy_entry(instance: &Instance, service_name: &str) -> Option<koi_proxy::ProxyEntry> {
    let listen_port = instance.metadata.proxy_port?;
    let first_tcp_port = instance
        .ports
        .iter()
        .find(|p| p.protocol == PortProtocol::Tcp)?;

    let host_ip = resolve_host_ip(instance);

    Some(koi_proxy::ProxyEntry {
        name: service_name.to_string(),
        listen_port,
        backend: format!("http://{}:{}", host_ip, first_tcp_port.host_port),
        allow_remote: instance.metadata.proxy_remote.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_health::ServiceCheckKind;
    use koi_runtime::instance::{InstanceState, KoiMetadata, PortMapping};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn instance_with(health_kind: Option<&str>, health_path: Option<&str>) -> Instance {
        Instance {
            id: "c1".into(),
            name: "svc".into(),
            ports: vec![PortMapping {
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::Tcp,
                host_ip: "10.0.0.5".into(),
            }],
            ips: vec!["10.0.0.5".into()],
            metadata: KoiMetadata {
                health_kind: health_kind.map(str::to_string),
                health_path: health_path.map(str::to_string),
                ..Default::default()
            },
            backend: "docker".into(),
            state: InstanceState::Running,
            discovered_at: chrono::Utc::now(),
            image: None,
        }
    }

    #[test]
    fn health_kind_tcp_overrides_path_heuristic() {
        // A health path alone would imply HTTP; explicit kind=tcp must win.
        let check = build_health_check(&instance_with(Some("TCP"), Some("/healthz")), "svc")
            .expect("check");
        assert!(matches!(check.kind, ServiceCheckKind::Tcp));
        assert_eq!(check.target, "10.0.0.5:8080");
    }

    #[test]
    fn health_kind_http_without_path_defaults_to_root() {
        // No path would imply TCP; explicit kind=http must win, defaulting to "/".
        let check = build_health_check(&instance_with(Some("http"), None), "svc").expect("check");
        assert!(matches!(check.kind, ServiceCheckKind::Http));
        assert_eq!(check.target, "http://10.0.0.5:8080/");
    }

    #[test]
    fn health_kind_absent_infers_from_path() {
        let http = build_health_check(&instance_with(None, Some("/up")), "svc").expect("check");
        assert!(matches!(http.kind, ServiceCheckKind::Http));
        assert_eq!(http.target, "http://10.0.0.5:8080/up");

        let tcp = build_health_check(&instance_with(None, None), "svc").expect("check");
        assert!(matches!(tcp.kind, ServiceCheckKind::Tcp));
        assert_eq!(tcp.target, "10.0.0.5:8080");
    }

    #[test]
    fn health_kind_unknown_falls_back_to_path_heuristic() {
        // An unrecognized kind is ignored (warned) and inference takes over.
        let check =
            build_health_check(&instance_with(Some("grpc"), Some("/x")), "svc").expect("check");
        assert!(matches!(check.kind, ServiceCheckKind::Http));
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("reserve ephemeral port")
            .local_addr()
            .expect("ephemeral address")
            .port()
    }

    #[tokio::test]
    async fn preexisting_runtime_instance_is_reconciled_and_reversed() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let service_name = format!("tier1-{}-{nonce}", std::process::id());
        let instance_id = format!("synthetic-{nonce}");
        let health_name = format!("runtime:{service_name}");
        let root = koi_common::test::ensure_data_dir("koi-compose-tests")
            .join("runtime-story")
            .join(&instance_id);
        std::fs::create_dir_all(&root).expect("create isolated story root");

        let cancel = CancellationToken::new();
        let runtime = Arc::new(RuntimeCore::new(koi_runtime::RuntimeConfig::default()));
        let mdns = Arc::new(
            koi_mdns::MdnsCore::with_cancel(cancel.clone())
                .await
                .expect("mDNS core"),
        );
        let dns = Arc::new(koi_dns::DnsRuntime::new(
            koi_dns::DnsCore::new(
                koi_dns::DnsConfig {
                    port: 0,
                    state_path: Some(root.join("dns.json")),
                    ..Default::default()
                },
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        let health = Arc::new(koi_health::HealthRuntime::new(Arc::new(
            koi_health::HealthCore::new(None, None, None, None).await,
        )));
        let proxy = Arc::new(koi_proxy::ProxyRuntime::new(Arc::new(
            koi_proxy::ProxyCore::with_data_dir(&root).expect("proxy core"),
        )));

        let proxy_port = free_port();
        let backend_port = free_port();
        let instance = Instance {
            id: instance_id.clone(),
            name: service_name.clone(),
            ports: vec![PortMapping {
                host_port: backend_port,
                container_port: 8080,
                protocol: PortProtocol::Tcp,
                host_ip: "127.0.0.1".into(),
            }],
            ips: vec!["127.0.0.1".into()],
            metadata: KoiMetadata {
                enable: Some(true),
                service_type: Some("_http._tcp".into()),
                name: Some(service_name.clone()),
                dns_name: Some(service_name.clone()),
                health_kind: Some("tcp".into()),
                health_interval: Some(1),
                health_timeout: Some(1),
                proxy_port: Some(proxy_port),
                proxy_remote: Some(false),
                ..Default::default()
            },
            backend: "synthetic".into(),
            state: InstanceState::Running,
            discovered_at: chrono::Utc::now(),
            image: Some("test-only/no-container".into()),
        };

        runtime
            .ingest_event(RuntimeEvent::Started(instance.clone()))
            .await;

        // Deliberately start the orchestrator after inventory is populated. This
        // is the daemon-restart ordering: the backend lists running containers
        // before the composition root can subscribe to live events.
        let orchestrator = spawn_orchestrator(
            &runtime,
            OrchestrationTargets {
                mdns: Some(Arc::clone(&mdns)),
                dns: Some(Arc::clone(&dns)),
                health: Some(Arc::clone(&health)),
                proxy: Some(Arc::clone(&proxy)),
            },
            None,
            cancel.clone(),
        );

        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let inventory = runtime.list_instances().await.expect("runtime inventory");
                let mdns_present = mdns
                    .admin_registrations()
                    .iter()
                    .any(|(_, registration)| registration.name == service_name);
                let dns_present = dns
                    .core()
                    .list_entries()
                    .iter()
                    .any(|entry| entry.name == service_name);
                let health_present = health
                    .core()
                    .list_checks()
                    .await
                    .iter()
                    .any(|check| check.name == health_name);
                let proxy_present = proxy
                    .status()
                    .await
                    .iter()
                    .any(|entry| entry.name == service_name && entry.state == "running");
                if inventory.iter().any(|entry| entry.id == instance_id)
                    && mdns_present
                    && dns_present
                    && health_present
                    && proxy_present
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("synthetic start must derive inventory, mDNS, DNS, health, and proxy state");

        let proxy_status = proxy
            .status()
            .await
            .into_iter()
            .find(|entry| entry.name == service_name)
            .expect("derived proxy status");
        assert_eq!(proxy_status.cert_source, "self-signed");
        assert!(proxy_status.error.is_none());
        assert_eq!(
            proxy_status.backend,
            format!("http://127.0.0.1:{backend_port}")
        );

        runtime
            .ingest_event(RuntimeEvent::Stopped {
                id: instance.id,
                name: instance.name,
            })
            .await;

        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let inventory_empty = runtime
                    .list_instances()
                    .await
                    .expect("runtime inventory")
                    .iter()
                    .all(|entry| entry.id != instance_id);
                let mdns_absent = mdns
                    .admin_registrations()
                    .iter()
                    .all(|(_, registration)| registration.name != service_name);
                let dns_absent = dns
                    .core()
                    .list_entries()
                    .iter()
                    .all(|entry| entry.name != service_name);
                let health_absent = health
                    .core()
                    .list_checks()
                    .await
                    .iter()
                    .all(|check| check.name != health_name);
                let proxy_absent = proxy
                    .status()
                    .await
                    .iter()
                    .all(|entry| entry.name != service_name);
                if inventory_empty && mdns_absent && dns_absent && health_absent && proxy_absent {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("synthetic stop must reverse inventory, mDNS, DNS, health, and proxy state");

        cancel.cancel();
        orchestrator.await.expect("orchestrator shutdown");
        proxy.stop_all().await;
        mdns.shutdown().await.expect("mDNS shutdown");
        std::fs::remove_dir_all(&root).expect("remove isolated story root");
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    use koi_runtime::instance::{InstanceState, KoiMetadata};

    fn labeled_instance(scope: Option<&str>, enabled: bool) -> Instance {
        let mut labels: HashMap<String, String> = HashMap::new();
        labels.insert("koi.enable".to_string(), enabled.to_string());
        if let Some(scope) = scope {
            labels.insert("koi.scope".to_string(), scope.to_string());
        }
        Instance {
            id: "c1".into(),
            name: "svc".into(),
            ports: vec![],
            ips: vec!["10.0.0.5".into()],
            metadata: KoiMetadata::from_labels(&labels),
            backend: "docker".into(),
            state: InstanceState::Running,
            discovered_at: chrono::Utc::now(),
            image: None,
        }
    }

    #[test]
    fn base_daemon_derives_unlabeled_containers_only() {
        assert!(should_orchestrate(&labeled_instance(None, true), None));
        assert!(!should_orchestrate(
            &labeled_instance(Some("run-1"), true),
            None
        ));
    }

    #[test]
    fn scoped_daemon_derives_only_its_own_scope() {
        assert!(should_orchestrate(
            &labeled_instance(Some("run-1"), true),
            Some("run-1")
        ));
        assert!(!should_orchestrate(
            &labeled_instance(Some("run-2"), true),
            Some("run-1")
        ));
        assert!(!should_orchestrate(
            &labeled_instance(None, true),
            Some("run-1")
        ));
    }

    #[test]
    fn explicit_disable_wins_over_scope() {
        assert!(!should_orchestrate(
            &labeled_instance(Some("run-1"), false),
            Some("run-1")
        ));
    }
}
