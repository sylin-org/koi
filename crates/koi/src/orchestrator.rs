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
pub(crate) struct OrchestrationTargets {
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
pub(crate) fn spawn_orchestrator(
    runtime: &Arc<RuntimeCore>,
    targets: OrchestrationTargets,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let mut rx = runtime.subscribe();
    let resources: Arc<Mutex<HashMap<String, OrchestratedResources>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let resources_clone = Arc::clone(&resources);
    let targets = Arc::new(targets);

    tokio::spawn(async move {
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
                            handle_start(&instance, &resources_clone, &targets).await;
                        }
                        Ok(RuntimeEvent::Stopped { id, name }) => {
                            handle_stop(&id, &name, &resources_clone, &targets).await;
                        }
                        Ok(RuntimeEvent::Updated(instance)) => {
                            // Re-register: stop then start
                            handle_stop(&instance.id, &instance.name, &resources_clone, &targets).await;
                            handle_start(&instance, &resources_clone, &targets).await;
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
                            // Reconciliation: new Started events will arrive from the backend.
                            // Duplicate registrations are handled idempotently in handle_start.
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
) {
    // Only orchestrate containers that opted in
    if !should_orchestrate(instance) {
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

            match mdns.register(payload) {
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
            match proxy.core().upsert(entry).await {
                Ok(_) => {
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
            if let Err(e) = mdns.unregister(mdns_id) {
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
            if let Err(e) = proxy.core().remove(proxy_name).await {
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
                let _ = mdns.unregister(mdns_id);
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
                let _ = proxy.core().remove(proxy_name).await;
            }
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Determine whether an instance should be orchestrated (opt-in policy).
fn should_orchestrate(instance: &Instance) -> bool {
    // Explicit disable always wins
    if instance.metadata.is_disabled() {
        return false;
    }
    // Must have an explicit opt-in signal
    instance.metadata.enable == Some(true)
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

    let health_path = instance.metadata.health_path.as_deref();

    let (check_kind, target) = if let Some(path) = health_path {
        // Health path present (explicit or implied) → HTTP check
        (
            koi_health::ServiceCheckKind::Http,
            format!("http://{}:{}{}", host_ip, first_tcp_port.host_port, path),
        )
    } else {
        // No path → TCP probe
        (
            koi_health::ServiceCheckKind::Tcp,
            format!("{}:{}", host_ip, first_tcp_port.host_port),
        )
    };

    Some(koi_health::HealthCheck {
        name: check_name,
        kind: check_kind,
        target,
        interval_secs: instance.metadata.health_interval.unwrap_or(30),
        timeout_secs: instance.metadata.health_timeout.unwrap_or(5),
    })
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
