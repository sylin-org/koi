//! Runtime lifecycle orchestrator.
//!
//! Watches the authoritative [`koi_runtime::RuntimeStatus`] and translates
//! the current container/service inventory into Koi domain operations:
//! mDNS announce, DNS entry, health check, proxy entry — and their
//! reverses on stop.
//!
//! This is the single place where runtime detection meets domain action.
//! Domain crates know nothing about containers; koi-runtime knows nothing
//! about mDNS. The orchestrator bridges the two.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use koi_runtime::heuristics;
use koi_runtime::instance::{Instance, PortMapping, PortProtocol};
use koi_runtime::{RuntimeCore, RuntimeStatus, RuntimeWatchState};

const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// One host-side address observation from a runtime port mapping.
///
/// Wildcard is kept distinct from a concrete address because it has different
/// truthful meanings at each boundary: it permits local loopback connections,
/// but only mDNS can turn it into machine-interface advertisements itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservedBinding {
    Wildcard(IpAddr),
    Concrete(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
enum EndpointProjectionError {
    #[error("no published TCP endpoint was observed")]
    NoTcpEndpoint,
    #[error("published TCP endpoint has host port 0")]
    ZeroHostPort,
    #[error("published TCP port {port} has no observed host binding")]
    MissingHostBinding { port: u16 },
    #[error("published TCP port {port} has invalid host binding '{binding}'")]
    InvalidHostBinding { port: u16, binding: String },
    #[error("runtime reported invalid instance address '{address}'")]
    InvalidInstanceAddress { address: String },
    #[error("only loopback addresses were observed; no network-advertisable address exists")]
    OnlyLoopbackAddresses,
    #[error("no observed non-loopback address is available for network advertisement")]
    NoAdvertisableAddress,
}

// ── Resource tracking ───────────────────────────────────────────────

/// Native resources created by the orchestrator for one runtime instance.
///
/// DNS, Health, and Proxy accept complete transient desired sets and therefore
/// need no per-instance cleanup handles here. mDNS is inherently lease-shaped,
/// so its explicit registrations remain under one session owner per instance.
#[derive(Default)]
struct MdnsLeases {
    /// mDNS registration IDs (one per published port).
    mdns_ids: Vec<String>,
    /// Fail-safe owner for this instance's derived registrations. Explicit
    /// withdrawal remains the fast path; session drop hands any unsettled ids
    /// to the mDNS reaper after cancellation, provider loss, or task abort.
    mdns_session: Option<koi_mdns::RegistrationSession>,
}

/// An applied side-effect set and the authoritative runtime facts from which it
/// was derived. The resource identifiers are cleanup handles, not a competing
/// inventory: desired membership always comes from `RuntimeStatus`.
struct MdnsAppliedInstance {
    source: Instance,
    leases: MdnsLeases,
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
    // Subscribe before reading the first value: a racing runtime transition is
    // either in the borrowed snapshot or remains pending on this receiver.
    let status = runtime.watch_status();
    let mdns_resources: Arc<Mutex<HashMap<String, MdnsAppliedInstance>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let targets = Arc::new(targets);
    let scope = scope.as_deref().map(str::to_owned);

    tokio::spawn(supervise_orchestrator(
        run_orchestrator(
            status,
            Arc::clone(&mdns_resources),
            Arc::clone(&targets),
            scope,
            cancel,
        ),
        mdns_resources,
        targets,
    ))
}

async fn supervise_orchestrator<F>(
    worker: F,
    mdns_resources: Arc<Mutex<HashMap<String, MdnsAppliedInstance>>>,
    targets: Arc<OrchestrationTargets>,
) where
    F: std::future::Future<Output = ()>,
{
    let result = std::panic::AssertUnwindSafe(worker).catch_unwind().await;
    if result.is_err() {
        tracing::error!("Runtime orchestrator panicked; retiring every derived resource");
        cleanup_all(&mdns_resources, &targets).await;
    }
}

async fn run_orchestrator(
    mut status: tokio::sync::watch::Receiver<Arc<RuntimeStatus>>,
    mdns_resources: Arc<Mutex<HashMap<String, MdnsAppliedInstance>>>,
    targets: Arc<OrchestrationTargets>,
    scope: Option<String>,
    cancel: CancellationToken,
) {
    if cancel.is_cancelled() {
        cleanup_all(&mdns_resources, &targets).await;
        return;
    }
    // Runtime may inventory existing instances before composition starts.
    // Reconcile the current snapshot so restart reconstructs their derived
    // resources. `watch` coalescing is desirable: only latest truth matters.
    let initial = status.borrow_and_update().clone();
    reconcile_runtime_status(
        initial.as_ref(),
        &mdns_resources,
        &targets,
        scope.as_deref(),
        true,
    )
    .await;
    let mut previous_state = initial.state;
    let mut retry = tokio::time::interval(RECONCILE_INTERVAL);
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Initial reconciliation above already did the work represented by the
    // interval's immediate first tick.
    retry.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("Orchestrator shutting down, cleaning up resources");
                cleanup_all(&mdns_resources, &targets).await;
                break;
            }
            changed = status.changed() => {
                if changed.is_err() {
                    tracing::error!(
                        "Runtime status observation closed; retaining the last accepted desire until composition shutdown"
                    );
                    // Losing a source is not a new empty snapshot. The closed
                    // receiver still retains Runtime's last authoritative
                    // value, so keep repairing that accepted desire until the
                    // composition owner explicitly cancels this bridge. This
                    // branch must not select `changed()` again: a closed watch
                    // resolves immediately and would otherwise busy-loop.
                    loop {
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => {
                                tracing::info!("Orchestrator shutting down after Runtime observation loss, cleaning up resources");
                                cleanup_all(&mdns_resources, &targets).await;
                                return;
                            }
                            _ = retry.tick() => {
                                let retained = status.borrow().clone();
                                reconcile_runtime_status(
                                    retained.as_ref(),
                                    &mdns_resources,
                                    &targets,
                                    scope.as_deref(),
                                    false,
                                ).await;
                            }
                        }
                    }
                }
                let current = status.borrow_and_update().clone();
                let repair_all = previous_state != RuntimeWatchState::Running
                    && current.state == RuntimeWatchState::Running;
                reconcile_runtime_status(
                    current.as_ref(),
                    &mdns_resources,
                    &targets,
                    scope.as_deref(),
                    repair_all,
                ).await;
                previous_state = current.state;
            }
            _ = retry.tick() => {
                // A downstream domain may temporarily reject a complete
                // desired set. Re-reading current Runtime truth makes that
                // failure self-healing without replaying events or keeping
                // a second durable inventory.
                let current = status.borrow_and_update().clone();
                reconcile_runtime_status(
                    current.as_ref(),
                    &mdns_resources,
                    &targets,
                    scope.as_deref(),
                    false,
                ).await;
                previous_state = current.state;
            }
        }
    }
}

/// Converge derived resources from the authoritative runtime snapshot. This is
/// used at startup and after every coalesced status notification. `repair_all`
/// deliberately re-applies the current inventory after backend recovery; no
/// event payload is ever replayed as a second source of truth.
async fn reconcile_runtime_status(
    status: &RuntimeStatus,
    mdns_resources: &Arc<Mutex<HashMap<String, MdnsAppliedInstance>>>,
    targets: &Arc<OrchestrationTargets>,
    scope: Option<&str>,
    repair_all: bool,
) {
    // Runtime deliberately retains its last inventory for diagnostics and for
    // lossless adapter reconnection. That snapshot is actionable while the
    // watcher is Running, temporarily Waiting, or still being reaped. Once the
    // source has observably Stopped/Failed (and while a fresh generation is not
    // yet reconciled), it is history rather than current network desire.
    let mut desired_instances = if runtime_inventory_is_actionable(status.state) {
        status
            .instances
            .iter()
            .filter(|instance| should_orchestrate(instance, scope))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    desired_instances.sort_by(|left, right| left.id.cmp(&right.id));
    let desired = desired_instances
        .iter()
        .map(|instance| instance.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let stale = mdns_resources
        .lock()
        .await
        .keys()
        .filter(|id| !desired.contains(id.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    for id in stale {
        handle_stop(&id, &id, mdns_resources, targets).await;
    }
    for instance in &desired_instances {
        let needs_apply = {
            let applied = mdns_resources.lock().await;
            applied.get(&instance.id).is_none_or(|current| {
                repair_all
                    || !same_orchestration_inputs(&current.source, instance)
                    || !mdns_application_is_complete(current, targets)
            })
        };
        if needs_apply {
            // The normal handler removes the previous concrete handles first,
            // so updates and incomplete prior attempts converge.
            handle_start(instance, mdns_resources, targets, scope).await;
        }
    }

    replace_derived_sets(&desired_instances, targets).await;
}

fn runtime_inventory_is_actionable(state: RuntimeWatchState) -> bool {
    matches!(
        state,
        RuntimeWatchState::Running | RuntimeWatchState::Waiting | RuntimeWatchState::Stopping
    )
}

// ── Event handlers ──────────────────────────────────────────────────

async fn handle_start(
    instance: &Instance,
    mdns_resources: &Arc<Mutex<HashMap<String, MdnsAppliedInstance>>>,
    targets: &Arc<OrchestrationTargets>,
    scope: Option<&str>,
) {
    // Only orchestrate containers that opted in
    if !should_orchestrate(instance, scope) {
        return;
    }

    // If already tracked (reconnection/duplicate), remove first
    {
        let map = mdns_resources.lock().await;
        if map.contains_key(&instance.id) {
            drop(map);
            handle_stop(&instance.id, &instance.name, mdns_resources, targets).await;
        }
    }

    let mut leases = MdnsLeases::default();
    let service_name = effective_name(instance);

    // ── mDNS: one registration per published TCP port ───────────
    if let Some(ref mdns) = targets.mdns {
        let session = mdns.open_registration_session();
        for port in &instance.ports {
            if port.protocol != PortProtocol::Tcp {
                continue;
            }

            let payload = match build_mdns_registration(instance, port, &service_name) {
                Ok(payload) => payload,
                Err(error) => {
                    report_projection_omission(instance, "mDNS", &error);
                    continue;
                }
            };
            let service_type = payload.service_type.clone();

            match mdns
                .register_with_policy(
                    payload,
                    koi_mdns::LeasePolicy::Session {
                        grace: std::time::Duration::ZERO,
                    },
                    Some(session.id().clone()),
                )
                .await
            {
                Ok(result) => {
                    tracing::info!(
                        name = %service_name,
                        service_type = %service_type,
                        port = port.host_port,
                        id = %result.id,
                        "Orchestrator: mDNS announced"
                    );
                    leases.mdns_ids.push(result.id);
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
        if !leases.mdns_ids.is_empty() {
            leases.mdns_session = Some(session);
        }
    }

    mdns_resources.lock().await.insert(
        instance.id.clone(),
        MdnsAppliedInstance {
            source: instance.clone(),
            leases,
        },
    );
}

async fn handle_stop(
    id: &str,
    name: &str,
    mdns_resources: &Arc<Mutex<HashMap<String, MdnsAppliedInstance>>>,
    targets: &Arc<OrchestrationTargets>,
) {
    let applied = mdns_resources.lock().await.remove(id);
    let Some(applied) = applied else { return };
    let leases = applied.leases;

    // ── mDNS unregister ─────────────────────────────────────────
    if let Some(ref mdns) = targets.mdns {
        for mdns_id in &leases.mdns_ids {
            if let Err(e) = mdns.unregister(mdns_id).await {
                tracing::warn!(id = mdns_id, error = %e, "Orchestrator: mDNS unregister failed");
            } else {
                tracing::info!(id = mdns_id, name, "Orchestrator: mDNS unregistered");
            }
        }
    }
}

/// Clean up all orchestrated resources (called on shutdown).
async fn cleanup_all(
    mdns_resources: &Arc<Mutex<HashMap<String, MdnsAppliedInstance>>>,
    targets: &Arc<OrchestrationTargets>,
) {
    // Clear all complete overlays before retiring per-registration mDNS
    // handles. Every downstream domain is asked even when another is absent.
    replace_derived_sets(&[], targets).await;
    let entries: Vec<(String, MdnsAppliedInstance)> = mdns_resources.lock().await.drain().collect();

    for (id, applied) in entries {
        tracing::debug!(id, "Cleaning up orchestrated resources");
        let leases = applied.leases;

        if let Some(ref mdns) = targets.mdns {
            for mdns_id in &leases.mdns_ids {
                let _ = mdns.unregister(mdns_id).await;
            }
        }
    }
}

/// Project one authoritative Runtime inventory into complete transient desired
/// sets. Each target domain owns validation, collision precedence, state
/// publication, and data-plane reconciliation. Nothing here is persisted and
/// no cleanup ledger competes with `RuntimeStatus` as current truth.
async fn replace_derived_sets(instances: &[&Instance], targets: &OrchestrationTargets) {
    let mut dns = BTreeMap::<String, (String, koi_dns::DnsEntry)>::new();
    let mut health = BTreeMap::<String, (String, koi_health::HealthCheck)>::new();
    let mut proxy = BTreeMap::<String, (String, koi_proxy::ProxyEntry)>::new();
    let mut instances = instances.to_vec();
    instances.sort_by(|left, right| left.id.cmp(&right.id));

    for instance in instances {
        let service_name = effective_name(instance);
        let dns_name = instance
            .metadata
            .dns_name
            .clone()
            .unwrap_or_else(|| service_name.clone());
        if let Some(target) = &targets.dns {
            match build_dns_entry(instance, &dns_name) {
                Ok(entry) => match target.validate_scoped_entry(&entry) {
                    Ok(()) => insert_derived(&mut dns, dns_name, &instance.id, entry, "DNS"),
                    Err(error) => tracing::warn!(
                        instance = %instance.id,
                        %error,
                        "Orchestrator: invalid Runtime DNS projection ignored"
                    ),
                },
                Err(error) => report_projection_omission(instance, "DNS", &error),
            }
        }
        if targets.health.is_some() {
            match build_health_check(instance, &service_name) {
                Ok(check) => match koi_health::HealthRuntime::validate_scoped_check(&check) {
                    Ok(()) => insert_derived(
                        &mut health,
                        check.name.clone(),
                        &instance.id,
                        check,
                        "health",
                    ),
                    Err(error) => tracing::warn!(
                        instance = %instance.id,
                        %error,
                        "Orchestrator: invalid Runtime health projection ignored"
                    ),
                },
                Err(error) => report_projection_omission(instance, "health", &error),
            }
        }
        if targets.proxy.is_some() {
            match build_proxy_entry(instance, &service_name) {
                Ok(Some(entry)) => match koi_proxy::ProxyRuntime::validate_scoped_entry(&entry) {
                    Ok(()) => {
                        insert_derived(&mut proxy, entry.name.clone(), &instance.id, entry, "proxy")
                    }
                    Err(error) => tracing::warn!(
                        instance = %instance.id,
                        %error,
                        "Orchestrator: invalid Runtime proxy projection ignored"
                    ),
                },
                Ok(None) => {}
                Err(error) => report_projection_omission(instance, "proxy", &error),
            }
        }
    }

    if let Some(target) = &targets.dns {
        if let Err(error) = target.replace_scoped_entries(
            koi_dns::DnsEntryScope::Runtime,
            dns.into_values().map(|(_, entry)| entry).collect(),
        ) {
            tracing::warn!(%error, "Orchestrator: DNS desired set rejected; retaining prior accepted set");
        }
    }
    if let Some(target) = &targets.health {
        if let Err(error) = target
            .replace_scoped_checks(
                koi_health::HealthCheckScope::Runtime,
                health.into_values().map(|(_, check)| check).collect(),
            )
            .await
        {
            tracing::warn!(%error, "Orchestrator: health desired set rejected; retaining prior accepted set");
        }
    }
    if let Some(target) = &targets.proxy {
        if let Err(error) = target
            .replace_scoped_entries(
                koi_proxy::ProxyEntryScope::Runtime,
                proxy.into_values().map(|(_, entry)| entry).collect(),
            )
            .await
        {
            tracing::warn!(%error, "Orchestrator: proxy desired set rejected; retaining prior accepted set");
        }
    }
}

/// Resolve duplicate runtime labels without depending on backend iteration
/// order. `RuntimeStatus.instances` is ID-sorted, so the first owner is stable
/// and every conflicting instance is named in the diagnostic.
fn insert_derived<T>(
    set: &mut BTreeMap<String, (String, T)>,
    name: String,
    instance_id: &str,
    value: T,
    capability: &'static str,
) {
    match set.entry(name) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert((instance_id.to_string(), value));
        }
        std::collections::btree_map::Entry::Occupied(slot) => {
            tracing::warn!(
                capability,
                name = slot.key(),
                owner = %slot.get().0,
                ignored = instance_id,
                "Runtime instances requested the same derived name; deterministic first owner retained"
            );
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Compare only runtime facts that affect derived Koi resources. Backend
/// bookkeeping, discovery timestamps and image display metadata cannot force
/// needless network teardown/re-registration.
fn same_orchestration_inputs(left: &Instance, right: &Instance) -> bool {
    left.name == right.name
        && left.ports == right.ports
        && left.ips == right.ips
        && left.metadata == right.metadata
}

/// A partial downstream application remains retryable on the next runtime
/// status change. Enabled targets with no corresponding handle are incomplete;
/// intentionally inapplicable Health/Proxy projections are complete as `None`.
fn mdns_application_is_complete(
    applied: &MdnsAppliedInstance,
    targets: &OrchestrationTargets,
) -> bool {
    let expected_mdns = targets.mdns.as_ref().map_or(0, |_| {
        applied
            .source
            .ports
            .iter()
            .filter(|port| port.protocol == PortProtocol::Tcp)
            .filter(|port| mdns_registration_ip(port).is_ok())
            .count()
    });
    applied.leases.mdns_ids.len() == expected_mdns
}

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

fn observed_binding(port: &PortMapping) -> Result<ObservedBinding, EndpointProjectionError> {
    if port.host_port == 0 {
        return Err(EndpointProjectionError::ZeroHostPort);
    }
    let binding = port.host_ip.trim();
    if binding.is_empty() {
        return Err(EndpointProjectionError::MissingHostBinding {
            port: port.host_port,
        });
    }
    let address =
        binding
            .parse::<IpAddr>()
            .map_err(|_| EndpointProjectionError::InvalidHostBinding {
                port: port.host_port,
                binding: binding.to_string(),
            })?;
    if address.is_unspecified() {
        Ok(ObservedBinding::Wildcard(address))
    } else {
        Ok(ObservedBinding::Concrete(address))
    }
}

/// Project one published mapping into the address this process can connect to.
/// A wildcard bind objectively includes the same-family loopback interface, so
/// this local-only derivation does not claim that loopback was runtime-observed.
fn local_endpoint(port: &PortMapping) -> Result<SocketAddr, EndpointProjectionError> {
    let address = match observed_binding(port)? {
        ObservedBinding::Concrete(address) => address,
        ObservedBinding::Wildcard(IpAddr::V4(_)) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        ObservedBinding::Wildcard(IpAddr::V6(_)) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    Ok(SocketAddr::new(address, port.host_port))
}

fn first_local_endpoint(instance: &Instance) -> Result<SocketAddr, EndpointProjectionError> {
    let mut first_error = None;
    let mut saw_tcp = false;
    for port in &instance.ports {
        if port.protocol != PortProtocol::Tcp {
            continue;
        }
        saw_tcp = true;
        match local_endpoint(port) {
            Ok(endpoint) => return Ok(endpoint),
            Err(error) => first_error.get_or_insert(error),
        };
    }
    if saw_tcp {
        Err(first_error.unwrap_or(EndpointProjectionError::NoTcpEndpoint))
    } else {
        Err(EndpointProjectionError::NoTcpEndpoint)
    }
}

fn instance_advertisement_ip(instance: &Instance) -> Result<IpAddr, EndpointProjectionError> {
    let mut invalid = None;
    let mut saw_loopback = false;
    for observed in &instance.ips {
        match observed.trim().parse::<IpAddr>() {
            Ok(address) if !address.is_unspecified() && !address.is_loopback() => {
                return Ok(address);
            }
            Ok(address) if address.is_loopback() => saw_loopback = true,
            Ok(_) => {}
            Err(_) => {
                invalid.get_or_insert_with(|| EndpointProjectionError::InvalidInstanceAddress {
                    address: observed.clone(),
                });
            }
        }
    }
    if let Some(error) = invalid {
        Err(error)
    } else if saw_loopback {
        Err(EndpointProjectionError::OnlyLoopbackAddresses)
    } else {
        Err(EndpointProjectionError::NoAdvertisableAddress)
    }
}

/// Select a concrete network-advertisable address without converting wildcard
/// or absent observations into a guessed host identity.
fn dns_advertisement_ip(instance: &Instance) -> Result<IpAddr, EndpointProjectionError> {
    let mut may_use_instance_address = !instance
        .ports
        .iter()
        .any(|port| port.protocol == PortProtocol::Tcp);
    let mut first_error = None;
    let mut saw_loopback = false;

    for port in &instance.ports {
        if port.protocol != PortProtocol::Tcp {
            continue;
        }
        match observed_binding(port) {
            Ok(ObservedBinding::Concrete(address)) if !address.is_loopback() => {
                return Ok(address);
            }
            Ok(ObservedBinding::Concrete(_)) => saw_loopback = true,
            Ok(ObservedBinding::Wildcard(_)) => may_use_instance_address = true,
            Err(error @ EndpointProjectionError::MissingHostBinding { .. }) => {
                may_use_instance_address = true;
                first_error.get_or_insert(error);
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }

    if may_use_instance_address {
        return instance_advertisement_ip(instance);
    }
    if saw_loopback {
        Err(EndpointProjectionError::OnlyLoopbackAddresses)
    } else if let Some(error) = first_error {
        Err(error)
    } else {
        Err(EndpointProjectionError::NoAdvertisableAddress)
    }
}

fn mdns_registration_ip(port: &PortMapping) -> Result<Option<String>, EndpointProjectionError> {
    match observed_binding(port)? {
        ObservedBinding::Wildcard(_) => Ok(None),
        ObservedBinding::Concrete(address) if address.is_loopback() => {
            Err(EndpointProjectionError::OnlyLoopbackAddresses)
        }
        ObservedBinding::Concrete(address) => Ok(Some(address.to_string())),
    }
}

fn build_mdns_registration(
    instance: &Instance,
    port: &PortMapping,
    service_name: &str,
) -> Result<koi_mdns::protocol::RegisterPayload, EndpointProjectionError> {
    let service_type = heuristics::resolve_service_type(
        port.container_port,
        false,
        instance.metadata.service_type.as_deref(),
    );
    Ok(koi_mdns::protocol::RegisterPayload {
        name: service_name.to_string(),
        service_type: service_type.to_string(),
        port: port.host_port,
        ip: mdns_registration_ip(port)?,
        lease_secs: None,
        txt: instance.metadata.txt.clone(),
    })
}

fn build_dns_entry(
    instance: &Instance,
    dns_name: &str,
) -> Result<koi_dns::DnsEntry, EndpointProjectionError> {
    Ok(koi_dns::DnsEntry {
        name: dns_name.to_string(),
        ip: dns_advertisement_ip(instance)?.to_string(),
        ttl: None,
    })
}

fn report_projection_omission(
    instance: &Instance,
    capability: &'static str,
    error: &EndpointProjectionError,
) {
    tracing::warn!(
        instance = %instance.id,
        capability,
        %error,
        "Orchestrator: Runtime projection omitted because no truthful endpoint is available"
    );
}

/// Build a health check configuration from instance metadata.
fn build_health_check(
    instance: &Instance,
    service_name: &str,
) -> Result<koi_health::HealthCheck, EndpointProjectionError> {
    let check_name = format!("runtime:{}", service_name);
    let endpoint = first_local_endpoint(instance)?;
    let health_path = instance.metadata.health_path.as_deref();

    // `koi.health.kind` (http|tcp) is an explicit operator override; when absent,
    // infer from whether a health path was given (path → HTTP probe, else TCP).
    let kind = instance
        .metadata
        .health_kind
        .as_deref()
        .map(|k| k.trim().to_ascii_lowercase());
    let (check_kind, target) = match kind.as_deref() {
        Some("tcp") => (koi_health::ServiceCheckKind::Tcp, endpoint.to_string()),
        Some("http") => (
            koi_health::ServiceCheckKind::Http,
            format!("http://{endpoint}{}", health_path.unwrap_or("/")),
        ),
        Some(other) => {
            tracing::warn!(
                kind = other,
                service = service_name,
                "ignoring unknown koi.health.kind (expected http|tcp); inferring from health path"
            );
            infer_check_kind(endpoint, health_path)
        }
        None => infer_check_kind(endpoint, health_path),
    };

    Ok(koi_health::HealthCheck {
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
    endpoint: SocketAddr,
    health_path: Option<&str>,
) -> (koi_health::ServiceCheckKind, String) {
    match health_path {
        Some(path) => (
            koi_health::ServiceCheckKind::Http,
            format!("http://{endpoint}{path}"),
        ),
        None => (koi_health::ServiceCheckKind::Tcp, endpoint.to_string()),
    }
}

/// Build a proxy entry if explicitly requested via metadata.
fn build_proxy_entry(
    instance: &Instance,
    service_name: &str,
) -> Result<Option<koi_proxy::ProxyEntry>, EndpointProjectionError> {
    let Some(listen_port) = instance.metadata.proxy_port else {
        return Ok(None);
    };
    let endpoint = first_local_endpoint(instance)?;

    Ok(Some(koi_proxy::ProxyEntry {
        name: service_name.to_string(),
        listen_port,
        backend: format!("http://{endpoint}"),
        allow_remote: instance.metadata.proxy_remote.unwrap_or(false),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hickory_proto::rr::RecordType;
    use koi_health::ServiceCheckKind;
    use koi_runtime::instance::{InstanceState, KoiMetadata, PortMapping};
    use koi_runtime::{RuntimeBackend, RuntimeError, RuntimeEvent, RuntimeObservation};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::sync::mpsc;

    struct TestRuntimeBackend {
        initial: Vec<Instance>,
        events: Mutex<Option<mpsc::UnboundedReceiver<RuntimeEvent>>>,
    }

    impl TestRuntimeBackend {
        fn controlled(
            initial: Vec<Instance>,
        ) -> (Box<dyn RuntimeBackend>, mpsc::UnboundedSender<RuntimeEvent>) {
            let (events, receiver) = mpsc::unbounded_channel();
            (
                Box::new(Self {
                    initial,
                    events: Mutex::new(Some(receiver)),
                }),
                events,
            )
        }
    }

    #[async_trait]
    impl RuntimeBackend for TestRuntimeBackend {
        fn name(&self) -> &'static str {
            "test-runtime-provider"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            Ok(self.initial.clone())
        }

        async fn begin_observation(
            self: Arc<Self>,
            tx: mpsc::Sender<RuntimeEvent>,
            cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            let mut events =
                self.events.lock().await.take().ok_or_else(|| {
                    RuntimeError::EventStream("test provider already armed".into())
                })?;
            let initial = self.initial.clone();
            Ok(RuntimeObservation::new(initial, async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return Ok(()),
                        event = events.recv() => match event {
                            Some(event) => {
                                if tx.send(event).await.is_err() {
                                    return Ok(());
                                }
                            }
                            None => return Ok(()),
                        }
                    }
                }
            }))
        }
    }

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

    #[test]
    fn absent_address_observations_omit_every_endpoint_instead_of_inventing_loopback() {
        let mut instance = instance_with(None, None);
        instance.ports[0].host_ip.clear();
        instance.ips.clear();
        instance.metadata.proxy_port = Some(9443);

        assert!(matches!(
            build_dns_entry(&instance, "svc"),
            Err(EndpointProjectionError::NoAdvertisableAddress)
        ));
        assert!(matches!(
            build_mdns_registration(&instance, &instance.ports[0], "svc"),
            Err(EndpointProjectionError::MissingHostBinding { .. })
        ));
        assert!(matches!(
            build_health_check(&instance, "svc"),
            Err(EndpointProjectionError::MissingHostBinding { .. })
        ));
        assert!(matches!(
            build_proxy_entry(&instance, "svc"),
            Err(EndpointProjectionError::MissingHostBinding { .. })
        ));
    }

    #[test]
    fn wildcard_binding_has_distinct_advertisement_and_local_connection_semantics() {
        let mut instance = instance_with(None, Some("/ready"));
        instance.ports[0].host_ip = "0.0.0.0".to_string();
        instance.ips = vec!["192.0.2.25".to_string()];
        instance.metadata.proxy_port = Some(9443);

        assert_eq!(
            build_dns_entry(&instance, "svc")
                .expect("observed DNS address")
                .ip,
            "192.0.2.25"
        );
        assert_eq!(
            build_mdns_registration(&instance, &instance.ports[0], "svc")
                .expect("wildcard mDNS projection")
                .ip,
            None
        );
        assert_eq!(
            build_health_check(&instance, "svc")
                .expect("local health endpoint")
                .target,
            "http://127.0.0.1:8080/ready"
        );
        assert_eq!(
            build_proxy_entry(&instance, "svc")
                .expect("local proxy endpoint")
                .expect("proxy requested")
                .backend,
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn explicit_loopback_is_local_truth_but_never_expands_into_advertisement() {
        let mut instance = instance_with(None, None);
        instance.ports[0].host_ip = "127.0.0.1".to_string();
        // A container-network address cannot widen an explicitly loopback-only
        // host mapping into a remotely advertised endpoint.
        instance.ips = vec!["192.0.2.25".to_string()];
        instance.metadata.proxy_port = Some(9443);

        assert!(matches!(
            build_dns_entry(&instance, "svc"),
            Err(EndpointProjectionError::OnlyLoopbackAddresses)
        ));
        assert!(matches!(
            build_mdns_registration(&instance, &instance.ports[0], "svc"),
            Err(EndpointProjectionError::OnlyLoopbackAddresses)
        ));
        assert_eq!(
            build_health_check(&instance, "svc")
                .expect("loopback is locally usable")
                .target,
            "127.0.0.1:8080"
        );
        assert_eq!(
            build_proxy_entry(&instance, "svc")
                .expect("loopback is locally usable")
                .expect("proxy requested")
                .backend,
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn ipv6_endpoints_preserve_addresses_and_format_authorities() {
        let mut instance = instance_with(Some("tcp"), None);
        instance.ports[0].host_ip = "2001:db8::25".to_string();
        instance.ips = vec!["2001:db8::25".to_string()];
        instance.metadata.proxy_port = Some(9443);
        instance.metadata.proxy_remote = Some(true);

        assert_eq!(
            build_dns_entry(&instance, "svc")
                .expect("IPv6 DNS entry")
                .ip,
            "2001:db8::25"
        );
        assert_eq!(
            build_mdns_registration(&instance, &instance.ports[0], "svc")
                .expect("IPv6 mDNS registration")
                .ip
                .as_deref(),
            Some("2001:db8::25")
        );
        let tcp = build_health_check(&instance, "svc").expect("IPv6 health target");
        assert_eq!(tcp.target, "[2001:db8::25]:8080");
        assert!(koi_health::HealthRuntime::validate_scoped_check(&tcp).is_ok());
        let proxy = build_proxy_entry(&instance, "svc")
            .expect("IPv6 proxy target")
            .expect("proxy requested");
        assert_eq!(proxy.backend, "http://[2001:db8::25]:8080");
        assert!(koi_proxy::ProxyRuntime::validate_scoped_entry(&proxy).is_ok());

        instance.metadata.health_kind = Some("http".to_string());
        instance.metadata.health_path = Some("/ready".to_string());
        assert_eq!(
            build_health_check(&instance, "svc")
                .expect("IPv6 HTTP health target")
                .target,
            "http://[2001:db8::25]:8080/ready"
        );

        instance.ports[0].host_ip = "::".to_string();
        instance.metadata.health_kind = Some("tcp".to_string());
        assert_eq!(
            build_health_check(&instance, "svc")
                .expect("IPv6 wildcard local target")
                .target,
            "[::1]:8080"
        );
    }

    #[test]
    fn orchestration_identity_ignores_presentation_only_runtime_fields() {
        let original = instance_with(None, None);
        let mut observation = original.clone();
        observation.backend = "another-adapter".to_string();
        observation.image = Some("new/display-image:latest".to_string());
        observation.discovered_at = original.discovered_at + chrono::Duration::seconds(30);

        assert!(same_orchestration_inputs(&original, &observation));
    }

    #[test]
    fn orchestration_identity_detects_a_changed_derived_resource() {
        let original = instance_with(None, None);
        let mut observation = original.clone();
        observation.ports[0].host_port += 1;

        assert!(!same_orchestration_inputs(&original, &observation));
    }

    #[tokio::test]
    async fn latest_snapshot_retires_stale_work_without_replaying_intermediate_events() {
        let mut old = instance_with(None, None);
        old.id = "old".to_string();
        old.name = "old".to_string();
        old.metadata.enable = Some(true);
        let mut latest = instance_with(None, None);
        latest.id = "latest".to_string();
        latest.name = "latest".to_string();
        latest.metadata.enable = Some(true);

        let resources = Arc::new(Mutex::new(HashMap::from([(
            old.id.clone(),
            MdnsAppliedInstance {
                source: old,
                leases: MdnsLeases::default(),
            },
        )])));
        let targets = Arc::new(OrchestrationTargets {
            mdns: None,
            dns: None,
            health: None,
            proxy: None,
        });
        let status = RuntimeStatus {
            revision: 9,
            active: true,
            state: RuntimeWatchState::Running,
            backend: Some("synthetic".to_string()),
            backend_error: None,
            instance_count: 1,
            instances: vec![latest.clone()],
        };

        reconcile_runtime_status(&status, &resources, &targets, None, false).await;

        let applied = resources.lock().await;
        assert_eq!(applied.len(), 1);
        assert_eq!(applied["latest"].source, latest);
        assert!(!applied.contains_key("old"));
    }

    #[tokio::test]
    async fn closed_runtime_observation_retains_last_desire_until_owner_cancels() {
        let mut instance = instance_with(None, None);
        instance.metadata.enable = Some(true);
        let status = RuntimeStatus {
            revision: 1,
            active: true,
            state: RuntimeWatchState::Running,
            backend: Some("synthetic".to_string()),
            backend_error: None,
            instance_count: 1,
            instances: vec![instance.clone()],
        };
        let (status_owner, status_rx) = tokio::sync::watch::channel(Arc::new(status));
        let resources = Arc::new(Mutex::new(HashMap::new()));
        let targets = Arc::new(OrchestrationTargets {
            mdns: None,
            dns: None,
            health: None,
            proxy: None,
        });
        let cancel = CancellationToken::new();
        let worker = tokio::spawn(run_orchestrator(
            status_rx,
            Arc::clone(&resources),
            targets,
            None,
            cancel.clone(),
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if resources.lock().await.contains_key(&instance.id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("initial Runtime desire is applied");

        drop(status_owner);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            resources.lock().await.contains_key(&instance.id),
            "source loss is not an explicit empty Runtime snapshot"
        );
        assert!(
            !worker.is_finished(),
            "the bridge must retain ownership while its source is unavailable"
        );

        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("cancelled bridge finishes")
            .expect("bridge task does not panic");
        assert!(resources.lock().await.is_empty());
    }

    #[tokio::test]
    async fn complete_projections_are_stable_and_invalid_instances_do_not_keep_stale_peers() {
        let root = koi_common::test::ensure_data_dir("koi-compose-tests").join(format!(
            "runtime-projection-{}",
            koi_common::id::generate_short_id()
        ));
        let dns = Arc::new(koi_dns::DnsRuntime::new(
            koi_dns::DnsCore::open(
                root.join("dns.json"),
                koi_dns::DnsConfig::default(),
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        let health = Arc::new(koi_health::HealthRuntime::new(Arc::new(
            koi_health::HealthCore::open(
                koi_health::HealthPaths::new(root.join("health.json"), root.join("health.log")),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("health core"),
        )));
        let targets = OrchestrationTargets {
            mdns: None,
            dns: Some(Arc::clone(&dns)),
            health: Some(Arc::clone(&health)),
            proxy: None,
        };

        let mut old = instance_with(None, None);
        old.id = "old".to_string();
        old.name = "old".to_string();
        old.metadata.name = Some("old".to_string());
        old.metadata.dns_name = Some("old".to_string());
        replace_derived_sets(&[&old], &targets).await;
        assert!(dns.resolve_local("old.internal.", RecordType::A).is_some());

        let mut later_id = instance_with(None, None);
        later_id.id = "b".to_string();
        later_id.name = "shared".to_string();
        later_id.metadata.name = Some("shared".to_string());
        later_id.metadata.dns_name = Some("shared".to_string());
        later_id.ports[0].host_ip = "10.0.0.22".to_string();

        let mut first_id = later_id.clone();
        first_id.id = "a".to_string();
        first_id.ports[0].host_ip = "10.0.0.11".to_string();

        let mut invalid = instance_with(None, None);
        invalid.id = "0-unusable".to_string();
        invalid.name = "shared".to_string();
        invalid.metadata.name = Some("shared".to_string());
        invalid.metadata.dns_name = Some("shared".to_string());
        invalid.metadata.health_interval = Some(0);
        invalid.ports[0].host_ip = "not-an-ip".to_string();
        invalid.ips.clear();

        // Deliberately reverse input order. The lexically first candidate has
        // no truthful endpoint and therefore cannot steal the shared name;
        // among valid candidates, the lower ID remains the stable owner.
        replace_derived_sets(&[&later_id, &invalid, &first_id], &targets).await;
        assert!(dns.resolve_local("old.internal.", RecordType::A).is_none());
        assert_eq!(
            dns.resolve_local("shared.internal.", RecordType::A)
                .expect("stable duplicate winner")
                .ips,
            ["10.0.0.11".parse::<std::net::IpAddr>().unwrap()]
        );
        let projected_health = health.status();
        let services = &projected_health.services;
        assert!(services.iter().all(|service| service.name != "runtime:old"));
        assert!(services
            .iter()
            .all(|service| service.name != "runtime:invalid"));
        assert_eq!(
            services
                .iter()
                .find(|service| service.name == "runtime:shared")
                .expect("stable health winner")
                .target,
            "10.0.0.11:8080"
        );

        let dns_status = dns.status();
        let health_status = health.status();
        replace_derived_sets(&[&first_id, &invalid, &later_id], &targets).await;
        assert!(Arc::ptr_eq(&dns_status, &dns.status()));
        assert!(Arc::ptr_eq(&health_status, &health.status()));

        replace_derived_sets(&[], &targets).await;
        assert!(dns
            .resolve_local("shared.internal.", RecordType::A)
            .is_none());
        assert!(health.status().services.is_empty());
        health.shutdown().await;
        dns.shutdown().await;
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn panicking_orchestrator_supervisor_clears_transient_desire() {
        let root = koi_common::test::ensure_data_dir("koi-compose-tests").join(format!(
            "runtime-panic-{}",
            koi_common::id::generate_short_id()
        ));
        let dns = Arc::new(koi_dns::DnsRuntime::new(
            koi_dns::DnsCore::open(
                root.join("dns.json"),
                koi_dns::DnsConfig::default(),
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        dns.replace_scoped_entries(
            koi_dns::DnsEntryScope::Runtime,
            vec![koi_dns::DnsEntry {
                name: "orphan".to_string(),
                ip: "10.0.0.7".to_string(),
                ttl: None,
            }],
        )
        .expect("seed transient desire");
        let health = Arc::new(koi_health::HealthRuntime::new(Arc::new(
            koi_health::HealthCore::open(
                koi_health::HealthPaths::new(root.join("health.json"), root.join("health.log")),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("health core"),
        )));
        health
            .replace_scoped_checks(
                koi_health::HealthCheckScope::Runtime,
                vec![koi_health::HealthCheck {
                    name: "runtime:orphan".to_string(),
                    kind: koi_health::ServiceCheckKind::Tcp,
                    target: "127.0.0.1:1".to_string(),
                    interval_secs: 30,
                    timeout_secs: 1,
                }],
            )
            .await
            .expect("seed transient health desire");
        let proxy = Arc::new(koi_proxy::ProxyRuntime::new(Arc::new(
            koi_proxy::ProxyCore::open(root.join("config.toml"), root.join("proxy-certs"))
                .expect("proxy core"),
        )));
        proxy
            .replace_scoped_entries(
                koi_proxy::ProxyEntryScope::Runtime,
                vec![koi_proxy::ProxyEntry {
                    name: "orphan".to_string(),
                    listen_port: free_port(),
                    backend: "http://127.0.0.1:1".to_string(),
                    allow_remote: false,
                }],
            )
            .await
            .expect("seed transient proxy desire");
        let targets = Arc::new(OrchestrationTargets {
            mdns: None,
            dns: Some(Arc::clone(&dns)),
            health: Some(Arc::clone(&health)),
            proxy: Some(Arc::clone(&proxy)),
        });

        supervise_orchestrator(
            async { panic!("injected orchestrator fault") },
            Arc::new(Mutex::new(HashMap::new())),
            targets,
        )
        .await;

        assert!(dns
            .resolve_local("orphan.internal.", RecordType::A)
            .is_none());
        assert!(health.status().services.is_empty());
        assert!(proxy.entries_snapshot().entries.is_empty());
        proxy.shutdown().await.expect("Proxy shutdown");
        health.shutdown().await;
        dns.shutdown().await;
        let _ = std::fs::remove_dir_all(root);
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
            koi_dns::DnsCore::open(
                root.join("dns.json"),
                koi_dns::DnsConfig {
                    port: 0,
                    ..Default::default()
                },
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        let health_state = root.join("health.json");
        let health = Arc::new(koi_health::HealthRuntime::new(Arc::new(
            koi_health::HealthCore::open(
                koi_health::HealthPaths::new(health_state.clone(), root.join("health.log")),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("health core"),
        )));
        let proxy = Arc::new(koi_proxy::ProxyRuntime::new(Arc::new(
            koi_proxy::ProxyCore::open(root.join("config.toml"), root.join("proxy-certs"))
                .expect("proxy core"),
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
                host_ip: "0.0.0.0".into(),
            }],
            ips: vec!["10.0.0.25".into()],
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

        let (backend, runtime_events) = TestRuntimeBackend::controlled(vec![instance.clone()]);
        runtime
            .start_with_backend(cancel.clone(), backend)
            .await
            .expect("runtime provider startup and initial reconciliation");

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

        let started = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let inventory = runtime.list_instances().await.expect("runtime inventory");
                let mdns_present = mdns
                    .admin_registrations()
                    .iter()
                    .any(|(_, registration)| registration.name == service_name);
                let dns_present = dns.resolve_local(&service_name, RecordType::A).is_some();
                let health_present = health
                    .status()
                    .services
                    .iter()
                    .any(|check| check.name == health_name);
                let proxy_present = proxy
                    .status()
                    .proxies
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
        .await;
        assert!(
            started.is_ok(),
            "synthetic start must derive inventory, mDNS, DNS, health, and proxy state; mdns={:?}, dns={:?}, health={:?}, proxy={:?}",
            mdns.admin_registrations(),
            dns.resolve_local(&service_name, RecordType::A).is_some(),
            health.status().services,
            proxy.status().proxies,
        );

        let proxy_status = proxy
            .status()
            .proxies
            .iter()
            .find(|entry| entry.name == service_name)
            .cloned()
            .expect("derived proxy status");
        assert_eq!(proxy_status.cert_source, "self-signed");
        assert!(proxy_status.error.is_none());
        assert_eq!(
            proxy_status.backend,
            format!("http://127.0.0.1:{backend_port}")
        );
        assert!(
            dns.catalog_snapshot().entries.is_empty(),
            "Runtime DNS projection must not become operator state"
        );
        assert!(
            !health_state.exists()
                || !std::fs::read_to_string(&health_state)
                    .expect("read health state")
                    .contains(&health_name),
            "Runtime health projection must not be persisted"
        );

        // A terminal source transition retains the inventory as diagnostic
        // history, but that history must not remain live network desire. This
        // is distinct from Waiting, where an adapter is reconnecting and the
        // last reconciled inventory intentionally stays actionable.
        runtime_events
            .send(RuntimeEvent::BackendStopped {
                backend: "synthetic".into(),
            })
            .expect("runtime source retirement");
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let inventory_retained = runtime
                    .list_instances()
                    .await
                    .expect("runtime inventory")
                    .iter()
                    .any(|entry| entry.id == instance_id);
                let mdns_absent = mdns
                    .admin_registrations()
                    .iter()
                    .all(|(_, registration)| registration.name != service_name);
                let dns_absent = dns.resolve_local(&service_name, RecordType::A).is_none();
                let health_absent = health
                    .status()
                    .services
                    .iter()
                    .all(|check| check.name != health_name);
                let proxy_absent = proxy
                    .status()
                    .proxies
                    .iter()
                    .all(|entry| entry.name != service_name);
                if inventory_retained && mdns_absent && dns_absent && health_absent && proxy_absent
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("source stop must retire every derived network resource");

        runtime_events
            .send(RuntimeEvent::BackendReconnected {
                backend: "synthetic".into(),
            })
            .expect("runtime source reconstruction");
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let mdns_present = mdns
                    .admin_registrations()
                    .iter()
                    .any(|(_, registration)| registration.name == service_name);
                let dns_present = dns.resolve_local(&service_name, RecordType::A).is_some();
                let health_present = health
                    .status()
                    .services
                    .iter()
                    .any(|check| check.name == health_name);
                let proxy_present = proxy
                    .status()
                    .proxies
                    .iter()
                    .any(|entry| entry.name == service_name && entry.state == "running");
                if mdns_present && dns_present && health_present && proxy_present {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("source recovery must reconstruct derived network resources");

        runtime_events
            .send(RuntimeEvent::Stopped {
                id: instance.id,
                name: instance.name,
            })
            .expect("runtime instance retirement");

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
                let dns_absent = dns.resolve_local(&service_name, RecordType::A).is_none();
                let health_absent = health
                    .status()
                    .services
                    .iter()
                    .all(|check| check.name != health_name);
                let proxy_absent = proxy
                    .status()
                    .proxies
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
        runtime.shutdown().await.expect("Runtime shutdown");
        proxy.shutdown().await.expect("Proxy shutdown");
        health.shutdown().await;
        dns.shutdown().await;
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
