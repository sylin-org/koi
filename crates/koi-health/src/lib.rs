//! Koi Health - network health monitoring (Phase 7).

mod checker;
pub mod http;
mod log;
mod machine;
mod service;
mod state;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use futures_util::FutureExt;
use tokio::sync::{broadcast, oneshot, watch, Mutex, Notify};
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;

use koi_common::integration::{
    CertmeshRosterSnapshot, CertmeshSnapshot, DnsProbe, MdnsDiscoverySnapshot, MdnsSnapshot,
    ProxyEntriesSnapshot, ProxyEntrySummary, ProxySnapshot,
};
use koi_common::status::StatusFeed;

use crate::checker::{
    is_due, run_checks_loop, run_checks_once, ProbeResult, ProbeTicket, ServiceCheckState,
};
use crate::machine::collect_machine_health;
use crate::state::{load_health_state, save_health_state, HealthCheckConfig, HealthChecksState};
use crate::state::{DEFAULT_INTERVAL_SECS, DEFAULT_TIMEOUT_SECS};

pub use machine::MachineHealth;
pub use service::ServiceCheckKind;
pub use service::ServiceStatus;
pub use service::ServiceStatus as HealthStatus;
pub use state::HealthCheckConfig as HealthCheck;

/// Default machine health threshold (seconds since last seen).
pub const DEFAULT_MACHINE_THRESHOLD_SECS: u64 = 60;

/// Health owns deadline transitions even while active probing is disarmed.
const OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);

const HEALTH_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IN_FLIGHT_LIFECYCLE_COMMANDS: usize = 32;

/// Events emitted by the health subsystem when service status changes.
#[derive(Debug, Clone)]
pub enum HealthEvent {
    /// A service's health status changed.
    StatusChanged { name: String, status: ServiceStatus },
}

/// Snapshot returned by health status queries.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct HealthSnapshot {
    /// Monotonic snapshot revision. It advances only for a semantic change.
    #[serde(default)]
    pub revision: u64,
    /// Whether the periodic service-probe loop is armed.
    #[serde(default)]
    pub running: bool,
    pub machines: Vec<MachineHealth>,
    pub services: Vec<ServiceHealth>,
}

/// Durable health-transition history returned by the Health query boundary.
///
/// Entries retain the stable line-oriented representation written by Health;
/// callers never receive or reconstruct the backing persistence path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct HealthTransitionLog {
    pub entries: String,
}

/// Service health summary (config + current status).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ServiceHealth {
    pub name: String,
    pub kind: ServiceCheckKind,
    pub target: String,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub status: ServiceStatus,
    pub last_checked: Option<DateTime<Utc>>,
    pub last_ok: Option<DateTime<Utc>>,
    pub message: Option<String>,
}

/// Errors surfaced by the health domain.
#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("invalid health check: {0}")]
    InvalidCheck(String),

    #[error("health check not found: {0}")]
    NotFound(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("health runtime has already shut down")]
    ShutDown,

    #[error("health lifecycle worker stopped unexpectedly: {0}")]
    Worker(String),
}

/// Owner of a process-local health-check desired-set projection.
///
/// Scoped checks are derived observations rather than operator configuration.
/// They are never persisted, are replaced as a complete set, and lose a name
/// collision to an explicitly configured operator check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HealthCheckScope {
    Runtime,
}

/// Default timeout for the shared HTTP client used by health checks.
const HTTP_CLIENT_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
struct EffectiveCheck {
    config: HealthCheckConfig,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionedServiceState {
    generation: u64,
    state: ServiceCheckState,
}

/// Health's authoritative mutable model.
///
/// This entire value sits behind one mutex. Configuration persistence, model
/// acceptance, immutable status publication, and semantic event emission all
/// cross that one boundary in order; adapters never lock its individual parts.
struct HealthModel {
    /// Durable operator configuration.
    checks: Vec<HealthCheckConfig>,
    /// Process-local complete desired sets from explicitly wired producers.
    scoped_checks: BTreeMap<HealthCheckScope, Vec<HealthCheckConfig>>,
    effective_checks: BTreeMap<String, EffectiveCheck>,
    service_states: HashMap<String, VersionedServiceState>,
    mdns_revision: Option<u64>,
    mdns_hosts: HashMap<String, MdnsHostObservation>,
    certmesh: Option<Arc<CertmeshRosterSnapshot>>,
    proxy_revision: Option<u64>,
    proxy_entries: Vec<ProxyEntrySummary>,
    next_generation: u64,
}

#[derive(Debug, Clone, Copy)]
struct MdnsHostObservation {
    address: std::net::IpAddr,
    observed_at: Instant,
}

impl HealthModel {
    fn new(
        checks: Vec<HealthCheckConfig>,
        mdns: Option<Arc<MdnsDiscoverySnapshot>>,
        certmesh: Option<Arc<CertmeshRosterSnapshot>>,
        proxy: Option<Arc<ProxyEntriesSnapshot>>,
        observed_at: Instant,
    ) -> Self {
        let mut model = Self {
            checks,
            scoped_checks: BTreeMap::new(),
            effective_checks: BTreeMap::new(),
            service_states: HashMap::new(),
            mdns_revision: None,
            mdns_hosts: HashMap::new(),
            certmesh: None,
            proxy_revision: None,
            proxy_entries: Vec::new(),
            next_generation: 0,
        };
        model.accept_mdns(mdns, observed_at);
        model.accept_certmesh(certmesh);
        model.accept_proxy(proxy);
        model.reconcile_effective_checks();
        model
    }

    fn allocate_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.saturating_add(1);
        self.next_generation
    }

    fn reconcile_effective_checks(&mut self) {
        let mut desired = BTreeMap::new();
        for check in &self.checks {
            desired.insert(check.name.clone(), check.clone());
        }
        // Explicit operator configuration wins. Scoped producers are ordered
        // deterministically and cannot silently replace either operator state
        // or an earlier scoped owner.
        for checks in self.scoped_checks.values() {
            for check in checks {
                desired
                    .entry(check.name.clone())
                    .or_insert_with(|| check.clone());
            }
        }
        // An explicitly configured check wins a name collision with a derived
        // proxy check. Scoped inputs win over this implicit cross-domain view.
        // This gives every displayed name exactly one identity.
        for check in proxy_checks(&self.proxy_entries) {
            desired.entry(check.name.clone()).or_insert(check);
        }

        let mut previous = std::mem::take(&mut self.effective_checks);
        let mut next = BTreeMap::new();
        for (name, config) in desired {
            if let Some(existing) = previous.remove(&name) {
                if existing.config == config {
                    next.insert(name, existing);
                    continue;
                }
            }

            self.service_states.remove(&name);
            let generation = self.allocate_generation();
            next.insert(name, EffectiveCheck { config, generation });
        }
        for name in previous.keys() {
            self.service_states.remove(name);
        }
        self.effective_checks = next;
    }

    fn accept_mdns(&mut self, next: Option<Arc<MdnsDiscoverySnapshot>>, observed_at: Instant) {
        let Some(next) = next else {
            return;
        };
        if self
            .mdns_revision
            .is_some_and(|current| current >= next.revision)
        {
            return;
        }

        let next_hosts = next.host_ips();
        self.mdns_hosts
            .retain(|hostname, _| next_hosts.contains_key(hostname));
        for (hostname, address) in next_hosts {
            let unchanged = self
                .mdns_hosts
                .get(&hostname)
                .is_some_and(|current| current.address == address);
            if !unchanged {
                self.mdns_hosts.insert(
                    hostname,
                    MdnsHostObservation {
                        address,
                        observed_at,
                    },
                );
            }
        }
        self.mdns_revision = Some(next.revision);
    }

    fn accept_certmesh(&mut self, next: Option<Arc<CertmeshRosterSnapshot>>) {
        let Some(next) = next else {
            return;
        };
        if self
            .certmesh
            .as_ref()
            .is_some_and(|current| current.revision >= next.revision)
        {
            return;
        }
        self.certmesh = Some(next);
    }

    fn accept_proxy(&mut self, next: Option<Arc<ProxyEntriesSnapshot>>) {
        let Some(next) = next else {
            return;
        };
        if self
            .proxy_revision
            .is_some_and(|current| current >= next.revision)
        {
            return;
        }
        self.proxy_revision = Some(next.revision);
        self.proxy_entries.clone_from(&next.entries);
    }

    fn probe_tickets(&self) -> Vec<ProbeTicket> {
        self.effective_checks
            .values()
            .filter_map(|effective| {
                let baseline = self
                    .service_states
                    .get(&effective.config.name)
                    .filter(|state| state.generation == effective.generation)
                    .map(|state| state.state.clone());
                is_due(&effective.config, baseline.as_ref()).then(|| ProbeTicket {
                    check: effective.config.clone(),
                    generation: effective.generation,
                    baseline,
                })
            })
            .collect()
    }
}

/// Durable resources owned by one Health domain instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPaths {
    state: PathBuf,
    transition_log: PathBuf,
}

impl HealthPaths {
    pub fn new(state: PathBuf, transition_log: PathBuf) -> Self {
        Self {
            state,
            transition_log,
        }
    }
}

struct HealthDomain {
    model: Mutex<HealthModel>,
    paths: HealthPaths,
    // Keep integration owners alive for as long as their watch receivers are
    // part of this domain. Status construction never rereads these ports.
    _mdns_source: Option<Arc<dyn MdnsSnapshot>>,
    dns: Option<Arc<dyn DnsProbe>>,
    _certmesh_source: Option<Arc<dyn CertmeshSnapshot>>,
    _proxy_source: Option<Arc<dyn ProxySnapshot>>,
    machine_threshold: Duration,
    running: AtomicBool,
    event_tx: broadcast::Sender<HealthEvent>,
    status: StatusFeed<HealthSnapshot>,
}

impl HealthDomain {
    fn publish_locked(&self, model: &HealthModel) -> Arc<HealthSnapshot> {
        let mut next = build_snapshot(
            model,
            self.dns.as_ref(),
            self.machine_threshold,
            self.running.load(Ordering::Acquire),
        );
        self.status.update(move |current| {
            // Runtime liveness is synchronously writable from Drop. Read it
            // inside the atomic status transaction so a concurrent model
            // publication cannot restore a stale running bit.
            next.running = self.running.load(Ordering::Acquire);
            next.revision = current.revision;
            if &next == current {
                return None;
            }
            next.revision = current.revision.saturating_add(1);
            Some(next)
        })
    }

    async fn refresh_observed(
        &self,
        mdns: Option<Arc<MdnsDiscoverySnapshot>>,
        certmesh: Option<Arc<CertmeshRosterSnapshot>>,
        proxy: Option<Arc<ProxyEntriesSnapshot>>,
        observed_at: Instant,
    ) {
        let mut model = self.model.lock().await;
        model.accept_mdns(mdns, observed_at);
        model.accept_certmesh(certmesh);
        model.accept_proxy(proxy);
        model.reconcile_effective_checks();
        self.publish_locked(&model);
    }

    async fn refresh_current(&self) {
        let model = self.model.lock().await;
        self.publish_locked(&model);
    }

    fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::Release);
        self.status.update(|current| {
            (current.running != running).then(|| {
                let mut next = current.clone();
                next.revision = current.revision.saturating_add(1);
                next.running = running;
                next
            })
        });
    }

    async fn list_checks(&self) -> Vec<HealthCheckConfig> {
        self.model.lock().await.checks.clone()
    }

    async fn add_check(&self, check: HealthCheckConfig) -> Result<(), HealthError> {
        service::validate_check(&check).map_err(HealthError::InvalidCheck)?;

        let mut model = self.model.lock().await;
        if model
            .checks
            .iter()
            .any(|existing| existing.name == check.name)
        {
            return Err(HealthError::InvalidCheck(format!(
                "check already exists: {}",
                check.name
            )));
        }

        let mut next_checks = model.checks.clone();
        next_checks.push(check);
        save_health_state(
            &self.paths.state,
            &HealthChecksState {
                checks: next_checks.clone(),
            },
        )
        .map_err(|error| state_error("write", &self.paths.state, error))?;

        model.checks = next_checks;
        model.reconcile_effective_checks();
        self.publish_locked(&model);
        Ok(())
    }

    async fn remove_check(&self, name: &str) -> Result<(), HealthError> {
        let mut model = self.model.lock().await;
        if !model.checks.iter().any(|check| check.name == name) {
            return Err(HealthError::NotFound(name.to_string()));
        }
        let next_checks = model
            .checks
            .iter()
            .filter(|check| check.name != name)
            .cloned()
            .collect::<Vec<_>>();
        save_health_state(
            &self.paths.state,
            &HealthChecksState {
                checks: next_checks.clone(),
            },
        )
        .map_err(|error| state_error("write", &self.paths.state, error))?;

        model.checks = next_checks;
        model.reconcile_effective_checks();
        self.publish_locked(&model);
        Ok(())
    }

    async fn replace_scoped_checks(
        &self,
        scope: HealthCheckScope,
        mut checks: Vec<HealthCheckConfig>,
    ) -> Result<(), HealthError> {
        for check in &checks {
            service::validate_check(check).map_err(HealthError::InvalidCheck)?;
        }
        checks.sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(pair) = checks.windows(2).find(|pair| pair[0].name == pair[1].name) {
            return Err(HealthError::InvalidCheck(format!(
                "duplicate scoped check: {}",
                pair[0].name
            )));
        }

        let mut model = self.model.lock().await;
        if model.scoped_checks.get(&scope) == Some(&checks) {
            return Ok(());
        }
        if checks.is_empty() {
            model.scoped_checks.remove(&scope);
        } else {
            model.scoped_checks.insert(scope, checks);
        }
        model.reconcile_effective_checks();
        self.publish_locked(&model);
        Ok(())
    }

    async fn prepare_probe_tickets(&self) -> Vec<ProbeTicket> {
        let model = self.model.lock().await;
        self.publish_locked(&model);
        model.probe_tickets()
    }

    async fn accept_probe_results(&self, results: Vec<ProbeResult>) {
        let mut model = self.model.lock().await;
        // A reactive Proxy update can replace this check while network I/O is
        // in flight; the generation carried by each ticket is the acceptance CAS.
        model.reconcile_effective_checks();
        let mut events = Vec::new();

        for result in results {
            let name = result.ticket.check.name.clone();
            let still_current = model.effective_checks.get(&name).is_some_and(|effective| {
                effective.generation == result.ticket.generation
                    && effective.config == result.ticket.check
            });
            if !still_current {
                continue;
            }

            let current = model
                .service_states
                .get(&name)
                .filter(|state| state.generation == result.ticket.generation)
                .map(|state| state.state.clone());
            if current != result.ticket.baseline {
                // Another overlapping probe already committed against this
                // baseline. Its newer observation remains authoritative.
                continue;
            }

            let previous = current.unwrap_or_default();
            let mut next = previous.clone();
            next.status = result.outcome.status;
            next.last_checked = Some(result.completed_at);
            next.message = result.outcome.message;
            if next.status == ServiceStatus::Up {
                next.last_ok = Some(result.completed_at);
            }

            if previous.status != next.status {
                let reason = next
                    .message
                    .clone()
                    .unwrap_or_else(|| "status_change".to_string());
                if let Err(error) = crate::log::append_transition(
                    &self.paths.transition_log,
                    &name,
                    previous.status,
                    next.status,
                    &reason,
                ) {
                    tracing::warn!(%error, check = %name, "failed to write health transition");
                }
                events.push(HealthEvent::StatusChanged {
                    name: name.clone(),
                    status: next.status,
                });
            }

            model.service_states.insert(
                name,
                VersionedServiceState {
                    generation: result.ticket.generation,
                    state: next,
                },
            );
        }

        // State precedes events. Keep the model gate through broadcast so a
        // subscriber's immediate status reread sees this revision or newer.
        self.publish_locked(&model);
        for event in events {
            let _ = self.event_tx.send(event);
        }
    }
}

/// Core health facade.
pub struct HealthCore {
    domain: Arc<HealthDomain>,
    started_at: Instant,
    http_client: reqwest::Client,
    observer_cancel: CancellationToken,
    infrastructure: Mutex<HealthInfrastructure>,
}

struct HealthInfrastructure {
    observer: Option<JoinHandle<()>>,
}

impl HealthCore {
    /// Open the Health domain against its explicitly composed durable resources.
    pub async fn open(
        paths: HealthPaths,
        mdns: Option<Arc<dyn MdnsSnapshot>>,
        dns: Option<Arc<dyn DnsProbe>>,
        certmesh: Option<Arc<dyn CertmeshSnapshot>>,
        proxy: Option<Arc<dyn ProxySnapshot>>,
    ) -> Result<Self, HealthError> {
        Self::with_settings(
            mdns,
            dns,
            certmesh,
            proxy,
            paths,
            Duration::from_secs(DEFAULT_MACHINE_THRESHOLD_SECS),
            OBSERVATION_INTERVAL,
        )
        .await
    }

    async fn with_settings(
        mdns: Option<Arc<dyn MdnsSnapshot>>,
        dns: Option<Arc<dyn DnsProbe>>,
        certmesh: Option<Arc<dyn CertmeshSnapshot>>,
        proxy: Option<Arc<dyn ProxySnapshot>>,
        paths: HealthPaths,
        machine_threshold: Duration,
        observation_interval: Duration,
    ) -> Result<Self, HealthError> {
        let state = load_health_state(&paths.state)
            .map_err(|error| state_error("read", &paths.state, error))?;
        validate_persisted_checks(&state.checks)?;

        // Subscribe first and seed from the receiver's current value. A change
        // racing construction is therefore either in the seed or pending on the
        // same latest-value receiver; there is no snapshot/subscription gap.
        let mut mdns_rx = mdns.as_ref().map(|source| source.watch_snapshot());
        let mut certmesh_rx = certmesh.as_ref().map(|source| source.watch_snapshot());
        let mut proxy_rx = proxy.as_ref().map(|source| source.watch_snapshot());
        let initial_mdns = mdns_rx.as_ref().map(|receiver| receiver.borrow().clone());
        let initial_certmesh = certmesh_rx
            .as_ref()
            .map(|receiver| receiver.borrow().clone());
        let initial_proxy = proxy_rx.as_ref().map(|receiver| receiver.borrow().clone());
        let model = HealthModel::new(
            state.checks,
            initial_mdns,
            initial_certmesh,
            initial_proxy,
            Instant::now(),
        );
        let initial_status = build_snapshot(&model, dns.as_ref(), machine_threshold, false);
        let (event_tx, _) = koi_common::events::event_channel();
        let domain = Arc::new(HealthDomain {
            model: Mutex::new(model),
            paths,
            _mdns_source: mdns,
            dns,
            _certmesh_source: certmesh,
            _proxy_source: proxy,
            machine_threshold,
            running: AtomicBool::new(false),
            event_tx,
            status: StatusFeed::new(initial_status),
        });

        let observer_cancel = CancellationToken::new();
        let observer = spawn_observation_loop(
            Arc::downgrade(&domain),
            mdns_rx.take(),
            certmesh_rx.take(),
            proxy_rx.take(),
            observer_cancel.clone(),
            observation_interval,
        );

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(HTTP_CLIENT_TIMEOUT_SECS))
            .build()
            .unwrap_or_default();
        Ok(Self {
            domain,
            started_at: Instant::now(),
            http_client,
            observer_cancel,
            infrastructure: Mutex::new(HealthInfrastructure {
                observer: Some(observer),
            }),
        })
    }

    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    /// Current immutable health status. This is a constant-time `Arc` clone
    /// with no I/O or async locking.
    pub fn status(&self) -> Arc<HealthSnapshot> {
        self.domain.status.current()
    }

    /// Subscribe to coalesced health status transitions.
    pub fn watch_status(&self) -> watch::Receiver<Arc<HealthSnapshot>> {
        self.domain.status.subscribe()
    }

    pub async fn list_checks(&self) -> Vec<HealthCheckConfig> {
        self.domain.list_checks().await
    }

    /// Read the durable transition history owned by this Health instance.
    pub async fn transition_log(&self) -> Result<HealthTransitionLog, HealthError> {
        let entries = log::read_log(&self.domain.paths.transition_log)
            .await
            .map_err(|error| state_error("read", &self.domain.paths.transition_log, error))?;
        Ok(HealthTransitionLog { entries })
    }

    pub async fn add_check(&self, check: HealthCheckConfig) -> Result<(), HealthError> {
        self.domain.add_check(check).await
    }

    pub async fn remove_check(&self, name: &str) -> Result<(), HealthError> {
        self.domain.remove_check(name).await
    }

    /// Atomically replace one transient producer's complete desired check set.
    pub async fn replace_scoped_checks(
        &self,
        scope: HealthCheckScope,
        checks: Vec<HealthCheckConfig>,
    ) -> Result<(), HealthError> {
        self.domain.replace_scoped_checks(scope, checks).await
    }

    /// Validate one prospective transient check without mutating the accepted
    /// desired set.
    pub fn validate_scoped_check(check: &HealthCheckConfig) -> Result<(), HealthError> {
        service::validate_check(check).map_err(HealthError::InvalidCheck)
    }

    pub async fn run_checks_once(&self) {
        run_checks_once(self).await;
    }

    pub fn subscribe(&self) -> broadcast::Receiver<HealthEvent> {
        self.domain.event_tx.subscribe()
    }

    pub(crate) async fn prepare_probe_tickets(&self) -> Vec<ProbeTicket> {
        self.domain.prepare_probe_tickets().await
    }

    pub(crate) async fn accept_probe_results(&self, results: Vec<ProbeResult>) {
        self.domain.accept_probe_results(results).await;
    }

    fn set_running(&self, running: bool) {
        self.domain.set_running(running);
    }

    /// Reap Health's input/deadline observer as part of runtime shutdown.
    async fn shutdown_until(&self, deadline: tokio::time::Instant) {
        // Signal before waiting for the ownership gate so the retained terminal
        // transaction starts making progress immediately.
        self.observer_cancel.cancel();
        let mut infrastructure = self.infrastructure.lock().await;
        if let Some(observer) = infrastructure.observer.as_mut() {
            if let Err(error) = finish_task_until(observer, deadline).await {
                if !error.is_cancelled() {
                    tracing::warn!(%error, "Health observation task failed during shutdown");
                }
            }
            infrastructure.observer = None;
        }
    }

    fn fail_close(&self) {
        self.observer_cancel.cancel();
        if let Ok(mut infrastructure) = self.infrastructure.try_lock() {
            if let Some(observer) = infrastructure.observer.take() {
                observer.abort();
            }
        }
    }
}

impl Drop for HealthCore {
    fn drop(&mut self) {
        self.observer_cancel.cancel();
        let infrastructure = self.infrastructure.get_mut();
        if let Some(observer) = &infrastructure.observer {
            observer.abort();
        }
    }
}

fn proxy_checks(entries: &[ProxyEntrySummary]) -> Vec<HealthCheckConfig> {
    entries
        .iter()
        .cloned()
        .map(|entry| HealthCheckConfig {
            name: format!("proxy:{}", entry.name),
            kind: ServiceCheckKind::Http,
            target: if entry.backend.contains("://") {
                entry.backend
            } else {
                format!("http://{}", entry.backend)
            },
            interval_secs: DEFAULT_INTERVAL_SECS,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        })
        .collect()
}

fn build_snapshot(
    model: &HealthModel,
    dns: Option<&Arc<dyn DnsProbe>>,
    machine_threshold: Duration,
    running: bool,
) -> HealthSnapshot {
    // One time sample makes every machine in this immutable projection agree
    // at threshold and certificate-expiry boundaries.
    let observed_at = Instant::now();
    let observed_utc = Utc::now();
    let mdns_hosts = model
        .mdns_hosts
        .iter()
        .map(|(hostname, observation)| (hostname.clone(), observation.observed_at))
        .collect::<HashMap<_, _>>();
    let machines = collect_machine_health(
        &mdns_hosts,
        dns,
        model.certmesh.as_deref(),
        machine_threshold,
        observed_at,
        observed_utc,
    );
    let services = model
        .effective_checks
        .values()
        .map(|effective| {
            let state = model
                .service_states
                .get(&effective.config.name)
                .filter(|state| state.generation == effective.generation)
                .map(|state| state.state.clone())
                .unwrap_or_default();
            ServiceHealth {
                name: effective.config.name.clone(),
                kind: effective.config.kind,
                target: effective.config.target.clone(),
                interval_secs: effective.config.interval_secs,
                timeout_secs: effective.config.timeout_secs,
                status: state.status,
                last_checked: state.last_checked,
                last_ok: state.last_ok,
                message: state.message,
            }
        })
        .collect();
    HealthSnapshot {
        revision: 0,
        running,
        machines,
        services,
    }
}

fn validate_persisted_checks(checks: &[HealthCheckConfig]) -> Result<(), HealthError> {
    let mut names = HashSet::new();
    for check in checks {
        service::validate_check(check).map_err(|error| {
            HealthError::InvalidCheck(format!("persisted check '{}': {error}", check.name))
        })?;
        if !names.insert(check.name.clone()) {
            return Err(HealthError::InvalidCheck(format!(
                "duplicate persisted check: {}",
                check.name
            )));
        }
    }
    Ok(())
}

fn state_error(operation: &str, path: &std::path::Path, error: std::io::Error) -> HealthError {
    HealthError::Io(format!("failed to {operation} {}: {error}", path.display()))
}

fn spawn_observation_loop(
    domain: Weak<HealthDomain>,
    mut mdns_rx: Option<watch::Receiver<Arc<MdnsDiscoverySnapshot>>>,
    mut certmesh_rx: Option<watch::Receiver<Arc<CertmeshRosterSnapshot>>>,
    mut proxy_rx: Option<watch::Receiver<Arc<ProxyEntriesSnapshot>>>,
    cancel: CancellationToken,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Construction already seeded a truthful snapshot. Consume Tokio's
        // immediate first tick so this loop observes at the configured cadence;
        // mDNS changes still arrive immediately through their watch branch.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = async {
                    mdns_rx
                        .as_mut()
                        .expect("mDNS receiver branch is guarded")
                        .changed()
                        .await
                }, if mdns_rx.is_some() => {
                    if changed.is_err() {
                        mdns_rx = None;
                        continue;
                    }
                    let snapshot = mdns_rx
                        .as_mut()
                        .expect("mDNS receiver remains available")
                        .borrow_and_update()
                        .clone();
                    let Some(domain) = domain.upgrade() else { break; };
                    domain
                        .refresh_observed(Some(snapshot), None, None, Instant::now())
                        .await;
                }
                changed = async {
                    certmesh_rx
                        .as_mut()
                        .expect("Certmesh receiver branch is guarded")
                        .changed()
                        .await
                }, if certmesh_rx.is_some() => {
                    if changed.is_err() {
                        certmesh_rx = None;
                        continue;
                    }
                    let snapshot = certmesh_rx
                        .as_mut()
                        .expect("Certmesh receiver remains available")
                        .borrow_and_update()
                        .clone();
                    let Some(domain) = domain.upgrade() else { break; };
                    domain
                        .refresh_observed(None, Some(snapshot), None, Instant::now())
                        .await;
                }
                changed = async {
                    proxy_rx
                        .as_mut()
                        .expect("Proxy receiver branch is guarded")
                        .changed()
                        .await
                }, if proxy_rx.is_some() => {
                    if changed.is_err() {
                        proxy_rx = None;
                        continue;
                    }
                    let snapshot = proxy_rx
                        .as_mut()
                        .expect("Proxy receiver remains available")
                        .borrow_and_update()
                        .clone();
                    let Some(domain) = domain.upgrade() else { break; };
                    domain
                        .refresh_observed(None, None, Some(snapshot), Instant::now())
                        .await;
                }
                _ = ticker.tick() => {
                    let Some(domain) = domain.upgrade() else { break; };
                    domain.refresh_current().await;
                }
            }
        }
    })
}

struct ActiveHealthLoop {
    generation: u64,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct HealthLifecycle {
    generation: u64,
    active: Option<ActiveHealthLoop>,
    shutting_down: bool,
}

/// Bounded owner for restartable lifecycle commands and the one terminal
/// transaction. Requesters own only reply waiters; admitted work retains the
/// runtime through settlement. Terminal election closes future admission and
/// publishes one shared completion to all shutdown callers.
struct HealthLifecycleTasks {
    tasks: std::sync::Mutex<Vec<JoinHandle<()>>>,
    admission: Arc<HealthLifecycleAdmission>,
    terminal: Arc<HealthTerminalState>,
}

struct HealthLifecycleAdmissionState {
    accepting: bool,
    in_flight: usize,
}

struct HealthLifecycleAdmission {
    capacity: Arc<tokio::sync::Semaphore>,
    state: std::sync::Mutex<HealthLifecycleAdmissionState>,
    idle: Notify,
}

struct HealthLifecyclePermit {
    admission: Arc<HealthLifecycleAdmission>,
    _capacity: tokio::sync::OwnedSemaphorePermit,
}

struct HealthTerminalState {
    outcome: std::sync::Mutex<Option<Option<String>>>,
    shutdown_changed: Notify,
}

impl HealthLifecycleTasks {
    fn new() -> Self {
        Self {
            tasks: std::sync::Mutex::new(Vec::new()),
            admission: Arc::new(HealthLifecycleAdmission {
                capacity: Arc::new(tokio::sync::Semaphore::new(
                    MAX_IN_FLIGHT_LIFECYCLE_COMMANDS,
                )),
                state: std::sync::Mutex::new(HealthLifecycleAdmissionState {
                    accepting: true,
                    in_flight: 0,
                }),
                idle: Notify::new(),
            }),
            terminal: Arc::new(HealthTerminalState {
                outcome: std::sync::Mutex::new(None),
                shutdown_changed: Notify::new(),
            }),
        }
    }

    async fn admit(&self) -> Option<HealthLifecyclePermit> {
        self.admission.clone().admit().await
    }

    fn begin_shutdown(&self) -> bool {
        self.admission.begin_shutdown()
    }

    fn is_shutting_down(&self) -> bool {
        self.admission.is_shutting_down()
    }

    fn retain(&self, task: JoinHandle<()>) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    fn abort_all(&self) {
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

impl HealthLifecycleAdmission {
    async fn admit(self: Arc<Self>) -> Option<HealthLifecyclePermit> {
        if !self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepting
        {
            return None;
        }
        let capacity = Arc::clone(&self.capacity).acquire_owned().await.ok()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.accepting {
            return None;
        }
        state.in_flight = state.in_flight.saturating_add(1);
        drop(state);
        Some(HealthLifecyclePermit {
            admission: self,
            _capacity: capacity,
        })
    }

    fn begin_shutdown(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.accepting {
            return false;
        }
        state.accepting = false;
        self.capacity.close();
        if state.in_flight == 0 {
            self.idle.notify_waiters();
        }
        true
    }

    fn is_shutting_down(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepting
    }

    async fn wait_idle(&self) {
        loop {
            let idle = self.idle.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .in_flight
                == 0
            {
                return;
            }
            idle.await;
        }
    }
}

impl Drop for HealthLifecyclePermit {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        if !state.accepting && state.in_flight == 0 {
            self.admission.idle.notify_waiters();
        }
    }
}

impl HealthTerminalState {
    fn finish(&self, failure: Option<String>) {
        let mut outcome = self
            .outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if outcome.is_none() {
            *outcome = Some(failure);
            drop(outcome);
            self.shutdown_changed.notify_waiters();
        }
    }

    async fn wait(&self) -> Option<String> {
        loop {
            let changed = self.shutdown_changed.notified();
            if let Some(outcome) = self
                .outcome
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
            {
                return outcome;
            }
            changed.await;
        }
    }
}

impl Drop for HealthLifecycleTasks {
    fn drop(&mut self) {
        self.abort_all();
    }
}

struct HealthRuntimeInner {
    core: Arc<HealthCore>,
    lifecycle: Mutex<HealthLifecycle>,
    generation_fence: AtomicU64,
    terminal_cancel: CancellationToken,
    #[cfg(test)]
    panic_next_stop: AtomicBool,
    #[cfg(test)]
    panic_next_shutdown: AtomicBool,
}

/// Runtime controller for active service probes.
///
/// Machine/input/deadline status observation is domain infrastructure and stays
/// live independently; this controller arms only real HTTP/TCP probe work.
#[derive(Clone)]
pub struct HealthRuntime {
    inner: Arc<HealthRuntimeInner>,
    lifecycle_tasks: Arc<HealthLifecycleTasks>,
}

impl HealthRuntime {
    pub fn new(core: Arc<HealthCore>) -> Self {
        let terminal_cancel = CancellationToken::new();
        Self {
            inner: Arc::new(HealthRuntimeInner {
                core,
                lifecycle: Mutex::new(HealthLifecycle::default()),
                generation_fence: AtomicU64::new(0),
                terminal_cancel,
                #[cfg(test)]
                panic_next_stop: AtomicBool::new(false),
                #[cfg(test)]
                panic_next_shutdown: AtomicBool::new(false),
            }),
            lifecycle_tasks: Arc::new(HealthLifecycleTasks::new()),
        }
    }

    pub fn core(&self) -> Arc<HealthCore> {
        Arc::clone(&self.inner.core)
    }

    pub async fn start(&self) -> Result<bool, HealthError> {
        let mut lifecycle = self.inner.lifecycle.lock().await;
        if lifecycle.shutting_down || self.lifecycle_tasks.is_shutting_down() {
            return Err(HealthError::ShutDown);
        }
        if lifecycle
            .active
            .as_ref()
            .is_some_and(|active| active.task.is_finished() || active.cancel.is_cancelled())
        {
            Self::reap_active_locked(
                &mut lifecycle,
                tokio::time::Instant::now() + HEALTH_STOP_TIMEOUT,
            )
            .await;
        }
        if lifecycle.active.is_some() {
            return Ok(false);
        }

        lifecycle.generation = lifecycle.generation.wrapping_add(1);
        let generation = lifecycle.generation;
        let cancel = self.inner.terminal_cancel.child_token();
        let loop_cancel = cancel.clone();
        let core = Arc::clone(&self.inner.core);
        let inner = Arc::downgrade(&self.inner);

        self.inner
            .generation_fence
            .store(generation, Ordering::Release);
        // This publication and task admission are synchronous after acquiring
        // the lifecycle gate, so caller cancellation cannot split them.
        core.set_running(true);
        let task = tokio::spawn(async move {
            let outcome = AssertUnwindSafe(run_checks_loop(Arc::clone(&core), loop_cancel))
                .catch_unwind()
                .await;
            if outcome.is_err() {
                tracing::error!(generation, "health check loop panicked");
            }
            if inner
                .upgrade()
                .is_none_or(|inner| inner.generation_fence.load(Ordering::Acquire) == generation)
            {
                core.set_running(false);
            }
        });

        lifecycle.active = Some(ActiveHealthLoop {
            generation,
            cancel,
            task,
        });
        Ok(true)
    }

    /// Disarm active probes and acknowledge release of their owned generation.
    ///
    /// `Ok(false)` is reserved for an accepted command that found probes
    /// already stopped. Closed admission or loss of the retained command owner
    /// is an error, never a successful no-op.
    pub async fn stop(&self) -> Result<bool, HealthError> {
        self.stop_with_timeout(HEALTH_STOP_TIMEOUT).await
    }

    async fn stop_with_timeout(&self, timeout: Duration) -> Result<bool, HealthError> {
        let Some(permit) = self.lifecycle_tasks.admit().await else {
            return Err(HealthError::ShutDown);
        };
        let (result_tx, result_rx) = oneshot::channel();
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            let _permit = permit;
            #[cfg(test)]
            if inner.panic_next_stop.swap(false, Ordering::AcqRel) {
                panic!("injected Health stop worker panic");
            }
            let result = Self::stop_owned(inner, timeout).await;
            let _ = result_tx.send(result);
        });
        self.lifecycle_tasks.retain(task);
        result_rx
            .await
            .map_err(|_| HealthError::Worker("stop ended before acknowledgement".into()))
    }

    async fn stop_owned(inner: Arc<HealthRuntimeInner>, timeout: Duration) -> bool {
        let mut lifecycle = inner.lifecycle.lock().await;
        if lifecycle.active.is_none() {
            return false;
        }
        Self::retire_active_locked(
            &inner,
            &mut lifecycle,
            tokio::time::Instant::now() + timeout,
        )
        .await;
        true
    }

    /// Permanently stop probes and reap Health's observation infrastructure.
    /// This terminal boundary is bounded and idempotent. Once admitted, a
    /// runtime-owned worker completes it even if the caller stops waiting.
    /// [`Self::stop`] remains restartable.
    pub async fn shutdown(&self) {
        self.shutdown_with_timeout(HEALTH_STOP_TIMEOUT).await;
    }

    async fn shutdown_with_timeout(&self, timeout: Duration) {
        if self.lifecycle_tasks.begin_shutdown() {
            // Election, cancellation, spawn, and retention contain no await;
            // the caller owns only the shared completion waiter from here.
            self.inner.core.observer_cancel.cancel();
            self.inner.terminal_cancel.cancel();
            let inner = Arc::clone(&self.inner);
            let admission = Arc::clone(&self.lifecycle_tasks.admission);
            let terminal = Arc::clone(&self.lifecycle_tasks.terminal);
            let worker = tokio::spawn(async move {
                let completion =
                    HealthTerminalCompletion::new(Arc::clone(&inner), Arc::clone(&terminal));
                admission.wait_idle().await;
                #[cfg(test)]
                if inner.panic_next_shutdown.swap(false, Ordering::AcqRel) {
                    panic!("injected Health terminal-shutdown panic");
                }
                let failure = AssertUnwindSafe(Self::shutdown_owned(&inner, timeout))
                    .catch_unwind()
                    .await
                    .err()
                    .map(|_| "Health terminal worker panicked".to_string());
                completion.settle(failure);
            });
            self.lifecycle_tasks.retain(worker);
        }
        if let Some(error) = self.lifecycle_tasks.terminal.wait().await {
            tracing::error!(%error, "Health shutdown completed with a terminal worker failure");
        }
    }

    async fn shutdown_owned(inner: &HealthRuntimeInner, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        {
            let mut lifecycle = inner.lifecycle.lock().await;
            lifecycle.shutting_down = true;
            if lifecycle.active.is_some() {
                Self::retire_active_locked(inner, &mut lifecycle, deadline).await;
            } else {
                inner.core.set_running(false);
            }
        }
        inner.core.shutdown_until(deadline).await;
    }

    async fn retire_active_locked(
        inner: &HealthRuntimeInner,
        lifecycle: &mut HealthLifecycle,
        deadline: tokio::time::Instant,
    ) {
        lifecycle.generation = lifecycle.generation.wrapping_add(1);
        inner
            .generation_fence
            .store(lifecycle.generation, Ordering::Release);
        if let Some(active) = lifecycle.active.as_ref() {
            active.cancel.cancel();
        }
        Self::reap_active_locked(lifecycle, deadline).await;
        inner.core.set_running(false);
    }

    async fn reap_active_locked(lifecycle: &mut HealthLifecycle, deadline: tokio::time::Instant) {
        let Some(active) = lifecycle.active.as_mut() else {
            return;
        };
        let generation = active.generation;
        if let Err(error) = finish_task_until(&mut active.task, deadline).await {
            if !error.is_cancelled() {
                tracing::warn!(%error, generation, "Health probe task failed during shutdown");
            }
        }
        lifecycle.active = None;
    }

    pub fn status(&self) -> Arc<HealthSnapshot> {
        self.inner.core.status()
    }

    pub fn watch_status(&self) -> watch::Receiver<Arc<HealthSnapshot>> {
        self.inner.core.watch_status()
    }

    /// Return durable operator-managed checks through the runtime boundary.
    pub async fn list_checks(&self) -> Vec<HealthCheckConfig> {
        self.inner.core.list_checks().await
    }

    pub async fn transition_log(&self) -> Result<HealthTransitionLog, HealthError> {
        self.inner.core.transition_log().await
    }

    /// Persist one operator-managed check through the runtime boundary.
    pub async fn add_check(&self, check: HealthCheckConfig) -> Result<(), HealthError> {
        self.inner.core.add_check(check).await
    }

    /// Remove one operator-managed check through the runtime boundary.
    pub async fn remove_check(&self, name: &str) -> Result<(), HealthError> {
        self.inner.core.remove_check(name).await
    }

    /// Atomically replace one transient producer's complete desired check set.
    pub async fn replace_scoped_checks(
        &self,
        scope: HealthCheckScope,
        checks: Vec<HealthCheckConfig>,
    ) -> Result<(), HealthError> {
        self.inner.core.replace_scoped_checks(scope, checks).await
    }

    /// Validate one prospective transient check without mutating the accepted
    /// desired set.
    pub fn validate_scoped_check(check: &HealthCheckConfig) -> Result<(), HealthError> {
        HealthCore::validate_scoped_check(check)
    }

    /// Subscribe to Health's semantic transition stream without piercing the
    /// runtime facade to reach its core.
    pub fn subscribe(&self) -> broadcast::Receiver<HealthEvent> {
        self.inner.core.subscribe()
    }
}

struct HealthTerminalCompletion {
    inner: Arc<HealthRuntimeInner>,
    terminal: Arc<HealthTerminalState>,
    settled: bool,
}

impl HealthTerminalCompletion {
    fn new(inner: Arc<HealthRuntimeInner>, terminal: Arc<HealthTerminalState>) -> Self {
        Self {
            inner,
            terminal,
            settled: false,
        }
    }

    fn settle(mut self, failure: Option<String>) {
        if failure.is_some() {
            self.inner.fail_close();
        }
        self.terminal.finish(failure);
        self.settled = true;
    }
}

impl Drop for HealthTerminalCompletion {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        self.inner.fail_close();
        self.terminal.finish(Some(
            "Health terminal worker stopped unexpectedly; resources were fail-closed".to_string(),
        ));
    }
}

impl HealthRuntimeInner {
    fn fail_close(&self) {
        self.terminal_cancel.cancel();
        self.generation_fence.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut lifecycle) = self.lifecycle.try_lock() {
            lifecycle.shutting_down = true;
            if let Some(active) = lifecycle.active.take() {
                active.cancel.cancel();
                active.task.abort();
            }
        }
        self.core.fail_close();
        self.core.set_running(false);
    }
}

impl Drop for HealthRuntime {
    fn drop(&mut self) {
        if Arc::strong_count(&self.lifecycle_tasks) == 1 {
            self.lifecycle_tasks.begin_shutdown();
            self.inner.fail_close();
            self.lifecycle_tasks.abort_all();
        }
    }
}

impl Drop for HealthRuntimeInner {
    fn drop(&mut self) {
        self.terminal_cancel.cancel();
        self.generation_fence.fetch_add(1, Ordering::AcqRel);
        self.core.set_running(false);
        let lifecycle = self.lifecycle.get_mut();
        if let Some(active) = lifecycle.active.as_mut() {
            active.cancel.cancel();
            active.task.abort();
        }
    }
}

async fn finish_task_until(
    task: &mut JoinHandle<()>,
    deadline: tokio::time::Instant,
) -> Result<(), JoinError> {
    if task.is_finished() {
        return (&mut *task).await;
    }
    match tokio::time::timeout_at(deadline, &mut *task).await {
        Ok(result) => result,
        Err(_) => {
            task.abort();
            (&mut *task).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::integration::{MemberSummary, ProxyEntrySummary};
    use koi_common::types::ServiceRecord;
    use std::future::pending;
    use std::net::SocketAddr;
    use tokio::task::JoinHandle;

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn test_state_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "koi-health-{label}-{}",
                koi_common::id::generate_short_id()
            ))
            .join("health.json")
    }

    fn test_log_path(label: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "koi-health-{label}-{}",
                koi_common::id::generate_short_id()
            ))
            .join("health.log")
    }

    async fn test_core(label: &str) -> HealthCore {
        HealthCore::open(
            HealthPaths::new(test_state_path(label), test_log_path(label)),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("health core")
    }

    fn check(name: &str, kind: ServiceCheckKind, target: impl Into<String>) -> HealthCheckConfig {
        HealthCheckConfig {
            name: name.to_string(),
            kind,
            target: target.into(),
            interval_secs: 30,
            timeout_secs: 1,
        }
    }

    #[tokio::test]
    async fn runtime_scope_is_complete_transient_and_operator_names_win() {
        let path = test_state_path("runtime-scope");
        let core = HealthCore::open(
            HealthPaths::new(path.clone(), path.with_extension("log")),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("health core");
        let runtime_checks = vec![
            check("zeta", ServiceCheckKind::Tcp, "127.0.0.1:2"),
            check("alpha", ServiceCheckKind::Tcp, "127.0.0.1:1"),
        ];
        core.replace_scoped_checks(HealthCheckScope::Runtime, runtime_checks.clone())
            .await
            .expect("runtime desired set");

        assert!(
            core.list_checks().await.is_empty(),
            "runtime checks are not operator state"
        );
        assert_eq!(
            core.status()
                .services
                .iter()
                .map(|service| service.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );

        let accepted = core.status();
        let mut reordered = runtime_checks;
        reordered.reverse();
        core.replace_scoped_checks(HealthCheckScope::Runtime, reordered)
            .await
            .expect("idempotent reorder");
        assert!(Arc::ptr_eq(&accepted, &core.status()));

        core.add_check(check("alpha", ServiceCheckKind::Tcp, "127.0.0.1:9"))
            .await
            .expect("operator check");
        assert_eq!(
            core.status()
                .services
                .iter()
                .find(|service| service.name == "alpha")
                .expect("alpha status")
                .target,
            "127.0.0.1:9"
        );
        core.remove_check("alpha")
            .await
            .expect("remove operator check");
        assert_eq!(
            core.status()
                .services
                .iter()
                .find(|service| service.name == "alpha")
                .expect("runtime alpha restored")
                .target,
            "127.0.0.1:1"
        );

        core.replace_scoped_checks(HealthCheckScope::Runtime, Vec::new())
            .await
            .expect("clear complete runtime set");
        assert!(core.status().services.is_empty());
        drop(core);

        let reopened = HealthCore::open(
            HealthPaths::new(path.clone(), path.with_extension("log")),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("reopen health core");
        assert!(reopened.list_checks().await.is_empty());
        assert!(reopened.status().services.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn invalid_runtime_replacement_preserves_the_last_accepted_set() {
        let core = test_core("invalid-runtime-scope").await;
        core.replace_scoped_checks(
            HealthCheckScope::Runtime,
            vec![check("good", ServiceCheckKind::Tcp, "127.0.0.1:1")],
        )
        .await
        .expect("initial runtime set");
        let accepted = core.status();
        let mut invalid = check("bad", ServiceCheckKind::Tcp, "127.0.0.1:2");
        invalid.interval_secs = 0;

        assert!(core
            .replace_scoped_checks(HealthCheckScope::Runtime, vec![invalid])
            .await
            .is_err());
        assert!(Arc::ptr_eq(&accepted, &core.status()));
        assert_eq!(core.status().services[0].name, "good");
    }

    struct MutableProxySnapshot {
        feed: StatusFeed<ProxyEntriesSnapshot>,
    }

    impl MutableProxySnapshot {
        fn new(entries: Vec<ProxyEntrySummary>) -> Self {
            Self {
                feed: StatusFeed::new(ProxyEntriesSnapshot {
                    revision: 0,
                    entries,
                }),
            }
        }

        fn replace(&self, entries: Vec<ProxyEntrySummary>) {
            self.feed.update(move |current| {
                (current.entries != entries).then_some(ProxyEntriesSnapshot {
                    revision: current.revision.saturating_add(1),
                    entries,
                })
            });
        }
    }

    impl ProxySnapshot for MutableProxySnapshot {
        fn snapshot(&self) -> Arc<ProxyEntriesSnapshot> {
            self.feed.current()
        }

        fn watch_snapshot(&self) -> watch::Receiver<Arc<ProxyEntriesSnapshot>> {
            self.feed.subscribe()
        }
    }

    struct MutableMdnsSnapshot {
        feed: StatusFeed<MdnsDiscoverySnapshot>,
    }

    impl MutableMdnsSnapshot {
        fn new(hostname: &str) -> Self {
            Self {
                feed: StatusFeed::new(discovery_snapshot(0, hostname)),
            }
        }

        fn replace_host(&self, hostname: &str) {
            let hostname = hostname.to_string();
            self.feed.update(move |current| {
                Some(discovery_snapshot(
                    current.revision.saturating_add(1),
                    &hostname,
                ))
            });
        }
    }

    impl MdnsSnapshot for MutableMdnsSnapshot {
        fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot> {
            self.feed.current()
        }

        fn watch_snapshot(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>> {
            self.feed.subscribe()
        }
    }

    fn discovery_snapshot(revision: u64, hostname: &str) -> MdnsDiscoverySnapshot {
        discovery_snapshot_with_hosts(revision, &[(hostname, "10.0.0.10")])
    }

    fn discovery_snapshot_with_hosts(
        revision: u64,
        hosts: &[(&str, &str)],
    ) -> MdnsDiscoverySnapshot {
        MdnsDiscoverySnapshot {
            revision,
            service_types: vec!["_http._tcp.local.".to_string()],
            records: hosts
                .iter()
                .map(|(hostname, address)| ServiceRecord {
                    name: format!("{hostname}-http"),
                    service_type: "_http._tcp.local.".to_string(),
                    host: Some(format!("{hostname}.local.")),
                    ip: Some((*address).to_string()),
                    port: Some(80),
                    txt: HashMap::new(),
                })
                .collect(),
            sources: Vec::new(),
            observations: Vec::new(),
        }
    }

    struct MutableCertmeshSnapshot {
        feed: StatusFeed<CertmeshRosterSnapshot>,
    }

    impl MutableCertmeshSnapshot {
        fn new(members: Vec<MemberSummary>) -> Self {
            Self {
                feed: StatusFeed::new(CertmeshRosterSnapshot {
                    revision: 0,
                    active_members: members,
                }),
            }
        }

        fn replace_members(&self, members: Vec<MemberSummary>) {
            self.feed.update(move |current| {
                Some(CertmeshRosterSnapshot {
                    revision: current.revision.saturating_add(1),
                    active_members: members,
                })
            });
        }
    }

    impl CertmeshSnapshot for MutableCertmeshSnapshot {
        fn snapshot(&self) -> Arc<CertmeshRosterSnapshot> {
            self.feed.current()
        }

        fn watch_snapshot(&self) -> watch::Receiver<Arc<CertmeshRosterSnapshot>> {
            self.feed.subscribe()
        }
    }

    fn member(hostname: &str, last_seen: Option<DateTime<Utc>>) -> MemberSummary {
        MemberSummary {
            hostname: hostname.to_string(),
            sans: Vec::new(),
            cert_expires: None,
            last_seen,
            status: "active".to_string(),
            proxy_entries: Vec::new(),
        }
    }

    async fn hanging_http_server() -> (
        SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<()>,
        JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener");
        let address = listener.local_addr().expect("listener address");
        let (accepted_tx, accepted_rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                let _ = accepted_tx.send(());
                held.push(stream);
            }
        });
        (address, accepted_rx, task)
    }

    #[test]
    fn health_snapshot_round_trips_with_revision_and_lifecycle() {
        let snapshot = HealthSnapshot {
            revision: 9,
            running: true,
            machines: Vec::new(),
            services: Vec::new(),
        };

        let json = serde_json::to_value(&snapshot).expect("serialize health status");
        let decoded: HealthSnapshot =
            serde_json::from_value(json).expect("deserialize health status");
        assert_eq!(decoded, snapshot);
    }

    #[tokio::test]
    async fn proxy_checks_normalize_bare_backends_to_http_urls() {
        let entries = vec![
            ProxyEntrySummary {
                name: "bare".to_string(),
                listen_port: 8443,
                backend: "127.0.0.1:3000".to_string(),
            },
            ProxyEntrySummary {
                name: "url".to_string(),
                listen_port: 9443,
                backend: "https://localhost:3001/healthz".to_string(),
            },
        ];

        let checks = proxy_checks(&entries);
        assert_eq!(checks[0].target, "http://127.0.0.1:3000");
        assert_eq!(checks[1].target, "https://localhost:3001/healthz");
        assert!(checks
            .iter()
            .all(|check| service::validate_check(check).is_ok()));
    }

    #[tokio::test]
    async fn proxy_entries_converge_reactively_and_equal_input_is_a_noop() {
        let first = ProxyEntrySummary {
            name: "api".to_string(),
            listen_port: 8443,
            backend: "127.0.0.1:3000".to_string(),
        };
        let proxy = Arc::new(MutableProxySnapshot::new(vec![first.clone()]));
        let proxy_port: Arc<dyn ProxySnapshot> = proxy.clone();
        let core = HealthCore::open(
            HealthPaths::new(
                test_state_path("proxy-reactive"),
                test_log_path("proxy-reactive"),
            ),
            None,
            None,
            None,
            Some(proxy_port),
        )
        .await
        .expect("health core");
        assert_eq!(core.status().services[0].target, "http://127.0.0.1:3000");

        let mut status_rx = core.watch_status();
        proxy.replace(vec![ProxyEntrySummary {
            backend: "127.0.0.1:4000".to_string(),
            ..first.clone()
        }]);
        tokio::time::timeout(Duration::from_secs(1), status_rx.changed())
            .await
            .expect("reactive Proxy propagation")
            .expect("health status feed open");
        let changed = status_rx.borrow_and_update().clone();
        assert_eq!(changed.services[0].target, "http://127.0.0.1:4000");

        let revision = changed.revision;
        proxy.replace(vec![ProxyEntrySummary {
            backend: "127.0.0.1:4000".to_string(),
            ..first
        }]);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), status_rx.changed())
                .await
                .is_err()
        );
        assert_eq!(core.status().revision, revision);

        proxy.replace(Vec::new());
        tokio::time::timeout(Duration::from_secs(1), status_rx.changed())
            .await
            .expect("Proxy removal propagation")
            .expect("health status feed open");
        assert!(status_rx.borrow_and_update().services.is_empty());
        core.shutdown_until(tokio::time::Instant::now() + HEALTH_STOP_TIMEOUT)
            .await;
    }

    #[tokio::test]
    async fn initial_status_is_seeded_from_persistence_and_mdns_watch() {
        let path = test_state_path("initial");
        let persisted = check("seeded", ServiceCheckKind::Tcp, "127.0.0.1:1");
        save_health_state(
            &path,
            &HealthChecksState {
                checks: vec![persisted],
            },
        )
        .expect("seed state");
        let mdns = Arc::new(MutableMdnsSnapshot::new("seed-host"));
        let mdns_port: Arc<dyn MdnsSnapshot> = mdns;

        let core = HealthCore::open(
            HealthPaths::new(path.clone(), path.with_extension("log")),
            Some(mdns_port),
            None,
            None,
            None,
        )
        .await
        .expect("health core");
        let status = core.status();

        assert_eq!(status.revision, 0);
        assert!(status
            .services
            .iter()
            .any(|service| service.name == "seeded"));
        assert!(status
            .machines
            .iter()
            .any(|machine| machine.hostname == "seed-host"));
    }

    #[tokio::test]
    async fn mdns_watch_updates_health_without_probe_runtime_or_poll_delay() {
        let mdns = Arc::new(MutableMdnsSnapshot::new("first-host"));
        let mdns_port: Arc<dyn MdnsSnapshot> = mdns.clone();
        let core = HealthCore::with_settings(
            Some(mdns_port),
            None,
            None,
            None,
            HealthPaths::new(test_state_path("mdns-watch"), test_log_path("mdns-watch")),
            Duration::from_secs(DEFAULT_MACHINE_THRESHOLD_SECS),
            Duration::from_secs(60),
        )
        .await
        .expect("health core");
        let before = core.status();
        assert_eq!(before.machines.len(), 1);
        let mut status_rx = core.watch_status();

        mdns.replace_host("second-host");
        tokio::time::timeout(Duration::from_secs(2), status_rx.changed())
            .await
            .expect("direct mDNS watch propagation")
            .expect("health status feed open");
        let status = status_rx.borrow_and_update().clone();
        assert!(!status.running);
        assert!(status.revision > before.revision);
        assert_eq!(status.machines.len(), 1);
        assert!(status
            .machines
            .iter()
            .any(|machine| machine.hostname == "second-host"));
        assert!(status
            .machines
            .iter()
            .all(|machine| machine.hostname != "first-host"));
    }

    #[tokio::test]
    async fn same_count_certmesh_replacement_updates_health_without_poll_delay() {
        let certmesh = Arc::new(MutableCertmeshSnapshot::new(vec![member(
            "first-member",
            None,
        )]));
        let certmesh_port: Arc<dyn CertmeshSnapshot> = certmesh.clone();
        let core = HealthCore::with_settings(
            None,
            None,
            Some(certmesh_port),
            None,
            HealthPaths::new(
                test_state_path("certmesh-watch"),
                test_log_path("certmesh-watch"),
            ),
            Duration::from_secs(DEFAULT_MACHINE_THRESHOLD_SECS),
            Duration::from_secs(60),
        )
        .await
        .expect("health core");
        let before = core.status();
        assert_eq!(before.machines.len(), 1);
        let mut status_rx = core.watch_status();

        certmesh.replace_members(vec![member("second-member", None)]);
        tokio::time::timeout(Duration::from_secs(2), status_rx.changed())
            .await
            .expect("direct Certmesh watch propagation")
            .expect("health status feed open");
        let status = status_rx.borrow_and_update().clone();
        assert!(status.revision > before.revision);
        assert_eq!(status.machines.len(), 1);
        assert_eq!(status.machines[0].hostname, "second-member");
    }

    #[test]
    fn mdns_recency_changes_only_for_the_host_observation_that_changed() {
        let first_observation = Instant::now();
        let mut model = HealthModel::new(
            Vec::new(),
            Some(Arc::new(discovery_snapshot_with_hosts(
                1,
                &[("stable", "10.0.0.10"), ("changed", "10.0.0.11")],
            ))),
            None,
            None,
            first_observation,
        );
        let second_observation = first_observation + Duration::from_secs(10);

        model.accept_mdns(
            Some(Arc::new(discovery_snapshot_with_hosts(
                2,
                &[("stable", "10.0.0.10"), ("changed", "10.0.0.12")],
            ))),
            second_observation,
        );

        assert_eq!(
            model.mdns_hosts["stable"].observed_at, first_observation,
            "an unrelated snapshot revision must not fabricate a fresh sighting"
        );
        assert_eq!(
            model.mdns_hosts["changed"].observed_at, second_observation,
            "a changed host projection is a newly accepted observation"
        );
    }

    #[tokio::test]
    async fn time_owned_machine_transition_publishes_while_probes_are_stopped() {
        let certmesh: Arc<dyn CertmeshSnapshot> =
            Arc::new(MutableCertmeshSnapshot::new(vec![member(
                "aging-member",
                Some(Utc::now()),
            )]));
        let core = HealthCore::with_settings(
            None,
            None,
            Some(certmesh),
            None,
            HealthPaths::new(
                test_state_path("time-transition"),
                test_log_path("time-transition"),
            ),
            Duration::from_secs(1),
            Duration::from_millis(50),
        )
        .await
        .expect("health core");
        assert_eq!(core.status().machines[0].status, ServiceStatus::Up);
        let mut status_rx = core.watch_status();

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                status_rx.changed().await.expect("health status feed open");
                if status_rx.borrow_and_update().machines[0].status == ServiceStatus::Down {
                    break;
                }
            }
        })
        .await
        .expect("time-derived transition");
        assert!(!core.status().running);
    }

    #[tokio::test]
    async fn transition_log_query_uses_only_the_domain_owned_path() {
        let selected = test_log_path("owned-transition-log");
        let foreign = test_log_path("foreign-transition-log");
        log::append_transition(
            &selected,
            "selected",
            ServiceStatus::Unknown,
            ServiceStatus::Up,
            "reachable",
        )
        .expect("append selected transition");
        log::append_transition(
            &foreign,
            "foreign",
            ServiceStatus::Unknown,
            ServiceStatus::Down,
            "unreachable",
        )
        .expect("append foreign transition");
        let core = HealthCore::open(
            HealthPaths::new(test_state_path("owned-transition-log"), selected.clone()),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("health core");

        let history = core.transition_log().await.expect("transition history");

        assert!(history.entries.contains("selected"));
        assert!(!history.entries.contains("foreign"));
        if let Some(parent) = selected.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
        if let Some(parent) = foreign.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[tokio::test]
    async fn status_feed_tracks_durable_mutations_and_rejected_noops() {
        let core = test_core("status-feed").await;
        let first = core.status();
        assert!(Arc::ptr_eq(&first, &core.status()));
        let mut status_rx = core.watch_status();
        let candidate = check("status", ServiceCheckKind::Tcp, "127.0.0.1:1");

        core.add_check(candidate.clone()).await.expect("add check");
        status_rx.changed().await.expect("add status");
        let added = status_rx.borrow_and_update().clone();
        assert!(added.revision > first.revision);
        assert!(added
            .services
            .iter()
            .any(|service| service.name == "status"));

        assert!(core.add_check(candidate).await.is_err());
        assert_eq!(core.status().revision, added.revision);
        assert!(!status_rx.has_changed().expect("status feed open"));

        core.remove_check("status").await.expect("remove check");
        status_rx.changed().await.expect("remove status");
        let removed = status_rx.borrow_and_update().clone();
        assert!(removed.revision > added.revision);
        assert!(removed.services.is_empty());
    }

    #[tokio::test]
    async fn failed_persistence_changes_neither_model_nor_status() {
        let blocker = std::env::temp_dir().join(format!(
            "koi-health-state-blocker-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::write(&blocker, b"not a directory").expect("path blocker");
        let core = HealthCore::open(
            HealthPaths::new(blocker.join("health.json"), blocker.join("health.log")),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("missing state file still constructs");
        let before = core.status();
        let status_rx = core.watch_status();

        let error = core
            .add_check(check("never", ServiceCheckKind::Tcp, "127.0.0.1:1"))
            .await
            .expect_err("write must fail");
        assert!(matches!(error, HealthError::Io(_)));
        assert!(core.list_checks().await.is_empty());
        assert!(Arc::ptr_eq(&before, &core.status()));
        assert!(!status_rx.has_changed().expect("status feed open"));
    }

    #[tokio::test]
    async fn corrupt_persistence_fails_construction_instead_of_becoming_empty() {
        let path = test_state_path("corrupt");
        std::fs::create_dir_all(path.parent().expect("state parent")).unwrap();
        std::fs::write(&path, b"{broken").unwrap();

        let result = HealthCore::open(
            HealthPaths::new(path.clone(), path.with_extension("log")),
            None,
            None,
            None,
            None,
        )
        .await;
        assert!(matches!(result, Err(HealthError::Io(_))));
    }

    #[tokio::test]
    async fn concurrent_config_commands_preserve_both_durable_updates() {
        let path = test_state_path("concurrent-config");
        let core = Arc::new(
            HealthCore::open(
                HealthPaths::new(path.clone(), path.with_extension("log")),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("health core"),
        );
        let left = {
            let core = Arc::clone(&core);
            tokio::spawn(async move {
                core.add_check(check("left", ServiceCheckKind::Tcp, "127.0.0.1:1"))
                    .await
            })
        };
        let right = {
            let core = Arc::clone(&core);
            tokio::spawn(async move {
                core.add_check(check("right", ServiceCheckKind::Tcp, "127.0.0.1:2"))
                    .await
            })
        };
        left.await.unwrap().expect("left add");
        right.await.unwrap().expect("right add");

        let durable = load_health_state(&path).expect("durable health state");
        assert_eq!(durable.checks.len(), 2);
        assert_eq!(core.status().services.len(), 2);
    }

    #[tokio::test]
    async fn stale_probe_cannot_mutate_a_replacement_check() {
        let (address, mut accepted, server) = hanging_http_server().await;
        let core = Arc::new(test_core("stale-probe").await);
        core.add_check(check(
            "replace-me",
            ServiceCheckKind::Http,
            format!("http://{address}/"),
        ))
        .await
        .expect("old check");
        let mut events = core.subscribe();
        let run = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.run_checks_once().await })
        };
        tokio::time::timeout(Duration::from_secs(2), accepted.recv())
            .await
            .expect("old probe started")
            .expect("accept signal");

        core.remove_check("replace-me").await.expect("remove old");
        core.add_check(check("replace-me", ServiceCheckKind::Tcp, "127.0.0.1:1"))
            .await
            .expect("replacement check");
        tokio::time::timeout(Duration::from_secs(3), run)
            .await
            .expect("old probe completed")
            .expect("probe task");

        let service = core
            .status()
            .services
            .iter()
            .find(|service| service.name == "replace-me")
            .cloned()
            .expect("replacement status");
        assert_eq!(service.kind, ServiceCheckKind::Tcp);
        assert_eq!(service.target, "127.0.0.1:1");
        assert_eq!(service.status, ServiceStatus::Unknown);
        assert!(service.last_checked.is_none());
        assert!(events.try_recv().is_err());
        server.abort();
    }

    #[tokio::test]
    async fn overlapping_probes_accept_exactly_one_result_for_a_baseline() {
        let (address, mut accepted, server) = hanging_http_server().await;
        let core = Arc::new(test_core("overlapping-probes").await);
        core.add_check(check(
            "overlap",
            ServiceCheckKind::Http,
            format!("http://{address}/"),
        ))
        .await
        .expect("check");
        let before = core.status().revision;
        let mut events = core.subscribe();
        let first = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.run_checks_once().await })
        };
        let second = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.run_checks_once().await })
        };
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), accepted.recv())
                .await
                .expect("probe started")
                .expect("accept signal");
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            first.await.expect("first probe task");
            second.await.expect("second probe task");
        })
        .await
        .expect("probes complete");

        assert_eq!(core.status().revision, before.saturating_add(1));
        assert_eq!(core.status().services[0].status, ServiceStatus::Down);
        assert!(events.try_recv().is_ok());
        assert!(events.try_recv().is_err());
        server.abort();
    }

    #[tokio::test]
    async fn event_subscriber_rereads_committed_status_or_newer() {
        let core = Arc::new(test_core("event-order").await);
        let runtime = HealthRuntime::new(Arc::clone(&core));
        core.add_check(check("event", ServiceCheckKind::Tcp, "127.0.0.1:1"))
            .await
            .expect("check");
        let before = core.status().revision;
        let mut events = runtime.subscribe();

        core.run_checks_once().await;
        let HealthEvent::StatusChanged { name, status } = events.try_recv().expect("status event");
        let current = core.status();
        let service = current
            .services
            .iter()
            .find(|service| service.name == name)
            .expect("event state in status");
        assert!(current.revision > before);
        assert_eq!(service.status, status);
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn runtime_lifecycle_is_revisioned_and_duplicate_start_is_a_noop() {
        let core = Arc::new(test_core("runtime").await);
        let runtime = HealthRuntime::new(core);
        let mut status_rx = runtime.watch_status();
        assert!(!runtime.status().running);

        assert!(runtime.start().await.expect("start runtime"));
        status_rx.changed().await.expect("running status");
        let running = status_rx.borrow_and_update().clone();
        assert!(running.running);
        assert!(!runtime.start().await.expect("duplicate start"));
        assert_eq!(runtime.status().revision, running.revision);

        assert!(runtime.stop().await.expect("stop Health"));
        status_rx.changed().await.expect("stopped status");
        assert!(!status_rx.borrow_and_update().running);

        assert!(runtime.start().await.expect("restart runtime"));
        assert!(runtime.status().running);
        runtime.shutdown().await;
        assert!(!runtime.status().running);
        assert!(matches!(runtime.start().await, Err(HealthError::ShutDown)));
        assert!(runtime.inner.lifecycle.lock().await.active.is_none());
        assert!(runtime
            .inner
            .core
            .infrastructure
            .lock()
            .await
            .observer
            .is_none());
    }

    #[tokio::test]
    async fn stop_reserves_false_for_an_accepted_already_stopped_command() {
        let core = Arc::new(test_core("stop-noop").await);
        let runtime = HealthRuntime::new(core);

        assert!(!runtime.stop().await.expect("accepted Health no-op"));

        runtime.shutdown().await;
        assert!(matches!(runtime.stop().await, Err(HealthError::ShutDown)));
    }

    #[tokio::test]
    async fn stop_surfaces_a_lost_owned_worker_acknowledgement() {
        let core = Arc::new(test_core("stop-worker-loss").await);
        let runtime = HealthRuntime::new(core);
        runtime.inner.panic_next_stop.store(true, Ordering::Release);

        let error = runtime
            .stop()
            .await
            .expect_err("lost Health owner must not look already stopped");
        assert!(matches!(
            error,
            HealthError::Worker(detail) if detail.contains("before acknowledgement")
        ));

        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_stop_converges_without_retry_and_remains_restartable() {
        let core = Arc::new(test_core("cancelled-stop").await);
        let runtime = HealthRuntime::new(core);
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let cancel = CancellationToken::new();
        let cancel_observer = cancel.clone();
        let task = tokio::spawn(async move {
            let _drop = DropFlag(task_dropped);
            pending::<()>().await;
        });
        tokio::task::yield_now().await;
        {
            let mut lifecycle = runtime.inner.lifecycle.lock().await;
            lifecycle.generation = 1;
            runtime.inner.generation_fence.store(1, Ordering::Release);
            lifecycle.active = Some(ActiveHealthLoop {
                generation: 1,
                cancel,
                task,
            });
        }
        runtime.inner.core.set_running(true);

        let requester_runtime = runtime.clone();
        let requester = tokio::spawn(async move {
            requester_runtime
                .stop_with_timeout(Duration::from_millis(50))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancel_observer.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned stop did not reach probe cancellation");
        requester.abort();
        let _ = requester.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if runtime.inner.lifecycle.lock().await.active.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned stop did not finish after requester cancellation");
        assert!(dropped.load(Ordering::SeqCst));
        assert!(!runtime.status().running);
        assert!(runtime.start().await.expect("restart after completed stop"));
        assert!(runtime.stop().await.expect("stop Health"));
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_terminal_shutdown_converges_without_retry() {
        let (address, mut accepted, server) = hanging_http_server().await;
        let core = Arc::new(test_core("cancelled-shutdown").await);
        core.add_check(HealthCheckConfig {
            timeout_secs: 30,
            ..check(
                "blocked",
                ServiceCheckKind::Http,
                format!("http://{address}"),
            )
        })
        .await
        .expect("check");
        let runtime = HealthRuntime::new(Arc::clone(&core));
        assert!(runtime.start().await.expect("start runtime"));
        tokio::time::timeout(Duration::from_secs(2), accepted.recv())
            .await
            .expect("probe began")
            .expect("accept signal");

        let requester_runtime = runtime.clone();
        let shutdown = tokio::spawn(async move {
            requester_runtime
                .shutdown_with_timeout(Duration::from_millis(50))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !runtime.inner.terminal_cancel.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal cancellation was not admitted");
        shutdown.abort();
        let _ = shutdown.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let active_reaped = runtime.inner.lifecycle.lock().await.active.is_none();
                let observer_reaped = runtime
                    .inner
                    .core
                    .infrastructure
                    .lock()
                    .await
                    .observer
                    .is_none();
                if active_reaped && observer_reaped {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned terminal shutdown did not fully reap Health");
        assert!(!runtime.status().running);
        assert!(matches!(runtime.start().await, Err(HealthError::ShutDown)));
        server.abort();
    }

    #[tokio::test]
    async fn panicked_terminal_owner_fail_closes_and_settles_waiters() {
        let core = Arc::new(test_core("panicked-shutdown").await);
        let runtime = Arc::new(HealthRuntime::new(Arc::clone(&core)));
        assert!(runtime.start().await.expect("start runtime"));
        runtime
            .inner
            .panic_next_shutdown
            .store(true, Ordering::Release);

        let first = {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.shutdown().await })
        };
        let second = {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.shutdown().await })
        };
        tokio::time::timeout(Duration::from_secs(2), first)
            .await
            .expect("first terminal waiter was stranded")
            .expect("first waiter task should not panic");
        tokio::time::timeout(Duration::from_secs(2), second)
            .await
            .expect("second terminal waiter was stranded")
            .expect("second waiter task should not panic");

        let failure = runtime
            .lifecycle_tasks
            .terminal
            .wait()
            .await
            .expect("terminal panic should be observable");
        assert!(failure.contains("stopped unexpectedly"));
        assert!(!core.status().running);
        assert!(runtime.inner.lifecycle.lock().await.active.is_none());
        assert!(core.infrastructure.lock().await.observer.is_none());
        assert!(matches!(runtime.start().await, Err(HealthError::ShutDown)));
    }

    #[tokio::test]
    async fn last_facade_drop_breaks_an_admitted_stop_owner_chain() {
        let core = Arc::new(test_core("last-owner-stop").await);
        let runtime = HealthRuntime::new(core);
        let inner = Arc::downgrade(&runtime.inner);
        let active_dropped = Arc::new(AtomicBool::new(false));
        let active_drop = Arc::clone(&active_dropped);
        let cancel = CancellationToken::new();
        let cancel_observer = cancel.clone();
        let active = tokio::spawn(async move {
            let _drop = DropFlag(active_drop);
            pending::<()>().await;
        });
        {
            let mut lifecycle = runtime.inner.lifecycle.lock().await;
            lifecycle.active = Some(ActiveHealthLoop {
                generation: 1,
                cancel,
                task: active,
            });
        }

        let stopping =
            tokio::spawn(async move { runtime.stop_with_timeout(Duration::from_secs(30)).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancel_observer.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("admitted stop did not reach probe cancellation");
        stopping.abort();
        let _ = stopping.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            while inner.upgrade().is_some() || !active_dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained command formed a last-owner cycle");
    }

    #[tokio::test]
    async fn dropping_last_runtime_handle_cancels_its_probe_loop() {
        let core = Arc::new(test_core("runtime-drop").await);
        let runtime = HealthRuntime::new(Arc::clone(&core));
        assert!(runtime.start().await.expect("start runtime"));
        assert!(core.status().running);

        drop(runtime);
        assert!(!core.status().running);
    }
}
