//! Koi Health - network health monitoring (Phase 7).

mod checker;
pub mod http;
pub mod log;
mod machine;
mod service;
mod state;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, RwLock};

use koi_common::capability::{Capability, CapabilityStatus};
use koi_common::integration::{CertmeshSnapshot, DnsProbe, MdnsSnapshot, ProxySnapshot};
use koi_common::runtime_state::DomainRuntime;

use crate::checker::{run_checks_loop, run_checks_once, ServiceCheckState};
use crate::machine::{collect_machine_health, MdnsTracker};
use crate::state::{load_health_state, save_health_state, HealthCheckConfig, HealthChecksState};
use crate::state::{DEFAULT_INTERVAL_SECS, DEFAULT_TIMEOUT_SECS};

pub use machine::MachineHealth;
pub use service::ServiceCheckKind;
pub use service::ServiceStatus;
pub use service::ServiceStatus as HealthStatus;
pub use state::HealthCheckConfig as HealthCheck;

/// Default machine health threshold (seconds since last seen).
pub const DEFAULT_MACHINE_THRESHOLD_SECS: u64 = 60;

/// Events emitted by the health subsystem when service status changes.
#[derive(Debug, Clone)]
pub enum HealthEvent {
    /// A service's health status changed.
    StatusChanged { name: String, status: ServiceStatus },
}

/// Snapshot returned by health status queries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct HealthSnapshot {
    pub machines: Vec<MachineHealth>,
    pub services: Vec<ServiceHealth>,
}

/// Service health summary (config + current status).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
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
}

/// Default timeout for the shared HTTP client used by health checks.
const HTTP_CLIENT_TIMEOUT_SECS: u64 = 10;

/// Core health facade.
pub struct HealthCore {
    mdns_tracker: Option<MdnsTracker>,
    dns: Option<Arc<dyn DnsProbe>>,
    certmesh: Option<Arc<dyn CertmeshSnapshot>>,
    proxy: Option<Arc<dyn ProxySnapshot>>,
    checks: Arc<RwLock<Vec<HealthCheckConfig>>>,
    service_states: Arc<RwLock<HashMap<String, ServiceCheckState>>>,
    machine_threshold: Duration,
    started_at: Instant,
    event_tx: broadcast::Sender<HealthEvent>,
    http_client: reqwest::Client,
}

impl HealthCore {
    pub async fn new(
        mdns: Option<Arc<dyn MdnsSnapshot>>,
        dns: Option<Arc<dyn DnsProbe>>,
        certmesh: Option<Arc<dyn CertmeshSnapshot>>,
        proxy: Option<Arc<dyn ProxySnapshot>>,
    ) -> Self {
        let checks = load_health_state()
            .map(|state| state.checks)
            .unwrap_or_default();

        let mdns_tracker = match mdns {
            Some(snapshot) => Some(MdnsTracker::spawn(snapshot).await),
            None => None,
        };

        let (event_tx, _) = koi_common::events::event_channel();

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(HTTP_CLIENT_TIMEOUT_SECS))
            .build()
            .unwrap_or_default();

        Self {
            mdns_tracker,
            dns,
            certmesh,
            proxy,
            checks: Arc::new(RwLock::new(checks)),
            service_states: Arc::new(RwLock::new(HashMap::new())),
            machine_threshold: Duration::from_secs(DEFAULT_MACHINE_THRESHOLD_SECS),
            started_at: Instant::now(),
            event_tx,
            http_client,
        }
    }

    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    /// Shared HTTP client for health checks.
    pub(crate) fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    pub async fn snapshot(&self) -> HealthSnapshot {
        let mdns_snapshot = self
            .mdns_tracker
            .as_ref()
            .map(|tracker| tracker.snapshot())
            .unwrap_or_default();

        let machines = collect_machine_health(
            &mdns_snapshot,
            self.dns.as_ref(),
            self.certmesh.as_ref(),
            self.machine_threshold,
        );

        let mut checks = self.checks.read().await.clone();
        checks.extend(self.proxy_checks());
        let states = self.service_states.read().await.clone();
        let services = checks
            .into_iter()
            .map(|check| {
                let state = states.get(&check.name).cloned().unwrap_or_default();
                ServiceHealth {
                    name: check.name,
                    kind: check.kind,
                    target: check.target,
                    interval_secs: check.interval_secs,
                    timeout_secs: check.timeout_secs,
                    status: state.status,
                    last_checked: state.last_checked,
                    last_ok: state.last_ok,
                    message: state.message,
                }
            })
            .collect();

        HealthSnapshot { machines, services }
    }

    pub async fn list_checks(&self) -> Vec<HealthCheckConfig> {
        self.checks.read().await.clone()
    }

    pub async fn add_check(&self, check: HealthCheckConfig) -> Result<(), HealthError> {
        service::validate_check(&check).map_err(HealthError::InvalidCheck)?;

        let mut checks = self.checks.write().await;
        if checks.iter().any(|c| c.name == check.name) {
            return Err(HealthError::InvalidCheck(format!(
                "check already exists: {}",
                check.name
            )));
        }

        checks.push(check);
        let state = HealthChecksState {
            checks: checks.clone(),
        };
        save_health_state(&state).map_err(|e| HealthError::Io(e.to_string()))?;
        Ok(())
    }

    pub async fn remove_check(&self, name: &str) -> Result<(), HealthError> {
        let mut checks = self.checks.write().await;
        let before = checks.len();
        checks.retain(|c| c.name != name);
        if checks.len() == before {
            return Err(HealthError::NotFound(name.to_string()));
        }
        let state = HealthChecksState {
            checks: checks.clone(),
        };
        save_health_state(&state).map_err(|e| HealthError::Io(e.to_string()))?;

        let mut states = self.service_states.write().await;
        states.remove(name);
        Ok(())
    }

    pub async fn run_checks_once(&self) {
        run_checks_once(self, &self.service_states).await;
    }

    /// Subscribe to health events.
    pub fn subscribe(&self) -> broadcast::Receiver<HealthEvent> {
        self.event_tx.subscribe()
    }

    /// Emit a health event (used by the checker loop).
    pub(crate) fn emit(&self, event: HealthEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Generate health checks from proxy entries.
    pub(crate) fn proxy_checks(&self) -> Vec<HealthCheckConfig> {
        let Some(proxy) = &self.proxy else {
            return Vec::new();
        };
        proxy
            .entries()
            .into_iter()
            .map(|entry| HealthCheckConfig {
                name: format!("proxy:{}", entry.name),
                kind: ServiceCheckKind::Http,
                target: entry.backend,
                interval_secs: DEFAULT_INTERVAL_SECS,
                timeout_secs: DEFAULT_TIMEOUT_SECS,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceCheckKind;
    use crate::state::HealthCheckConfig;

    /// Drives a real status transition through HealthCore: subscribe → add a TCP
    /// check pointing at a closed local port → run_checks_once() (real TCP attempt
    /// fails) → the Unknown→Down transition emits StatusChanged through the core's
    /// own channel. Fails if the checker stops emitting (tests Koi, not tokio).
    #[tokio::test]
    async fn run_checks_emits_status_changed_through_core() {
        let _ = koi_common::test::ensure_data_dir("koi-health-event-tests");

        let core = HealthCore::new(None, None, None, None).await;
        let mut rx = core.subscribe();

        // Unique name so concurrent / repeated tests in the same process don't
        // collide on the persisted check list. Port 1 is effectively never
        // listening, so the TCP connect fails fast on localhost (no network).
        let name = format!("evt-{}", koi_common::id::generate_short_id());
        core.add_check(HealthCheckConfig {
            name: name.clone(),
            kind: ServiceCheckKind::Tcp,
            target: "127.0.0.1:1".to_string(),
            interval_secs: 1,
            timeout_secs: 1,
        })
        .await
        .expect("add_check should succeed");

        // First run: Unknown -> Down, which emits a StatusChanged for our check.
        core.run_checks_once().await;

        let event = rx
            .try_recv()
            .expect("a StatusChanged should have been emitted");
        let HealthEvent::StatusChanged {
            name: evt_name,
            status,
        } = event;
        assert_eq!(evt_name, name);
        assert!(
            matches!(status, ServiceStatus::Down),
            "closed local port should report Down, got {status:?}"
        );

        // Cleanup the persisted check so the shared state file stays tidy.
        let _ = core.remove_check(&name).await;
    }

    /// Probes for a tick must run CONCURRENTLY: N checks against a server that
    /// accepts but never replies each hang until their own timeout, so the tick
    /// should take ~one timeout, not N. Guards the regression where a slow /
    /// timing-out check serialized (delayed) all the others.
    #[tokio::test]
    async fn run_checks_probe_concurrently() {
        let _ = koi_common::test::ensure_data_dir("koi-health-concurrency-tests");

        // Accept connections but never respond, and HOLD the streams open so the
        // client side blocks until its request timeout. Dropping the streams
        // would close the connection and fail fast, defeating the measurement.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let core = HealthCore::new(None, None, None, None).await;

        let timeout_secs = 1u64;
        let n = 4usize;
        let mut names = Vec::new();
        for _ in 0..n {
            let name = format!("conc-{}", koi_common::id::generate_short_id());
            core.add_check(HealthCheckConfig {
                name: name.clone(),
                kind: ServiceCheckKind::Http,
                target: format!("http://{addr}/"),
                interval_secs: 1,
                timeout_secs,
            })
            .await
            .expect("add_check should succeed");
            names.push(name);
        }

        let start = std::time::Instant::now();
        core.run_checks_once().await;
        let elapsed = start.elapsed();

        // Lower bound: the probes really hit their ~1s timeout (not a fast-fail).
        // Upper bound: well under the sequential floor (n * timeout = 4s).
        assert!(
            elapsed >= std::time::Duration::from_millis(700),
            "probes should have hit their ~1s timeout, took {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(3000),
            "{n} x {timeout_secs}s checks must run concurrently (sequential would be ~{}s), took {elapsed:?}",
            n as u64 * timeout_secs
        );

        for name in &names {
            let _ = core.remove_check(name).await;
        }
    }
}

#[async_trait::async_trait]
impl Capability for HealthCore {
    fn name(&self) -> &str {
        "health"
    }

    async fn status(&self) -> CapabilityStatus {
        let (total, up) = match self.service_states.try_read() {
            Ok(services) => {
                let total = services.len();
                let up = services
                    .values()
                    .filter(|s| matches!(s.status, ServiceStatus::Up))
                    .count();
                (total, up)
            }
            Err(_) => (0, 0),
        };
        let summary = format!("{} services up ({} total)", up, total);
        CapabilityStatus {
            name: "health".to_string(),
            summary,
            healthy: true,
        }
    }
}

/// Runtime controller for the background service checks.
///
/// A thin wrapper over the shared [`DomainRuntime`] start/stop machine; the only
/// health-specific piece is the spawned loop (`run_checks_loop(core, token)`).
#[derive(Clone)]
pub struct HealthRuntime {
    inner: DomainRuntime<HealthCore>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct HealthRuntimeStatus {
    pub running: bool,
}

impl HealthRuntime {
    pub fn new(core: Arc<HealthCore>) -> Self {
        Self {
            inner: DomainRuntime::new(core),
        }
    }

    pub fn core(&self) -> Arc<HealthCore> {
        self.inner.core()
    }

    pub async fn start(&self) -> Result<bool, HealthError> {
        let core = self.inner.core();
        // DomainRuntime::start signals already-running via Ok(false) and never yields
        // AlreadyRunning for this launcher; the Result<_, HealthError> shape is preserved.
        let started = self
            .inner
            .start(move |token| tokio::spawn(run_checks_loop(core, token)))
            .await
            .unwrap_or(false);
        Ok(started)
    }

    pub async fn stop(&self) -> bool {
        self.inner.stop().await
    }

    pub async fn status(&self) -> HealthRuntimeStatus {
        HealthRuntimeStatus {
            running: self.inner.status().await.running,
        }
    }
}
