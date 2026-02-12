//! Koi Health — network health monitoring (Phase 7).

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
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use koi_common::capability::{Capability, CapabilityStatus};

use crate::checker::{run_checks_once, run_checks_loop, ServiceCheckState};
use crate::machine::{collect_machine_health, MdnsTracker};
use crate::state::{load_health_state, save_health_state, HealthCheckConfig, HealthChecksState};
use crate::state::{DEFAULT_INTERVAL_SECS, DEFAULT_TIMEOUT_SECS};
use koi_proxy::config as proxy_config;

pub use machine::MachineHealth;
pub use service::ServiceCheckKind;
pub use service::ServiceStatus;
pub use service::ServiceStatus as HealthStatus;
pub use state::HealthCheckConfig as HealthCheck;

/// Default machine health threshold (seconds since last seen).
pub const DEFAULT_MACHINE_THRESHOLD_SECS: u64 = 60;

/// Snapshot returned by health status queries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthSnapshot {
	pub machines: Vec<MachineHealth>,
	pub services: Vec<ServiceHealth>,
}

/// Service health summary (config + current status).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Core health facade.
pub struct HealthCore {
	mdns_tracker: Option<MdnsTracker>,
	dns: Option<Arc<koi_dns::DnsRuntime>>,
	checks: Arc<RwLock<Vec<HealthCheckConfig>>>,
	service_states: Arc<RwLock<HashMap<String, ServiceCheckState>>>,
	machine_threshold: Duration,
	started_at: Instant,
}

impl HealthCore {
	pub async fn new(
		mdns: Option<Arc<koi_mdns::MdnsCore>>,
		dns: Option<Arc<koi_dns::DnsRuntime>>,
	) -> Self {
		let checks = load_health_state()
			.map(|state| state.checks)
			.unwrap_or_default();

		let mdns_tracker = match mdns {
			Some(core) => Some(MdnsTracker::spawn(core).await),
			None => None,
		};

		Self {
			mdns_tracker,
			dns,
			checks: Arc::new(RwLock::new(checks)),
			service_states: Arc::new(RwLock::new(HashMap::new())),
			machine_threshold: Duration::from_secs(DEFAULT_MACHINE_THRESHOLD_SECS),
			started_at: Instant::now(),
		}
	}

	pub fn started_at(&self) -> Instant {
		self.started_at
	}

	pub fn dns_runtime(&self) -> Option<Arc<koi_dns::DnsRuntime>> {
		self.dns.clone()
	}

	pub async fn snapshot(&self) -> HealthSnapshot {
		let mdns_snapshot = self
			.mdns_tracker
			.as_ref()
			.map(|tracker| tracker.snapshot())
			.unwrap_or_default();

		let machines = collect_machine_health(
			&mdns_snapshot,
			self.dns.as_ref().map(Arc::clone),
			self.machine_threshold,
		);

		let mut checks = self.checks.read().await.clone();
		checks.extend(proxy_checks());
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
		let state = HealthChecksState { checks: checks.clone() };
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
		let state = HealthChecksState { checks: checks.clone() };
		save_health_state(&state).map_err(|e| HealthError::Io(e.to_string()))?;

		let mut states = self.service_states.write().await;
		states.remove(name);
		Ok(())
	}

	pub async fn run_checks_once(&self) {
		run_checks_once(self, &self.service_states).await;
	}
}

fn proxy_checks() -> Vec<HealthCheckConfig> {
	let Ok(entries) = proxy_config::load_entries() else {
		return Vec::new();
	};
	entries
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

impl Capability for HealthCore {
	fn name(&self) -> &str {
		"health"
	}

	fn status(&self) -> CapabilityStatus {
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
pub struct HealthRuntime {
	core: Arc<HealthCore>,
	state: Arc<tokio::sync::Mutex<RuntimeState>>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct HealthRuntimeStatus {
	pub running: bool,
}

struct RuntimeState {
	running: bool,
	cancel: Option<CancellationToken>,
}

impl HealthRuntime {
	pub fn new(core: Arc<HealthCore>) -> Self {
		Self {
			core,
			state: Arc::new(tokio::sync::Mutex::new(RuntimeState {
				running: false,
				cancel: None,
			})),
		}
	}

	pub fn core(&self) -> Arc<HealthCore> {
		Arc::clone(&self.core)
	}

	pub async fn start(&self) -> Result<bool, HealthError> {
		let mut state = self.state.lock().await;
		if state.running {
			return Ok(false);
		}
		let token = CancellationToken::new();
		state.cancel = Some(token.clone());
		state.running = true;
		drop(state);

		let core = Arc::clone(&self.core);
		let state = Arc::clone(&self.state);
		tokio::spawn(async move {
			run_checks_loop(core, token).await;
			let mut guard = state.lock().await;
			guard.running = false;
			guard.cancel = None;
		});

		Ok(true)
	}

	pub async fn stop(&self) -> bool {
		let mut state = self.state.lock().await;
		if let Some(token) = state.cancel.take() {
			token.cancel();
			state.running = false;
			true
		} else {
			false
		}
	}

	pub async fn status(&self) -> HealthRuntimeStatus {
		let state = self.state.lock().await;
		HealthRuntimeStatus {
			running: state.running,
		}
	}
}
