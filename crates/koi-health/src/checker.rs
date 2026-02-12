use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::log::append_transition;
use crate::service::{run_check, ServiceStatus};
use crate::state::{HealthCheckConfig, DEFAULT_INTERVAL_SECS, DEFAULT_TIMEOUT_SECS};
use crate::HealthCore;
use koi_proxy::config as proxy_config;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceCheckState {
    pub status: ServiceStatus,
    pub last_checked: Option<DateTime<Utc>>,
    pub last_ok: Option<DateTime<Utc>>,
    pub message: Option<String>,
}

impl Default for ServiceCheckState {
    fn default() -> Self {
        Self {
            status: ServiceStatus::Unknown,
            last_checked: None,
            last_ok: None,
            message: None,
        }
    }
}

pub async fn run_checks_loop(core: Arc<HealthCore>, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                run_checks_once(&core, &core.service_states).await;
            }
        }
    }
}

pub async fn run_checks_once(
    core: &HealthCore,
    states: &Arc<RwLock<HashMap<String, ServiceCheckState>>>,
) {
    let mut checks = core.list_checks().await;
    checks.extend(proxy_checks());
    if checks.is_empty() {
        return;
    }

    for check in checks {
        if !is_due(&check, states).await {
            continue;
        }

        let outcome = run_check(&check).await;
        let now = Utc::now();

        let previous = {
            let guard = states.read().await;
            guard.get(&check.name).cloned().unwrap_or_default()
        };

        let mut next = previous.clone();
        next.status = outcome.status;
        next.last_checked = Some(now);
        next.message = outcome.message;
        if matches!(next.status, ServiceStatus::Up) {
            next.last_ok = Some(now);
        }

        if previous.status != next.status {
            let reason = next
                .message
                .clone()
                .unwrap_or_else(|| "status_change".to_string());
            if let Err(e) = append_transition(&check.name, previous.status, next.status, &reason) {
                tracing::warn!(error = %e, check = %check.name, "Failed to write health transition");
            }
        }

        let mut guard = states.write().await;
        guard.insert(check.name.clone(), next);
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
            kind: crate::service::ServiceCheckKind::Http,
            target: entry.backend,
            interval_secs: DEFAULT_INTERVAL_SECS,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        })
        .collect()
}

async fn is_due(
    check: &HealthCheckConfig,
    states: &Arc<RwLock<HashMap<String, ServiceCheckState>>>,
) -> bool {
    let guard = states.read().await;
    let Some(state) = guard.get(&check.name) else {
        return true;
    };
    let Some(last) = state.last_checked else {
        return true;
    };
    let elapsed = Utc::now().signed_duration_since(last);
    elapsed.num_seconds() >= check.interval_secs as i64
}
