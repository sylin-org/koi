use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use tokio::task::JoinSet;

use crate::log::append_transition;
use crate::service::{run_check, ServiceCheckOutcome, ServiceStatus};
use crate::state::HealthCheckConfig;
use crate::HealthCore;

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
    checks.extend(core.proxy_checks());
    if checks.is_empty() {
        return;
    }

    // Snapshot the due checks under a single read guard, then release it before
    // probing — checks must not serialize behind the state lock.
    let due: Vec<HealthCheckConfig> = {
        let guard = states.read().await;
        checks.into_iter().filter(|c| is_due(c, &guard)).collect()
    };
    if due.is_empty() {
        return;
    }

    // Probe all due checks CONCURRENTLY. A slow or timing-out check no longer
    // stalls the rest of the tick — each carries its own per-check timeout in
    // `run_check`, so the worst tick latency is one timeout, not their sum.
    // The reqwest client is cheaply cloneable (Arc inside); each task owns its
    // check + client clone so the futures are `'static`.
    let client = core.http_client().clone();
    let mut probes: JoinSet<(HealthCheckConfig, ServiceCheckOutcome, DateTime<Utc>)> =
        JoinSet::new();
    for check in due {
        let client = client.clone();
        probes.spawn(async move {
            let outcome = run_check(&check, &client).await;
            (check, outcome, Utc::now())
        });
    }

    // Apply results as each probe completes. Order-independent: every transition
    // is computed against that check's own previous state, and listeners
    // subscribe by check name (not by emission order).
    while let Some(joined) = probes.join_next().await {
        let (check, outcome, now) = match joined {
            Ok(triple) => triple,
            Err(e) => {
                tracing::warn!(error = %e, "health check probe task failed");
                continue;
            }
        };

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
            core.emit(crate::HealthEvent::StatusChanged {
                name: check.name.clone(),
                status: next.status,
            });
        }

        let mut guard = states.write().await;
        guard.insert(check.name.clone(), next);
    }
}

/// Whether a check is due to run, evaluated against an already-held read guard
/// of the state map (so the whole due-set can be computed under one lock).
fn is_due(check: &HealthCheckConfig, states: &HashMap<String, ServiceCheckState>) -> bool {
    let Some(state) = states.get(&check.name) else {
        return true;
    };
    let Some(last) = state.last_checked else {
        return true;
    };
    let elapsed = Utc::now().signed_duration_since(last);
    elapsed.num_seconds() >= check.interval_secs as i64
}
