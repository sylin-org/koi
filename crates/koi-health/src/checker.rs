use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::service::{run_check, ServiceCheckOutcome, ServiceStatus};
use crate::state::HealthCheckConfig;
use crate::HealthCore;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ServiceCheckState {
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

/// Versioned read ticket for one probe.
///
/// Network work happens without the Health model lock. The ticket carries both
/// the check generation and the exact state observed while scheduling so the
/// result can be accepted with compare-and-swap semantics later.
#[derive(Debug, Clone)]
pub(crate) struct ProbeTicket {
    pub check: HealthCheckConfig,
    pub generation: u64,
    pub baseline: Option<ServiceCheckState>,
}

#[derive(Debug)]
pub(crate) struct ProbeResult {
    pub ticket: ProbeTicket,
    pub outcome: ServiceCheckOutcome,
    pub completed_at: DateTime<Utc>,
}

pub(crate) async fn run_checks_loop(core: Arc<HealthCore>, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => run_checks_once(&core).await,
        }
    }
}

pub(crate) async fn run_checks_once(core: &HealthCore) {
    let tickets = core.prepare_probe_tickets().await;
    if tickets.is_empty() {
        return;
    }

    // Probes remain concurrent and carry no model guard across network I/O.
    // Acceptance below is one short Health-owned transaction.
    let client = core.http_client().clone();
    let mut probes = JoinSet::new();
    for ticket in tickets {
        let client = client.clone();
        probes.spawn(async move {
            let outcome = run_check(&ticket.check, &client).await;
            ProbeResult {
                ticket,
                outcome,
                completed_at: Utc::now(),
            }
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = probes.join_next().await {
        match joined {
            Ok(result) => results.push(result),
            Err(error) => tracing::warn!(%error, "health check probe task failed"),
        }
    }
    core.accept_probe_results(results).await;
}

pub(crate) fn is_due(check: &HealthCheckConfig, state: Option<&ServiceCheckState>) -> bool {
    let Some(last) = state.and_then(|state| state.last_checked) else {
        return true;
    };
    let elapsed = Utc::now().signed_duration_since(last);
    elapsed.num_seconds() >= check.interval_secs as i64
}
