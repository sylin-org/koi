//! Dashboard wiring — connects the daemon's aggregate status to the shared
//! dashboard infrastructure in `koi_dashboard::dashboard`.
//!
//! This module provides:
//! - A snapshot closure that captures one product-status revision (the injected `SnapshotFn`)
//! - A builder that produces the `DashboardState` consumed by `koi-dashboard`
//!
//! The rich snapshot detail (capabilities + health/DNS/certmesh/proxy/UDP) is built by
//! `koi_compose::snapshot::build_dashboard_snapshot`, the single projection shared with the
//! embedded snapshot. The event forwarder lives in `koi_dashboard::forward` (the single,
//! deduplicated superset shared with koi-embedded).

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::broadcast;

use koi_dashboard::dashboard::{DashboardIdentity, DashboardState};

// ── Build dashboard state ───────────────────────────────────────────
//
// The event forwarder lives in `koi_dashboard::forward` (the single, deduplicated
// superset). Only the `SnapshotFn` wiring stays here; the snapshot body itself is the
// shared `koi_compose::snapshot::build_dashboard_snapshot`.

/// Construct the `DashboardState` for the daemon.
pub fn build_dashboard_state(
    cores: &koi_compose::cores::Cores,
    host: &koi_compose::host::HostIdentity,
    started_at: Instant,
    mode: &'static str,
) -> DashboardState {
    let system_status = Arc::clone(&cores.system_status);

    let snapshot_fn: koi_dashboard::dashboard::SnapshotFn = Arc::new(move || {
        let status = system_status.status();
        Box::pin(async move { koi_compose::snapshot::build_dashboard_snapshot(status.as_ref()) })
    });

    let (event_tx, _) = broadcast::channel(256);

    DashboardState {
        identity: DashboardIdentity {
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: std::env::consts::OS.to_string(),
            hostname: host.hostname().to_string(),
            hostname_fqdn: host.local_fqdn().to_string(),
        },
        mode,
        snapshot_fn,
        event_tx,
        started_at,
    }
}
