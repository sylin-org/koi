//! Dashboard adapter — system-level operational overview.
//!
//! Provides the shared dashboard infrastructure (HTML serving, snapshot
//! endpoint, SSE event stream) that both the standalone daemon and
//! embedded mode can mount.  Domain-specific logic is injected via a
//! boxed async closure (snapshot) and a broadcast channel (events).
//!
//! This module owns zero domain logic.  All data flows through the
//! abstractions the caller provides.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::Extension;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use serde::Serialize;
use tokio::sync::broadcast;
use tokio_stream::Stream;

// ── HTML asset ──────────────────────────────────────────────────────

const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");

// ── Public types ────────────────────────────────────────────────────

/// Identity information injected by the caller so the snapshot reflects
/// the host binary's version, not koi-common's.
#[derive(Clone, Debug)]
pub struct DashboardIdentity {
    pub version: String,
    pub platform: String,
}

/// A domain-agnostic SSE event forwarded by the caller.
#[derive(Clone, Debug)]
pub struct DashboardSseEvent {
    /// SSE event type (e.g. "mdns.found", "health.changed").
    pub event_type: String,
    /// Unique event ID (typically UUID v7).
    pub id: String,
    /// JSON payload.
    pub data: serde_json::Value,
}

/// Type alias for the async snapshot closure.
///
/// The caller provides a closure that queries all domain cores and
/// returns a complete JSON snapshot.  koi-common wraps it with
/// identity / uptime / mode metadata.
pub type SnapshotFn =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = serde_json::Value> + Send>> + Send + Sync>;

/// Shared state for the dashboard routes.
///
/// Construct this in the binary crate or koi-embedded and inject it
/// via `axum::Extension`.
#[derive(Clone)]
pub struct DashboardState {
    pub identity: DashboardIdentity,
    pub mode: &'static str,
    pub snapshot_fn: SnapshotFn,
    pub event_tx: broadcast::Sender<DashboardSseEvent>,
    pub started_at: Instant,
}

// ── Snapshot envelope ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct DashboardSnapshot {
    version: String,
    platform: String,
    hostname: String,
    hostname_fqdn: String,
    uptime_secs: u64,
    mode: String,
    #[serde(flatten)]
    details: serde_json::Value,
}

// ── SSE stream ──────────────────────────────────────────────────────

fn dashboard_event_stream(
    state: DashboardState,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        let mut rx = state.event_tx.subscribe();
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat.tick().await; // skip immediate tick

        loop {
            let event = tokio::select! {
                Ok(ev) = rx.recv() => {
                    Event::default()
                        .event(&ev.event_type)
                        .id(ev.id)
                        .json_data(ev.data)
                        .ok()
                },
                _ = heartbeat.tick() => {
                    Event::default()
                        .event("heartbeat")
                        .json_data(serde_json::json!({
                            "uptime_secs": state.started_at.elapsed().as_secs()
                        })).ok()
                },
            };

            if let Some(ev) = event {
                yield Ok(ev);
            }
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /` — Serve the dashboard SPA.
pub async fn get_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

/// `GET /v1/dashboard/snapshot` — System-level JSON snapshot.
pub async fn get_snapshot(
    Extension(state): Extension<DashboardState>,
) -> impl IntoResponse {
    let hostname = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let hostname_fqdn = format!("{hostname}.local");

    let details = (state.snapshot_fn)().await;

    Json(DashboardSnapshot {
        version: state.identity.version.clone(),
        platform: state.identity.platform.clone(),
        hostname,
        hostname_fqdn,
        uptime_secs: state.started_at.elapsed().as_secs(),
        mode: state.mode.to_string(),
        details,
    })
}

/// `GET /v1/dashboard/events` — Unified SSE event stream.
pub async fn get_events(
    Extension(state): Extension<DashboardState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    Sse::new(dashboard_event_stream(state)).keep_alive(KeepAlive::default())
}
