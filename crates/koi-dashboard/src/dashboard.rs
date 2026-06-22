//! Dashboard surface — system-level operational overview.
//!
//! Serves the dashboard HTML, a JSON snapshot endpoint, and an SSE event stream.
//! Domain data flows in through a boxed async snapshot closure ([`SnapshotFn`]) and a
//! broadcast channel ([`DashboardSseEvent`]) — this module owns zero domain logic. The
//! event forwarder that feeds the channel lives in [`crate::forward`].

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

/// Identity information injected by the caller so the snapshot reflects the host
/// binary's version, not koi-dashboard's.
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

/// Versioned, serializable wire DTO for the `GET /v1/events` SSE stream (1.1).
///
/// Consumers (Koan, rake, browsers) read this over HTTP; it must be stable and
/// self-describing. The `event_v` field names this outer envelope version
/// (`"event_v"` is chosen over `"v"` to avoid collision with a nested
/// `Envelope.v` field when event payloads carry an envelope).
///
/// A consumer that sees an unknown `event_v` MUST skip the event rather than
/// error — forward-compatible by design.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KoiEventWire {
    /// Outer wire version. Currently always `1`. Consumers skip unknown versions.
    pub event_v: u8,
    /// Dotted-namespace event type, e.g. `"certmesh.cert_renewed"`.
    pub event_type: String,
    /// Monotonically increasing, globally-unique event ID (UUID v7 prefix).
    pub id: String,
    /// Event-type-specific payload. Schema lives in `trust-protocol.md §7`.
    pub data: serde_json::Value,
}

impl From<&DashboardSseEvent> for KoiEventWire {
    fn from(e: &DashboardSseEvent) -> Self {
        Self {
            event_v: 1,
            event_type: e.event_type.clone(),
            id: e.id.clone(),
            data: e.data.clone(),
        }
    }
}

/// Type alias for the async snapshot closure.
///
/// The caller provides a closure that queries all domain cores and returns a complete
/// JSON snapshot. koi-dashboard wraps it with identity / uptime / mode metadata. This
/// inversion keeps the dashboard surface free of domain coupling.
pub type SnapshotFn =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = serde_json::Value> + Send>> + Send + Sync>;

/// Shared state for the dashboard routes. Construct in the binary crate or
/// koi-embedded and inject via `axum::Extension`.
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

fn dashboard_event_stream(state: DashboardState) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        let mut rx = state.event_tx.subscribe();
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat.tick().await; // skip immediate tick

        loop {
            let event = tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(ev) => {
                            Event::default()
                                .event(&ev.event_type)
                                .id(ev.id)
                                .json_data(ev.data)
                                .ok()
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(dropped = n, "Dashboard SSE stream lagged");
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
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

/// `GET /` — Serve the dashboard SPA with a Content-Security-Policy header.
pub async fn get_dashboard() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_SECURITY_POLICY, crate::HTML_CSP)],
        Html(DASHBOARD_HTML),
    )
}

/// `GET /v1/dashboard/snapshot` — System-level JSON snapshot.
pub async fn get_snapshot(Extension(state): Extension<DashboardState>) -> impl IntoResponse {
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

/// `GET /v1/events` — DAT-gated wire event stream (wishlist 1.1/1.2).
///
/// Each SSE event carries a `KoiEventWire` JSON object in its `data:` field.
/// Returns 503 when the event forwarder is not running.
pub async fn get_wire_events(
    dashboard: Option<Extension<DashboardState>>,
) -> axum::response::Response {
    let Some(Extension(state)) = dashboard else {
        return koi_common::http::error_response(
            koi_common::error::ErrorCode::CapabilityDisabled,
            "event stream is not available (dashboard/event-forwarder is disabled)",
        );
    };

    Sse::new(wire_event_stream(state))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn wire_event_stream(state: DashboardState) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        let mut rx = state.event_tx.subscribe();
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat.tick().await;
        loop {
            let event = tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(ev) => {
                            let wire = KoiEventWire::from(&ev);
                            Event::default()
                                .event(&ev.event_type)
                                .id(&ev.id)
                                .json_data(wire)
                                .ok()
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(dropped = n, "events SSE stream lagged");
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                },
                _ = heartbeat.tick() => {
                    Some(Event::default().event("heartbeat").data("{}"))
                },
            };
            if let Some(ev) = event {
                yield Ok(ev);
            }
        }
    }
}
