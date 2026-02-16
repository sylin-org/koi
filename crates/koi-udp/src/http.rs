//! HTTP routes for UDP bridging - bind, unbind, recv (SSE), send, status, heartbeat.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Path, Query};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post, put};
use axum::Router;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use koi_common::error::ErrorCode;
use koi_common::http::error_response;

use crate::{BindingInfo, UdpBindRequest, UdpDatagram, UdpRuntime, UdpSendRequest};

// ── Route path constants ────────────────────────────────────────────

pub mod paths {
    pub const PREFIX: &str = "/v1/udp";
    pub const BIND: &str = "/v1/udp/bind";
    pub const UNBIND: &str = "/v1/udp/bind/{id}";
    pub const RECV: &str = "/v1/udp/recv/{id}";
    pub const SEND: &str = "/v1/udp/send/{id}";
    pub const STATUS: &str = "/v1/udp/status";
    pub const HEARTBEAT: &str = "/v1/udp/heartbeat/{id}";

    /// Strip the prefix for sub-router mounting.
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

// ── SSE idle timeout ────────────────────────────────────────────────

/// Default idle timeout for the recv SSE stream.
/// `None` = no auto-close (UDP streams are long-lived by default).
const DEFAULT_SSE_IDLE: Option<Duration> = None;

/// Query parameters for the recv SSE endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct RecvParams {
    /// Seconds of silence before the SSE stream closes.
    /// - absent → keep open indefinitely (default for UDP)
    /// - `0` → keep open indefinitely
    /// - `N` → close after N seconds of silence
    pub idle_for: Option<u64>,
}

/// Parse the `idle_for` query parameter into an optional duration.
/// - `None` (absent) → `DEFAULT_SSE_IDLE` (infinite for UDP)
/// - `Some(0)` → `None` (infinite, no timeout)
/// - `Some(n)` → `Some(Duration::from_secs(n))`
fn idle_duration(idle_for: Option<u64>) -> Option<Duration> {
    match idle_for {
        None => DEFAULT_SSE_IDLE,
        Some(0) => None,
        Some(n) => Some(Duration::from_secs(n)),
    }
}

// ── OpenAPI schema ──────────────────────────────────────────────────

#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(BindingInfo, UdpBindRequest, UdpSendRequest, UdpDatagram)))]
pub struct UdpApiDoc;

// ── Router constructor ──────────────────────────────────────────────

pub fn routes(runtime: Arc<UdpRuntime>) -> Router {
    use paths::rel;

    Router::new()
        .route(rel(paths::BIND), post(bind_handler))
        .route(rel(paths::UNBIND), delete(unbind_handler))
        .route(rel(paths::RECV), get(recv_handler))
        .route(rel(paths::SEND), post(send_handler))
        .route(rel(paths::STATUS), get(status_handler))
        .route(rel(paths::HEARTBEAT), put(heartbeat_handler))
        .layer(Extension(runtime))
}

// ── Error mapping ───────────────────────────────────────────────────

fn map_error(e: crate::UdpError) -> axum::response::Response {
    match &e {
        crate::UdpError::NotFound(_) => error_response(ErrorCode::NotFound, e.to_string()),
        crate::UdpError::InvalidAddr(_) => {
            error_response(ErrorCode::InvalidPayload, e.to_string())
        }
        crate::UdpError::Io(_) => error_response(ErrorCode::IoError, e.to_string()),
        crate::UdpError::Base64(_) => error_response(ErrorCode::InvalidPayload, e.to_string()),
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// POST /v1/udp/bind - create a new UDP binding.
async fn bind_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Json(req): Json<UdpBindRequest>,
) -> impl IntoResponse {
    match runtime.bind(req).await {
        Ok(info) => (axum::http::StatusCode::CREATED, Json(info)).into_response(),
        Err(e) => map_error(e),
    }
}

/// DELETE /v1/udp/bind/{id} - remove a binding and close the socket.
async fn unbind_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match runtime.unbind(&id).await {
        Ok(()) => Json(serde_json::json!({ "unbound": id })).into_response(),
        Err(e) => map_error(e),
    }
}

/// GET /v1/udp/recv/{id}?idle_for=N - SSE stream of incoming datagrams.
async fn recv_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Path(id): Path<String>,
    Query(params): Query<RecvParams>,
) -> impl IntoResponse {
    let rx = match runtime.subscribe(&id).await {
        Ok(rx) => rx,
        Err(e) => return map_error(e),
    };

    let idle = idle_duration(params.idle_for);

    let stream = async_stream::stream! {
        let mut rx = BroadcastStream::new(rx);
        loop {
            let next = match idle {
                Some(dur) => match tokio::time::timeout(dur, rx.next()).await {
                    Ok(Some(item)) => Some(item),
                    Ok(None) => break,   // channel closed
                    Err(_) => break,     // idle timeout - close stream
                },
                None => rx.next().await,
            };
            match next {
                Some(Ok(datagram)) => {
                    let json = serde_json::to_string(&datagram).unwrap_or_default();
                    let id = uuid::Uuid::now_v7().to_string();
                    yield Ok::<_, Infallible>(Event::default().id(id).event("datagram").data(json));
                }
                Some(Err(_)) => continue, // lagged - skip
                None => break,            // channel closed
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// POST /v1/udp/send/{id} - send a datagram through a binding.
async fn send_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Path(id): Path<String>,
    Json(req): Json<UdpSendRequest>,
) -> impl IntoResponse {
    match runtime.send(&id, req).await {
        Ok(bytes) => Json(serde_json::json!({ "sent": bytes })).into_response(),
        Err(e) => map_error(e),
    }
}

/// GET /v1/udp/status - list all active bindings.
async fn status_handler(Extension(runtime): Extension<Arc<UdpRuntime>>) -> Json<serde_json::Value> {
    let bindings = runtime.status().await;
    Json(serde_json::json!({ "bindings": bindings }))
}

/// PUT /v1/udp/heartbeat/{id} - extend a binding's lease.
async fn heartbeat_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match runtime.heartbeat(&id).await {
        Ok(()) => Json(serde_json::json!({ "renewed": id })).into_response(),
        Err(e) => map_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── idle_duration tests ──────────────────────────────────────────

    #[test]
    fn idle_duration_absent_returns_none_infinite() {
        let d = idle_duration(None);
        assert!(d.is_none(), "UDP default is infinite (no auto-close)");
    }

    #[test]
    fn idle_duration_zero_returns_none_infinite() {
        let d = idle_duration(Some(0));
        assert!(d.is_none());
    }

    #[test]
    fn idle_duration_explicit_value() {
        let d = idle_duration(Some(10));
        assert_eq!(d, Some(Duration::from_secs(10)));
    }
}
