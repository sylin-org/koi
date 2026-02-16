//! HTTP routes for UDP bridging — bind, unbind, recv (SSE), send, status, heartbeat.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Json;
use axum::routing::{delete, get, post};
use axum::Router;
use futures_util::stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::{BindingInfo, UdpBindRequest, UdpRuntime, UdpSendRequest};

// ── Route path constants ────────────────────────────────────────────

pub mod paths {
    pub const PREFIX: &str = "/v1/udp";
    pub const BIND: &str = "/v1/udp/bind";
    pub const UNBIND: &str = "/v1/udp/bind/:id";
    pub const RECV: &str = "/v1/udp/recv/:id";
    pub const SEND: &str = "/v1/udp/send/:id";
    pub const STATUS: &str = "/v1/udp/status";
    pub const HEARTBEAT: &str = "/v1/udp/heartbeat/:id";

    /// Strip the prefix for sub-router mounting.
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

// ── OpenAPI schema ──────────────────────────────────────────────────

#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(BindingInfo)))]
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
        .route(rel(paths::HEARTBEAT), post(heartbeat_handler))
        .layer(Extension(runtime))
}

// ── Handlers ────────────────────────────────────────────────────────

/// POST /v1/udp/bind — create a new UDP binding.
async fn bind_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Json(req): Json<UdpBindRequest>,
) -> Result<Json<BindingInfo>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    match runtime.bind(req).await {
        Ok(info) => Ok(Json(info)),
        Err(e) => Err((
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )),
    }
}

/// DELETE /v1/udp/bind/:id — remove a binding and close the socket.
async fn unbind_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    match runtime.unbind(&id).await {
        Ok(()) => Ok(Json(serde_json::json!({ "status": "unbound" }))),
        Err(e) => Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e.to_string() })),
        )),
    }
}

/// GET /v1/udp/recv/:id — SSE stream of incoming datagrams.
async fn recv_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Path(id): Path<String>,
) -> Result<
    Sse<impl Stream<Item = Result<Event, Infallible>>>,
    (axum::http::StatusCode, Json<serde_json::Value>),
> {
    let rx = runtime.subscribe(&id).await.map_err(|e| {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
    })?;

    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(datagram) => {
            let json = serde_json::to_string(&datagram).unwrap_or_default();
            Some(Ok(Event::default().event("datagram").data(json)))
        }
        Err(_) => None,
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// POST /v1/udp/send/:id — send a datagram through a binding.
async fn send_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Path(id): Path<String>,
    Json(req): Json<UdpSendRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    match runtime.send(&id, req).await {
        Ok(bytes) => Ok(Json(serde_json::json!({ "bytes_sent": bytes }))),
        Err(e) => {
            let status = match &e {
                crate::UdpError::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
                _ => axum::http::StatusCode::BAD_REQUEST,
            };
            Err((status, Json(serde_json::json!({ "error": e.to_string() }))))
        }
    }
}

/// GET /v1/udp/status — list all active bindings.
async fn status_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
) -> Json<serde_json::Value> {
    let bindings = runtime.status().await;
    Json(serde_json::json!({ "bindings": bindings }))
}

/// POST /v1/udp/heartbeat/:id — extend a binding's lease.
async fn heartbeat_handler(
    Extension(runtime): Extension<Arc<UdpRuntime>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    match runtime.heartbeat(&id).await {
        Ok(()) => Ok(Json(serde_json::json!({ "status": "ok" }))),
        Err(e) => Err((
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e.to_string() })),
        )),
    }
}
