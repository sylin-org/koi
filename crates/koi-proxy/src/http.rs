use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use koi_common::error::ErrorCode;

use crate::config::ProxyEntry;
use crate::{ensure_backend_allowed, ProxyError, ProxyRuntime, ProxyRuntimeStatus, ProxyStatus};

#[derive(Debug, Deserialize, ToSchema)]
struct AddProxyRequest {
    name: String,
    listen_port: u16,
    backend: String,
    #[serde(default)]
    allow_remote: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct ProxyEntriesResponse {
    entries: Vec<ProxyEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
struct StatusOk {
    status: String,
}

/// Route path constants - single source of truth for axum routing AND the command manifest.
pub mod paths {
    pub const PREFIX: &str = "/v1/proxy";

    pub const STATUS: &str = "/v1/proxy/status";
    pub const LIST: &str = "/v1/proxy/list";
    pub const ADD: &str = "/v1/proxy/add";
    pub const REMOVE: &str = "/v1/proxy/remove/{name}";

    /// Strip the crate nest prefix to get the relative path for axum routing.
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

/// Build proxy domain routes. The binary crate mounts these at `/v1/proxy/`.
pub fn routes(runtime: Arc<ProxyRuntime>) -> Router {
    use paths::rel;
    Router::new()
        .route(rel(paths::STATUS), get(status_handler))
        .route(rel(paths::LIST), get(entries_handler))
        .route(rel(paths::ADD), post(add_entry_handler))
        .route(rel(paths::REMOVE), delete(remove_entry_handler))
        .layer(Extension(runtime))
}

#[utoipa::path(get, path = "/status", tag = "proxy",
    summary = "Active proxy status",
    responses((status = 200, body = ProxyRuntimeStatus)))]
async fn status_handler(Extension(runtime): Extension<Arc<ProxyRuntime>>) -> impl IntoResponse {
    Json(runtime.status().as_ref().clone())
}

#[utoipa::path(get, path = "/list", tag = "proxy",
    summary = "List proxy entries",
    responses((status = 200, body = ProxyEntriesResponse)))]
async fn entries_handler(Extension(runtime): Extension<Arc<ProxyRuntime>>) -> impl IntoResponse {
    let entries = runtime.entries().await;
    Json(serde_json::json!({ "entries": entries }))
}

#[utoipa::path(post, path = "/add", tag = "proxy",
    summary = "Add or update a proxy entry",
    request_body = AddProxyRequest,
    responses((status = 200, body = StatusOk)))]
async fn add_entry_handler(
    Extension(runtime): Extension<Arc<ProxyRuntime>>,
    Json(payload): Json<AddProxyRequest>,
) -> impl IntoResponse {
    let entry = ProxyEntry {
        name: payload.name,
        listen_port: payload.listen_port,
        backend: payload.backend,
        allow_remote: payload.allow_remote,
    };

    if let Err(e) = ensure_backend_allowed(&entry.backend, entry.allow_remote) {
        return map_error(e).into_response();
    }
    if entry.allow_remote {
        tracing::warn!(backend = %entry.backend, "Proxy backend traffic is unencrypted");
    }

    match runtime.upsert(entry).await {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(e) => map_error(e).into_response(),
    }
}

#[utoipa::path(delete, path = "/remove/{name}", tag = "proxy",
    summary = "Remove a proxy entry",
    params(("name" = String, Path, description = "Proxy entry name")),
    responses((status = 200, body = StatusOk)))]
async fn remove_entry_handler(
    Extension(runtime): Extension<Arc<ProxyRuntime>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match runtime.remove(&name).await {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(e) => map_error(e).into_response(),
    }
}

fn map_error(err: ProxyError) -> impl IntoResponse {
    match err {
        ProxyError::InvalidConfig(msg) | ProxyError::Config(msg) => {
            koi_common::http::error_response(ErrorCode::InvalidPayload, msg)
        }
        ProxyError::NotFound(msg) => koi_common::http::error_response(ErrorCode::NotFound, msg),
        ProxyError::Io(msg) => koi_common::http::error_response(ErrorCode::IoError, msg),
        ProxyError::Worker(msg) => koi_common::http::error_response(ErrorCode::Internal, msg),
        ProxyError::ShutDown => koi_common::http::error_response(
            ErrorCode::ShuttingDown,
            "proxy runtime has already shut down",
        ),
    }
}

/// OpenAPI documentation for the proxy domain.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        status_handler,
        entries_handler,
        add_entry_handler,
        remove_entry_handler
    ),
    components(schemas(
        AddProxyRequest,
        ProxyEntry,
        ProxyStatus,
        ProxyRuntimeStatus,
        ProxyEntriesResponse,
        StatusOk,
    ))
)]
pub struct ProxyApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn worker_failure_is_an_internal_execution_error() {
        let response = map_error(ProxyError::Worker("lost acknowledgement".into())).into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read error body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("decode error body");
        assert_eq!(body["error"], "internal");
        assert_eq!(body["message"], "lost acknowledgement");
    }
}
