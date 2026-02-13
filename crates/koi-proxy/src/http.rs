use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use koi_common::error::ErrorCode;

use crate::config::ProxyEntry;
use crate::{ensure_backend_allowed, ProxyError, ProxyRuntime};

#[derive(Debug, Deserialize, ToSchema)]
struct AddProxyRequest {
    name: String,
    listen_port: u16,
    backend: String,
    #[serde(default)]
    allow_remote: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct ProxyStatusResponse {
    proxies: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ProxyEntriesResponse {
    entries: Vec<ProxyEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
struct StatusOk {
    status: String,
}

/// Route path constants — single source of truth for axum routing AND the command manifest.
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

/// Proxy runtime status.
async fn status_handler(Extension(runtime): Extension<Arc<ProxyRuntime>>) -> impl IntoResponse {
    let status = runtime.status().await;
    Json(serde_json::json!({ "proxies": status }))
}

/// List proxy entries.
async fn entries_handler(Extension(runtime): Extension<Arc<ProxyRuntime>>) -> impl IntoResponse {
    let entries = runtime.core().entries().await;
    Json(serde_json::json!({ "entries": entries }))
}

/// Add or update a proxy entry.
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

    let backend = match url::Url::parse(&entry.backend) {
        Ok(url) => url,
        Err(e) => {
            return koi_common::http::error_response(
                ErrorCode::InvalidPayload,
                format!("invalid_backend: {e}"),
            )
            .into_response();
        }
    };

    if let Err(e) = ensure_backend_allowed(&backend, entry.allow_remote) {
        return map_error(e).into_response();
    }
    if entry.allow_remote {
        let host = backend.host_str().unwrap_or("unknown");
        tracing::warn!("Backend traffic to {} is unencrypted", host);
    }

    match runtime.core().upsert(entry).await {
        Ok(_) => {
            if let Err(e) = runtime.reload().await {
                tracing::warn!(error = %e, "Failed to reload proxy runtime after add");
            }
            Json(serde_json::json!({ "status": "ok" })).into_response()
        }
        Err(e) => map_error(e).into_response(),
    }
}

/// Remove a proxy entry by name.
async fn remove_entry_handler(
    Extension(runtime): Extension<Arc<ProxyRuntime>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match runtime.core().remove(&name).await {
        Ok(_) => {
            if let Err(e) = runtime.reload().await {
                tracing::warn!(error = %e, "Failed to reload proxy runtime after remove");
            }
            Json(serde_json::json!({ "status": "ok" })).into_response()
        }
        Err(e) => map_error(e).into_response(),
    }
}

fn map_error(err: ProxyError) -> impl IntoResponse {
    match err {
        ProxyError::InvalidConfig(msg) | ProxyError::Config(msg) => {
            koi_common::http::error_response(ErrorCode::InvalidPayload, msg)
        }
        ProxyError::NotFound(msg) => koi_common::http::error_response(ErrorCode::NotFound, msg),
        ProxyError::Io(msg) | ProxyError::Forward(msg) => {
            koi_common::http::error_response(ErrorCode::IoError, msg)
        }
    }
}

/// OpenAPI documentation for the proxy domain.
#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(
    AddProxyRequest,
    ProxyEntry,
    ProxyStatusResponse,
    ProxyEntriesResponse,
    StatusOk
)))]
pub struct ProxyApiDoc;
