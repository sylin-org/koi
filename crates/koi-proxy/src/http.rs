use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get};
use axum::Router;
use serde::Deserialize;

use koi_common::error::ErrorCode;

use crate::config::ProxyEntry;
use crate::{ensure_backend_allowed, ProxyError, ProxyRuntime};

#[derive(Debug, Deserialize)]
struct AddProxyRequest {
    name: String,
    listen_port: u16,
    backend: String,
    #[serde(default)]
    allow_remote: bool,
}

/// Build proxy domain routes. The binary crate mounts these at `/v1/proxy/`.
pub fn routes(runtime: Arc<ProxyRuntime>) -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .route("/entries", get(entries_handler).post(add_entry_handler))
        .route("/entries/{name}", delete(remove_entry_handler))
        .layer(Extension(runtime))
}

async fn status_handler(Extension(runtime): Extension<Arc<ProxyRuntime>>) -> impl IntoResponse {
    let status = runtime.status().await;
    Json(serde_json::json!({ "proxies": status }))
}

async fn entries_handler(Extension(runtime): Extension<Arc<ProxyRuntime>>) -> impl IntoResponse {
    let entries = runtime.core().entries().await;
    Json(serde_json::json!({ "entries": entries }))
}

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
