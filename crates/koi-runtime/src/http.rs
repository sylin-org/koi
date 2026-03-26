//! Runtime adapter HTTP route handlers.
//!
//! Domain-owned routes mounted by the binary crate at `/v1/runtime/`.

use std::sync::Arc;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use utoipa::ToSchema;

use crate::instance::Instance;
use crate::RuntimeCore;

/// Route path constants.
pub mod paths {
    pub const PREFIX: &str = "/v1/runtime";
    pub const STATUS: &str = "/v1/runtime/status";
    pub const INSTANCES: &str = "/v1/runtime/instances";

    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

/// Build the runtime router with domain-owned routes.
pub fn routes(core: Arc<RuntimeCore>) -> Router {
    use paths::rel;
    Router::new()
        .route(rel(paths::STATUS), get(status_handler))
        .route(rel(paths::INSTANCES), get(instances_handler))
        .layer(Extension(core))
}

/// Runtime adapter status.
#[derive(Debug, Serialize, ToSchema)]
pub struct RuntimeStatus {
    /// Whether the runtime adapter is active.
    pub active: bool,
    /// Backend name (docker, podman, systemd, etc.).
    pub backend: Option<String>,
    /// Number of tracked instances.
    pub instance_count: usize,
}

/// GET /status — Runtime adapter status.
#[utoipa::path(get, path = "/status", tag = "runtime",
    summary = "Runtime adapter status",
    responses((status = 200, body = RuntimeStatus)))]
async fn status_handler(Extension(core): Extension<Arc<RuntimeCore>>) -> impl IntoResponse {
    let status = core.status().await;
    Json(status)
}

/// GET /instances — List all tracked instances.
#[utoipa::path(get, path = "/instances", tag = "runtime",
    summary = "List runtime-managed instances",
    responses((status = 200, body = Vec<Instance>)))]
async fn instances_handler(Extension(core): Extension<Arc<RuntimeCore>>) -> impl IntoResponse {
    match core.list_instances().await {
        Ok(instances) => (StatusCode::OK, Json(instances)).into_response(),
        Err(e) => {
            let code = koi_common::error::ErrorCode::from(&e);
            let status = StatusCode::from_u16(code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            koi_common::http::error_response_with_status(status, code, e.to_string())
        }
    }
}

/// OpenAPI documentation for the runtime domain.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(status_handler, instances_handler),
    components(schemas(
        RuntimeStatus,
        Instance,
        crate::instance::PortMapping,
        crate::instance::PortProtocol,
        crate::instance::InstanceState,
        crate::instance::KoiMetadata,
    ))
)]
pub struct RuntimeApiDoc;
