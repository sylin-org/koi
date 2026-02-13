use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use koi_common::error::ErrorCode;

use crate::service::ServiceCheckKind;
use crate::state::{DEFAULT_INTERVAL_SECS, DEFAULT_TIMEOUT_SECS};
use crate::{HealthCheckConfig, HealthCore, HealthError, HealthSnapshot};

#[derive(Debug, Deserialize, ToSchema)]
struct AddCheckRequest {
    name: String,
    kind: String,
    target: String,
    interval_secs: Option<u64>,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ChecksListResponse {
    checks: Vec<HealthCheckConfig>,
}

#[derive(Debug, Serialize, ToSchema)]
struct StatusOk {
    status: String,
}

/// Route path constants — single source of truth for axum routing AND the command manifest.
pub mod paths {
    pub const PREFIX: &str = "/v1/health";

    pub const STATUS: &str = "/v1/health/status";
    pub const LIST: &str = "/v1/health/list";
    pub const ADD: &str = "/v1/health/add";
    pub const REMOVE: &str = "/v1/health/remove/{name}";

    /// Strip the crate nest prefix to get the relative path for axum routing.
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

/// Build health domain routes. The binary crate mounts these at `/v1/health/`.
pub fn routes(core: Arc<HealthCore>) -> Router {
    use paths::rel;
    Router::new()
        .route(rel(paths::STATUS), get(status_handler))
        .route(rel(paths::LIST), get(list_checks_handler))
        .route(rel(paths::ADD), post(add_check_handler))
        .route(rel(paths::REMOVE), delete(remove_check_handler))
        .layer(Extension(core))
}

/// Health snapshot with machine and service status.
async fn status_handler(Extension(core): Extension<Arc<HealthCore>>) -> impl IntoResponse {
    let snapshot: HealthSnapshot = core.snapshot().await;
    Json(snapshot)
}

/// List configured health checks.
async fn list_checks_handler(Extension(core): Extension<Arc<HealthCore>>) -> impl IntoResponse {
    let checks = core.list_checks().await;
    Json(serde_json::json!({ "checks": checks }))
}

/// Add a health check.
async fn add_check_handler(
    Extension(core): Extension<Arc<HealthCore>>,
    Json(payload): Json<AddCheckRequest>,
) -> impl IntoResponse {
    let kind = match parse_kind(&payload.kind) {
        Some(kind) => kind,
        None => {
            return koi_common::http::error_response(
                ErrorCode::InvalidPayload,
                "invalid_check_kind",
            )
            .into_response();
        }
    };

    let check = HealthCheckConfig {
        name: payload.name,
        kind,
        target: payload.target,
        interval_secs: payload.interval_secs.unwrap_or(DEFAULT_INTERVAL_SECS),
        timeout_secs: payload.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
    };

    match core.add_check(check).await {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(err) => map_error(err),
    }
}

/// Remove a health check by name.
async fn remove_check_handler(
    Extension(core): Extension<Arc<HealthCore>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match core.remove_check(&name).await {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(err) => map_error(err),
    }
}

fn parse_kind(kind: &str) -> Option<ServiceCheckKind> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "http" => Some(ServiceCheckKind::Http),
        "tcp" => Some(ServiceCheckKind::Tcp),
        _ => None,
    }
}

fn map_error(err: HealthError) -> axum::response::Response {
    match err {
        HealthError::InvalidCheck(msg) => {
            koi_common::http::error_response(ErrorCode::InvalidPayload, msg)
        }
        HealthError::NotFound(msg) => koi_common::http::error_response(ErrorCode::NotFound, msg),
        HealthError::Io(msg) => koi_common::http::error_response(ErrorCode::IoError, msg),
    }
}

/// OpenAPI documentation for the health domain.
#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(
    HealthSnapshot,
    AddCheckRequest,
    ChecksListResponse,
    StatusOk,
    HealthCheckConfig,
    crate::ServiceHealth,
    crate::MachineHealth,
    crate::ServiceCheckKind,
    crate::ServiceStatus,
)))]
pub struct HealthApiDoc;
