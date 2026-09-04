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
use crate::{HealthCheckConfig, HealthError, HealthRuntime, HealthSnapshot, HealthTransitionLog};

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

/// Route path constants - single source of truth for axum routing AND the command manifest.
pub mod paths {
    pub const PREFIX: &str = "/v1/health";

    pub const STATUS: &str = "/v1/health/status";
    pub const LOG: &str = "/v1/health/log";
    pub const LIST: &str = "/v1/health/list";
    pub const ADD: &str = "/v1/health/add";
    pub const REMOVE: &str = "/v1/health/remove/{name}";

    /// Strip the crate nest prefix to get the relative path for axum routing.
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

/// Build health domain routes. The binary crate mounts these at `/v1/health/`.
pub fn routes(runtime: Arc<HealthRuntime>) -> Router {
    use paths::rel;
    Router::new()
        .route(rel(paths::STATUS), get(status_handler))
        .route(rel(paths::LOG), get(log_handler))
        .route(rel(paths::LIST), get(list_checks_handler))
        .route(rel(paths::ADD), post(add_check_handler))
        .route(rel(paths::REMOVE), delete(remove_check_handler))
        .layer(Extension(runtime))
}

#[utoipa::path(get, path = "/status", tag = "health",
    summary = "Snapshot of all checks with current state",
    responses((status = 200, body = HealthSnapshot)))]
async fn status_handler(Extension(runtime): Extension<Arc<HealthRuntime>>) -> impl IntoResponse {
    Json(runtime.status().as_ref().clone())
}

#[utoipa::path(get, path = "/log", tag = "health",
    summary = "Read durable health transition history",
    responses((status = 200, body = HealthTransitionLog)))]
async fn log_handler(
    Extension(runtime): Extension<Arc<HealthRuntime>>,
) -> axum::response::Response {
    match runtime.transition_log().await {
        Ok(log) => Json(log).into_response(),
        Err(error) => map_error(error),
    }
}

#[utoipa::path(get, path = "/list", tag = "health",
    summary = "List registered check configurations",
    responses((status = 200, body = ChecksListResponse)))]
async fn list_checks_handler(
    Extension(runtime): Extension<Arc<HealthRuntime>>,
) -> impl IntoResponse {
    let checks = runtime.list_checks().await;
    Json(serde_json::json!({ "checks": checks }))
}

#[utoipa::path(post, path = "/add", tag = "health",
    summary = "Register a health check",
    request_body = AddCheckRequest,
    responses((status = 200, body = StatusOk)))]
async fn add_check_handler(
    Extension(runtime): Extension<Arc<HealthRuntime>>,
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

    match runtime.add_check(check).await {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(err) => map_error(err),
    }
}

#[utoipa::path(delete, path = "/remove/{name}", tag = "health",
    summary = "Remove a health check",
    params(("name" = String, Path, description = "Check name")),
    responses((status = 200, body = StatusOk)))]
async fn remove_check_handler(
    Extension(runtime): Extension<Arc<HealthRuntime>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match runtime.remove_check(&name).await {
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
        HealthError::ShutDown => koi_common::http::error_response(
            ErrorCode::ShuttingDown,
            "health runtime has already shut down",
        ),
        HealthError::Worker(message) => {
            koi_common::http::error_response(ErrorCode::Internal, message)
        }
    }
}

/// OpenAPI documentation for the health domain.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        status_handler,
        log_handler,
        list_checks_handler,
        add_check_handler,
        remove_check_handler
    ),
    components(schemas(
        HealthSnapshot,
        HealthTransitionLog,
        AddCheckRequest,
        ChecksListResponse,
        StatusOk,
        HealthCheckConfig,
        crate::ServiceHealth,
        crate::MachineHealth,
        crate::ServiceCheckKind,
        crate::ServiceStatus,
    ))
)]
pub struct HealthApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    #[tokio::test]
    async fn status_endpoint_serializes_the_authoritative_health_snapshot() {
        let state_path =
            koi_common::test::ensure_data_dir("koi-health-http-status-tests").join("health.json");
        let core = Arc::new(
            crate::HealthCore::open(
                crate::HealthPaths::new(state_path.clone(), state_path.with_extension("log")),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("health core"),
        );
        let runtime = Arc::new(HealthRuntime::new(core));
        let expected = runtime.status();

        let response = status_handler(Extension(runtime)).await.into_response();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("status body");
        let actual: HealthSnapshot = serde_json::from_slice(&bytes).expect("health status JSON");
        assert_eq!(&actual, expected.as_ref());
    }

    #[tokio::test]
    async fn log_endpoint_reads_the_transition_history_owned_by_health() {
        let root = koi_common::test::ensure_data_dir("koi-health-http-log-tests")
            .join(format!("log-{}", koi_common::id::generate_short_id()));
        let state_path = root.join("health.json");
        let log_path = state_path.with_extension("log");
        crate::log::append_transition(
            &log_path,
            "api",
            crate::ServiceStatus::Unknown,
            crate::ServiceStatus::Down,
            "connection refused",
        )
        .expect("append transition fixture");
        let core = Arc::new(
            crate::HealthCore::open(
                crate::HealthPaths::new(state_path, log_path),
                None,
                None,
                None,
                None,
            )
            .await
            .expect("health core"),
        );
        let response = log_handler(Extension(Arc::new(HealthRuntime::new(core)))).await;

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("log body");
        let actual: HealthTransitionLog =
            serde_json::from_slice(&bytes).expect("health transition log JSON");
        assert!(actual.entries.contains("api | Unknown -> Down"));
        assert!(actual.entries.contains("connection refused"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn openapi_declares_the_real_transition_log_route() {
        let spec = HealthApiDoc::openapi();
        assert!(spec.paths.paths.contains_key("/log"));
    }
}
