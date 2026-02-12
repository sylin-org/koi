use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get};
use axum::Router;
use serde::Deserialize;

use koi_common::error::ErrorCode;

use crate::state::{DEFAULT_INTERVAL_SECS, DEFAULT_TIMEOUT_SECS};
use crate::{HealthCore, HealthError, HealthSnapshot, HealthCheckConfig};
use crate::service::ServiceCheckKind;

#[derive(Clone)]
struct HealthHttpState {
    core: Arc<HealthCore>,
}

#[derive(Debug, Deserialize)]
struct AddCheckRequest {
    name: String,
    kind: String,
    target: String,
    interval_secs: Option<u64>,
    timeout_secs: Option<u64>,
}

/// Build health domain routes. The binary crate mounts these at `/v1/health/`.
pub fn routes(core: Arc<HealthCore>) -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .route("/checks", get(list_checks_handler).post(add_check_handler))
        .route("/checks/{name}", delete(remove_check_handler))
        .with_state(HealthHttpState { core })
}

async fn status_handler(State(state): State<HealthHttpState>) -> impl IntoResponse {
    let snapshot: HealthSnapshot = state.core.snapshot().await;
    Json(snapshot)
}

async fn list_checks_handler(State(state): State<HealthHttpState>) -> impl IntoResponse {
    let checks = state.core.list_checks().await;
    Json(serde_json::json!({ "checks": checks }))
}

async fn add_check_handler(
    State(state): State<HealthHttpState>,
    Json(payload): Json<AddCheckRequest>,
) -> impl IntoResponse {
    let kind = match parse_kind(&payload.kind) {
        Some(kind) => kind,
        None => {
            return error_response(
                axum::http::StatusCode::BAD_REQUEST,
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

    match state.core.add_check(check).await {
        Ok(()) => Json(serde_json::json!({ "status": "ok" })).into_response(),
        Err(err) => map_error(err),
    }
}

async fn remove_check_handler(
    State(state): State<HealthHttpState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.core.remove_check(&name).await {
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
        HealthError::InvalidCheck(msg) => error_response(
            axum::http::StatusCode::BAD_REQUEST,
            ErrorCode::InvalidPayload,
            &msg,
        )
        .into_response(),
        HealthError::NotFound(msg) => error_response(
            axum::http::StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            &msg,
        )
        .into_response(),
        HealthError::Io(msg) => error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::IoError,
            &msg,
        )
        .into_response(),
    }
}

fn error_response(
    status: axum::http::StatusCode,
    code: ErrorCode,
    message: &str,
) -> impl IntoResponse {
    let body = serde_json::json!({
        "error": code,
        "message": message,
    });
    (status, Json(body))
}
