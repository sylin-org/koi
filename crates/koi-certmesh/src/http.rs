//! Certmesh HTTP route handlers.
//!
//! Domain-owned routes mounted by the binary crate at `/v1/certmesh/`.
//! Handlers delegate to `CertmeshState` domain methods (shared with facade).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::CertmeshState;
use crate::error::CertmeshError;
use crate::protocol::JoinRequest;

/// Build the certmesh router with domain-owned routes.
///
/// The binary crate mounts this at `/v1/certmesh/`.
pub(crate) fn routes(state: Arc<CertmeshState>) -> Router {
    Router::new()
        .route("/join", post(join_handler))
        .route("/status", get(status_handler))
        .with_state(state)
}

/// POST /join — Enroll a new member in the mesh.
async fn join_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<JoinRequest>,
) -> impl IntoResponse {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let sans = vec![hostname.clone(), format!("{hostname}.local")];

    let ca_guard = state.ca.lock().await;
    let ca = match ca_guard.as_ref() {
        Some(ca) => ca,
        None => {
            return if crate::ca::is_ca_initialized() {
                error_response(StatusCode::SERVICE_UNAVAILABLE, &CertmeshError::CaLocked)
            } else {
                error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &CertmeshError::CaNotInitialized,
                )
            };
        }
    };

    let mut roster = state.roster.lock().await;
    let totp_guard = state.totp_secret.lock().await;
    let totp_secret = match totp_guard.as_ref() {
        Some(s) => s,
        None => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &CertmeshError::CaLocked,
            );
        }
    };
    let mut rate_limiter = state.rate_limiter.lock().await;

    match crate::enrollment::process_enrollment(
        ca,
        &mut roster,
        totp_secret,
        &mut rate_limiter,
        &request,
        &hostname,
        &sans,
        &state.profile,
    ) {
        Ok((response, _issued)) => {
            // Save roster after successful enrollment
            let roster_path = crate::ca::roster_path();
            if let Err(e) = crate::roster::save_roster(&roster, &roster_path) {
                tracing::warn!(error = %e, "Failed to save roster after enrollment");
            }
            match serde_json::to_value(&response) {
                Ok(val) => (StatusCode::OK, Json(val)).into_response(),
                Err(e) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &CertmeshError::Internal(format!("Serialization error: {e}")),
                ),
            }
        }
        Err(e) => {
            let code = koi_common::error::ErrorCode::from(&e);
            let status = StatusCode::from_u16(code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error_response(status, &e)
        }
    }
}

/// GET /status — Certmesh status overview.
async fn status_handler(
    State(state): State<Arc<CertmeshState>>,
) -> impl IntoResponse {
    let ca_guard = state.ca.lock().await;
    let roster = state.roster.lock().await;
    let status = crate::build_status(&ca_guard, &roster, &state.profile);
    Json(status)
}

fn error_response(status: StatusCode, error: &CertmeshError) -> axum::response::Response {
    let code = koi_common::error::ErrorCode::from(error);
    let body = serde_json::json!({
        "error": code,
        "message": error.to_string(),
    });
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certmesh_state_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CertmeshState>();
    }
}
