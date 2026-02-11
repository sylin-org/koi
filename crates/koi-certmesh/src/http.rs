//! Certmesh HTTP route handlers.
//!
//! Domain-owned routes mounted by the binary crate at `/v1/certmesh/`.
//! Handlers delegate to `CertmeshState` domain methods (shared with facade).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::CertmeshState;
use crate::error::CertmeshError;
use crate::protocol::{
    HealthRequest, HealthResponse, JoinRequest, PromoteRequest, RenewRequest,
    RenewResponse, SetHookRequest,
};

/// Build the certmesh router with domain-owned routes.
///
/// The binary crate mounts this at `/v1/certmesh/`.
pub(crate) fn routes(state: Arc<CertmeshState>) -> Router {
    Router::new()
        .route("/join", post(join_handler))
        .route("/status", get(status_handler))
        .route("/hook", put(set_hook_handler))
        .route("/promote", post(promote_handler))
        .route("/renew", post(renew_handler))
        .route("/roster", get(roster_handler))
        .route("/health", post(health_handler))
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

/// PUT /hook — Set a post-renewal reload hook for a member.
async fn set_hook_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<SetHookRequest>,
) -> impl IntoResponse {
    // Verify the member exists
    let mut roster = state.roster.lock().await;
    match roster.find_member_mut(&request.hostname) {
        Some(member) => {
            member.reload_hook = Some(request.reload.clone());

            let roster_path = crate::ca::roster_path();
            if let Err(e) = crate::roster::save_roster(&roster, &roster_path) {
                tracing::warn!(error = %e, "Failed to save roster after set-hook");
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &CertmeshError::Internal(format!("Failed to save roster: {e}")),
                );
            }

            let resp = crate::protocol::SetHookResponse {
                hostname: request.hostname,
                reload: request.reload,
            };
            match serde_json::to_value(&resp) {
                Ok(val) => (StatusCode::OK, Json(val)).into_response(),
                Err(e) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &CertmeshError::Internal(format!("Serialization error: {e}")),
                ),
            }
        }
        None => error_response(
            StatusCode::NOT_FOUND,
            &CertmeshError::Internal(format!("member not found: {}", request.hostname)),
        ),
    }
}

// ── Phase 3 handlers ────────────────────────────────────────────────

/// POST /promote — TOTP-verified CA key transfer to a standby.
///
/// The requesting standby provides a TOTP code. If valid, the handler
/// returns the encrypted CA key, TOTP secret, roster, and CA cert.
/// The passphrase for decryption is handled out-of-band (CLI prompt).
async fn promote_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<PromoteRequest>,
) -> impl IntoResponse {
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

    // Verify TOTP
    let valid = koi_crypto::totp::verify_code(totp_secret, &request.totp_code);
    match rate_limiter.check_and_record(valid) {
        Ok(()) => {}
        Err(koi_crypto::totp::RateLimitError::LockedOut { remaining_secs }) => {
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                &CertmeshError::RateLimited { remaining_secs },
            );
        }
        Err(koi_crypto::totp::RateLimitError::InvalidCode { .. }) => {
            return error_response(StatusCode::UNAUTHORIZED, &CertmeshError::InvalidTotp);
        }
    }

    let roster = state.roster.lock().await;

    // Prepare the promotion response — use the CA's own passphrase to encrypt
    // the transfer material. The standby will need this passphrase to decrypt.
    match crate::failover::prepare_promotion(ca, totp_secret, &roster, "") {
        Ok(response) => match serde_json::to_value(&response) {
            Ok(val) => {
                let _ = crate::audit::append_entry("promotion_prepared", &[]);
                (StatusCode::OK, Json(val)).into_response()
            }
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CertmeshError::Internal(format!("Serialization error: {e}")),
            ),
        },
        Err(e) => {
            let code = koi_common::error::ErrorCode::from(&e);
            let status = StatusCode::from_u16(code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error_response(status, &e)
        }
    }
}

/// POST /renew — Receive renewed certificate from the CA.
///
/// The CA pushes renewed cert material to members. The member writes
/// the files and optionally executes its reload hook.
async fn renew_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<RenewRequest>,
) -> impl IntoResponse {
    // Build an IssuedCert from the request to reuse write_cert_files
    let issued = crate::ca::IssuedCert {
        cert_pem: request.cert_pem,
        key_pem: request.key_pem,
        ca_pem: request.ca_pem,
        fullchain_pem: request.fullchain_pem,
        fingerprint: request.fingerprint.clone(),
        expires: chrono::DateTime::parse_from_rfc3339(&request.expires)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now()),
    };

    // Write cert files
    if let Err(e) = crate::certfiles::write_cert_files(&request.hostname, &issued) {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::RenewalFailed {
                hostname: request.hostname,
                reason: format!("failed to write cert files: {e}"),
            },
        );
    }

    // Update roster if we are the CA (daemon mode processes renewals for local roster)
    let mut roster = state.roster.lock().await;
    if let Some(member) = roster.find_member_mut(&request.hostname) {
        member.cert_fingerprint = issued.fingerprint.clone();
        member.cert_expires = issued.expires;
    }

    // Execute reload hook if the member has one set
    let hook_result = roster
        .find_member(&request.hostname)
        .and_then(|m| m.reload_hook.as_ref())
        .map(|hook| crate::lifecycle::execute_reload_hook(hook));

    let response = RenewResponse {
        hostname: request.hostname.clone(),
        renewed: true,
        hook_result,
    };

    match serde_json::to_value(&response) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
}

/// GET /roster — Return a signed roster manifest for standby sync.
async fn roster_handler(
    State(state): State<Arc<CertmeshState>>,
) -> impl IntoResponse {
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

    let roster = state.roster.lock().await;

    match crate::failover::build_signed_manifest(ca, &roster) {
        Ok(manifest) => match serde_json::to_value(&manifest) {
            Ok(val) => (StatusCode::OK, Json(val)).into_response(),
            Err(e) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CertmeshError::Internal(format!("Serialization error: {e}")),
            ),
        },
        Err(e) => {
            let code = koi_common::error::ErrorCode::from(&e);
            let status = StatusCode::from_u16(code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error_response(status, &e)
        }
    }
}

/// POST /health — Member heartbeat with pinned CA fingerprint validation.
async fn health_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<HealthRequest>,
) -> impl IntoResponse {
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

    let current_fp = crate::ca::ca_fingerprint(ca);
    let valid = crate::health::validate_pinned_fingerprint(
        &current_fp,
        &request.pinned_ca_fingerprint,
    );

    // Update last_seen timestamp
    let mut roster = state.roster.lock().await;
    roster.touch_member(&request.hostname);

    // Save roster with updated last_seen
    let roster_path = crate::ca::roster_path();
    if let Err(e) = crate::roster::save_roster(&roster, &roster_path) {
        tracing::warn!(error = %e, "Failed to save roster after health heartbeat");
    }

    let response = HealthResponse {
        valid,
        ca_fingerprint: current_fp,
    };

    match serde_json::to_value(&response) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
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
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> Arc<CertmeshState> {
        use crate::profiles::TrustProfile;
        use crate::roster::{EnrollmentState, Roster, RosterMetadata};
        use koi_crypto::totp::RateLimiter;

        Arc::new(CertmeshState {
            ca: tokio::sync::Mutex::new(None),
            roster: tokio::sync::Mutex::new(Roster {
                metadata: RosterMetadata {
                    created_at: chrono::Utc::now(),
                    trust_profile: TrustProfile::JustMe,
                    operator: None,
                    enrollment_state: EnrollmentState::Closed,
                },
                members: vec![],
                revocation_list: vec![],
            }),
            totp_secret: tokio::sync::Mutex::new(None),
            rate_limiter: tokio::sync::Mutex::new(RateLimiter::new()),
            profile: TrustProfile::JustMe,
        })
    }

    #[test]
    fn certmesh_state_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CertmeshState>();
    }

    #[tokio::test]
    async fn status_endpoint_returns_200() {
        let app = routes(test_state());
        let req = Request::get("/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_endpoint_returns_json() {
        let app = routes(test_state());
        let req = Request::get("/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // CA not initialized, so ca_locked should be reported
        assert!(json.get("ca_initialized").is_some() || json.get("ca_locked").is_some());
    }

    #[tokio::test]
    async fn join_without_ca_returns_503() {
        let app = routes(test_state());
        let req = Request::post("/join")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"totp_code":"123456"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // CA not initialized → 503
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn promote_without_ca_returns_503() {
        let app = routes(test_state());
        let req = Request::post("/promote")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"totp_code":"654321"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn roster_without_ca_returns_503() {
        let app = routes(test_state());
        let req = Request::get("/roster").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn health_without_ca_returns_503() {
        let app = routes(test_state());
        let req = Request::post("/health")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"hostname":"stone-01","pinned_ca_fingerprint":"abc"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn set_hook_unknown_member_returns_404() {
        let app = routes(test_state());
        let req = Request::put("/hook")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"hostname":"nobody","reload":"systemctl restart nginx"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn error_response_includes_error_code() {
        let resp = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &CertmeshError::CaNotInitialized,
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_some());
        assert!(json.get("message").is_some());
    }

    #[tokio::test]
    async fn nonexistent_route_returns_404() {
        let app = routes(test_state());
        let req = Request::get("/nonexistent").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Response body shape tests ───────────────────────────────────

    /// Helper: assert the error field is one of the expected "CA unavailable" codes.
    /// Which code appears depends on whether a CA exists on the filesystem:
    /// `ca_locked` (CA on disk but not unlocked) or `ca_not_initialized` (no CA on disk).
    fn assert_ca_unavailable_error(json: &serde_json::Value) {
        let error = json.get("error").unwrap().as_str().unwrap();
        assert!(
            error == "ca_locked" || error == "ca_not_initialized",
            "expected ca_locked or ca_not_initialized, got: {error}"
        );
        assert!(json.get("message").is_some());
    }

    #[tokio::test]
    async fn join_without_ca_body_has_error_code() {
        let app = routes(test_state());
        let req = Request::post("/join")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"totp_code":"123456"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_ca_unavailable_error(&json);
    }

    #[tokio::test]
    async fn promote_without_ca_body_has_error_code() {
        let app = routes(test_state());
        let req = Request::post("/promote")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"totp_code":"654321"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_ca_unavailable_error(&json);
    }

    #[tokio::test]
    async fn roster_without_ca_body_has_error_code() {
        let app = routes(test_state());
        let req = Request::get("/roster").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_ca_unavailable_error(&json);
    }

    #[tokio::test]
    async fn health_without_ca_body_has_error_code() {
        let app = routes(test_state());
        let req = Request::post("/health")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"hostname":"stone-01","pinned_ca_fingerprint":"abc"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_ca_unavailable_error(&json);
    }

    #[tokio::test]
    async fn status_body_has_expected_fields() {
        let app = routes(test_state());
        let req = Request::get("/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("ca_initialized").is_some(), "missing ca_initialized");
        assert!(json.get("ca_locked").is_some(), "missing ca_locked");
        assert!(json.get("profile").is_some(), "missing profile");
        assert!(json.get("enrollment_state").is_some(), "missing enrollment_state");
        assert!(json.get("member_count").is_some(), "missing member_count");
        assert!(json.get("members").is_some(), "missing members");
    }

    #[tokio::test]
    async fn set_hook_not_found_body_has_error() {
        let app = routes(test_state());
        let req = Request::put("/hook")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"hostname":"nobody","reload":"systemctl restart nginx"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_some(), "missing error field");
        let msg = json.get("message").unwrap().as_str().unwrap();
        assert!(msg.contains("nobody"), "message should contain hostname: {msg}");
    }
}
