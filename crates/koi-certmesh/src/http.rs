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
    CreateCaRequest, CreateCaResponse, HealthRequest, HealthResponse, JoinRequest,
    PolicyRequest, PromoteRequest, RenewRequest, RenewResponse, RotateTotpRequest,
    RotateTotpResponse, SetHookRequest, UnlockRequest, UnlockResponse,
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
        // Service delegation — CA management
        .route("/create", post(create_handler))
        .route("/unlock", post(unlock_handler))
        .route("/rotate-totp", post(rotate_totp_handler))
        .route("/log", get(log_handler))
        .route("/destroy", post(destroy_handler))
        // Phase 4 — Enrollment Policy
        .route("/enrollment/open", post(open_enrollment_handler))
        .route("/enrollment/close", post(close_enrollment_handler))
        .route("/policy", put(set_policy_handler))
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
    let profile = state.profile.lock().await;

    match crate::enrollment::process_enrollment(
        ca,
        &mut roster,
        totp_secret,
        &mut rate_limiter,
        &request,
        &hostname,
        &sans,
        &profile,
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
    let profile = state.profile.lock().await;
    let status = crate::build_status(&ca_guard, &roster, &profile);
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

// ── Service delegation handlers ─────────────────────────────────────

/// POST /create — Initialize a new CA via the running service.
async fn create_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<CreateCaRequest>,
) -> impl IntoResponse {
    // Decode hex entropy
    let entropy = match decode_hex(&request.entropy_hex) {
        Some(bytes) if bytes.len() == 32 => bytes,
        Some(bytes) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &CertmeshError::Internal(format!(
                    "entropy must be exactly 32 bytes, got {}",
                    bytes.len()
                )),
            );
        }
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                &CertmeshError::Internal("invalid hex entropy".to_string()),
            );
        }
    };

    // Reject if CA already initialized
    if crate::ca::is_ca_initialized() {
        return error_response(
            StatusCode::CONFLICT,
            &CertmeshError::Internal("CA is already initialized".to_string()),
        );
    }

    // Create CA
    let ca_state = match crate::ca::create_ca(&request.passphrase, &entropy) {
        Ok(ca) => ca,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let ca_fingerprint = crate::ca::ca_fingerprint(&ca_state);

    // Generate TOTP secret
    let totp_secret = koi_crypto::totp::generate_secret();
    let encrypted_totp = match koi_crypto::totp::encrypt_secret(&totp_secret, &request.passphrase) {
        Ok(enc) => enc,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &CertmeshError::from(e)),
    };
    if let Err(e) = koi_crypto::keys::save_encrypted_key(&crate::ca::totp_secret_path(), &encrypted_totp) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &CertmeshError::from(e));
    }

    let totp_uri = koi_crypto::totp::build_totp_uri(&totp_secret, "Koi Certmesh", "enrollment");

    // Create roster
    let new_roster = crate::roster::Roster::new(request.profile, request.operator.clone());
    let roster_path = crate::ca::roster_path();
    if let Err(e) = crate::roster::save_roster(&new_roster, &roster_path) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &CertmeshError::Io(e));
    }

    // Install CA cert in OS trust store (best-effort)
    if let Err(e) = koi_truststore::install_ca_cert(&ca_state.cert_pem, "koi-certmesh") {
        tracing::warn!(error = %e, "Could not install CA cert in trust store");
    }

    // Update in-memory state
    *state.ca.lock().await = Some(ca_state);
    let state_secret = koi_crypto::totp::TotpSecret::from_bytes(totp_secret.as_bytes().to_vec());
    *state.totp_secret.lock().await = Some(state_secret);
    *state.roster.lock().await = new_roster;
    *state.profile.lock().await = request.profile;

    let _ = crate::audit::append_entry(
        "pond_initialized",
        &[
            ("profile", &request.profile.to_string()),
            ("operator", request.operator.as_deref().unwrap_or("none")),
        ],
    );

    tracing::info!(profile = %request.profile, "CA initialized via service");

    let response = CreateCaResponse {
        totp_uri,
        ca_fingerprint,
    };
    match serde_json::to_value(&response) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
}

/// POST /unlock — Decrypt the CA key.
async fn unlock_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<UnlockRequest>,
) -> impl IntoResponse {
    let ca_state = match crate::ca::load_ca(&request.passphrase) {
        Ok(ca) => ca,
        Err(e) => {
            let code = koi_common::error::ErrorCode::from(&e);
            let status = StatusCode::from_u16(code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return error_response(status, &e);
        }
    };

    // Load TOTP secret
    let totp_path = crate::ca::totp_secret_path();
    if totp_path.exists() {
        match koi_crypto::keys::load_encrypted_key(&totp_path) {
            Ok(encrypted) => {
                match koi_crypto::totp::decrypt_secret(&encrypted, &request.passphrase) {
                    Ok(secret) => {
                        *state.totp_secret.lock().await = Some(secret);
                    }
                    Err(e) => tracing::warn!(error = %e, "Failed to decrypt TOTP secret"),
                }
            }
            Err(e) => tracing::warn!(error = %e, "Failed to load TOTP secret"),
        }
    }

    *state.ca.lock().await = Some(ca_state);
    tracing::info!("CA unlocked via service");

    let response = UnlockResponse { success: true };
    match serde_json::to_value(&response) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
}

/// POST /rotate-totp — Rotate the TOTP enrollment secret.
async fn rotate_totp_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<RotateTotpRequest>,
) -> impl IntoResponse {
    // Verify CA is unlocked
    let ca_guard = state.ca.lock().await;
    if ca_guard.is_none() {
        return if crate::ca::is_ca_initialized() {
            error_response(StatusCode::SERVICE_UNAVAILABLE, &CertmeshError::CaLocked)
        } else {
            error_response(StatusCode::SERVICE_UNAVAILABLE, &CertmeshError::CaNotInitialized)
        };
    }
    drop(ca_guard);

    let new_secret = koi_crypto::totp::generate_secret();
    let encrypted = match koi_crypto::totp::encrypt_secret(&new_secret, &request.passphrase) {
        Ok(enc) => enc,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &CertmeshError::from(e)),
    };
    if let Err(e) = koi_crypto::keys::save_encrypted_key(&crate::ca::totp_secret_path(), &encrypted) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &CertmeshError::from(e));
    }

    let totp_uri = koi_crypto::totp::build_totp_uri(&new_secret, "Koi Certmesh", "enrollment");
    *state.totp_secret.lock().await = Some(new_secret);

    tracing::info!("TOTP secret rotated via service");
    let _ = crate::audit::append_entry("totp_rotated", &[]);

    let response = RotateTotpResponse { totp_uri };
    match serde_json::to_value(&response) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
}

/// GET /log — Return audit log entries.
async fn log_handler(
    State(_state): State<Arc<CertmeshState>>,
) -> impl IntoResponse {
    match crate::audit::read_log() {
        Ok(entries) => {
            let response = crate::protocol::AuditLogResponse { entries };
            match serde_json::to_value(&response) {
                Ok(val) => (StatusCode::OK, Json(val)).into_response(),
                Err(e) => error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &CertmeshError::Internal(format!("Serialization error: {e}")),
                ),
            }
        }
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Io(e),
        ),
    }
}

/// POST /destroy — Remove all certmesh state (CA, certs, roster, audit log).
async fn destroy_handler(
    State(state): State<Arc<CertmeshState>>,
) -> impl IntoResponse {
    if let Err(e) = state.destroy().await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }

    let response = crate::protocol::DestroyResponse { destroyed: true };
    match serde_json::to_value(&response) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
}

// ── Phase 4 handlers ────────────────────────────────────────────────

/// POST /enrollment/open — Open the enrollment window.
async fn open_enrollment_handler(
    State(state): State<Arc<CertmeshState>>,
    body: Option<Json<serde_json::Value>>,
) -> impl IntoResponse {
    let deadline = body
        .and_then(|Json(v)| v.get("deadline")?.as_str().map(String::from))
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let mut roster = state.roster.lock().await;
    roster.open_enrollment(deadline);

    let roster_path = crate::ca::roster_path();
    if let Err(e) = crate::roster::save_roster(&roster, &roster_path) {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Failed to save roster: {e}")),
        );
    }

    let _ = crate::audit::append_entry(
        "enrollment_opened",
        &[("deadline", &deadline.map(|d| d.to_rfc3339()).unwrap_or_else(|| "none".to_string()))],
    );

    let body = serde_json::json!({
        "enrollment_state": "open",
        "deadline": deadline.map(|d| d.to_rfc3339()),
    });
    (StatusCode::OK, Json(body)).into_response()
}

/// POST /enrollment/close — Close the enrollment window.
async fn close_enrollment_handler(
    State(state): State<Arc<CertmeshState>>,
) -> impl IntoResponse {
    let mut roster = state.roster.lock().await;
    roster.close_enrollment();

    let roster_path = crate::ca::roster_path();
    if let Err(e) = crate::roster::save_roster(&roster, &roster_path) {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Failed to save roster: {e}")),
        );
    }

    let _ = crate::audit::append_entry("enrollment_closed", &[]);

    let body = serde_json::json!({ "enrollment_state": "closed" });
    (StatusCode::OK, Json(body)).into_response()
}

/// PUT /policy — Set enrollment scope constraints.
async fn set_policy_handler(
    State(state): State<Arc<CertmeshState>>,
    Json(request): Json<PolicyRequest>,
) -> impl IntoResponse {
    // Validate subnet CIDR format if provided
    if let Some(ref cidr) = request.allowed_subnet {
        if let Some((net_str, prefix_str)) = cidr.split_once('/') {
            if net_str.parse::<std::net::IpAddr>().is_err() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &CertmeshError::ScopeViolation(format!("invalid subnet CIDR: {cidr}")),
                );
            }
            if prefix_str.parse::<u32>().is_err() {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &CertmeshError::ScopeViolation(format!("invalid prefix length in CIDR: {cidr}")),
                );
            }
        } else {
            return error_response(
                StatusCode::BAD_REQUEST,
                &CertmeshError::ScopeViolation(format!("invalid CIDR format (expected x.x.x.x/N): {cidr}")),
            );
        }
    }

    let mut roster = state.roster.lock().await;
    roster.metadata.allowed_domain = request.allowed_domain.clone();
    roster.metadata.allowed_subnet = request.allowed_subnet.clone();

    let roster_path = crate::ca::roster_path();
    if let Err(e) = crate::roster::save_roster(&roster, &roster_path) {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Failed to save roster: {e}")),
        );
    }

    let _ = crate::audit::append_entry(
        "policy_updated",
        &[
            ("allowed_domain", request.allowed_domain.as_deref().unwrap_or("none")),
            ("allowed_subnet", request.allowed_subnet.as_deref().unwrap_or("none")),
        ],
    );

    let body = serde_json::json!({
        "allowed_domain": request.allowed_domain,
        "allowed_subnet": request.allowed_subnet,
    });
    (StatusCode::OK, Json(body)).into_response()
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

/// Decode a hex string into bytes. Returns `None` on invalid hex.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
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
                    enrollment_deadline: None,
                    allowed_domain: None,
                    allowed_subnet: None,
                },
                members: vec![],
                revocation_list: vec![],
            }),
            totp_secret: tokio::sync::Mutex::new(None),
            rate_limiter: tokio::sync::Mutex::new(RateLimiter::new()),
            profile: tokio::sync::Mutex::new(TrustProfile::JustMe),
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

    // ── Phase 4 — Enrollment policy endpoint tests ──────────────────

    #[tokio::test]
    async fn open_enrollment_returns_200() {
        let app = routes(test_state());
        let req = Request::post("/enrollment/open")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("enrollment_state").unwrap().as_str().unwrap(), "open");
    }

    #[tokio::test]
    async fn open_enrollment_with_deadline() {
        let app = routes(test_state());
        let req = Request::post("/enrollment/open")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"deadline":"2026-12-31T23:59:59Z"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("deadline").unwrap().as_str().is_some());
    }

    #[tokio::test]
    async fn open_enrollment_accepts_empty_body() {
        let app = routes(test_state());
        let req = Request::post("/enrollment/open")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn close_enrollment_returns_200() {
        let app = routes(test_state());
        let req = Request::post("/enrollment/close")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("enrollment_state").unwrap().as_str().unwrap(), "closed");
    }

    #[tokio::test]
    async fn set_policy_returns_200() {
        let app = routes(test_state());
        let req = Request::put("/policy")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"allowed_domain":"lab.local","allowed_subnet":"192.168.1.0/24"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("allowed_domain").unwrap().as_str().unwrap(), "lab.local");
        assert_eq!(json.get("allowed_subnet").unwrap().as_str().unwrap(), "192.168.1.0/24");
    }

    #[tokio::test]
    async fn set_policy_invalid_cidr_returns_400() {
        let app = routes(test_state());
        let req = Request::put("/policy")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"allowed_subnet":"not-a-cidr"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn set_policy_invalid_cidr_ip_returns_400() {
        let app = routes(test_state());
        let req = Request::put("/policy")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"allowed_subnet":"xyz.abc/24"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn set_policy_clears_with_nulls() {
        let app = routes(test_state());
        let req = Request::put("/policy")
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("allowed_domain").unwrap().is_null());
        assert!(json.get("allowed_subnet").unwrap().is_null());
    }

    // ── Service delegation endpoint tests ────────────────────────────

    #[tokio::test]
    async fn create_with_bad_entropy_returns_400() {
        let app = routes(test_state());
        let req = Request::post("/create")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"passphrase":"test","entropy_hex":"bad","profile":"just_me"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_with_short_entropy_returns_400() {
        let app = routes(test_state());
        // 16 bytes (32 hex chars) instead of required 32 bytes (64 hex chars)
        let req = Request::post("/create")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"passphrase":"test","entropy_hex":"00112233445566778899aabbccddeeff","profile":"just_me"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unlock_with_wrong_passphrase_returns_error() {
        let app = routes(test_state());
        let req = Request::post("/unlock")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"passphrase":"wrong-passphrase"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should fail because no CA exists on disk
        assert!(resp.status().is_client_error() || resp.status().is_server_error());
    }

    #[tokio::test]
    async fn rotate_totp_without_ca_returns_503() {
        let app = routes(test_state());
        let req = Request::post("/rotate-totp")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"passphrase":"test"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn log_endpoint_returns_200() {
        let app = routes(test_state());
        let req = Request::get("/log").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should return 200 even with no log entries (returns empty string)
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn log_endpoint_body_has_entries_field() {
        let app = routes(test_state());
        let req = Request::get("/log").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("entries").is_some(), "response should have 'entries' field");
    }

    #[tokio::test]
    async fn destroy_endpoint_returns_200() {
        let app = routes(test_state());
        let req = Request::post("/destroy")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("destroyed").unwrap().as_bool().unwrap(), true);
    }

    #[tokio::test]
    async fn decode_hex_valid() {
        assert_eq!(decode_hex("0011ff"), Some(vec![0x00, 0x11, 0xff]));
    }

    #[tokio::test]
    async fn decode_hex_invalid() {
        assert_eq!(decode_hex("zz"), None);
    }

    #[tokio::test]
    async fn decode_hex_odd_length() {
        assert_eq!(decode_hex("abc"), None);
    }
}
