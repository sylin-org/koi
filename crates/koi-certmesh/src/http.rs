//! Certmesh HTTP route handlers.
//!
//! Domain-owned routes mounted by the binary crate at `/v1/certmesh/`.
//! Handlers delegate to `CertmeshState` domain methods (shared with facade).

use std::sync::Arc;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::error::CertmeshError;
use crate::{CertmeshCore, CertmeshState};
use koi_common::encoding::{hex_decode, hex_encode};

use crate::protocol::{
    AuditLogResponse, BackupRequest, BackupResponse, CertmeshStatus, CreateCaRequest,
    CreateCaResponse, DestroyResponse, EnrollmentSummary, HealthRequest, HealthResponse,
    InstallCertRequest, InstallCertResponse, InviteRequest, InviteResponse, JoinRequest,
    JoinResponse, MemberCsrRequest, MemberCsrResponse, PromoteRequest, PromoteResponse,
    RenewRequest, RenewResponse, RestoreRequest, RestoreResponse, RevokeRequest, RevokeResponse,
    RotateAuthRequest, RotateAuthResponse, SetHookRequest, SetHookResponse, UnlockRequest,
    UnlockResponse,
};

/// Authenticated client certificate CN, injected by the mTLS adapter as an axum Extension.
///
/// When a request arrives over the mTLS port, the adapter extracts the CN from the
/// client certificate and attaches it as `Extension(ClientCn(cn))`. Handlers that
/// need per-caller authorization (set-hook, health, renew) check this against the
/// hostname in the request body. Handlers on the plain HTTP port receive `None`.
#[derive(Clone, Debug)]
pub struct ClientCn(pub String);

/// Route path constants - single source of truth for axum routing AND the command manifest.
pub mod paths {
    pub const PREFIX: &str = "/v1/certmesh";

    pub const JOIN: &str = "/v1/certmesh/join";
    pub const INVITE: &str = "/v1/certmesh/invite";
    /// Local: generate this member's keypair + CSR (key persisted locally).
    pub const MEMBER_CSR: &str = "/v1/certmesh/member-csr";
    /// Local: install a CA-signed cert next to the member key.
    pub const MEMBER_CERT: &str = "/v1/certmesh/member-cert";
    pub const STATUS: &str = "/v1/certmesh/status";
    /// Signed, monotonic trust bundle (ADR-017 P1). A GET, so the DAT middleware
    /// exempts it — it is integrity-protected by its own signature, like a CRL.
    pub const TRUST_BUNDLE: &str = "/v1/certmesh/trust-bundle";
    pub const SET_HOOK: &str = "/v1/certmesh/set-hook";
    pub const PROMOTE: &str = "/v1/certmesh/promote";
    pub const RENEW: &str = "/v1/certmesh/renew";
    pub const HEALTH: &str = "/v1/certmesh/health";
    pub const CREATE: &str = "/v1/certmesh/create";
    pub const UNLOCK: &str = "/v1/certmesh/unlock";
    pub const ROTATE_AUTH: &str = "/v1/certmesh/rotate-auth";
    pub const LOG: &str = "/v1/certmesh/log";
    pub const DESTROY: &str = "/v1/certmesh/destroy";
    pub const BACKUP: &str = "/v1/certmesh/backup";
    pub const RESTORE: &str = "/v1/certmesh/restore";
    pub const REVOKE: &str = "/v1/certmesh/revoke";
    pub const OPEN_ENROLLMENT: &str = "/v1/certmesh/open-enrollment";
    pub const CLOSE_ENROLLMENT: &str = "/v1/certmesh/close-enrollment";

    /// Strip the crate nest prefix to get the relative path for axum routing.
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

/// Build the certmesh router with domain-owned routes.
///
/// The binary crate mounts this at `/v1/certmesh/`.
pub(crate) fn routes(state: Arc<CertmeshState>) -> Router {
    use paths::rel;
    Router::new()
        .route(rel(paths::JOIN), post(join_handler))
        .route(rel(paths::INVITE), post(invite_handler))
        .route(rel(paths::MEMBER_CSR), post(member_csr_handler))
        .route(rel(paths::MEMBER_CERT), post(member_cert_handler))
        .route(rel(paths::STATUS), get(status_handler))
        .route(rel(paths::TRUST_BUNDLE), get(trust_bundle_handler))
        .route(rel(paths::SET_HOOK), put(set_hook_handler))
        // NOTE: /renew is intentionally NOT on the plain-HTTP router. Renewal is
        // member-initiated over mTLS only (ADR-017 F6) — it lives on
        // `inter_node_routes` where the caller's identity comes from its client
        // cert. A plain-HTTP renewal has no authenticated CN and is refused.
        .route(rel(paths::HEALTH), post(health_handler))
        // Service delegation - CA management
        .route(rel(paths::CREATE), post(create_handler))
        .route(rel(paths::UNLOCK), post(unlock_handler))
        .route(rel(paths::ROTATE_AUTH), post(rotate_auth_handler))
        .route(rel(paths::LOG), get(log_handler))
        .route(rel(paths::DESTROY), post(destroy_handler))
        .route(rel(paths::BACKUP), post(backup_handler))
        .route(rel(paths::RESTORE), post(restore_handler))
        .route(rel(paths::REVOKE), post(revoke_handler))
        // Enrollment toggle
        .route(rel(paths::OPEN_ENROLLMENT), post(open_enrollment_handler))
        .route(rel(paths::CLOSE_ENROLLMENT), post(close_enrollment_handler))
        .layer(Extension(state))
}

/// Build the inter-node router for the mTLS listener.
///
/// Contains only routes that require mutual TLS between mesh members:
/// promote, health, renew, set-hook.
/// Mounted by the binary crate on the mTLS port (5642).
pub(crate) fn inter_node_routes(state: Arc<CertmeshState>) -> Router {
    use paths::rel;
    Router::new()
        .route(rel(paths::PROMOTE), post(promote_handler))
        .route(rel(paths::HEALTH), post(health_handler))
        .route(rel(paths::RENEW), post(renew_handler))
        .route(rel(paths::SET_HOOK), put(set_hook_handler))
        .layer(Extension(state))
}

/// POST /join - Enroll a new member in the mesh.
#[utoipa::path(post, path = "/join", tag = "certmesh",
    summary = "Enroll a new member in the certificate mesh",
    request_body = JoinRequest,
    responses((status = 200, body = JoinResponse)))]
async fn join_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<JoinRequest>,
) -> impl IntoResponse {
    let core = CertmeshCore::from_state(Arc::clone(&state));

    match core.enroll(&request).await {
        Ok(response) => match serde_json::to_value(&response) {
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

/// POST /invite - Mint a single-use, hostname-bound enrollment invite (ADR-015 F2).
///
/// Operator-only: this route is DAT-gated by the binary's auth middleware (it is
/// NOT in the `/join` exemption), so only a caller holding the local daemon token
/// can mint invites.
#[utoipa::path(post, path = "/invite", tag = "certmesh",
    summary = "Mint a single-use enrollment invite token",
    request_body = InviteRequest,
    responses((status = 200, body = InviteResponse)))]
async fn invite_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<InviteRequest>,
) -> impl IntoResponse {
    let core = CertmeshCore::from_state(Arc::clone(&state));
    match core.mint_invite(&request.hostname, request.ttl_mins).await {
        Ok(response) => match serde_json::to_value(&response) {
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

/// POST /member-csr - Generate this member's keypair + CSR (ADR-015 F1).
///
/// Local/operator-only (DAT-gated): the daemon generates the keypair, persists
/// the private key locally, and returns only the CSR. The key never leaves here.
#[utoipa::path(post, path = "/member-csr", tag = "certmesh",
    summary = "Generate this member's keypair and CSR (key kept local)",
    request_body = MemberCsrRequest,
    responses((status = 200, body = MemberCsrResponse)))]
async fn member_csr_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<MemberCsrRequest>,
) -> impl IntoResponse {
    let core = CertmeshCore::from_state(Arc::clone(&state));
    match core
        .prepare_member_csr(&request.hostname, &request.sans)
        .await
    {
        Ok(csr) => {
            let response = MemberCsrResponse { csr };
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

/// POST /member-cert - Install a CA-signed cert next to the member key (ADR-015 F1).
///
/// Local/operator-only (DAT-gated): writes the signed leaf + CA next to the key
/// the daemon already holds, and trusts the CA root.
#[utoipa::path(post, path = "/member-cert", tag = "certmesh",
    summary = "Install a CA-signed cert next to the member key",
    request_body = InstallCertRequest,
    responses((status = 200, body = InstallCertResponse)))]
async fn member_cert_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<InstallCertRequest>,
) -> impl IntoResponse {
    let core = CertmeshCore::from_state(Arc::clone(&state));
    match core
        .install_member_cert(
            &request.hostname,
            &request.cert_pem,
            &request.ca_pem,
            request.ca_endpoint.as_deref(),
            request.ca_fingerprint.as_deref(),
            &request.sans,
            request.policy.clone(),
        )
        .await
    {
        Ok(cert_path) => {
            let response = InstallCertResponse {
                installed: true,
                cert_path,
            };
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

/// GET /trust-bundle - the signed, monotonic mesh-truth bundle (ADR-017 P1/F4).
///
/// Self-verifying (detached ES256 signature by the CA key over canonical bytes),
/// so it is a DAT-exempt read like a CRL. Members pull it on an interval, verify
/// the signature against their **pinned** CA fingerprint, and reject any bundle
/// with `seq <= last_seen` (anti-rollback).
#[utoipa::path(get, path = "/trust-bundle", tag = "certmesh",
    summary = "Signed, monotonic trust bundle (membership, revocation, policy)",
    responses((status = 200, body = crate::bundle::SignedBundle)))]
async fn trust_bundle_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
) -> impl IntoResponse {
    let ca_guard = state.ca.lock().await;
    let ca = match ca_guard.as_ref() {
        Some(ca) => ca,
        None => {
            return if state.paths.is_ca_initialized() {
                error_response(StatusCode::SERVICE_UNAVAILABLE, &CertmeshError::CaLocked)
            } else {
                error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &CertmeshError::CaNotInitialized,
                )
            };
        }
    };
    let signed = {
        let roster = state.roster.lock().await;
        crate::bundle::sign(&roster, ca, chrono::Utc::now().to_rfc3339())
    };
    drop(ca_guard);
    let signed = match signed {
        Ok(s) => s,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    match serde_json::to_value(&signed) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
}

/// GET /status - Certmesh status overview.
#[utoipa::path(get, path = "/status", tag = "certmesh",
    summary = "Certificate mesh status overview",
    responses((status = 200, body = CertmeshStatus)))]
async fn status_handler(Extension(state): Extension<Arc<CertmeshState>>) -> impl IntoResponse {
    let ca_guard = state.ca.lock().await;
    let roster = state.roster.lock().await;
    let auth_guard = state.auth.lock().await;
    let auth_method = auth_guard.as_ref().map(|a| a.method_name());
    let status = crate::build_status(&state.paths, &ca_guard, &roster, auth_method);
    Json(status)
}

/// PUT /hook - Set a post-renewal reload hook for a member.
#[utoipa::path(put, path = "/set-hook", tag = "certmesh",
    summary = "Set reload hook for a member",
    request_body = SetHookRequest,
    responses((status = 200, body = SetHookResponse)))]
async fn set_hook_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    client_cn: Option<Extension<ClientCn>>,
    Json(request): Json<SetHookRequest>,
) -> impl IntoResponse {
    // CN authorization: if present, caller can only set hooks for their own hostname
    if let Some(Extension(ClientCn(ref caller))) = client_cn {
        if caller != &request.hostname {
            return error_response(
                StatusCode::FORBIDDEN,
                &CertmeshError::Internal(format!(
                    "CN mismatch: authenticated as '{}' but requesting hook for '{}'",
                    caller, request.hostname
                )),
            );
        }
    }

    // Delegate to the domain facade, which is the single source of truth for
    // hook validation (forbidden metacharacters + absolute-path requirement)
    // and persistence.
    let core = CertmeshCore::from_state(Arc::clone(&state));
    match core
        .set_reload_hook(&request.hostname, &request.reload)
        .await
    {
        Ok(()) => {
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
        Err(e) => {
            let code = koi_common::error::ErrorCode::from(&e);
            let status = StatusCode::from_u16(code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            error_response(status, &e)
        }
    }
}

// ── Service delegation handlers ─────────────────────────────────────

/// POST /create - Initialize a new CA via the running service.
#[utoipa::path(post, path = "/create", tag = "certmesh",
    summary = "Initialize private CA",
    request_body = CreateCaRequest,
    responses((status = 200, body = CreateCaResponse)))]
async fn create_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<CreateCaRequest>,
) -> impl IntoResponse {
    let core = CertmeshCore::from_state(Arc::clone(&state));
    match core.create(request).await {
        Ok(response) => match serde_json::to_value(&response) {
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

/// POST /unlock - Decrypt the CA key.
#[utoipa::path(post, path = "/unlock", tag = "certmesh",
    summary = "Decrypt CA key with passphrase",
    request_body = UnlockRequest,
    responses((status = 200, body = UnlockResponse)))]
async fn unlock_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<UnlockRequest>,
) -> impl IntoResponse {
    let ca_state = match crate::ca::load_ca(&request.passphrase, &state.paths) {
        Ok(ca) => ca,
        Err(e) => {
            // Audit the failed unlock before returning (ADR-017 F9/F14).
            let _ = crate::audit::append_entry_to(
                &state.paths.audit_log_path(),
                "unlock_failed",
                &[("via", "http")],
            );
            let code = koi_common::error::ErrorCode::from(&e);
            let status = StatusCode::from_u16(code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return error_response(status, &e);
        }
    };

    // Load auth credential from auth.json
    let auth_path = state.paths.auth_path();
    if auth_path.exists() {
        let auth_path_clone = auth_path.clone();
        match tokio::task::spawn_blocking(move || std::fs::read_to_string(&auth_path_clone)).await {
            Ok(Ok(json)) => match serde_json::from_str::<koi_crypto::auth::StoredAuth>(&json) {
                Ok(stored) => match stored.unlock(&request.passphrase) {
                    Ok(auth_state) => {
                        *state.auth.lock().await = Some(auth_state);
                    }
                    Err(e) => tracing::warn!(error = %e, "Failed to unlock auth credential"),
                },
                Err(e) => tracing::warn!(error = %e, "Failed to parse auth.json"),
            },
            Ok(Err(e)) => tracing::warn!(error = %e, "Failed to read auth.json"),
            Err(e) => tracing::warn!(error = %e, "Failed to spawn auth.json read task"),
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

/// POST /rotate-auth - Rotate the enrollment auth credential.
#[utoipa::path(post, path = "/rotate-auth", tag = "certmesh",
    summary = "Rotate enrollment auth credential",
    request_body = RotateAuthRequest,
    responses((status = 200, body = RotateAuthResponse)))]
async fn rotate_auth_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<RotateAuthRequest>,
) -> impl IntoResponse {
    let core = CertmeshCore::from_state(Arc::clone(&state));
    match core
        .rotate_auth(&request.passphrase, request.method.as_deref())
        .await
    {
        Ok(setup) => {
            let response = RotateAuthResponse { auth_setup: setup };
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

/// GET /log - Return audit log entries.
#[utoipa::path(get, path = "/log", tag = "certmesh",
    summary = "Read audit log entries",
    responses((status = 200, body = AuditLogResponse)))]
async fn log_handler(Extension(state): Extension<Arc<CertmeshState>>) -> impl IntoResponse {
    match crate::audit::read_log_from(&state.paths.audit_log_path()) {
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
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &CertmeshError::Io(e)),
    }
}

/// POST /destroy - Remove all certmesh state (CA, certs, roster, audit log).
#[utoipa::path(post, path = "/destroy", tag = "certmesh",
    summary = "Destroy all certmesh state",
    responses((status = 200, body = DestroyResponse)))]
async fn destroy_handler(Extension(state): Extension<Arc<CertmeshState>>) -> impl IntoResponse {
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

// ── Phase 5 handlers ───────────────────────────────────────────────

/// POST /backup - Create an encrypted certmesh backup bundle.
#[utoipa::path(post, path = "/backup", tag = "certmesh",
    summary = "Create encrypted backup",
    request_body = BackupRequest,
    responses((status = 200, body = BackupResponse)))]
async fn backup_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<BackupRequest>,
) -> impl IntoResponse {
    let core = crate::CertmeshCore::from_state(Arc::clone(&state));
    match core
        .backup(&request.ca_passphrase, &request.backup_passphrase)
        .await
    {
        Ok(bundle) => {
            let response = BackupResponse {
                backup_hex: hex_encode(&bundle),
                format: "koi-backup-v1".to_string(),
                version: crate::backup::BACKUP_VERSION,
            };
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

/// POST /restore - Restore certmesh state from a backup bundle.
#[utoipa::path(post, path = "/restore", tag = "certmesh",
    summary = "Restore from backup",
    request_body = RestoreRequest,
    responses((status = 200, body = RestoreResponse)))]
async fn restore_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<RestoreRequest>,
) -> impl IntoResponse {
    let backup_bytes = match hex_decode(&request.backup_hex) {
        Ok(bytes) => bytes,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &CertmeshError::BackupInvalid(e)),
    };

    let core = crate::CertmeshCore::from_state(Arc::clone(&state));
    match core
        .restore(
            &backup_bytes,
            &request.backup_passphrase,
            &request.new_passphrase,
        )
        .await
    {
        Ok(()) => {
            let response = RestoreResponse { restored: true };
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

/// POST /revoke - Revoke a member.
#[utoipa::path(post, path = "/revoke", tag = "certmesh",
    summary = "Revoke a member certificate",
    request_body = RevokeRequest,
    responses((status = 200, body = RevokeResponse)))]
async fn revoke_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    Json(request): Json<RevokeRequest>,
) -> impl IntoResponse {
    let core = crate::CertmeshCore::from_state(Arc::clone(&state));
    match core
        .revoke_member(
            &request.hostname,
            request.operator.clone(),
            request.reason.clone(),
        )
        .await
    {
        Ok(()) => {
            let response = RevokeResponse { revoked: true };
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

// ── Enrollment toggle handlers ──────────────────────────────────────

/// Toggle the enrollment window and return an [`EnrollmentSummary`] (shared by the
/// open/close handlers). The mutation + persist happen in **one** single-writer
/// commit (F8), so a concurrent enroll can't overwrite the posture with a stale
/// snapshot. Posture is not bundle content, so no `seq` bump.
async fn save_and_summarize_enrollment(
    state: &Arc<CertmeshState>,
    open: bool,
) -> axum::response::Response {
    let committed = state
        .touch_roster(|roster| {
            if open {
                roster.open_enrollment();
            } else {
                roster.close_enrollment();
            }
            Ok(())
        })
        .await;
    if let Err(e) = committed {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Failed to save roster: {e}")),
        );
    }

    let summary = EnrollmentSummary {
        enrollment_state: crate::roster::EnrollmentState::from_open(open),
    };
    match serde_json::to_value(&summary) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
}

/// POST /open-enrollment - Open the enrollment window (until explicitly closed).
#[utoipa::path(post, path = "/open-enrollment", tag = "certmesh",
    summary = "Open enrollment window",
    responses((status = 200, body = EnrollmentSummary)))]
async fn open_enrollment_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
) -> impl IntoResponse {
    let _ = crate::audit::append_entry_to(&state.paths.audit_log_path(), "enrollment_opened", &[]);
    save_and_summarize_enrollment(&state, true).await
}

/// POST /close-enrollment - Close the enrollment window.
#[utoipa::path(post, path = "/close-enrollment", tag = "certmesh",
    summary = "Close enrollment window",
    responses((status = 200, body = EnrollmentSummary)))]
async fn close_enrollment_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
) -> impl IntoResponse {
    let _ = crate::audit::append_entry_to(&state.paths.audit_log_path(), "enrollment_closed", &[]);
    save_and_summarize_enrollment(&state, false).await
}

// ── Phase 3 handlers ────────────────────────────────────────────────

/// POST /promote - auth-verified CA key transfer to a standby.
///
/// The requesting standby provides an auth response. If valid, the handler
/// returns the encrypted CA key, auth data, roster, and CA cert.
/// The passphrase for decryption is handled out-of-band (CLI prompt).
#[utoipa::path(post, path = "/promote", tag = "certmesh",
    summary = "Promote standby CA (key transfer)",
    request_body = PromoteRequest,
    responses((status = 200, body = PromoteResponse)))]
async fn promote_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    client_cn: Option<Extension<ClientCn>>,
    Json(request): Json<PromoteRequest>,
) -> impl IntoResponse {
    if let Some(Extension(ClientCn(ref caller))) = client_cn {
        tracing::info!(%caller, "promote requested by authenticated member");
    }

    let ca_guard = state.ca.lock().await;
    let ca = match ca_guard.as_ref() {
        Some(ca) => ca,
        None => {
            return if state.paths.is_ca_initialized() {
                error_response(StatusCode::SERVICE_UNAVAILABLE, &CertmeshError::CaLocked)
            } else {
                error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &CertmeshError::CaNotInitialized,
                )
            };
        }
    };

    let auth_guard = state.auth.lock().await;
    let auth_state = match auth_guard.as_ref() {
        Some(s) => s,
        None => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, &CertmeshError::CaLocked);
        }
    };

    let mut rate_limiter = state.rate_limiter.lock().await;

    // Verify auth
    let adapter = koi_crypto::auth::adapter_for(auth_state);
    let challenge_guard = state.pending_challenge.lock().await;
    let challenge = challenge_guard
        .as_ref()
        .cloned()
        .unwrap_or(koi_crypto::auth::AuthChallenge::Totp);
    let valid = adapter
        .verify(auth_state, &challenge, &request.auth)
        .unwrap_or(false);
    let check = rate_limiter.check_and_record(valid);
    // Persist the limiter regardless of outcome (ADR-017 F7) — snapshot + drop the
    // guard before the blocking write.
    let limiter_snapshot = rate_limiter.clone();
    drop(rate_limiter);
    if let Err(e) = crate::persist_rate_limiter(&state.paths, &limiter_snapshot) {
        tracing::warn!(error = %e, "Could not persist rate-limiter state");
    }
    match check {
        Ok(()) => {}
        Err(koi_crypto::totp::RateLimitError::LockedOut { remaining_secs }) => {
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                &CertmeshError::RateLimited { remaining_secs },
            );
        }
        Err(koi_crypto::totp::RateLimitError::InvalidCode { .. }) => {
            return error_response(StatusCode::UNAUTHORIZED, &CertmeshError::InvalidAuth);
        }
    }

    let roster = state.roster.lock().await;

    let Some(client_pk) = request.ephemeral_public.as_ref() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            &CertmeshError::Internal("ephemeral_public is required for promotion".into()),
        );
    };

    match crate::failover::prepare_promotion(ca, auth_state, &roster, client_pk) {
        Ok(response) => match serde_json::to_value(&response) {
            Ok(val) => {
                let _ = crate::audit::append_entry_to(
                    &state.paths.audit_log_path(),
                    "promotion_prepared",
                    &[],
                );
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

/// POST /renew - **mTLS-only** member-initiated, CSR-only rotate-key renewal.
///
/// The member sends only a CSR for its freshly rotated keypair (ADR-017 F6); the
/// CA verifies the caller's mTLS client cert CN matches `hostname`, confirms the
/// member is enrolled + active + not revoked, signs the CSR with the **authorized
/// SANs recorded at enrollment** (renewal never expands the SAN set), updates the
/// roster, and returns the leaf. The CA **never** generates or receives a member
/// private key.
#[utoipa::path(post, path = "/renew", tag = "certmesh",
    summary = "Renew a member certificate from a CSR (mTLS, rotate-key)",
    request_body = RenewRequest,
    responses((status = 200, body = RenewResponse)))]
async fn renew_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    client_cn: Option<Extension<ClientCn>>,
    Json(request): Json<RenewRequest>,
) -> impl IntoResponse {
    // mTLS required: the caller identity is its client certificate's CN. A
    // plain-HTTP request (no ClientCn) has no authenticated identity → refuse.
    let caller = match client_cn {
        Some(Extension(ClientCn(cn))) => cn,
        None => {
            return error_response(
                StatusCode::FORBIDDEN,
                &CertmeshError::Internal(
                    "certificate renewal requires mTLS client authentication".into(),
                ),
            );
        }
    };
    if caller != request.hostname {
        return error_response(
            StatusCode::FORBIDDEN,
            &CertmeshError::Internal(format!(
                "CN mismatch: authenticated as '{}' but renewing for '{}'",
                caller, request.hostname
            )),
        );
    }

    let ca_guard = state.ca.lock().await;
    let ca = match ca_guard.as_ref() {
        Some(ca) => ca,
        None => {
            return if state.paths.is_ca_initialized() {
                error_response(StatusCode::SERVICE_UNAVAILABLE, &CertmeshError::CaLocked)
            } else {
                error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &CertmeshError::CaNotInitialized,
                )
            };
        }
    };

    // The member must be enrolled, active, and not revoked. The authorized SANs
    // are the ones recorded at enrollment — a renewal CSR cannot expand them.
    let (authorized_sans, lifetime_days) = {
        let roster = state.roster.lock().await;
        if roster.is_revoked(&request.hostname) {
            // Boundary revocation, audited (ADR-017 F9/F14): a revoked member's
            // renewal is refused at the CA, not merely dropped.
            let _ = crate::audit::append_entry_to(
                &state.paths.audit_log_path(),
                "mtls_revoked_rejected",
                &[("hostname", request.hostname.as_str()), ("op", "renew")],
            );
            return error_response(
                StatusCode::FORBIDDEN,
                &CertmeshError::Revoked(request.hostname.clone()),
            );
        }
        match roster.find_member(&request.hostname) {
            Some(m) if m.status == crate::roster::MemberStatus::Active => (
                m.cert_sans.clone(),
                roster.metadata.policy.leaf_lifetime_days,
            ),
            Some(_) => {
                return error_response(
                    StatusCode::FORBIDDEN,
                    &CertmeshError::Internal(format!(
                        "member '{}' is not active",
                        request.hostname
                    )),
                );
            }
            None => {
                return error_response(
                    StatusCode::NOT_FOUND,
                    &CertmeshError::NotFound(request.hostname.clone()),
                );
            }
        }
    };

    // Sign the member's CSR — no key generation, authorized SANs only.
    let leaf_pem = match crate::csr::sign_csr(ca, &request.csr, &authorized_sans, lifetime_days) {
        Ok(pem) => pem,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &e),
    };
    let ca_cert = ca.cert_pem.clone();
    let ca_fingerprint = crate::ca::ca_fingerprint(ca);
    drop(ca_guard);

    // Fingerprint + expiry from the issued leaf (same convention as enrollment).
    let fingerprint = match pem::parse(&leaf_pem) {
        Ok(der) => koi_crypto::pinning::fingerprint_sha256(der.contents()),
        Err(e) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CertmeshError::Certificate(format!("issued leaf parse: {e}")),
            );
        }
    };
    let expires = chrono::Utc::now() + chrono::Duration::days(i64::from(lifetime_days));

    // Update the roster member's fingerprint/expiry/last_seen and bump `seq`
    // (a rotation is a membership change the trust bundle must reflect — F8).
    if let Err(e) = state
        .commit_roster(|roster| {
            if let Some(member) = roster.find_member_mut(&request.hostname) {
                member.cert_fingerprint = fingerprint.clone();
                member.cert_expires = expires;
                member.last_seen = Some(chrono::Utc::now());
            }
            Ok(())
        })
        .await
    {
        tracing::warn!(error = %e, "Failed to save roster after renewal");
    }

    let _ = crate::audit::append_entry_to(
        &state.paths.audit_log_path(),
        "cert_renewed",
        &[
            ("hostname", request.hostname.as_str()),
            ("fingerprint", &fingerprint),
            ("expires", &expires.to_rfc3339()),
        ],
    );

    let response = RenewResponse {
        hostname: request.hostname.clone(),
        service_cert: leaf_pem,
        ca_cert,
        ca_fingerprint,
        expires: expires.to_rfc3339(),
    };

    match serde_json::to_value(&response) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &CertmeshError::Internal(format!("Serialization error: {e}")),
        ),
    }
}

/// POST /health - Member heartbeat with pinned CA fingerprint validation.
#[utoipa::path(post, path = "/health", tag = "certmesh",
    summary = "Member health heartbeat",
    request_body = HealthRequest,
    responses((status = 200, body = HealthResponse)))]
async fn health_handler(
    Extension(state): Extension<Arc<CertmeshState>>,
    client_cn: Option<Extension<ClientCn>>,
    Json(request): Json<HealthRequest>,
) -> impl IntoResponse {
    // CN authorization: caller can only report health for their own hostname
    if let Some(Extension(ClientCn(ref caller))) = client_cn {
        if caller != &request.hostname {
            return error_response(
                StatusCode::FORBIDDEN,
                &CertmeshError::Internal(format!(
                    "CN mismatch: authenticated as '{}' but reporting health for '{}'",
                    caller, request.hostname
                )),
            );
        }
    }

    let ca_guard = state.ca.lock().await;
    let ca = match ca_guard.as_ref() {
        Some(ca) => ca,
        None => {
            return if state.paths.is_ca_initialized() {
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
    let valid =
        crate::health::validate_pinned_fingerprint(&current_fp, &request.pinned_ca_fingerprint);
    drop(ca_guard); // release the CA lock before the roster commit (no lock held across disk I/O)

    // Boundary enforcement (ADR-017 F4): a revoked member's heartbeat is refused
    // here at the CA, not merely recorded. Otherwise record last_seen (no seq
    // bump — liveness is not part of the trust bundle).
    if let Err(e) = state
        .touch_roster(|roster| {
            if roster.is_revoked(&request.hostname) {
                return Err(CertmeshError::Revoked(request.hostname.clone()));
            }
            roster.touch_member(&request.hostname);
            Ok(())
        })
        .await
    {
        if matches!(e, CertmeshError::Revoked(_)) {
            // Boundary revocation, audited (ADR-017 F9/F14).
            let _ = crate::audit::append_entry_to(
                &state.paths.audit_log_path(),
                "mtls_revoked_rejected",
                &[("hostname", request.hostname.as_str()), ("op", "health")],
            );
        }
        return error_response(StatusCode::FORBIDDEN, &e);
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
    koi_common::http::error_response_with_status(status, code, error.to_string())
}

/// Posture-aware auth gate middleware backing
/// [`CertmeshCore::require_auth`](crate::CertmeshCore::require_auth) (ADR-020 §6).
///
/// No-op in Open posture (the node holds no identity → homelab-open); in secure
/// posture it requires an authenticated client CN (the mTLS [`ClientCn`] the
/// listener / same-port dial injects) and returns 401 when absent.
pub(crate) async fn require_auth_mw(
    axum::extract::State(state): axum::extract::State<Arc<CertmeshState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Open node → no identity, no expectation of auth → pass.
    if !crate::node_has_identity(&state.paths) {
        return next.run(req).await;
    }
    // Secure node → require an authenticated client identity.
    if req.extensions().get::<ClientCn>().is_some() {
        next.run(req).await
    } else {
        error_response(StatusCode::UNAUTHORIZED, &CertmeshError::InvalidAuth)
    }
}

/// OpenAPI documentation for the certmesh domain.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        join_handler,
        invite_handler,
        member_csr_handler,
        member_cert_handler,
        status_handler,
        trust_bundle_handler,
        set_hook_handler,
        promote_handler,
        renew_handler,
        health_handler,
        create_handler,
        unlock_handler,
        rotate_auth_handler,
        log_handler,
        destroy_handler,
        backup_handler,
        restore_handler,
        revoke_handler,
        open_enrollment_handler,
        close_enrollment_handler,
    ),
    components(schemas(
        crate::protocol::JoinRequest,
        crate::protocol::JoinResponse,
        crate::protocol::InviteRequest,
        crate::protocol::InviteResponse,
        crate::protocol::MemberCsrRequest,
        crate::protocol::MemberCsrResponse,
        crate::protocol::InstallCertRequest,
        crate::protocol::InstallCertResponse,
        crate::protocol::CertmeshStatus,
        crate::protocol::MemberSummary,
        crate::bundle::SignedBundle,
        crate::bundle::TrustBundle,
        crate::bundle::BundleMember,
        crate::bundle::BundleRevoked,
        crate::roster::CertPolicy,
        crate::protocol::SetHookRequest,
        crate::protocol::SetHookResponse,
        crate::protocol::CreateCaRequest,
        crate::protocol::CreateCaResponse,
        crate::protocol::UnlockRequest,
        crate::protocol::UnlockResponse,
        crate::protocol::RotateAuthRequest,
        crate::protocol::RotateAuthResponse,
        crate::protocol::AuditLogResponse,
        crate::protocol::DestroyResponse,
        crate::protocol::BackupRequest,
        crate::protocol::BackupResponse,
        crate::protocol::RestoreRequest,
        crate::protocol::RestoreResponse,
        crate::protocol::RevokeRequest,
        crate::protocol::RevokeResponse,
        crate::protocol::EnrollmentSummary,
        crate::protocol::PromoteRequest,
        crate::protocol::PromoteResponse,
        crate::protocol::RenewRequest,
        crate::protocol::RenewResponse,
        crate::protocol::HookResult,
        crate::protocol::HealthRequest,
        crate::protocol::HealthResponse,
        crate::roster::EnrollmentState,
        koi_crypto::keys::EncryptedKey,
    ))
)]
pub struct CertmeshApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_extension() -> Arc<CertmeshState> {
        use crate::certmesh_paths::CertmeshPaths;
        use crate::roster::{Roster, RosterMetadata};
        use koi_crypto::totp::RateLimiter;
        use std::sync::atomic::{AtomicU64, Ordering};

        // Each fixture gets its own subdir under the (process-wide) test base so handlers
        // that persist the roster (open/close-enrollment, set-hook, …) never race on a
        // shared roster.json when the suite runs in parallel (`cargo test`).
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir =
            koi_common::test::ensure_data_dir("koi-certmesh-http-tests").join(format!("ext-{n}"));
        let paths = CertmeshPaths::with_data_dir(data_dir);
        let posture_tx = crate::initial_posture_tx(&paths);
        Arc::new(CertmeshState {
            paths,
            ca: tokio::sync::Mutex::new(None),
            roster: tokio::sync::Mutex::new(Roster {
                metadata: RosterMetadata {
                    created_at: chrono::Utc::now(),
                    enrollment_open: false,
                    requires_approval: false,
                    operator: None,
                    policy: crate::roster::CertPolicy::default(),
                    seq: 0,
                },
                members: vec![],
                revocation_list: vec![],
            }),
            auth: tokio::sync::Mutex::new(None),
            pending_challenge: tokio::sync::Mutex::new(None),
            rate_limiter: tokio::sync::Mutex::new(RateLimiter::new()),
            approval_tx: tokio::sync::Mutex::new(None),
            event_tx: tokio::sync::broadcast::channel(16).0,
            posture_tx,
        })
    }

    #[test]
    fn certmesh_state_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CertmeshState>();
    }

    // ── ADR-020 P2: require_auth gate ───────────────────────────────

    fn ra_paths(tag: &str) -> crate::certmesh_paths::CertmeshPaths {
        let dir = std::env::temp_dir().join(format!("koi-cm-ra-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        crate::certmesh_paths::CertmeshPaths::with_data_dir(dir)
    }

    // Make `paths` read as a secure node: a member.json anchor + a leaf on disk.
    fn make_secure(paths: &crate::certmesh_paths::CertmeshPaths) {
        let hostname = CertmeshCore::local_hostname().unwrap();
        let ms = crate::member::MemberState {
            hostname: hostname.clone(),
            ca_host: "h".to_string(),
            ca_mtls_port: 5642,
            ca_http_port: 5641,
            ca_fingerprint: "fp".to_string(),
            sans: vec![],
            policy: crate::roster::CertPolicy::default(),
            last_bundle_seq: 0,
            reload_hook: None,
        };
        crate::member::save(&paths.member_state_path(), &ms).unwrap();
        let leaf = paths.certs_dir().join(&hostname);
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("cert.pem"), b"x").unwrap();
        std::fs::write(leaf.join("key.pem"), b"x").unwrap();
    }

    fn gated_app(core: &CertmeshCore) -> Router {
        let inner = Router::new().route("/w", post(|| async { StatusCode::OK }));
        core.require_auth(inner)
    }

    #[tokio::test]
    async fn require_auth_passes_in_open_posture() {
        let core = CertmeshCore::uninitialized_with_paths(ra_paths("open"));
        let req = Request::post("/w").body(Body::empty()).unwrap();
        let resp = gated_app(&core).oneshot(req).await.unwrap();
        // Open → homelab-open, the write route is reachable without auth.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_auth_rejects_unauthenticated_when_secure() {
        let paths = ra_paths("secure-no-cn");
        make_secure(&paths);
        let core = CertmeshCore::uninitialized_with_paths(paths);
        let req = Request::post("/w").body(Body::empty()).unwrap();
        let resp = gated_app(&core).oneshot(req).await.unwrap();
        // Secure + no client cert → 401.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_auth_allows_authenticated_cn_when_secure() {
        let paths = ra_paths("secure-cn");
        make_secure(&paths);
        let core = CertmeshCore::uninitialized_with_paths(paths);
        let mut req = Request::post("/w").body(Body::empty()).unwrap();
        req.extensions_mut().insert(ClientCn("web-01".to_string()));
        let resp = gated_app(&core).oneshot(req).await.unwrap();
        // Secure + authenticated client CN → passes.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_endpoint_returns_200() {
        let app = routes(test_extension());
        let req = Request::get("/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_endpoint_returns_json() {
        let app = routes(test_extension());
        let req = Request::get("/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // CA not initialized, so ca_locked should be reported
        assert!(json.get("ca_initialized").is_some() || json.get("ca_locked").is_some());
    }

    #[tokio::test]
    async fn join_without_ca_returns_503() {
        let app = routes(test_extension());
        let req = Request::post("/join")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"hostname":"stone-05","auth":{"method":"totp","code":"123456"}}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // CA not initialized → 503
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn member_csr_returns_csr_without_ca() {
        // Generating the member keypair + CSR is local and needs no CA.
        let app = routes(test_extension());
        let req = Request::post("/member-csr")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"hostname":"web-01","sans":["10.0.0.9"]}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("csr")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("CERTIFICATE REQUEST"),
            "member-csr must return a PEM CSR"
        );
    }

    #[tokio::test]
    async fn invite_without_ca_returns_503() {
        // Minting requires an initialized CA; with none on disk → 503.
        let app = routes(test_extension());
        let req = Request::post("/invite")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"hostname":"web-01","ttl_mins":15}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn promote_without_ca_returns_503() {
        let app = inter_node_routes(test_extension());
        let req = Request::post("/promote")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"auth":{"method":"totp","code":"654321"}}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn health_without_ca_returns_503() {
        let app = routes(test_extension());
        let req = Request::post("/health")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"hostname":"stone-01","pinned_ca_fingerprint":"abc"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn set_hook_unknown_member_returns_404() {
        let app = routes(test_extension());
        let reload = if cfg!(unix) {
            "/usr/bin/systemctl restart nginx"
        } else {
            "C:\\Windows\\System32\\cmd.exe /c restart"
        };
        let body = serde_json::json!({"hostname": "nobody", "reload": reload}).to_string();
        let req = Request::put("/set-hook")
            .header("content-type", "application/json")
            .body(Body::from(body))
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
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_some());
        assert!(json.get("message").is_some());
    }

    #[tokio::test]
    async fn nonexistent_route_returns_404() {
        let app = routes(test_extension());
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
        let app = routes(test_extension());
        let req = Request::post("/join")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"hostname":"stone-05","auth":{"method":"totp","code":"123456"}}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_ca_unavailable_error(&json);
    }

    #[tokio::test]
    async fn promote_without_ca_body_has_error_code() {
        let app = inter_node_routes(test_extension());
        let req = Request::post("/promote")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"auth":{"method":"totp","code":"654321"}}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_ca_unavailable_error(&json);
    }

    #[tokio::test]
    async fn health_without_ca_body_has_error_code() {
        let app = routes(test_extension());
        let req = Request::post("/health")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"hostname":"stone-01","pinned_ca_fingerprint":"abc"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_ca_unavailable_error(&json);
    }

    #[tokio::test]
    async fn status_body_has_expected_fields() {
        let app = routes(test_extension());
        let req = Request::get("/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("ca_initialized").is_some(),
            "missing ca_initialized"
        );
        assert!(json.get("ca_locked").is_some(), "missing ca_locked");
        assert!(
            json.get("enrollment_open").is_some(),
            "missing enrollment_open"
        );
        assert!(
            json.get("requires_approval").is_some(),
            "missing requires_approval"
        );
        assert!(
            json.get("enrollment_state").is_some(),
            "missing enrollment_state"
        );
        assert!(json.get("member_count").is_some(), "missing member_count");
        assert!(json.get("members").is_some(), "missing members");
    }

    #[tokio::test]
    async fn set_hook_not_found_body_has_error() {
        let app = routes(test_extension());
        let reload = if cfg!(unix) {
            "/usr/bin/systemctl restart nginx"
        } else {
            "C:\\Windows\\System32\\cmd.exe /c restart"
        };
        let body = serde_json::json!({"hostname": "nobody", "reload": reload}).to_string();
        let req = Request::put("/set-hook")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_some(), "missing error field");
        let msg = json.get("message").unwrap().as_str().unwrap();
        assert!(
            msg.contains("not found"),
            "message should indicate not found: {msg}"
        );
    }

    #[tokio::test]
    async fn set_hook_relative_path_returns_400() {
        let app = routes(test_extension());
        let req = Request::put("/set-hook")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"hostname":"stone-01","reload":"systemctl restart nginx"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── Enrollment toggle endpoint tests ────────────────────────────

    #[tokio::test]
    async fn open_enrollment_returns_200() {
        let app = routes(test_extension());
        let req = Request::post("/open-enrollment")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json.get("enrollment_state").unwrap().as_str().unwrap(),
            "open"
        );
    }

    #[tokio::test]
    async fn close_enrollment_returns_200() {
        let app = routes(test_extension());
        let req = Request::post("/close-enrollment")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json.get("enrollment_state").unwrap().as_str().unwrap(),
            "closed"
        );
    }

    // ── Service delegation endpoint tests ────────────────────────────

    #[tokio::test]
    async fn create_with_bad_entropy_returns_400() {
        let app = routes(test_extension());
        let req = Request::post("/create")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"passphrase":"test","entropy_hex":"bad","enrollment_open":true,"requires_approval":false}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_with_short_entropy_returns_400() {
        let app = routes(test_extension());
        // 16 bytes (32 hex chars) instead of required 32 bytes (64 hex chars)
        let req = Request::post("/create")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"passphrase":"test","entropy_hex":"00112233445566778899aabbccddeeff","enrollment_open":true,"requires_approval":false}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unlock_with_wrong_passphrase_returns_error() {
        let app = routes(test_extension());
        let req = Request::post("/unlock")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"passphrase":"wrong-passphrase"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should fail because no CA exists on disk
        assert!(resp.status().is_client_error() || resp.status().is_server_error());
    }

    #[tokio::test]
    async fn rotate_auth_without_ca_returns_503() {
        let app = routes(test_extension());
        let req = Request::post("/rotate-auth")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"passphrase":"test"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn log_endpoint_returns_200() {
        let app = routes(test_extension());
        let req = Request::get("/log").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should return 200 even with no log entries (returns empty string)
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn log_endpoint_body_has_entries_field() {
        let app = routes(test_extension());
        let req = Request::get("/log").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json.get("entries").is_some(),
            "response should have 'entries' field"
        );
    }

    #[tokio::test]
    async fn destroy_endpoint_returns_200() {
        let app = routes(test_extension());
        let req = Request::post("/destroy").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("destroyed").unwrap().as_bool().unwrap());
    }
}
