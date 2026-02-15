//! Koi Certmesh — certificate mesh with pluggable enrollment auth (Phase 2+).
//!
//! Provides a private Certificate Authority that mints ECDSA P-256 certificates,
//! pluggable enrollment authentication (TOTP or FIDO2), trust store installation,
//! and a roster of enrolled members. Two machines on the same LAN can establish
//! mutual TLS trust without external infrastructure.

pub mod audit;
pub mod backup;
pub mod ca;
pub mod certfiles;
pub mod enrollment;
pub mod entropy;
pub mod error;
pub mod failover;
pub mod health;
pub mod http;
pub mod lifecycle;
pub mod pond_ceremony;
pub mod profiles;
pub mod protocol;
pub mod roster;
pub mod wordlist;

use std::sync::Arc;

use axum::Router;
use koi_common::capability::{Capability, CapabilityStatus};
use koi_crypto::auth::AuthState;
use koi_crypto::totp::RateLimiter;
use tokio::sync::{broadcast, mpsc, oneshot};

pub use error::CertmeshError;
use profiles::TrustProfile;
use roster::Roster;

/// mDNS service type for CA discovery.
/// Used by the binary crate to announce the CA via koi-mdns.
pub const CERTMESH_SERVICE_TYPE: &str = "_certmesh._tcp";

/// Capacity for the certmesh event broadcast channel.
const BROADCAST_CHANNEL_CAPACITY: usize = 256;

/// Events emitted by the certmesh subsystem when roster membership changes.
#[derive(Debug, Clone)]
pub enum CertmeshEvent {
    /// A new member was enrolled in the mesh.
    MemberJoined {
        hostname: String,
        fingerprint: String,
    },
    /// A member was revoked from the mesh.
    MemberRevoked { hostname: String },
    /// All certmesh state was destroyed.
    Destroyed,
}

// ── Internal shared state ───────────────────────────────────────────

/// Internal shared state for CertmeshCore and HTTP handlers.
/// Not exposed outside this crate — all access goes through CertmeshCore methods.
pub(crate) struct CertmeshState {
    pub(crate) ca: tokio::sync::Mutex<Option<ca::CaState>>,
    pub(crate) roster: tokio::sync::Mutex<Roster>,
    pub(crate) auth: tokio::sync::Mutex<Option<AuthState>>,
    pub(crate) pending_challenge: tokio::sync::Mutex<Option<koi_crypto::auth::AuthChallenge>>,
    pub(crate) rate_limiter: tokio::sync::Mutex<RateLimiter>,
    pub(crate) profile: tokio::sync::Mutex<TrustProfile>,
    pub(crate) approval_tx: tokio::sync::Mutex<Option<mpsc::Sender<ApprovalRequest>>>,
    pub(crate) event_tx: broadcast::Sender<CertmeshEvent>,
}

/// Enrollment approval request sent to the operator prompt.
#[derive(Debug)]
pub struct ApprovalRequest {
    pub hostname: String,
    pub profile: TrustProfile,
    pub respond_to: oneshot::Sender<ApprovalDecision>,
}

/// Enrollment approval decision from the operator prompt.
#[derive(Debug)]
pub enum ApprovalDecision {
    Approved { operator: Option<String> },
    Denied,
}

const APPROVAL_TIMEOUT_SECS: u64 = 300;

impl CertmeshState {
    /// Destroy all certmesh state — shared by CertmeshCore::destroy() and the HTTP handler.
    pub(crate) async fn destroy(&self) -> Result<(), CertmeshError> {
        // Clear in-memory state first
        *self.ca.lock().await = None;
        *self.auth.lock().await = None;
        *self.pending_challenge.lock().await = None;
        *self.roster.lock().await = Roster::empty();
        *self.profile.lock().await = TrustProfile::default();

        // Remove platform-sealed key material (best-effort)
        if let Err(e) = koi_crypto::tpm::delete_key_material("koi-certmesh-ca") {
            tracing::debug!(error = %e, "No platform-sealed key material to clean up");
        }

        // Remove certmesh directory (contains ca/, roster.json)
        let certmesh_dir = ca::certmesh_dir();
        if certmesh_dir.exists() {
            std::fs::remove_dir_all(&certmesh_dir)?;
            tracing::info!(path = %certmesh_dir.display(), "Certmesh data directory removed");
        }

        // Remove issued certificate files
        let certs_dir = koi_common::paths::koi_certs_dir();
        if certs_dir.exists() {
            std::fs::remove_dir_all(&certs_dir)?;
            tracing::info!(path = %certs_dir.display(), "Certificate files removed");
        }

        // Remove audit log
        let audit_path = audit::audit_log_path();
        if audit_path.exists() {
            std::fs::remove_file(&audit_path)?;
            tracing::info!(path = %audit_path.display(), "Audit log removed");
        }

        tracing::info!("Certmesh state destroyed");
        Ok(())
    }
}

// ── CertmeshCore — domain facade ────────────────────────────────────

/// CertmeshCore — the main domain facade.
///
/// Wraps the shared certmesh state and exposes commands,
/// status, and HTTP routes to the binary crate.
pub struct CertmeshCore {
    state: Arc<CertmeshState>,
}

impl CertmeshCore {
    /// Construct a facade from an existing shared state.
    pub(crate) fn from_state(state: Arc<CertmeshState>) -> Self {
        Self { state }
    }

    /// Create a new CertmeshCore with an unlocked (decrypted) CA.
    pub fn new(
        ca: ca::CaState,
        roster: Roster,
        auth_state: AuthState,
        profile: TrustProfile,
    ) -> Self {
        Self {
            state: Arc::new(CertmeshState {
                ca: tokio::sync::Mutex::new(Some(ca)),
                roster: tokio::sync::Mutex::new(roster),
                auth: tokio::sync::Mutex::new(Some(auth_state)),
                pending_challenge: tokio::sync::Mutex::new(None),
                rate_limiter: tokio::sync::Mutex::new(RateLimiter::new()),
                profile: tokio::sync::Mutex::new(profile),
                approval_tx: tokio::sync::Mutex::new(None),
                event_tx: broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0,
            }),
        }
    }

    /// Create a CertmeshCore in locked state (CA initialized but not unlocked).
    pub fn locked(roster: Roster, profile: TrustProfile) -> Self {
        Self {
            state: Arc::new(CertmeshState {
                ca: tokio::sync::Mutex::new(None),
                roster: tokio::sync::Mutex::new(roster),
                auth: tokio::sync::Mutex::new(None),
                pending_challenge: tokio::sync::Mutex::new(None),
                rate_limiter: tokio::sync::Mutex::new(RateLimiter::new()),
                profile: tokio::sync::Mutex::new(profile),
                approval_tx: tokio::sync::Mutex::new(None),
                event_tx: broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0,
            }),
        }
    }

    /// Create a CertmeshCore in uninitialized state (no CA created yet).
    ///
    /// HTTP routes are still mounted so `/create` is reachable on a fresh install.
    /// All operations that require an initialized CA will return `CaNotInitialized`.
    pub fn uninitialized() -> Self {
        Self {
            state: Arc::new(CertmeshState {
                ca: tokio::sync::Mutex::new(None),
                roster: tokio::sync::Mutex::new(Roster::empty()),
                auth: tokio::sync::Mutex::new(None),
                pending_challenge: tokio::sync::Mutex::new(None),
                rate_limiter: tokio::sync::Mutex::new(RateLimiter::new()),
                profile: tokio::sync::Mutex::new(TrustProfile::default()),
                approval_tx: tokio::sync::Mutex::new(None),
                event_tx: broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0,
            }),
        }
    }

    /// Build the HTTP router for this domain.
    ///
    /// The binary crate mounts this at `/v1/certmesh/`.
    pub fn routes(&self) -> Router {
        http::routes(Arc::clone(&self.state))
    }

    /// Build the HTTP router for external embedding.
    ///
    /// This mirrors `routes()` but avoids exposing CertmeshState.
    pub fn http_routes(&self) -> Router {
        http::routes(Arc::clone(&self.state))
    }

    /// Set the approval channel used for enrollment approvals.
    pub async fn set_approval_channel(&self, tx: mpsc::Sender<ApprovalRequest>) {
        *self.state.approval_tx.lock().await = Some(tx);
    }

    /// Subscribe to certmesh events.
    pub fn subscribe(&self) -> broadcast::Receiver<CertmeshEvent> {
        self.state.event_tx.subscribe()
    }

    // NOTE: CA creation logic lives exclusively in `create_handler` (http.rs)
    // which handles entropy decoding, self-enrollment, policy overrides,
    // and trust-store installation. There is no separate CertmeshCore method
    // to avoid divergence between two code paths.

    /// Read the audit log entries.
    pub fn read_audit_log(&self) -> Result<String, CertmeshError> {
        audit::read_log().map_err(CertmeshError::Io)
    }

    /// Destroy all certmesh state — CA key, certs, roster, and audit log.
    ///
    /// Removes all certmesh data from disk and resets in-memory state to
    /// uninitialized. This is irreversible. Used for testing cleanup and
    /// full mesh teardown.
    pub async fn destroy(&self) -> Result<(), CertmeshError> {
        self.state.destroy().await?;
        let _ = self.state.event_tx.send(CertmeshEvent::Destroyed);
        Ok(())
    }

    /// Process an enrollment request. Returns the join response on success.
    ///
    /// The joining machine’s hostname comes from the request — not from
    /// `hostname::get()` which would return the CA server’s hostname.
    pub async fn enroll(
        &self,
        request: &protocol::JoinRequest,
    ) -> Result<protocol::JoinResponse, CertmeshError> {
        let hostname = &request.hostname;
        if hostname.is_empty() {
            return Err(CertmeshError::Internal(
                "join request must include the joining machine's hostname".to_string(),
            ));
        }
        // Default SANs: hostname + hostname.local, plus any extras the joiner sent
        let mut sans = vec![hostname.clone(), format!("{hostname}.local")];
        for extra in &request.sans {
            if !sans.contains(extra) {
                sans.push(extra.clone());
            }
        }

        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if ca::is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let roster = self.state.roster.lock().await;
        let auth_guard = self.state.auth.lock().await;
        let auth_state = auth_guard.as_ref().ok_or(CertmeshError::CaLocked)?;
        let challenge_guard = self.state.pending_challenge.lock().await;
        let challenge = challenge_guard
            .as_ref()
            .cloned()
            .unwrap_or(koi_crypto::auth::AuthChallenge::Totp);
        let mut rate_limiter = self.state.rate_limiter.lock().await;
        let profile = roster.metadata.trust_profile;
        let requires_approval = roster.requires_approval();
        let fallback_operator = roster.metadata.operator.clone();
        drop(roster);

        let approved_by = if requires_approval {
            request_approval(&self.state, hostname, profile).await?
        } else {
            fallback_operator
        };

        let mut roster = self.state.roster.lock().await;

        let (response, _issued) = enrollment::process_enrollment(
            ca,
            &mut roster,
            auth_state,
            &challenge,
            &mut rate_limiter,
            request,
            hostname,
            &sans,
            approved_by,
        )?;

        // Save roster after successful enrollment
        let roster_path = ca::roster_path();
        if let Err(e) = roster::save_roster(&roster, &roster_path) {
            tracing::warn!(error = %e, "Failed to save roster after enrollment");
        }

        let _ = self.state.event_tx.send(CertmeshEvent::MemberJoined {
            hostname: response.hostname.clone(),
            fingerprint: response.ca_fingerprint.clone(),
        });

        Ok(response)
    }

    /// Get the current certmesh status.
    pub async fn certmesh_status(&self) -> protocol::CertmeshStatus {
        let ca_guard = self.state.ca.lock().await;
        let roster = self.state.roster.lock().await;
        let profile = self.state.profile.lock().await;
        let auth_guard = self.state.auth.lock().await;
        let auth_method = auth_guard.as_ref().map(|a| a.method_name());
        build_status(&ca_guard, &roster, &profile, auth_method)
    }

    /// Produce an mDNS announcement descriptor if this node is an unlocked primary.
    ///
    /// Returns `None` if the CA is locked or this node is not primary.
    /// The binary crate translates this into an mDNS `RegisterPayload`.
    pub async fn ca_announcement(&self, http_port: u16) -> Option<protocol::CaAnnouncement> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref()?;

        let roster = self.state.roster.lock().await;
        let primary = roster.primary()?;

        let mut txt = std::collections::HashMap::new();
        txt.insert("role".to_string(), "primary".to_string());
        txt.insert("fingerprint".to_string(), ca::ca_fingerprint(ca));
        let profile = self.state.profile.lock().await;
        txt.insert("profile".to_string(), profile.to_string());

        Some(protocol::CaAnnouncement {
            name: format!("koi-ca-{}", primary.hostname),
            port: http_port,
            txt,
        })
    }

    /// Set the post-renewal reload hook for a member.
    pub async fn set_reload_hook(&self, hostname: &str, hook: &str) -> Result<(), CertmeshError> {
        let mut roster = self.state.roster.lock().await;
        let member = roster
            .find_member_mut(hostname)
            .ok_or_else(|| CertmeshError::Internal(format!("member not found: {hostname}")))?;
        member.reload_hook = Some(hook.to_string());

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;

        tracing::info!(hostname, hook, "Reload hook set");
        Ok(())
    }

    /// Unlock the CA with a passphrase.
    pub async fn unlock(&self, passphrase: &str) -> Result<(), CertmeshError> {
        let ca_state = ca::load_ca(passphrase)?;

        // Load auth credential from auth.json
        let auth_path = ca::auth_path();
        if auth_path.exists() {
            let json = std::fs::read_to_string(&auth_path)?;
            let stored: koi_crypto::auth::StoredAuth = serde_json::from_str(&json)
                .map_err(|e| CertmeshError::Internal(format!("auth.json parse error: {e}")))?;
            let auth_state = stored
                .unlock(passphrase)
                .map_err(|e| CertmeshError::Internal(format!("auth unlock failed: {e}")))?;
            *self.state.auth.lock().await = Some(auth_state);
        }

        *self.state.ca.lock().await = Some(ca_state);

        tracing::info!("CA unlocked");
        Ok(())
    }

    /// Unlock the CA with a pre-unwrapped master key (TOTP, FIDO2, or auto-unlock).
    ///
    /// This bypasses passphrase-based auth.json decryption. The auth
    /// credential (for API gating) is not loaded — callers should use
    /// the slot table's embedded TOTP shared_secret for verification
    /// if auth gating is needed.
    pub async fn unlock_with_master_key(&self, master_key: &[u8; 32]) -> Result<(), CertmeshError> {
        let ca_state = ca::load_ca_with_master_key(master_key)?;
        *self.state.ca.lock().await = Some(ca_state);
        tracing::info!("CA unlocked via master key (non-passphrase slot)");
        Ok(())
    }

    /// Unlock the CA using a TOTP code against the unlock slot table.
    ///
    /// Loads the slot table, verifies the TOTP code, unwraps the master
    /// key, and decrypts the CA key.
    pub async fn unlock_with_totp(&self, code: &str) -> Result<(), CertmeshError> {
        let slot_table = ca::load_slot_table()?
            .ok_or_else(|| CertmeshError::Internal("no slot table found".into()))?;

        let master_key = slot_table
            .unwrap_with_totp(code)
            .map_err(|e| CertmeshError::Crypto(e.to_string()))?;

        self.unlock_with_master_key(&master_key).await
    }

    /// Unlock the CA using a FIDO2 credential (after assertion verification).
    ///
    /// The caller is responsible for verifying the WebAuthn assertion.
    /// This function performs the cryptographic unwrap using the
    /// credential ID.
    pub async fn unlock_with_fido2(&self, credential_id: &[u8]) -> Result<(), CertmeshError> {
        let slot_table = ca::load_slot_table()?
            .ok_or_else(|| CertmeshError::Internal("no slot table found".into()))?;

        let master_key = slot_table
            .unwrap_with_fido2(credential_id)
            .map_err(|e| CertmeshError::Crypto(e.to_string()))?;

        self.unlock_with_master_key(&master_key).await
    }

    // ── Phase 4 — Enrollment Policy ─────────────────────────────────

    /// Open the enrollment window, optionally with a deadline.
    pub async fn open_enrollment(
        &self,
        deadline: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), CertmeshError> {
        let mut roster = self.state.roster.lock().await;
        roster.open_enrollment(deadline);

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;

        if let Some(d) = deadline {
            tracing::info!(deadline = %d, "Enrollment window opened with deadline");
        } else {
            tracing::info!("Enrollment window opened (no deadline)");
        }
        let _ = audit::append_entry(
            "enrollment_opened",
            &[(
                "deadline",
                &deadline
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "none".to_string()),
            )],
        );
        Ok(())
    }

    /// Close the enrollment window.
    pub async fn close_enrollment(&self) -> Result<(), CertmeshError> {
        let mut roster = self.state.roster.lock().await;
        roster.close_enrollment();

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;

        tracing::info!("Enrollment window closed");
        let _ = audit::append_entry("enrollment_closed", &[]);
        Ok(())
    }

    /// Set scope constraints (domain and/or subnet).
    pub async fn set_policy(
        &self,
        allowed_domain: Option<String>,
        allowed_subnet: Option<String>,
    ) -> Result<(), CertmeshError> {
        // Validate subnet CIDR format before saving
        if let Some(ref cidr) = allowed_subnet {
            if let Some((net_str, prefix_str)) = cidr.split_once('/') {
                net_str.parse::<std::net::IpAddr>().map_err(|_| {
                    CertmeshError::ScopeViolation(format!("invalid subnet CIDR: {cidr}"))
                })?;
                prefix_str.parse::<u32>().map_err(|_| {
                    CertmeshError::ScopeViolation(format!("invalid prefix length in CIDR: {cidr}"))
                })?;
            } else {
                return Err(CertmeshError::ScopeViolation(format!(
                    "invalid CIDR format (expected x.x.x.x/N): {cidr}"
                )));
            }
        }

        let mut roster = self.state.roster.lock().await;
        roster.metadata.allowed_domain = allowed_domain.clone();
        roster.metadata.allowed_subnet = allowed_subnet.clone();

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;

        tracing::info!(
            domain = ?allowed_domain,
            subnet = ?allowed_subnet,
            "Enrollment policy updated"
        );
        let _ = audit::append_entry(
            "policy_updated",
            &[
                (
                    "allowed_domain",
                    allowed_domain.as_deref().unwrap_or("none"),
                ),
                (
                    "allowed_subnet",
                    allowed_subnet.as_deref().unwrap_or("none"),
                ),
            ],
        );
        Ok(())
    }

    /// Rotate the auth credential — generates new credential, persists, returns setup info.
    ///
    /// If `method` is `None`, keeps the current method. If `Some("totp")` or
    /// `Some("fido2")`, switches to that method.
    pub async fn rotate_auth(
        &self,
        passphrase: &str,
        method: Option<&str>,
    ) -> Result<koi_crypto::auth::AuthSetup, CertmeshError> {
        // Verify CA is unlocked
        let ca_guard = self.state.ca.lock().await;
        if ca_guard.is_none() {
            return Err(if ca::is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            });
        }
        drop(ca_guard);

        let current_method = self
            .state
            .auth
            .lock()
            .await
            .as_ref()
            .map(|a| a.method_name())
            .unwrap_or("totp");
        let target = method.unwrap_or(current_method);

        let (new_state, stored, setup) = match target {
            "totp" => {
                let new_secret = koi_crypto::totp::generate_secret();
                let stored = koi_crypto::auth::store_totp(&new_secret, passphrase)?;
                let uri =
                    koi_crypto::totp::build_totp_uri(&new_secret, "Koi Certmesh", "enrollment");
                let setup = koi_crypto::auth::AuthSetup::Totp { totp_uri: uri };
                (AuthState::Totp(new_secret), stored, setup)
            }
            "fido2" => {
                // FIDO2 rotation requires re-registration via the CLI.
                // For now, return an error — the full flow is wired through the
                // /auth/challenge + /auth/register endpoints (future).
                return Err(CertmeshError::Internal(
                    "FIDO2 rotation requires re-registration via CLI".into(),
                ));
            }
            other => {
                return Err(CertmeshError::Internal(format!(
                    "unknown auth method: {other}"
                )));
            }
        };

        let json = serde_json::to_string_pretty(&stored)
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?;
        std::fs::write(ca::auth_path(), json)?;
        *self.state.auth.lock().await = Some(new_state);

        tracing::info!(method = target, "auth credential rotated");
        let _ = audit::append_entry("auth_rotated", &[("method", target)]);
        Ok(setup)
    }

    // ── Phase 5 — Backup/Restore/Revocation ───────────────────────

    /// Create an encrypted backup bundle for the certmesh state.
    pub async fn backup(
        &self,
        ca_passphrase: &str,
        backup_passphrase: &str,
    ) -> Result<Vec<u8>, CertmeshError> {
        if !ca::is_ca_initialized() {
            return Err(CertmeshError::CaNotInitialized);
        }

        let ca_state = ca::load_ca(ca_passphrase)?;

        // Load auth state for backup
        let auth_path = ca::auth_path();
        let json = std::fs::read_to_string(&auth_path)
            .map_err(|e| CertmeshError::Internal(format!("cannot read auth.json: {e}")))?;
        let stored: koi_crypto::auth::StoredAuth = serde_json::from_str(&json)
            .map_err(|e| CertmeshError::Internal(format!("auth.json parse error: {e}")))?;
        let auth_state = stored
            .unlock(ca_passphrase)
            .map_err(|e| CertmeshError::Internal(format!("auth unlock failed: {e}")))?;

        let roster = self.state.roster.lock().await;
        let roster_json = serde_json::to_string(&*roster)
            .map_err(|e| CertmeshError::Internal(format!("roster serialization failed: {e}")))?;

        let audit_log = audit::read_log().map_err(CertmeshError::Io)?;

        let ca_key_pem = ca_state.key.private_key_pem().to_string();
        let payload = backup::BackupPayload::new(
            ca_key_pem,
            ca_state.cert_pem.clone(),
            auth_state.method_name().to_string(),
            auth_state.to_backup_bytes(),
            roster_json,
            audit_log,
        );

        let bundle = backup::encode_backup(&payload, backup_passphrase)?;
        let _ = audit::append_entry("backup_created", &[]);
        Ok(bundle)
    }

    /// Restore certmesh state from an encrypted backup bundle.
    pub async fn restore(
        &self,
        backup_bytes: &[u8],
        backup_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<(), CertmeshError> {
        let payload = backup::decode_backup(backup_bytes, backup_passphrase)?;

        let ca_key = koi_crypto::keys::ca_keypair_from_pem(&payload.ca_key_pem)?;
        let encrypted_key = koi_crypto::keys::encrypt_key(&ca_key, new_passphrase)?;
        std::fs::create_dir_all(ca::ca_dir())?;
        koi_crypto::keys::save_encrypted_key(&ca::ca_key_path(), &encrypted_key)?;
        std::fs::write(ca::ca_cert_path(), &payload.ca_cert_pem)?;

        let auth_state = AuthState::from_backup(&payload.auth_method, payload.auth_data)
            .map_err(|e| CertmeshError::Internal(format!("auth restore failed: {e}")))?;

        // Persist restored auth credential
        let stored = match &auth_state {
            AuthState::Totp(secret) => koi_crypto::auth::store_totp(secret, new_passphrase)?,
            AuthState::Fido2(cred) => koi_crypto::auth::store_fido2(cred.clone()),
        };
        let auth_json = serde_json::to_string_pretty(&stored)
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?;
        std::fs::write(ca::auth_path(), auth_json)?;

        if let Some(parent) = ca::roster_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(ca::roster_path(), &payload.roster_json)?;
        if let Some(parent) = audit::audit_log_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(audit::audit_log_path(), &payload.audit_log)?;

        let restored_roster: Roster = serde_json::from_str(&payload.roster_json)
            .map_err(|e| CertmeshError::Internal(format!("roster deserialization failed: {e}")))?;

        let ca_state = ca::load_ca(new_passphrase)?;
        *self.state.ca.lock().await = Some(ca_state);
        *self.state.auth.lock().await = Some(auth_state);
        *self.state.profile.lock().await = restored_roster.metadata.trust_profile;
        *self.state.roster.lock().await = restored_roster;

        let _ = audit::append_entry("backup_restored", &[]);
        Ok(())
    }

    /// Revoke a member and persist the revocation list.
    pub async fn revoke_member(
        &self,
        hostname: &str,
        operator: Option<String>,
        reason: Option<String>,
    ) -> Result<(), CertmeshError> {
        let mut roster = self.state.roster.lock().await;
        roster
            .revoke_member(hostname, operator.clone(), reason.clone())
            .map_err(CertmeshError::NotFound)?;

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;

        let _ = self.state.event_tx.send(CertmeshEvent::MemberRevoked {
            hostname: hostname.to_string(),
        });

        let _ = audit::append_entry(
            "member_revoked",
            &[
                ("hostname", hostname),
                ("operator", operator.as_deref().unwrap_or("unknown")),
                ("reason", reason.as_deref().unwrap_or("none")),
            ],
        );
        Ok(())
    }

    // ── Phase 3 — Lifecycle ────────────────────────────────────────

    /// Renew all members whose certs are within the renewal threshold.
    ///
    /// Returns a list of (hostname, result) pairs. Each result is either
    /// Ok(hook_result) or Err(e). Callers can inspect which renewals
    /// succeeded and which failed without aborting the entire batch.
    pub async fn renew_all_due(
        &self,
    ) -> Vec<(String, Result<Option<protocol::HookResult>, CertmeshError>)> {
        let ca_guard = self.state.ca.lock().await;
        let ca = match ca_guard.as_ref() {
            Some(ca) => ca,
            None => return Vec::new(),
        };

        let mut roster = self.state.roster.lock().await;

        let hostnames: Vec<String> = lifecycle::members_needing_renewal(&roster)
            .iter()
            .map(|m| m.hostname.clone())
            .collect();

        let mut results = Vec::new();
        for hostname in &hostnames {
            let result = lifecycle::renew_and_update_member(ca, &mut roster, hostname);
            results.push((hostname.clone(), result));
        }

        // Save roster after all renewals
        if !hostnames.is_empty() {
            let roster_path = ca::roster_path();
            if let Err(e) = roster::save_roster(&roster, &roster_path) {
                tracing::warn!(error = %e, "Failed to save roster after batch renewal");
            }
        }

        results
    }

    /// Receive a renewal push from the CA and install the cert files.
    ///
    /// The member-side counterpart to `renew_all_due`. Returns the
    /// renewal response including any hook result.
    pub async fn receive_renewal(
        &self,
        request: &protocol::RenewRequest,
    ) -> Result<protocol::RenewResponse, CertmeshError> {
        let issued = ca::IssuedCert {
            cert_pem: request.cert_pem.clone(),
            key_pem: request.key_pem.clone(),
            ca_pem: request.ca_pem.clone(),
            fullchain_pem: request.fullchain_pem.clone(),
            fingerprint: request.fingerprint.clone(),
            expires: chrono::DateTime::parse_from_rfc3339(&request.expires)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
        };

        certfiles::write_cert_files(&request.hostname, &issued)?;

        // Update roster
        let mut roster = self.state.roster.lock().await;
        if roster.is_revoked(&request.hostname) {
            return Err(CertmeshError::Revoked(request.hostname.clone()));
        }
        if let Some(member) = roster.find_member_mut(&request.hostname) {
            member.cert_fingerprint = issued.fingerprint.clone();
            member.cert_expires = issued.expires;
        }

        let hook_result = roster
            .find_member(&request.hostname)
            .and_then(|m| m.reload_hook.as_ref())
            .map(|hook| lifecycle::execute_reload_hook(hook));

        Ok(protocol::RenewResponse {
            hostname: request.hostname.clone(),
            renewed: true,
            hook_result,
        })
    }

    /// Validate a member's health heartbeat.
    pub async fn health_check(
        &self,
        request: &protocol::HealthRequest,
    ) -> Result<protocol::HealthResponse, CertmeshError> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if ca::is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let current_fp = ca::ca_fingerprint(ca);
        let valid =
            health::validate_pinned_fingerprint(&current_fp, &request.pinned_ca_fingerprint);

        let mut roster = self.state.roster.lock().await;
        if roster.is_revoked(&request.hostname) {
            return Err(CertmeshError::Revoked(request.hostname.clone()));
        }
        roster.touch_member(&request.hostname);

        let roster_path = ca::roster_path();
        if let Err(e) = roster::save_roster(&roster, &roster_path) {
            tracing::warn!(error = %e, "Failed to save roster after health heartbeat");
        }

        Ok(protocol::HealthResponse {
            valid,
            ca_fingerprint: current_fp,
        })
    }

    /// Build a signed roster manifest for standby sync.
    pub async fn roster_manifest(&self) -> Result<protocol::RosterManifest, CertmeshError> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if ca::is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let roster = self.state.roster.lock().await;
        failover::build_signed_manifest(ca, &roster)
    }

    /// Accept a roster sync from the primary (standby-side).
    ///
    /// Verifies the manifest signature and replaces the local roster.
    pub async fn accept_roster_sync(
        &self,
        manifest: &protocol::RosterManifest,
    ) -> Result<(), CertmeshError> {
        let verified_roster = failover::verify_manifest(manifest)?;

        let mut roster = self.state.roster.lock().await;
        *roster = verified_roster;

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;

        tracing::info!("Roster synced from primary");
        Ok(())
    }

    /// Get the current node's roster role (if any).
    ///
    /// Returns `None` if the roster has no entry matching the local hostname.
    pub async fn node_role(&self) -> Option<roster::MemberRole> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .ok()?;
        let roster = self.state.roster.lock().await;
        roster.find_member(&hostname).map(|m| m.role.clone())
    }

    /// List hostnames of active standby members.
    pub async fn standby_hostnames(&self) -> Vec<String> {
        let roster = self.state.roster.lock().await;
        roster
            .standbys()
            .iter()
            .map(|m| m.hostname.clone())
            .collect()
    }

    /// Promote the local member to primary and demote any existing primary.
    /// Returns true if the roster was updated.
    pub async fn promote_self_to_primary(&self) -> Result<bool, CertmeshError> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .map_err(|_| CertmeshError::Internal("hostname unavailable".to_string()))?;

        let mut roster = self.state.roster.lock().await;
        let already_primary = roster
            .find_member(&hostname)
            .map(|m| m.role == roster::MemberRole::Primary)
            .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;

        if already_primary {
            return Ok(false);
        }

        for m in roster.members.iter_mut() {
            if m.role == roster::MemberRole::Primary {
                m.role = roster::MemberRole::Standby;
            }
        }

        if let Some(member) = roster.find_member_mut(&hostname) {
            member.role = roster::MemberRole::Primary;
        } else {
            return Err(CertmeshError::NotFound(hostname.clone()));
        }

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;
        Ok(true)
    }

    /// Demote the local member to standby. Returns true if the roster changed.
    pub async fn demote_self_to_standby(&self) -> Result<bool, CertmeshError> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .map_err(|_| CertmeshError::Internal("hostname unavailable".to_string()))?;

        let mut roster = self.state.roster.lock().await;
        let member = roster
            .find_member_mut(&hostname)
            .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;

        if member.role == roster::MemberRole::Standby {
            return Ok(false);
        }

        member.role = roster::MemberRole::Standby;

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;
        Ok(true)
    }

    /// Add alias SANs to a member's roster entry (used by DNS alias feedback).
    ///
    /// Returns true if any SANs were added.
    pub async fn add_alias_sans(
        &self,
        hostname: &str,
        sans: &[String],
    ) -> Result<bool, CertmeshError> {
        let mut roster = self.state.roster.lock().await;
        let member = roster
            .find_member_mut(hostname)
            .ok_or_else(|| CertmeshError::NotFound(hostname.to_string()))?;

        let mut changed = false;
        for san in sans {
            if !member.cert_sans.iter().any(|s| s == san) {
                member.cert_sans.push(san.clone());
                changed = true;
            }
        }

        if changed {
            let roster_path = ca::roster_path();
            roster::save_roster(&roster, &roster_path)?;
        }

        Ok(changed)
    }

    /// Get the local hostname.
    pub fn local_hostname() -> Option<String> {
        hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .ok()
    }

    /// Get the pinned CA fingerprint for the local node (if set).
    pub async fn pinned_ca_fingerprint(&self) -> Option<String> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .ok()?;
        let roster = self.state.roster.lock().await;
        roster
            .find_member(&hostname)
            .and_then(|m| m.pinned_ca_fingerprint.clone())
    }

    /// Prepare promotion material for a standby.
    ///
    /// Called on the primary when a standby requests promotion.
    pub async fn promote(
        &self,
        passphrase: &str,
    ) -> Result<protocol::PromoteResponse, CertmeshError> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if ca::is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let auth_guard = self.state.auth.lock().await;
        let auth_state = auth_guard.as_ref().ok_or(CertmeshError::CaLocked)?;

        let roster = self.state.roster.lock().await;
        failover::prepare_promotion(ca, auth_state, &roster, passphrase)
    }
}

async fn request_approval(
    state: &CertmeshState,
    hostname: &str,
    profile: TrustProfile,
) -> Result<Option<String>, CertmeshError> {
    let tx = state
        .approval_tx
        .lock()
        .await
        .clone()
        .ok_or(CertmeshError::ApprovalUnavailable)?;

    let (respond_to, response_rx) = oneshot::channel();
    let request = ApprovalRequest {
        hostname: hostname.to_string(),
        profile,
        respond_to,
    };

    if tx.send(request).await.is_err() {
        return Err(CertmeshError::ApprovalUnavailable);
    }

    let decision = match tokio::time::timeout(
        std::time::Duration::from_secs(APPROVAL_TIMEOUT_SECS),
        response_rx,
    )
    .await
    {
        Ok(Ok(decision)) => decision,
        Ok(Err(_)) => return Err(CertmeshError::ApprovalUnavailable),
        Err(_) => return Err(CertmeshError::ApprovalTimeout),
    };

    match decision {
        ApprovalDecision::Approved { operator } => {
            if profile.requires_operator() && operator.as_deref().unwrap_or("").is_empty() {
                return Err(CertmeshError::ApprovalDenied);
            }
            Ok(operator)
        }
        ApprovalDecision::Denied => Err(CertmeshError::ApprovalDenied),
    }
}

impl Capability for CertmeshCore {
    fn name(&self) -> &str {
        "certmesh"
    }

    fn status(&self) -> CapabilityStatus {
        // Use try_lock for sync Capability trait — best effort
        let ca_initialized = ca::is_ca_initialized();
        let ca_locked = self
            .state
            .ca
            .try_lock()
            .map(|guard| guard.is_none())
            .unwrap_or(true);
        let member_count = self
            .state
            .roster
            .try_lock()
            .map(|guard| guard.active_count())
            .unwrap_or(0);

        let profile = self
            .state
            .profile
            .try_lock()
            .map(|p| *p)
            .unwrap_or_default();

        let (summary, healthy) = if !ca_initialized {
            ("ready \u{2014} run certmesh create".to_string(), true)
        } else if ca_locked {
            ("CA locked".to_string(), false)
        } else {
            (
                format!(
                    "{} ({} member{})",
                    profile,
                    member_count,
                    if member_count == 1 { "" } else { "s" }
                ),
                true,
            )
        };

        CapabilityStatus {
            name: "certmesh".to_string(),
            summary,
            healthy,
        }
    }
}

// ── Shared helpers ──────────────────────────────────────────────────

/// Build a CertmeshStatus from locked guards. Used by both the facade
/// method and the HTTP handler to avoid duplicating the mapping logic.
pub(crate) fn build_status(
    ca_guard: &Option<ca::CaState>,
    roster: &Roster,
    profile: &TrustProfile,
    auth_method: Option<&str>,
) -> protocol::CertmeshStatus {
    let ca_fingerprint = match ca_guard {
        Some(ca) => Some(ca::ca_fingerprint(ca)),
        None => ca::ca_fingerprint_from_disk().ok(),
    };

    protocol::CertmeshStatus {
        ca_initialized: ca::is_ca_initialized(),
        ca_locked: ca_guard.is_none(),
        ca_fingerprint,
        profile: *profile,
        enrollment_state: roster.metadata.enrollment_state.clone(),
        enrollment_deadline: roster.metadata.enrollment_deadline.map(|d| d.to_rfc3339()),
        allowed_domain: roster.metadata.allowed_domain.clone(),
        allowed_subnet: roster.metadata.allowed_subnet.clone(),
        auth_method: auth_method.map(|s| s.to_string()),
        member_count: roster.active_count(),
        members: roster
            .members
            .iter()
            .map(|m| protocol::MemberSummary {
                hostname: m.hostname.clone(),
                role: format!("{:?}", m.role).to_lowercase(),
                status: format!("{:?}", m.status).to_lowercase(),
                cert_fingerprint: m.cert_fingerprint.clone(),
                cert_expires: m.cert_expires.to_rfc3339(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::{MemberRole, MemberStatus, RosterMember};
    use chrono::{Duration, Utc};

    fn make_test_ca() -> ca::CaState {
        let _ = koi_common::test::ensure_data_dir("koi-certmesh-core-tests");
        ca::create_ca("test-pass", &[42u8; 32]).unwrap().0
    }

    fn make_test_roster_with_member(hostname: &str, role: MemberRole) -> Roster {
        let mut r = Roster::new(TrustProfile::JustMe, None);
        r.members.push(RosterMember {
            hostname: hostname.to_string(),
            role,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp-test".to_string(),
            cert_expires: Utc::now() + Duration::days(25),
            cert_sans: vec![hostname.to_string(), format!("{hostname}.local")],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: Some("pinned-fp".to_string()),
            proxy_entries: Vec::new(),
        });
        r
    }

    fn make_unlocked_core(ca: ca::CaState, roster: Roster) -> CertmeshCore {
        let _ = koi_common::test::ensure_data_dir("koi-certmesh-core-tests");
        let totp = koi_crypto::totp::generate_secret();
        let auth_state = koi_crypto::auth::AuthState::Totp(totp);
        CertmeshCore::new(ca, roster, auth_state, TrustProfile::JustMe)
    }

    fn make_locked_core(roster: Roster) -> CertmeshCore {
        CertmeshCore::locked(roster, TrustProfile::JustMe)
    }

    // ── renew_all_due ────────────────────────────────────────────────

    #[tokio::test]
    async fn renew_all_due_returns_empty_when_ca_locked() {
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let results = core.renew_all_due().await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn renew_all_due_returns_empty_when_no_members_due() {
        let ca = make_test_ca();
        // Cert expires in 25 days — well beyond the 10-day threshold
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        let results = core.renew_all_due().await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn renew_all_due_renews_expiring_members() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        // Expires in 5 days — within the 10-day threshold
        roster.members.push(RosterMember {
            hostname: "expiring-host".to_string(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "old-fp".to_string(),
            cert_expires: Utc::now() + Duration::days(5),
            cert_sans: vec!["expiring-host".to_string()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        let core = make_unlocked_core(ca, roster);

        let results = core.renew_all_due().await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "expiring-host");
        assert!(results[0].1.is_ok());
    }

    #[tokio::test]
    async fn renew_all_due_partial_failure_continues() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        // Valid member that will succeed
        roster.members.push(RosterMember {
            hostname: "good-host".to_string(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp-1".to_string(),
            cert_expires: Utc::now() + Duration::days(3),
            cert_sans: vec!["good-host".to_string()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        // Another valid member
        roster.members.push(RosterMember {
            hostname: "also-good".to_string(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp-2".to_string(),
            cert_expires: Utc::now() + Duration::days(2),
            cert_sans: vec!["also-good".to_string()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        let core = make_unlocked_core(ca, roster);

        let results = core.renew_all_due().await;
        // Both members should be processed (no short-circuit)
        assert_eq!(results.len(), 2);
    }

    // ── health_check ─────────────────────────────────────────────────

    #[tokio::test]
    async fn health_check_returns_error_when_ca_locked() {
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let request = protocol::HealthRequest {
            hostname: "stone-01".to_string(),
            pinned_ca_fingerprint: "some-fp".to_string(),
        };
        let result = core.health_check(&request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn health_check_validates_matching_fingerprint() {
        let ca = make_test_ca();
        let ca_fp = ca::ca_fingerprint(&ca);
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let request = protocol::HealthRequest {
            hostname: "stone-01".to_string(),
            pinned_ca_fingerprint: ca_fp,
        };
        let result = core.health_check(&request).await.unwrap();
        assert!(result.valid);
        assert!(!result.ca_fingerprint.is_empty());
    }

    #[tokio::test]
    async fn health_check_rejects_mismatched_fingerprint() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let request = protocol::HealthRequest {
            hostname: "stone-01".to_string(),
            pinned_ca_fingerprint: "wrong-fingerprint".to_string(),
        };
        let result = core.health_check(&request).await.unwrap();
        assert!(!result.valid);
    }

    #[tokio::test]
    async fn health_check_updates_last_seen() {
        let ca = make_test_ca();
        let ca_fp = ca::ca_fingerprint(&ca);
        let mut roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        // Ensure last_seen is None initially
        roster.members[0].last_seen = None;
        let core = make_unlocked_core(ca, roster);

        let request = protocol::HealthRequest {
            hostname: "stone-01".to_string(),
            pinned_ca_fingerprint: ca_fp,
        };
        core.health_check(&request).await.unwrap();

        // Verify last_seen was updated via the roster state
        let roster = core.state.roster.lock().await;
        assert!(roster.members[0].last_seen.is_some());
    }

    // ── roster_manifest ──────────────────────────────────────────────

    #[tokio::test]
    async fn roster_manifest_returns_error_when_ca_locked() {
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let result = core.roster_manifest().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn roster_manifest_returns_signed_manifest() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let manifest = core.roster_manifest().await.unwrap();
        assert!(!manifest.roster_json.is_empty());
        assert!(!manifest.signature.is_empty());
        assert!(!manifest.ca_public_key.is_empty());
    }

    #[tokio::test]
    async fn roster_manifest_is_verifiable() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let manifest = core.roster_manifest().await.unwrap();
        // The manifest should pass verification
        let verified = failover::verify_manifest(&manifest);
        assert!(verified.is_ok());
        assert_eq!(verified.unwrap().members.len(), 1);
    }

    // ── accept_roster_sync ───────────────────────────────────────────

    #[tokio::test]
    async fn accept_roster_sync_replaces_roster() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        // Build a manifest with a different roster
        let ca2 = make_test_ca();
        let mut roster2 = make_test_roster_with_member("stone-01", MemberRole::Primary);
        roster2.members.push(RosterMember {
            hostname: "stone-02".to_string(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp-2".to_string(),
            cert_expires: Utc::now() + Duration::days(25),
            cert_sans: vec!["stone-02".to_string()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        let manifest = failover::build_signed_manifest(&ca2, &roster2).unwrap();

        core.accept_roster_sync(&manifest).await.unwrap();

        let roster = core.state.roster.lock().await;
        assert_eq!(roster.members.len(), 2);
    }

    #[tokio::test]
    async fn accept_roster_sync_rejects_invalid_manifest() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let manifest = protocol::RosterManifest {
            roster_json: "{}".to_string(),
            signature: vec![0u8; 64],
            ca_public_key: "bad-pem".to_string(),
        };

        let result = core.accept_roster_sync(&manifest).await;
        assert!(matches!(result, Err(CertmeshError::InvalidManifest)));
    }

    // ── promote ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn promote_returns_error_when_ca_locked() {
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let result = core.promote("passphrase").await;
        assert!(matches!(result, Err(CertmeshError::CaLocked)));
    }

    #[tokio::test]
    async fn promote_returns_encrypted_material() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let response = core.promote("test-passphrase").await.unwrap();
        assert!(!response.encrypted_ca_key.ciphertext.is_empty());
        assert!(!response.auth_data.is_null());
        assert!(!response.roster_json.is_empty());
        assert!(response.ca_cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn promote_response_can_be_accepted() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let response = core.promote("round-trip-pass").await.unwrap();

        // Accept the promotion on the standby side
        let (ca_key, accepted_auth, accepted_roster) =
            failover::accept_promotion(&response, "round-trip-pass").unwrap();
        assert!(!ca_key.public_key_pem().is_empty());
        assert_eq!(accepted_auth.method_name(), "totp");
        assert_eq!(accepted_roster.members.len(), 1);
    }

    // ── receive_renewal ──────────────────────────────────────────────

    #[tokio::test]
    async fn receive_renewal_updates_roster_member() {
        let ca = make_test_ca();
        let mut roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        roster.members[0].cert_fingerprint = "old-fp".to_string();
        let core = make_unlocked_core(ca, roster);

        let request = protocol::RenewRequest {
            hostname: "stone-01".to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n".to_string(),
            ca_pem: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n".to_string(),
            fullchain_pem: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n"
                .to_string(),
            fingerprint: "new-fp-abc123".to_string(),
            expires: "2026-04-01T00:00:00Z".to_string(),
        };

        let result = core.receive_renewal(&request).await.unwrap();
        assert!(result.renewed);
        assert_eq!(result.hostname, "stone-01");

        // Verify roster was updated
        let roster = core.state.roster.lock().await;
        assert_eq!(roster.members[0].cert_fingerprint, "new-fp-abc123");
    }

    #[tokio::test]
    async fn receive_renewal_handles_invalid_expires_gracefully() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let request = protocol::RenewRequest {
            hostname: "stone-01".to_string(),
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            ca_pem: "ca".to_string(),
            fullchain_pem: "chain".to_string(),
            fingerprint: "new-fp".to_string(),
            expires: "not-a-date".to_string(),
        };

        // Should not panic — falls back to Utc::now()
        let result = core.receive_renewal(&request).await.unwrap();
        assert!(result.renewed);
    }

    #[tokio::test]
    async fn receive_renewal_skips_roster_update_for_unknown_member() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let request = protocol::RenewRequest {
            hostname: "unknown-host".to_string(),
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            ca_pem: "ca".to_string(),
            fullchain_pem: "chain".to_string(),
            fingerprint: "fp".to_string(),
            expires: "2026-04-01T00:00:00Z".to_string(),
        };

        let result = core.receive_renewal(&request).await.unwrap();
        assert!(result.renewed);
        // No hook result since member not in roster
        assert!(result.hook_result.is_none());

        // Original roster should be unchanged
        let roster = core.state.roster.lock().await;
        assert_eq!(roster.members[0].cert_fingerprint, "fp-test");
    }

    #[tokio::test]
    async fn receive_renewal_executes_hook_if_set() {
        let ca = make_test_ca();
        let mut roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let cmd = "echo renewed";
        roster.members[0].reload_hook = Some(cmd.to_string());
        let core = make_unlocked_core(ca, roster);

        let request = protocol::RenewRequest {
            hostname: "stone-01".to_string(),
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            ca_pem: "ca".to_string(),
            fullchain_pem: "chain".to_string(),
            fingerprint: "new-fp".to_string(),
            expires: "2026-04-01T00:00:00Z".to_string(),
        };

        let result = core.receive_renewal(&request).await.unwrap();
        assert!(result.hook_result.is_some());
        let hook = result.hook_result.unwrap();
        assert!(hook.success);
    }

    // ── local_hostname ───────────────────────────────────────────────

    #[test]
    fn local_hostname_returns_some() {
        let hostname = CertmeshCore::local_hostname();
        assert!(hostname.is_some());
        assert!(!hostname.unwrap().is_empty());
    }

    // ── build_status ─────────────────────────────────────────────────

    #[test]
    fn build_status_locked_ca() {
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let status = build_status(&None, &roster, &TrustProfile::JustMe, None);
        assert!(status.ca_locked);
        assert_eq!(status.member_count, 1);
        assert_eq!(status.members.len(), 1);
        assert_eq!(status.members[0].hostname, "stone-01");
        assert_eq!(status.members[0].role, "primary");
    }

    #[test]
    fn build_status_unlocked_ca() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);
        let status = build_status(&Some(ca), &roster, &TrustProfile::JustMe, None);
        assert!(!status.ca_locked);
        assert_eq!(status.member_count, 0);
    }

    #[test]
    fn build_status_member_roles_lowercase() {
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        roster.members.push(RosterMember {
            hostname: "standby-01".to_string(),
            role: MemberRole::Standby,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec![],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        let status = build_status(&None, &roster, &TrustProfile::JustMe, None);
        assert_eq!(status.members[0].role, "standby");
        assert_eq!(status.members[0].status, "active");
    }

    // ── Phase 4 — Enrollment policy facade tests ────────────────────

    #[tokio::test]
    async fn open_enrollment_changes_state() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::MyOrganization, Some("Admin".into()));
        let core = make_unlocked_core(ca, roster);

        // Initially closed
        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Closed);

        // Open
        core.open_enrollment(None).await.unwrap();
        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Open);
        assert!(status.enrollment_deadline.is_none());
    }

    #[tokio::test]
    async fn open_enrollment_with_deadline() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::MyOrganization, Some("Admin".into()));
        let core = make_unlocked_core(ca, roster);

        let deadline = Utc::now() + Duration::hours(2);
        core.open_enrollment(Some(deadline)).await.unwrap();

        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Open);
        assert!(status.enrollment_deadline.is_some());
    }

    #[tokio::test]
    async fn close_enrollment_changes_state() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);
        let core = make_unlocked_core(ca, roster);

        // Initially open for JustMe
        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Open);

        // Close
        core.close_enrollment().await.unwrap();
        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Closed);
    }

    #[tokio::test]
    async fn set_policy_updates_constraints() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);
        let core = make_unlocked_core(ca, roster);

        core.set_policy(
            Some("lab.local".to_string()),
            Some("192.168.1.0/24".to_string()),
        )
        .await
        .unwrap();

        let status = core.certmesh_status().await;
        assert_eq!(status.allowed_domain.as_deref(), Some("lab.local"));
        assert_eq!(status.allowed_subnet.as_deref(), Some("192.168.1.0/24"));
    }

    #[tokio::test]
    async fn set_policy_clears_constraints() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        roster.metadata.allowed_domain = Some("old.local".to_string());
        let core = make_unlocked_core(ca, roster);

        core.set_policy(None, None).await.unwrap();

        let status = core.certmesh_status().await;
        assert!(status.allowed_domain.is_none());
        assert!(status.allowed_subnet.is_none());
    }

    #[tokio::test]
    async fn set_policy_rejects_invalid_cidr() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);
        let core = make_unlocked_core(ca, roster);

        let result = core.set_policy(None, Some("not-a-cidr".to_string())).await;
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[tokio::test]
    async fn set_policy_rejects_cidr_with_bad_ip() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);
        let core = make_unlocked_core(ca, roster);

        let result = core.set_policy(None, Some("xyz.abc/24".to_string())).await;
        assert!(matches!(result, Err(CertmeshError::ScopeViolation(_))));
    }

    #[tokio::test]
    async fn rotate_auth_fails_when_ca_locked() {
        let roster = Roster::new(TrustProfile::JustMe, None);
        let core = make_locked_core(roster);
        let result = core.rotate_auth("test-pass", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn build_status_includes_policy_fields() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::MyOrganization, Some("Admin".into()));
        roster.metadata.allowed_domain = Some("school.local".to_string());
        roster.metadata.allowed_subnet = Some("10.0.0.0/8".to_string());
        roster.metadata.enrollment_deadline = Some(Utc::now() + Duration::hours(1));

        let status = build_status(&Some(ca), &roster, &TrustProfile::MyOrganization, None);
        assert_eq!(status.allowed_domain.as_deref(), Some("school.local"));
        assert_eq!(status.allowed_subnet.as_deref(), Some("10.0.0.0/8"));
        assert!(status.enrollment_deadline.is_some());
    }

    // ── CertmeshCore::uninitialized() state ─────────────────────────

    #[tokio::test]
    async fn uninitialized_core_status_shows_empty_roster() {
        let core = CertmeshCore::uninitialized();
        let status = core.certmesh_status().await;
        // ca_initialized reflects filesystem state, not in-memory state.
        // ca_locked is false because we have no CA at all (not locked, just absent).
        assert_eq!(status.member_count, 0);
        assert!(status.members.is_empty());
        // The in-memory CA is None, so ca_locked should be true
        // (None means "no key loaded" which is the locked state).
        assert!(status.ca_locked);
    }

    #[tokio::test]
    async fn uninitialized_core_enroll_returns_error() {
        let core = CertmeshCore::uninitialized();
        let request = protocol::JoinRequest {
            hostname: "stone-05".to_string(),
            auth: koi_crypto::auth::AuthResponse::Totp {
                code: "123456".to_string(),
            },
            sans: vec![],
        };
        let result = core.enroll(&request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn uninitialized_core_promote_returns_error() {
        let core = CertmeshCore::uninitialized();
        let result = core.promote("passphrase").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn uninitialized_core_roster_manifest_returns_error() {
        let core = CertmeshCore::uninitialized();
        let result = core.roster_manifest().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn uninitialized_core_renew_all_due_returns_empty() {
        let core = CertmeshCore::uninitialized();
        let results = core.renew_all_due().await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn uninitialized_core_rotate_auth_returns_error() {
        let core = CertmeshCore::uninitialized();
        let result = core.rotate_auth("passphrase", None).await;
        assert!(result.is_err());
    }

    // ── node_role ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn node_role_returns_none_for_empty_roster() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);
        let core = make_unlocked_core(ca, roster);
        // Empty roster has no members, so node_role returns None
        // (regardless of local hostname)
        let role = core.node_role().await;
        // May or may not match the local hostname — depends on environment
        // but for an empty roster it should always be None
        assert!(role.is_none());
    }

    #[tokio::test]
    async fn node_role_returns_role_for_matching_hostname() {
        let ca = make_test_ca();
        let hostname = CertmeshCore::local_hostname().unwrap();
        let roster = make_test_roster_with_member(&hostname, MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        let role = core.node_role().await;
        assert_eq!(role, Some(MemberRole::Primary));
    }

    // ── pinned_ca_fingerprint ──────────────────────────────────────────

    #[tokio::test]
    async fn pinned_ca_fingerprint_returns_none_for_empty_roster() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);
        let core = make_unlocked_core(ca, roster);
        let fp = core.pinned_ca_fingerprint().await;
        assert!(fp.is_none());
    }

    #[tokio::test]
    async fn pinned_ca_fingerprint_returns_value_for_matching_member() {
        let ca = make_test_ca();
        let hostname = CertmeshCore::local_hostname().unwrap();
        let mut roster = make_test_roster_with_member(&hostname, MemberRole::Primary);
        roster.members[0].pinned_ca_fingerprint = Some("test-pinned-fp".to_string());
        let core = make_unlocked_core(ca, roster);
        let fp = core.pinned_ca_fingerprint().await;
        assert_eq!(fp.as_deref(), Some("test-pinned-fp"));
    }

    // ── ca_announcement ────────────────────────────────────────────────

    #[tokio::test]
    async fn ca_announcement_returns_none_when_ca_locked() {
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let ann = core.ca_announcement(5641).await;
        assert!(ann.is_none());
    }

    #[tokio::test]
    async fn ca_announcement_returns_none_when_no_primary() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Member);
        let core = make_unlocked_core(ca, roster);
        let ann = core.ca_announcement(5641).await;
        assert!(ann.is_none());
    }

    #[tokio::test]
    async fn ca_announcement_returns_descriptor_for_primary() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        let ann = core.ca_announcement(5641).await.unwrap();
        assert!(ann.name.contains("koi-ca-"));
        assert_eq!(ann.port, 5641);
        assert_eq!(ann.txt.get("role").unwrap(), "primary");
        assert!(ann.txt.contains_key("fingerprint"));
        assert!(ann.txt.contains_key("profile"));
    }

    // ── Capability::status() ───────────────────────────────────────────

    #[test]
    fn capability_status_uninitialised() {
        let core = CertmeshCore::uninitialized();
        let status = core.status();
        assert_eq!(status.name, "certmesh");
        // When no CA files exist on disk this is a healthy "ready" state.
        // On a dev machine with existing CA files it appears as "CA locked"
        // because the filesystem check sees them but the core has no loaded CA.
        if ca::is_ca_initialized() {
            assert!(!status.healthy);
            assert!(
                status.summary.contains("locked"),
                "unexpected summary: {}",
                status.summary
            );
        } else {
            assert!(status.healthy);
            assert!(
                status.summary.contains("ready"),
                "unexpected summary: {}",
                status.summary
            );
        }
    }

    #[test]
    fn capability_status_locked() {
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let status = core.status();
        assert_eq!(status.name, "certmesh");
        assert!(!status.healthy);
    }

    #[test]
    fn capability_status_unlocked() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        let status = core.status();
        assert_eq!(status.name, "certmesh");
        assert!(status.healthy);
        assert!(
            status.summary.contains("1 member"),
            "summary: {}",
            status.summary
        );
    }

    // ── certmesh_status facade ─────────────────────────────────────────

    #[tokio::test]
    async fn certmesh_status_returns_profile() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::MyOrganization, Some("ops".to_string()));
        let totp = koi_crypto::totp::generate_secret();
        let auth = koi_crypto::auth::AuthState::Totp(totp);
        let core = CertmeshCore::new(ca, roster, auth, TrustProfile::MyOrganization);
        let status = core.certmesh_status().await;
        assert_eq!(status.profile, TrustProfile::MyOrganization);
    }

    // ── set_reload_hook facade ─────────────────────────────────────────

    #[tokio::test]
    async fn set_reload_hook_unknown_member_returns_error() {
        let ca = make_test_ca();
        let roster = Roster::new(TrustProfile::JustMe, None);
        let core = make_unlocked_core(ca, roster);
        let result = core.set_reload_hook("nonexistent", "echo hi").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn set_reload_hook_sets_hook_for_known_member() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("stone-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        core.set_reload_hook("stone-01", "systemctl restart nginx")
            .await
            .unwrap();
        let roster = core.state.roster.lock().await;
        assert_eq!(
            roster.members[0].reload_hook.as_deref(),
            Some("systemctl restart nginx")
        );
    }
}
