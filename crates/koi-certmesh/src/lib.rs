//! Koi Certmesh — certificate mesh with TOTP enrollment (Phase 2).
//!
//! Provides a private Certificate Authority that mints ECDSA P-256 certificates,
//! TOTP-based enrollment for mesh members, trust store installation, and a
//! roster of enrolled members. Two machines on the same LAN can establish
//! mutual TLS trust without external infrastructure.

pub mod audit;
pub mod ca;
pub mod certfiles;
pub mod enrollment;
pub mod entropy;
pub mod error;
pub mod http;
pub mod profiles;
pub mod protocol;
pub mod roster;

use std::sync::Arc;

use axum::Router;
use koi_common::capability::{Capability, CapabilityStatus};
use koi_crypto::totp::RateLimiter;

pub use error::CertmeshError;
use profiles::TrustProfile;
use roster::Roster;

// ── Internal shared state ───────────────────────────────────────────

/// Internal shared state for CertmeshCore and HTTP handlers.
/// Not exposed outside this crate — all access goes through CertmeshCore methods.
pub(crate) struct CertmeshState {
    pub(crate) ca: tokio::sync::Mutex<Option<ca::CaState>>,
    pub(crate) roster: tokio::sync::Mutex<Roster>,
    pub(crate) totp_secret: tokio::sync::Mutex<Option<koi_crypto::totp::TotpSecret>>,
    pub(crate) rate_limiter: tokio::sync::Mutex<RateLimiter>,
    pub(crate) profile: TrustProfile,
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
    /// Create a new CertmeshCore with an unlocked (decrypted) CA.
    pub fn new(
        ca: ca::CaState,
        roster: Roster,
        totp_secret: koi_crypto::totp::TotpSecret,
        profile: TrustProfile,
    ) -> Self {
        Self {
            state: Arc::new(CertmeshState {
                ca: tokio::sync::Mutex::new(Some(ca)),
                roster: tokio::sync::Mutex::new(roster),
                totp_secret: tokio::sync::Mutex::new(Some(totp_secret)),
                rate_limiter: tokio::sync::Mutex::new(RateLimiter::new()),
                profile,
            }),
        }
    }

    /// Create a CertmeshCore in locked state (CA initialized but not unlocked).
    pub fn locked(roster: Roster, profile: TrustProfile) -> Self {
        Self {
            state: Arc::new(CertmeshState {
                ca: tokio::sync::Mutex::new(None),
                roster: tokio::sync::Mutex::new(roster),
                totp_secret: tokio::sync::Mutex::new(None),
                rate_limiter: tokio::sync::Mutex::new(RateLimiter::new()),
                profile,
            }),
        }
    }

    /// Build the HTTP router for this domain.
    ///
    /// The binary crate mounts this at `/v1/certmesh/`.
    pub fn routes(&self) -> Router {
        http::routes(Arc::clone(&self.state))
    }

    /// Process an enrollment request. Returns the join response on success.
    pub async fn enroll(
        &self,
        request: &protocol::JoinRequest,
    ) -> Result<protocol::JoinResponse, CertmeshError> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let sans = vec![hostname.clone(), format!("{hostname}.local")];

        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if ca::is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let mut roster = self.state.roster.lock().await;
        let totp_guard = self.state.totp_secret.lock().await;
        let totp_secret = totp_guard
            .as_ref()
            .ok_or(CertmeshError::CaLocked)?;
        let mut rate_limiter = self.state.rate_limiter.lock().await;

        let (response, _issued) = enrollment::process_enrollment(
            ca,
            &mut roster,
            totp_secret,
            &mut rate_limiter,
            request,
            &hostname,
            &sans,
            &self.state.profile,
        )?;

        // Save roster after successful enrollment
        let roster_path = ca::roster_path();
        if let Err(e) = roster::save_roster(&roster, &roster_path) {
            tracing::warn!(error = %e, "Failed to save roster after enrollment");
        }

        Ok(response)
    }

    /// Get the current certmesh status.
    pub async fn certmesh_status(&self) -> protocol::CertmeshStatus {
        let ca_guard = self.state.ca.lock().await;
        let roster = self.state.roster.lock().await;
        build_status(&ca_guard, &roster, &self.state.profile)
    }

    /// Unlock the CA with a passphrase.
    pub async fn unlock(
        &self,
        passphrase: &str,
    ) -> Result<(), CertmeshError> {
        let ca_state = ca::load_ca(passphrase)?;

        // Load TOTP secret
        let totp_path = ca::totp_secret_path();
        if totp_path.exists() {
            let encrypted = koi_crypto::keys::load_encrypted_key(&totp_path)?;
            let secret = koi_crypto::totp::decrypt_secret(&encrypted, passphrase)?;
            *self.state.totp_secret.lock().await = Some(secret);
        }

        *self.state.ca.lock().await = Some(ca_state);

        tracing::info!("CA unlocked");
        Ok(())
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

        let summary = if !ca_initialized {
            "CA not initialized".to_string()
        } else if ca_locked {
            "CA locked".to_string()
        } else {
            format!(
                "{} ({} member{})",
                self.state.profile,
                member_count,
                if member_count == 1 { "" } else { "s" }
            )
        };

        CapabilityStatus {
            name: "certmesh".to_string(),
            summary,
            healthy: ca_initialized && !ca_locked,
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
) -> protocol::CertmeshStatus {
    protocol::CertmeshStatus {
        ca_initialized: ca::is_ca_initialized(),
        ca_locked: ca_guard.is_none(),
        profile: profile.clone(),
        enrollment_state: roster.metadata.enrollment_state.clone(),
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
