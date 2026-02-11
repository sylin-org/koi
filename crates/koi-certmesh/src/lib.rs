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
pub mod failover;
pub mod health;
pub mod http;
pub mod lifecycle;
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

/// mDNS service type for CA discovery.
/// Used by the binary crate to announce the CA via koi-mdns.
pub const CERTMESH_SERVICE_TYPE: &str = "_certmesh._tcp";

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
        txt.insert(
            "fingerprint".to_string(),
            ca::ca_fingerprint(ca),
        );
        txt.insert("profile".to_string(), self.state.profile.to_string());

        Some(protocol::CaAnnouncement {
            name: format!("koi-ca-{}", primary.hostname),
            port: http_port,
            txt,
        })
    }

    /// Set the post-renewal reload hook for a member.
    pub async fn set_reload_hook(
        &self,
        hostname: &str,
        hook: &str,
    ) -> Result<(), CertmeshError> {
        let mut roster = self.state.roster.lock().await;
        let member = roster.find_member_mut(hostname).ok_or_else(|| {
            CertmeshError::Internal(format!("member not found: {hostname}"))
        })?;
        member.reload_hook = Some(hook.to_string());

        let roster_path = ca::roster_path();
        roster::save_roster(&roster, &roster_path)?;

        tracing::info!(hostname, hook, "Reload hook set");
        Ok(())
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
        let valid = health::validate_pinned_fingerprint(
            &current_fp,
            &request.pinned_ca_fingerprint,
        );

        let mut roster = self.state.roster.lock().await;
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
    pub async fn roster_manifest(
        &self,
    ) -> Result<protocol::RosterManifest, CertmeshError> {
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

        let totp_guard = self.state.totp_secret.lock().await;
        let totp_secret = totp_guard
            .as_ref()
            .ok_or(CertmeshError::CaLocked)?;

        let roster = self.state.roster.lock().await;
        failover::prepare_promotion(ca, totp_secret, &roster, passphrase)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::{MemberRole, MemberStatus, RosterMember};
    use chrono::{Duration, Utc};

    fn make_test_ca() -> ca::CaState {
        ca::create_ca("test-pass", &vec![42u8; 32]).unwrap()
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
        });
        r
    }

    fn make_unlocked_core(
        ca: ca::CaState,
        roster: Roster,
    ) -> CertmeshCore {
        let totp = koi_crypto::totp::generate_secret();
        CertmeshCore::new(ca, roster, totp, TrustProfile::JustMe)
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
        assert!(!response.encrypted_totp_secret.ciphertext.is_empty());
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
        let (ca_key, totp, accepted_roster) =
            failover::accept_promotion(&response, "round-trip-pass").unwrap();
        assert!(!ca_key.public_key_pem().is_empty());
        assert!(!totp.as_bytes().is_empty());
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
            fullchain_pem: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n".to_string(),
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
        let cmd = if cfg!(windows) { "echo renewed" } else { "echo renewed" };
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
        let status = build_status(&None, &roster, &TrustProfile::JustMe);
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
        let status = build_status(&Some(ca), &roster, &TrustProfile::JustMe);
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
        });
        let status = build_status(&None, &roster, &TrustProfile::JustMe);
        assert_eq!(status.members[0].role, "standby");
        assert_eq!(status.members[0].status, "active");
    }
}
