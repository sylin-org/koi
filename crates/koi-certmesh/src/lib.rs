//! Koi Certmesh - certificate mesh with pluggable enrollment auth (Phase 2+).
//!
//! Provides a private Certificate Authority that mints ECDSA P-256 certificates,
//! pluggable enrollment authentication (TOTP), a typed CA-anchor projection,
//! and a roster of enrolled members. Two machines on the same LAN can establish
//! mutual TLS trust without external infrastructure.

pub mod acme;
mod audit;
pub mod backup;
mod blocking_worker;
mod bootstrap;
pub mod bundle;
pub mod ca;
#[cfg(test)]
mod certfiles;
pub mod certmesh_paths;
pub mod client;
#[cfg(test)]
mod conformance;
pub mod csr;
pub mod diagnosis;
mod enrollment;
pub mod entropy;
pub mod envelope;
pub mod error;
pub mod failover;
pub mod health;
pub mod http;
pub mod init_ceremony;
pub mod invite;
mod issuance_names;
pub mod lifecycle;
pub mod member;
pub mod mtls;
mod observation;
pub mod principal;
pub mod profiles;
pub mod protocol;
mod repository;
pub mod roster;
pub mod sealed;
pub mod serve;
pub mod status;
pub mod wordlist;

pub use certmesh_paths::CertmeshPaths;

use std::sync::Arc;

use axum::Router;
use koi_common::posture::Posture;
use koi_crypto::auth::AuthState;
use koi_crypto::totp::RateLimiter;
use tokio::sync::{broadcast, mpsc, oneshot};
use zeroize::Zeroizing;

pub use bundle::SignedBundle;
pub use ca::LeafUsage;
pub use client::PeerClient;
pub use csr::sign_csr;
pub use error::CertmeshError;
pub use issuance_names::IssuanceNames;
pub use observation::CertmeshObservation;
use roster::Roster;
pub use status::{
    CertmeshAuthorityStatus, CertmeshBootstrapStatus, CertmeshCaAnchor, CertmeshCaAnchorSnapshot,
    CertmeshCaAnchorState, CertmeshIdentityStatus, CertmeshMemberStatus, CertmeshReloadStatus,
    CertmeshRenewalStatus, CertmeshRole, CertmeshStatus, IdentityCondition,
};

/// mDNS service type for CA discovery.
/// Used by the binary crate to announce the CA via koi-mdns.
pub const CERTMESH_SERVICE_TYPE: &str = "_certmesh._tcp";

/// Maximum clock skew tolerated by certmesh security timestamps.
///
/// Certificate validity is backdated by this amount and signed-envelope
/// freshness accepts the same ±window. One policy constant keeps a LAN member
/// with a slightly slower clock from rejecting a freshly issued identity while
/// preserving the existing bounded replay tolerance.
pub const CLOCK_SKEW_TOLERANCE_SECS: i64 = 300;

/// Events emitted by the certmesh subsystem.
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
    /// A leaf certificate was renewed successfully (ADR-020 reactive plane). On a
    /// member node this is its own leaf (`renew_self_if_due`); on a CA node it also
    /// fires when the CA signs a member's renewal (`renew_member`, ADR-021), where
    /// `expires_at` is that member's new leaf expiry.
    CertRenewed {
        /// When the new leaf expires (RFC 3339).
        expires_at: chrono::DateTime<chrono::Utc>,
    },
    /// The leaf will expire soon; renewal is overdue. Fires each time the renewal
    /// loop skips (CA unreachable) while the leaf is past its `renew_threshold`.
    CertExpiringSoon {
        /// Whole days until expiry (may be 0 or negative if already expired).
        days_left: i64,
    },
    /// A renewal attempt failed. `consecutive_failures` lets a consumer decide
    /// when to alert vs. absorb a transient CA hiccup.
    CertRenewalFailed {
        /// Human-readable reason from the renewal outcome.
        reason: String,
        /// How many consecutive failures (including this one).
        consecutive_failures: u32,
    },
    /// A trust-bundle pull updated the roster or policy, or confirmed revocation.
    BundleUpdated {
        /// `true` when the bundle explicitly listed this node as revoked — the node
        /// should stop serving and surface a clear error (ADR-020 §revocation).
        self_revoked: bool,
    },
    /// This node durably accepted CA material and is now an unlocked standby.
    PromotedToAuthority { hostname: String },
    /// The post-certificate activation hook completed and its durable intent
    /// was cleared.
    ReloadHookCompleted { command: String },
    /// The active certificate remains authoritative, but its local consumer
    /// did not reload; the durable intent will be retried at startup.
    ReloadHookFailed { command: String, reason: String },
}

// ── Internal shared state ───────────────────────────────────────────

/// Internal shared state for CertmeshCore and HTTP handlers.
/// Not exposed outside this crate - all access goes through CertmeshCore methods.
///
/// Aggregate model cells are synchronous on purpose. Their critical sections are
/// short, in-memory reads or replacements and every writer already holds the
/// asynchronous `transition` gate. Once a durable repository commit succeeds,
/// updating these cells and publishing projections must remain in the same poll:
/// dropping a caller may not strand disk one generation ahead of memory/status.
pub(crate) struct ModelCell<T>(std::sync::Mutex<T>);

impl<T> ModelCell<T> {
    fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    /// Acquire a bounded in-memory model cell without introducing a cancellation
    /// point. Callers must not retain the guard across an operation that can wait.
    fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// HTTP/facade sharing wrapper. The worker and aggregate are siblings so an
/// accepted worker closure can retain the aggregate without creating an
/// `Arc<State> -> worker -> Arc<State>` ownership cycle.
pub(crate) struct CertmeshState {
    pub(crate) domain: Arc<CertmeshDomain>,
    pub(crate) blocking: blocking_worker::CertmeshBlockingWorker,
    pub(crate) reloads: Arc<lifecycle::ReloadExecutor>,
}

impl CertmeshState {
    fn own(domain: CertmeshDomain) -> Self {
        Self {
            domain: Arc::new(domain),
            blocking: blocking_worker::CertmeshBlockingWorker::new(),
            reloads: Arc::new(lifecycle::ReloadExecutor::new()),
        }
    }
}

impl std::ops::Deref for CertmeshState {
    type Target = CertmeshDomain;

    fn deref(&self) -> &Self::Target {
        &self.domain
    }
}

pub(crate) struct CertmeshDomain {
    /// Resolved filesystem paths (immutable after construction).
    pub(crate) paths: CertmeshPaths,
    /// Machine identity accepted by the application composition. Certmesh does
    /// not re-observe the operating system: certificate names, roster role
    /// changes, renewal, and failover all use this one launch fact.
    pub(crate) local_hostname: Option<Arc<str>>,
    /// Immutable certificate-name policy, injected once by the composition root.
    pub(crate) issuance_names: IssuanceNames,
    pub(crate) ca: ModelCell<Option<ca::CaState>>,
    pub(crate) roster: ModelCell<Roster>,
    pub(crate) auth: ModelCell<Option<AuthState>>,
    /// The one live ACME account model shared by every HTTP adapter. Its durable
    /// file participates in the Certmesh repository; adapters never load their
    /// own parallel registry.
    pub(crate) acme_accounts: acme::account::AccountStore,
    pub(crate) pending_challenge: ModelCell<Option<koi_crypto::auth::AuthChallenge>>,
    pub(crate) rate_limiter: ModelCell<RateLimiter>,
    pub(crate) approval_tx: ModelCell<Option<mpsc::Sender<ApprovalRequest>>>,
    /// One-shot, short-lived key agreement held only by the local daemon while
    /// an operator-driven promotion is in flight.
    pub(crate) pending_promotion: ModelCell<Option<PendingPromotion>>,
    pub(crate) event_tx: broadcast::Sender<CertmeshEvent>,
    /// The sole Certmesh read model exposed across the domain boundary.
    pub(crate) status: koi_common::status::StatusFeed<CertmeshStatus>,
    /// Narrow public roster projection for DNS, Health, and other integration
    /// consumers that must not gain access to private Certmesh status.
    pub(crate) roster_snapshot:
        koi_common::status::StatusFeed<koi_common::integration::CertmeshRosterSnapshot>,
    /// Sensitive in-process identity projection for TLS consumers. It is kept
    /// separate from serializable status so private keys cannot leak onto a
    /// transport by accident.
    pub(crate) tls_identity:
        koi_common::status::StatusFeed<koi_common::integration::TlsIdentitySnapshot>,
    /// Sensitive CA desired-state projection consumed only by composition's
    /// Trust bridge. It publishes before primary status as a causal fence.
    pub(crate) ca_anchor: koi_common::status::StatusFeed<CertmeshCaAnchorSnapshot>,
    /// Serializes complete domain transitions: model reads/writes, durable
    /// artifact commits, projection publication, and semantic events. This is
    /// deliberately broader than a persistence lock: readers can never observe
    /// mixed generations while a multi-artifact command is committing.
    pub(crate) transition: Arc<tokio::sync::Mutex<()>>,
    /// The sole persistence boundary for aggregate artifact write-sets.
    pub(crate) repository: Arc<repository::CertmeshRepository>,
    /// Process-local renewal attempt truth. This model cell is projected into
    /// `CertmeshStatus` before renewal events leave the domain.
    pub(crate) renewal: ModelCell<CertmeshRenewalStatus>,
    /// A visible repository generation whose crash durability has not yet been
    /// confirmed. Status remains qualified until recovery or a later durable
    /// commit settles this process-local fact.
    pub(crate) repository_settlement_error: ModelCell<Option<String>>,
}

fn initial_local_hostname() -> Option<Arc<str>> {
    #[cfg(test)]
    {
        // Unit tests exercise domain transitions without an application
        // composition root. Their explicit fixture identity never ships in a
        // production build.
        Some(Arc::from("certmesh-test-host"))
    }
    #[cfg(not(test))]
    {
        None
    }
}

pub(crate) struct PendingPromotion {
    id: String,
    keypair: koi_crypto::key_agreement::EphemeralKeyPair,
    expires_at: tokio::time::Instant,
}

const CREDENTIAL_CLEANUP_LEDGER_VERSION: u32 = 1;

/// Durable outbox record for irreversible platform credential retirement.
/// It lives outside `certmesh/`, so removing the aggregate and recording the
/// remaining effects share one filesystem transaction.
#[derive(serde::Serialize, serde::Deserialize)]
struct CredentialCleanupLedger {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    totp_slot_table: Option<Vec<u8>>,
    delete_auto_unlock_vault: bool,
    delete_ca_tpm: bool,
}

/// Enrollment approval request sent to the operator prompt.
#[derive(Debug)]
pub struct ApprovalRequest {
    pub hostname: String,
    /// Whether this mesh requires operator approval (carries the operator name
    /// requirement that the old `profile` flag used to encode).
    pub requires_approval: bool,
    pub respond_to: oneshot::Sender<ApprovalDecision>,
}

/// Enrollment approval decision from the operator prompt.
#[derive(Debug)]
pub enum ApprovalDecision {
    Approved { operator: Option<String> },
    Denied,
}

const APPROVAL_TIMEOUT_SECS: u64 = 300;

/// Hard ceiling on a single member-pull renewal request (connect + handshake +
/// request + body). Bounds a black-holed CA so the renewal loop and daemon
/// shutdown never wait on the OS TCP timeout.
const RENEWAL_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Result of daemon self-enrollment for the mTLS listener.
///
/// Contains all PEM material needed to configure TLS with client cert
/// verification. Cloneable so the same leaf can configure both the mTLS and the
/// ACME server-auth listeners.
#[derive(Clone)]
pub struct SelfEnrollment {
    /// The daemon's certificate (signed by the CA).
    pub cert_pem: String,
    /// The daemon's private key.
    pub key_pem: String,
    /// The CA certificate (for client verification).
    pub ca_cert_pem: String,
}

/// This node's live cryptographic identity (ADR-020 §7): its CA-signed leaf plus
/// the CA anchor it chains to. The unified replacement for the previously
/// fragmented [`SelfEnrollment`] (cert/key/CA, no hostname) and
/// [`member::MemberState`] (CA coordinates, no cert). Returned by
/// [`CertmeshCore::local_identity`] and `ensure_identity`.
///
/// Cloneable so the same leaf can configure multiple listeners/clients. `Debug`
/// is redacted — the private key is never logged.
#[derive(Clone)]
pub struct Identity {
    /// This node's hostname (its certificate CN / cert directory name).
    pub hostname: String,
    /// The node's leaf certificate (PEM), signed by the CA.
    pub cert_pem: String,
    /// The node's private key (PEM). Never logged (redacted `Debug`).
    pub key_pem: String,
    /// The CA root certificate (PEM) the leaf chains to.
    pub ca_cert_pem: String,
    /// SHA-256 (hex) of the CA cert DER — the pin peers verify against.
    pub ca_fingerprint: String,
    /// Renewal/expiry health of the leaf (ADR-020 §13: "loud, not silent").
    pub renewal: RenewalHealth,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("hostname", &self.hostname)
            .field("ca_fingerprint", &self.ca_fingerprint)
            .field("renewal", &self.renewal)
            .field("cert_pem", &"<redacted>")
            .field("key_pem", &"<redacted>")
            .field("ca_cert_pem", &"<redacted>")
            .finish()
    }
}

/// Derived renewal/expiry health of a leaf certificate (ADR-020 §13).
///
/// The schedule facts a node and operator need so identity expiry is never a
/// silent surprise: when the leaf expires, when renewal is due, and whether it is
/// overdue or already expired. Attempt-level fields (last attempt, failure streak)
/// are wired by the renewal loop in a later increment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct RenewalHealth {
    /// When the current leaf expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// When renewal becomes due (`expires_at` − `renew_threshold_days`).
    pub next_renewal_at: chrono::DateTime<chrono::Utc>,
    /// Whole days until expiry (negative once expired).
    pub expires_in_days: i64,
    /// At/past the renewal point but the leaf has not yet rotated.
    pub renew_overdue: bool,
    /// At/past expiry — renewal failed or never ran.
    pub expired: bool,
}

impl RenewalHealth {
    /// Derive health from a leaf cert PEM and the CA-held policy. `None` when the
    /// certificate's validity window cannot be parsed.
    fn from_leaf(cert_pem: &str, policy: &roster::CertPolicy) -> Option<Self> {
        let expires_at = leaf_not_after_utc(cert_pem)?;
        let next_renewal_at =
            expires_at - chrono::Duration::days(i64::from(policy.renew_threshold_days));
        let now = chrono::Utc::now();
        Some(Self {
            expires_at,
            next_renewal_at,
            expires_in_days: (expires_at - now).num_days(),
            renew_overdue: now >= next_renewal_at,
            expired: now >= expires_at,
        })
    }
}

/// Serializable, key-redacting projection of [`Identity`] for cross-process and
/// cross-language consumers (ADR-020 reactive plane / wishlist 5.3).
///
/// The private key and all raw PEM material are omitted — only the non-sensitive
/// scheduling and anchor facts that a consumer needs to surface "who is this node
/// and when does its identity expire?" without leaking key material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct IdentityInfo {
    /// This node's hostname (its certificate CN).
    pub hostname: String,
    /// SHA-256 (hex) of the CA cert DER — the mesh anchor the peer pins to.
    pub ca_fingerprint: String,
    /// Renewal and expiry schedule.
    pub renewal: RenewalHealth,
}

impl From<&Identity> for IdentityInfo {
    fn from(id: &Identity) -> Self {
        Self {
            hostname: id.hostname.clone(),
            ca_fingerprint: id.ca_fingerprint.clone(),
            renewal: id.renewal.clone(),
        }
    }
}

impl CertmeshDomain {
    fn require_local_hostname(&self, operation: &str) -> Result<String, CertmeshError> {
        self.local_hostname
            .as_deref()
            .map(ToString::to_string)
            .ok_or_else(|| {
                CertmeshError::Internal(format!(
                    "local hostname was not supplied while {operation}; refusing to invent a certificate identity"
                ))
            })
    }

    /// Fail closed unless the durable aggregate says this node owns the CA.
    /// Every roster mutation passes through this gate, including internal ACME
    /// and health paths, so a joined member can never grow a shadow authority
    /// roster on disk.
    fn require_authority_under_transition(&self) -> Result<(), CertmeshError> {
        match self.status.current().role {
            CertmeshRole::Authority => Ok(()),
            CertmeshRole::Member => Err(CertmeshError::Conflict(
                "member nodes cannot mutate the Certmesh authority roster".into(),
            )),
            CertmeshRole::Open => Err(CertmeshError::CaNotInitialized),
        }
    }

    /// Rebuild and publish the authoritative projection after a successful
    /// transition. No-op refreshes preserve both the allocation and revision.
    pub(crate) async fn refresh_status(&self) -> Arc<CertmeshStatus> {
        let _transition = self.transition.lock().await;
        self.refresh_status_under_transition()
    }

    /// Rebuild status while the caller holds [`Self::transition`].
    pub(crate) fn refresh_status_under_transition(&self) -> Arc<CertmeshStatus> {
        let (ca_unlocked, ca_fingerprint) = {
            let ca = self.ca.lock();
            (ca.is_some(), ca.as_ref().map(ca::ca_fingerprint))
        };
        let roster = self.roster.lock().clone();
        let auth_method = self
            .auth
            .lock()
            .as_ref()
            .map(|auth| auth.method_name().to_string());
        let current_status = self.status.current();
        let revision = current_status.revision;
        let (mut next, next_tls_material) = status::build_with_tls(
            &self.paths,
            self.local_hostname.as_deref(),
            ca_unlocked,
            ca_fingerprint,
            &roster,
            auth_method,
            revision,
        );
        next.renewal = self.renewal.lock().clone();
        if let Some(reason) = self.repository_settlement_error.lock().as_deref() {
            status::qualify_repository_durability(&mut next, reason);
        }
        let status_changed = next != *current_status;
        if status_changed {
            next.revision = current_status.revision.saturating_add(1);
        }

        // Specialized projections publish before the primary status. The
        // primary feed is the causal fence: once a status watcher observes a
        // transition, every projection derived from that same aggregate
        // generation is already current.
        self.tls_identity.update(move |current| {
            if current.material == next_tls_material {
                None
            } else {
                Some(koi_common::integration::TlsIdentitySnapshot {
                    revision: current.revision.saturating_add(1),
                    material: next_tls_material,
                })
            }
        });
        let active_members = status::active_members(&next);
        self.roster_snapshot.update(move |current| {
            if current.active_members == active_members {
                None
            } else {
                Some(koi_common::integration::CertmeshRosterSnapshot {
                    revision: current.revision.saturating_add(1),
                    active_members,
                })
            }
        });
        let next_anchor =
            status::build_ca_anchor(&self.paths, self.local_hostname.as_deref(), next.role, 0)
                .state;
        self.ca_anchor.update(move |current| {
            if current.state == next_anchor {
                None
            } else {
                Some(CertmeshCaAnchorSnapshot {
                    revision: current.revision.saturating_add(1),
                    state: next_anchor,
                })
            }
        });
        if status_changed {
            self.status.publish(next)
        } else {
            current_status
        }
    }

    /// Accept one failed local renewal attempt into the aggregate model. The
    /// caller holds `transition` and publishes status before emitting its event.
    pub(crate) fn record_renewal_failure_under_transition(&self, reason: String) -> u32 {
        let mut renewal = self.renewal.lock();
        renewal.consecutive_failures = renewal.consecutive_failures.saturating_add(1);
        renewal.last_error = Some(reason);
        renewal.consecutive_failures
    }

    /// Clear a local failure streak only when a replacement certificate really
    /// committed. The caller holds `transition` and publishes the same causal
    /// generation before success events leave the boundary.
    pub(crate) fn clear_renewal_failure_under_transition(&self) {
        *self.renewal.lock() = CertmeshRenewalStatus::default();
    }

    /// Settle a repository commit only after the caller has accepted its
    /// visible generation into every affected in-memory model.
    pub(crate) fn finish_commit_under_transition(
        &self,
        outcome: koi_common::persist::AtomicCommit,
    ) -> Result<(), CertmeshError> {
        let result = match outcome {
            koi_common::persist::AtomicCommit::Durable => {
                *self.repository_settlement_error.lock() = None;
                Ok(())
            }
            koi_common::persist::AtomicCommit::DurabilityUncertain(error) => {
                let reason = error.to_string();
                *self.repository_settlement_error.lock() = Some(reason.clone());
                Err(CertmeshError::DurabilityUncertain(reason))
            }
        };
        self.refresh_status_under_transition();
        result
    }

    /// Destroy all certmesh state - shared by CertmeshCore::destroy() and the HTTP handler.
    pub(crate) fn destroy_under_transition(&self) -> Result<(), CertmeshError> {
        // A prior teardown may have committed while its platform store was
        // temporarily unavailable. Retry those independent outbox records before
        // adding this command's cleanup work.
        self.retry_credential_cleanups_under_transition();

        let slot_path = self.paths.slot_table_path();
        let totp_slot_table = if slot_path.exists() {
            koi_crypto::unlock_slots::SlotTable::prepare_totp_cleanup_ledger(&slot_path)
                .map_err(|error| CertmeshError::Crypto(error.to_string()))?
        } else {
            None
        };
        let cleanup_path = new_credential_cleanup_path(&self.paths);
        let cleanup_bytes = serde_json::to_vec_pretty(&CredentialCleanupLedger {
            version: CREDENTIAL_CLEANUP_LEDGER_VERSION,
            totp_slot_table,
            delete_auto_unlock_vault: true,
            delete_ca_tpm: true,
        })
        .map_err(|error| {
            CertmeshError::Internal(format!("serialize credential cleanup ledger: {error}"))
        })?;

        // All local artifacts disappear at one repository commit point. A
        // pre-replace failure restores the complete prior generation and
        // publishes nothing; post-replace uncertainty leaves the new visible
        // generation in force but withholds semantic success.
        // The cleanup ledger joins that commit, so no external credential is
        // touched until its ownership record is independently durable.
        let certmesh_dir = self.paths.certmesh_dir();
        let certs_dir = self.paths.certs_dir();
        let audit_path = self.paths.audit_log_path();
        let mut transaction = repository::ArtifactTransaction::new();
        transaction.write(cleanup_path.clone(), cleanup_bytes, true);
        transaction.remove_tree(&certmesh_dir)?;
        transaction.remove_tree(&certs_dir)?;
        transaction.remove(audit_path);
        let outcome = self.commit_artifacts_under_transition(transaction)?;

        // Clear in-memory state only after persistent state and any required
        // external-credential ownership ledger have committed successfully.
        *self.ca.lock() = None;
        *self.auth.lock() = None;
        *self.pending_challenge.lock() = None;
        *self.pending_promotion.lock() = None;
        *self.roster.lock() = Roster::empty();
        self.clear_renewal_failure_under_transition();
        self.acme_accounts.clear();

        self.finish_commit_under_transition(outcome)?;

        tracing::info!("Certmesh state destroyed");

        // Platform stores cannot participate in the filesystem transaction.
        // Retire their exact product-owned labels only after the aggregate is
        // durably gone. A failed attempt leaves the outbox in place for boot
        // retry and remains visible as a degraded diagnosis.
        let repository = Arc::clone(&self.repository);
        let cleanup_paths = self.paths.clone();
        let attempted_path = cleanup_path.clone();
        match koi_common::blocking::run_to_completion(move || {
            retire_credential_cleanup(&cleanup_paths, &repository, &attempted_path)
        }) {
            Ok(()) => {
                self.refresh_status_under_transition();
            }
            Err(error) => {
                tracing::warn!(%error, path = %cleanup_path.display(), "Certmesh credential cleanup deferred");
            }
        }

        // Directory and platform-store cleanup cannot affect the committed
        // aggregate generation. Remove only directories that remain empty so a
        // concurrently-created unrelated artifact can never be erased.
        for directory in [&certs_dir, &certmesh_dir, &self.paths.log_dir()] {
            if let Err(error) = remove_empty_tree(directory) {
                tracing::debug!(%error, path = %directory.display(), "Could not remove empty Certmesh directory");
            }
        }
        Ok(())
    }

    /// Retry pending external effects while the caller holds the transition.
    pub(crate) fn retry_credential_cleanups_under_transition(&self) {
        let paths = self.paths.clone();
        let repository = Arc::clone(&self.repository);
        koi_common::blocking::run_to_completion(move || {
            retry_credential_cleanups(&paths, &repository)
        });
    }

    /// Fence creation of a new trust generation until every cleanup owned by a
    /// prior destroyed generation has completed. This makes replay safe: an old
    /// fixed-label credential can never be retired after a replacement CA starts.
    pub(crate) fn require_cleanup_complete_under_transition(&self) -> Result<(), CertmeshError> {
        self.retry_credential_cleanups_under_transition();
        if self.paths.credential_cleanup_pending() {
            return Err(CertmeshError::Conflict(
                "platform credential cleanup from a prior Certmesh generation is still pending"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Commit a roster mutation while the caller holds [`Self::transition`].
    pub(crate) fn commit_roster_under_transition<F, R>(
        &self,
        bump_seq: bool,
        audit_line: Option<Vec<u8>>,
        mutate: F,
    ) -> Result<(R, koi_common::persist::AtomicCommit), CertmeshError>
    where
        F: FnOnce(&mut Roster) -> Result<R, CertmeshError>,
    {
        self.require_authority_under_transition()?;
        // Prepare against a private generation. Nothing — including a fallible
        // audit read or serialization — may make an uncommitted roster visible
        // through the live aggregate model.
        let mut snapshot = self.roster.lock().clone();
        let out = mutate(&mut snapshot)?;
        if bump_seq {
            snapshot.metadata.seq = snapshot.metadata.seq.saturating_add(1);
        }
        let mut transaction = repository::ArtifactTransaction::new();
        let bytes = serde_json::to_vec_pretty(&snapshot)
            .map_err(|error| CertmeshError::Internal(format!("serialize roster: {error}")))?;
        transaction.write(self.paths.roster_path(), bytes, true);
        if let Some(line) = audit_line {
            transaction.append(self.paths.audit_log_path(), line, true)?;
        }
        let repository = Arc::clone(&self.repository);
        let outcome =
            koi_common::blocking::run_to_completion(move || repository.commit(transaction))?;
        // Persistence is the commit point. The caller's retained transition
        // closure owns this model publication and every subsequent projection
        // and semantic-event step, even if its request future was cancelled.
        *self.roster.lock() = snapshot;
        Ok((out, outcome))
    }

    /// Commit an arbitrary aggregate write-set while the caller holds the
    /// transition gate. This is the only route from commands to durable files.
    pub(crate) fn commit_artifacts_under_transition(
        &self,
        transaction: repository::ArtifactTransaction,
    ) -> Result<koi_common::persist::AtomicCommit, CertmeshError> {
        let repository = Arc::clone(&self.repository);
        koi_common::blocking::run_to_completion(move || repository.commit(transaction))
    }

    /// Append one audit record through the same durable repository while the
    /// caller holds the transition gate.
    pub(crate) fn commit_audit_under_transition(
        &self,
        event: &str,
        fields: &[(&str, &str)],
    ) -> Result<(), CertmeshError> {
        let mut transaction = repository::ArtifactTransaction::new();
        transaction.append(
            self.paths.audit_log_path(),
            audit::render_entry(event, fields),
            true,
        )?;
        let outcome = self.commit_artifacts_under_transition(transaction)?;
        self.finish_commit_under_transition(outcome)
    }
}

fn new_credential_cleanup_path(paths: &CertmeshPaths) -> std::path::PathBuf {
    use rand::RngCore;

    loop {
        let mut random = [0u8; 16];
        rand::rng().fill_bytes(&mut random);
        let path = paths.credential_cleanup_dir().join(format!(
            "{}.json",
            koi_common::encoding::hex_encode(&random)
        ));
        if !path.exists() {
            return path;
        }
    }
}

fn retire_credential_cleanup(
    paths: &CertmeshPaths,
    repository: &repository::CertmeshRepository,
    path: &std::path::Path,
) -> Result<(), CertmeshError> {
    // A ledger belongs to a generation that has already been destroyed. Never
    // replay fixed-label cleanup across a restored or manually-created trust
    // generation, even if an older binary bypassed the creation fence.
    if paths.is_ca_initialized() || paths.member_state_path().exists() {
        return Err(CertmeshError::Conflict(
            "refusing stale credential cleanup while a Certmesh generation exists".into(),
        ));
    }
    let bytes = std::fs::read(path)?;
    let ledger: CredentialCleanupLedger = serde_json::from_slice(&bytes).map_err(|error| {
        CertmeshError::Internal(format!("parse credential cleanup ledger: {error}"))
    })?;
    if ledger.version != CREDENTIAL_CLEANUP_LEDGER_VERSION {
        return Err(CertmeshError::Internal(format!(
            "unsupported credential cleanup ledger version {}",
            ledger.version
        )));
    }
    if let Some(slot_table) = ledger.totp_slot_table.as_deref() {
        koi_crypto::unlock_slots::SlotTable::retire_totp_cleanup_bytes(slot_table)
            .map_err(|error| CertmeshError::Crypto(error.to_string()))?;
    }
    if ledger.delete_auto_unlock_vault {
        koi_crypto::vault::Vault::delete_persisted_entry(
            paths.data_dir(),
            CertmeshCore::VAULT_AUTO_UNLOCK_KEY,
        )?;
    }
    if ledger.delete_ca_tpm {
        koi_crypto::tpm::delete_key_material("koi-certmesh-ca")
            .map_err(|error| CertmeshError::Crypto(error.to_string()))?;
    }
    let mut transaction = repository::ArtifactTransaction::new();
    transaction.remove(path.to_path_buf());
    repository.commit_durable(transaction)?;
    if let Some(directory) = path.parent() {
        if let Err(error) = remove_empty_tree(directory) {
            tracing::debug!(%error, path = %directory.display(), "Could not remove empty credential-cleanup directory");
        }
    }
    Ok(())
}

fn retry_credential_cleanups(paths: &CertmeshPaths, repository: &repository::CertmeshRepository) {
    let entries = match std::fs::read_dir(paths.credential_cleanup_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            tracing::warn!(%error, "Could not inspect pending Certmesh credential cleanup");
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, "Could not inspect a Certmesh credential cleanup ledger");
                continue;
            }
        };
        match entry.file_type() {
            Ok(kind) if kind.is_file() => {}
            Ok(_) => {
                tracing::warn!(path = %entry.path().display(), "Ignoring unexpected entry in Certmesh credential-cleanup outbox");
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, path = %entry.path().display(), "Could not inspect Certmesh credential cleanup ledger");
                continue;
            }
        }
        if let Err(error) = retire_credential_cleanup(paths, repository, &entry.path()) {
            tracing::warn!(%error, path = %entry.path().display(), "Certmesh credential cleanup remains pending");
        }
    }
}

// ── CertmeshCore - domain facade ────────────────────────────────────

fn remove_empty_tree(path: &std::path::Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_empty_tree(&entry.path())?;
        }
    }
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// CertmeshCore - the main domain facade.
///
/// Wraps the shared certmesh state and exposes commands,
/// status, and HTTP routes to the binary crate.
///
/// `Clone` is a cheap `Arc` bump — every clone shares the same underlying
/// `CertmeshState` (CA, roster, auth). This lets the composition layer hold a
/// facade while also building an `AcmeState` over the same state.
#[derive(Clone)]
pub struct CertmeshCore {
    state: Arc<CertmeshState>,
}

// impl CertmeshCore is split across cohesive submodules (certmesh M2).
// Each child module does 'use super::*' to inherit lib.rs's imports, sibling
// modules, and crate-private state + helpers.
mod core_admin;
mod core_auth;
mod core_enroll;
mod core_failover;
mod core_identity;
mod core_lifecycle;
mod core_member;
mod core_renewal;
mod core_setup;
mod core_status_clock;

/// Shell metacharacters forbidden in reload hook commands.
///
/// Single source of truth for hook-command validation (the HTTP handler
/// delegates to [`CertmeshCore::set_reload_hook`], which calls
/// [`validate_reload_hook`]).
const HOOK_FORBIDDEN: &[char] = &[
    ';', '|', '&', '$', '`', '>', '<', '(', ')', '\n', '\r', '\0', '*', '?', '[', ']', '{', '}',
    '~', '%', '!',
];

/// Validate a post-renewal reload hook command.
///
/// This is the **single source of truth** for hook validation — every caller
/// (HTTP, embedded, CLI) is protected because they all route through
/// [`CertmeshCore::set_reload_hook`], which calls this. The validation is the
/// superset of all prior checks:
///
/// 1. No shell metacharacters ([`HOOK_FORBIDDEN`]).
/// 2. The command must be an **absolute path** — on Unix it must start with
///    `/`; on Windows it must begin with a drive-letter path (`X:\…`) or UNC
///    path (`\\…`). This blocks `PATH`-relative command injection.
pub(crate) fn validate_reload_hook(hook: &str) -> Result<(), CertmeshError> {
    if hook.contains(HOOK_FORBIDDEN) {
        return Err(CertmeshError::InvalidPayload(
            "reload hook contains forbidden characters".into(),
        ));
    }
    #[cfg(unix)]
    if !hook.starts_with('/') {
        return Err(CertmeshError::InvalidPayload(
            "reload hook must be an absolute path".into(),
        ));
    }
    #[cfg(windows)]
    {
        let bytes = hook.as_bytes();
        let drive_letter = bytes.len() >= 3 && bytes[1] == b':';
        let unc = hook.starts_with("\\\\");
        if !(drive_letter || unc) {
            return Err(CertmeshError::InvalidPayload(
                "reload hook must be an absolute path".into(),
            ));
        }
    }
    Ok(())
}

/// Outcome of a member trust-bundle pull ([`CertmeshCore::pull_trust_bundle`]).
#[derive(Debug)]
pub enum BundleOutcome {
    /// This node has no member state — it never joined a mesh. Nothing to pull.
    NotApplicable,
    /// The bundle verified but its `seq` matches what we already have.
    NoChange { seq: u64 },
    /// A newer, verified bundle was accepted; policy + `last_bundle_seq` updated.
    Updated { seq: u64, self_revoked: bool },
}

/// Outcome of a member-pull renewal attempt ([`CertmeshCore::renew_self_if_due`]).
#[derive(Debug)]
pub enum RenewOutcome {
    /// This node has no member renewal state — it never joined a mesh (e.g. it is
    /// the CA, or unconfigured). Nothing to do.
    NotApplicable,
    /// The local leaf is not yet within the renewal threshold.
    NotDue {
        not_after: chrono::DateTime<chrono::Utc>,
    },
    /// The leaf was renewed (key rotated); carries the new expiry and any reload
    /// hook result.
    Renewed {
        expires: String,
        hook: Option<protocol::HookResult>,
    },
}

/// Parse a leaf certificate PEM and return its `not_after` as a UTC datetime.
///
/// Returns `None` on unparseable PEM/DER or an out-of-range timestamp.
/// The `not_after` (expiry) instant of a leaf certificate PEM, or `None` if it
/// cannot be parsed. A **stateless** reader for an *arbitrary* leaf (a discovered
/// peer's cert, an operator-pasted cert) — no trust validation, just the field
/// (ADR-022 N3). For this node's *own* leaf with full renewal health, prefer
/// [`CertmeshCore::local_identity`] → `Identity::renewal`.
pub fn leaf_not_after_utc(cert_pem: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use x509_parser::prelude::FromDer;
    let der = pem::parse(cert_pem).ok()?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.contents()).ok()?;
    chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
}

/// The Common Name (CN) of a leaf certificate PEM, or `None` if it cannot be
/// parsed. A **stateless** reader for an *arbitrary* leaf — no trust validation,
/// just the subject CN (ADR-022 N3). Complements the DER-taking
/// [`mtls::extract_cn`] with a PEM entry point.
pub fn leaf_cn(cert_pem: &str) -> Option<String> {
    let der = pem::parse(cert_pem).ok()?;
    crate::mtls::extract_cn(der.contents())
}

/// Whether the recorded machine binding still matches this host (ADR-017 F11).
///
/// `true` when no binding was recorded (a pre-F11 CA — not machine-checked) or
/// when the recorded fingerprint matches the current host. `false` only when a
/// recorded binding no longer matches, or can't be re-derived — both of which
/// must fail auto-unlock safe (boot locked).
///
/// Free function (not a method) so the daemon boot path
/// (`koi_compose::init_certmesh_core`, which builds the core *after* deciding
/// whether to auto-unlock) can gate on it with only the resolved paths. It does
/// blocking I/O (a file read; a subprocess on Windows/macOS) — call it from a sync
/// context or via `spawn_blocking`.
pub fn machine_binding_ok(paths: &CertmeshPaths) -> bool {
    let recorded = match std::fs::read_to_string(paths.machine_bind_path()) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return true, // no binding recorded → not machine-checked
    };
    match koi_crypto::vault::machine_fingerprint() {
        Some(current) => koi_crypto::pinning::fingerprints_match(&current, &recorded),
        None => false, // recorded a binding but machine-id is now unreadable → fail safe
    }
}

/// Load the persisted TOTP rate-limiter state (ADR-017 F7).
///
/// Only a missing file creates a fresh limiter. Corruption or I/O failure is
/// aggregate damage and must stop bootstrap rather than erase a lockout.
fn load_rate_limiter(paths: &CertmeshPaths) -> Result<RateLimiter, CertmeshError> {
    match std::fs::read(paths.rate_limiter_path()) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
            CertmeshError::Internal(format!(
                "persisted enrollment rate limiter at '{}' is invalid: {error}",
                paths.rate_limiter_path().display()
            ))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(RateLimiter::new()),
        Err(error) => Err(CertmeshError::Io(error)),
    }
}

/// The single source of truth for hostname validation (ADR-017 F15): full
/// **RFC 1123**, used everywhere a hostname becomes a certificate SAN/CN or a
/// directory name under `certs/`.
///
/// Rules: total length 1..=253; one or more dot-separated labels; each label
/// 1..=63 chars of ASCII alphanumeric or hyphen, with no leading or trailing
/// hyphen. This subsumes the old per-call-site denylists — path separators (`/`
/// `\`), `..`, `:`, NUL, and spaces are all rejected by construction, so a
/// validated hostname is safe both as a SAN and as a single-segment directory
/// name (it can never escape the certs directory).
pub(crate) fn validate_hostname(hostname: &str) -> Result<(), CertmeshError> {
    let reject = |msg: String| Err(CertmeshError::InvalidPayload(msg));
    if hostname.is_empty() || hostname.len() > 253 {
        return reject(format!(
            "hostname length must be 1..=253 characters: {hostname:?}"
        ));
    }
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return reject(format!(
                "hostname label length must be 1..=63 characters: {hostname:?}"
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return reject(format!(
                "hostname has invalid characters (RFC 1123 allows alphanumerics + hyphen): {hostname:?}"
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return reject(format!(
                "hostname label must not start or end with a hyphen: {hostname:?}"
            ));
        }
    }
    Ok(())
}

/// Decode a hex string into bytes. Returns `None` on invalid hex or odd length.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

async fn request_approval(
    state: &CertmeshState,
    hostname: &str,
    requires_approval: bool,
) -> Result<Option<String>, CertmeshError> {
    let tx = state
        .approval_tx
        .lock()
        .clone()
        .ok_or(CertmeshError::ApprovalUnavailable)?;

    let (respond_to, response_rx) = oneshot::channel();
    let request = ApprovalRequest {
        hostname: hostname.to_string(),
        requires_approval,
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
            // When approval is required, an operator name must accompany it
            // (the audit trail needs an accountable name).
            if requires_approval && operator.as_deref().unwrap_or("").is_empty() {
                return Err(CertmeshError::ApprovalDenied);
            }
            Ok(operator)
        }
        ApprovalDecision::Denied => Err(CertmeshError::ApprovalDenied),
    }
}

// ── Shared helpers ──────────────────────────────────────────────────

#[cfg(test)]
mod core_tests;
