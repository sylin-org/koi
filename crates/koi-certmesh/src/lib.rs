//! Koi Certmesh - certificate mesh with pluggable enrollment auth (Phase 2+).
//!
//! Provides a private Certificate Authority that mints ECDSA P-256 certificates,
//! pluggable enrollment authentication (TOTP), trust store installation,
//! and a roster of enrolled members. Two machines on the same LAN can establish
//! mutual TLS trust without external infrastructure.

pub mod acme;
pub mod audit;
pub mod backup;
pub mod bundle;
pub mod ca;
pub mod certfiles;
pub mod certmesh_paths;
pub mod client;
#[cfg(test)]
mod conformance;
pub mod csr;
pub mod diagnosis;
pub mod enrollment;
pub mod entropy;
pub mod envelope;
pub mod error;
pub mod failover;
pub mod health;
pub mod http;
pub mod init_ceremony;
pub mod invite;
pub mod lifecycle;
pub mod member;
pub mod mtls;
pub mod profiles;
pub mod protocol;
pub mod roster;
pub mod sealed;
pub mod serve;
pub mod wordlist;

pub use certmesh_paths::CertmeshPaths;

use std::sync::Arc;

use axum::Router;
use koi_common::capability::{Capability, CapabilityStatus};
use koi_common::posture::Posture;
use koi_crypto::auth::AuthState;
use koi_crypto::totp::RateLimiter;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use zeroize::Zeroizing;

pub use client::PeerClient;
pub use csr::sign_csr;
pub use error::CertmeshError;
use roster::Roster;

/// mDNS service type for CA discovery.
/// Used by the binary crate to announce the CA via koi-mdns.
pub const CERTMESH_SERVICE_TYPE: &str = "_certmesh._tcp";

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
/// Not exposed outside this crate - all access goes through CertmeshCore methods.
pub(crate) struct CertmeshState {
    /// Resolved filesystem paths (immutable after construction).
    pub(crate) paths: CertmeshPaths,
    pub(crate) ca: tokio::sync::Mutex<Option<ca::CaState>>,
    pub(crate) roster: tokio::sync::Mutex<Roster>,
    pub(crate) auth: tokio::sync::Mutex<Option<AuthState>>,
    pub(crate) pending_challenge: tokio::sync::Mutex<Option<koi_crypto::auth::AuthChallenge>>,
    pub(crate) rate_limiter: tokio::sync::Mutex<RateLimiter>,
    pub(crate) approval_tx: tokio::sync::Mutex<Option<mpsc::Sender<ApprovalRequest>>>,
    pub(crate) event_tx: broadcast::Sender<CertmeshEvent>,
    /// Latest node posture, published on every identity-mutating op so a listener
    /// supervisor (ADR-020 §5) can react to Open↔Authenticated transitions without
    /// polling. Seeded from disk at construction; coalesced (no-op when unchanged).
    pub(crate) posture_tx: watch::Sender<Posture>,
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// The posture watch seeded from disk: a node is `signed` when it already holds a
/// usable CA-anchored leaf. Used by every `CertmeshState` constructor so the watch
/// reports the right value before any mutation (ADR-020 §5).
fn initial_posture_tx(paths: &CertmeshPaths) -> watch::Sender<Posture> {
    watch::channel(Posture {
        signed: node_has_identity(paths),
        encrypted: false,
    })
    .0
}

impl CertmeshState {
    /// Recompute this node's posture from disk and publish it on the watch
    /// (ADR-020 §5). Coalesced — a `send` (and thus a `PostureChanged`) fires only
    /// when the posture actually changed. Called after every identity-mutating op
    /// (create / self-enroll / member install / destroy).
    pub(crate) fn republish_posture(&self) {
        let next = Posture {
            signed: node_has_identity(&self.paths),
            encrypted: false,
        };
        self.posture_tx.send_if_modified(|cur| {
            if *cur != next {
                *cur = next;
                true
            } else {
                false
            }
        });
    }

    /// Destroy all certmesh state - shared by CertmeshCore::destroy() and the HTTP handler.
    pub(crate) async fn destroy(&self) -> Result<(), CertmeshError> {
        // Clear in-memory state first
        *self.ca.lock().await = None;
        *self.auth.lock().await = None;
        *self.pending_challenge.lock().await = None;
        *self.roster.lock().await = Roster::empty();

        // Remove platform-sealed key material (best-effort)
        if let Err(e) = koi_crypto::tpm::delete_key_material("koi-certmesh-ca") {
            tracing::debug!(error = %e, "No platform-sealed key material to clean up");
        }

        // Filesystem cleanup via spawn_blocking to avoid blocking the async executor
        let certmesh_dir = self.paths.certmesh_dir();
        let certs_dir = self.paths.certs_dir();
        let audit_path = self.paths.audit_log_path();
        tokio::task::spawn_blocking(move || {
            if certmesh_dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(&certmesh_dir) {
                    tracing::warn!(error = %e, "Failed to remove certmesh directory");
                } else {
                    tracing::info!(path = %certmesh_dir.display(), "Certmesh data directory removed");
                }
            }
            if certs_dir.exists() {
                if let Err(e) = std::fs::remove_dir_all(&certs_dir) {
                    tracing::warn!(error = %e, "Failed to remove certificate files");
                } else {
                    tracing::info!(path = %certs_dir.display(), "Certificate files removed");
                }
            }
            if audit_path.exists() {
                if let Err(e) = std::fs::remove_file(&audit_path) {
                    tracing::warn!(error = %e, "Failed to remove audit log");
                } else {
                    tracing::info!(path = %audit_path.display(), "Audit log removed");
                }
            }
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("destroy task: {e}")))?;

        tracing::info!("Certmesh state destroyed");
        self.republish_posture();
        Ok(())
    }

    /// Single-writer commit of a **membership** change (ADR-017 F8).
    ///
    /// Holds the roster lock for the entire read-modify-write, bumps `seq`, and
    /// persists atomically *while still holding the lock* — so concurrent commits
    /// serialize in `seq` order and can never lose an update (the old
    /// `clone → drop → write` pattern could). Persists only when `mutate` returns
    /// `Ok`; the closure must not leave the roster mutated on `Err`.
    pub(crate) async fn commit_roster<F, R>(&self, mutate: F) -> Result<R, CertmeshError>
    where
        F: FnOnce(&mut Roster) -> Result<R, CertmeshError>,
    {
        self.commit_inner(true, mutate).await
    }

    /// Persist a **non-membership** change (e.g. `last_seen`) without bumping
    /// `seq`, still holding the lock across the atomic write. The trust bundle is
    /// unaffected (it does not carry liveness), so its `seq`/cache stay stable.
    pub(crate) async fn touch_roster<F, R>(&self, mutate: F) -> Result<R, CertmeshError>
    where
        F: FnOnce(&mut Roster) -> Result<R, CertmeshError>,
    {
        self.commit_inner(false, mutate).await
    }

    async fn commit_inner<F, R>(&self, bump_seq: bool, mutate: F) -> Result<R, CertmeshError>
    where
        F: FnOnce(&mut Roster) -> Result<R, CertmeshError>,
    {
        let mut roster = self.roster.lock().await;
        let out = mutate(&mut roster)?;
        if bump_seq {
            roster.metadata.seq = roster.metadata.seq.saturating_add(1);
        }
        let snapshot = roster.clone();
        let path = self.paths.roster_path();
        // Persist off the executor but keep the roster lock held so writes
        // serialize in seq order (single writer).
        let saved = tokio::task::spawn_blocking(move || roster::save_roster(&snapshot, &path))
            .await
            .map_err(|e| std::io::Error::other(format!("roster save task: {e}")))
            .and_then(|r| r)
            .map_err(CertmeshError::Io);
        if let Err(e) = saved {
            // A failed persist is a trust-relevant event: the in-memory roster
            // advanced but the durable copy did not (ADR-017 F9). Audit before
            // returning so the gap is visible.
            let _ = audit::append_entry_to(
                &self.paths.audit_log_path(),
                "roster_persist_failed",
                &[("error", &e.to_string())],
            );
            return Err(e);
        }
        Ok(out)
    }
}

// ── CertmeshCore - domain facade ────────────────────────────────────

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

impl CertmeshCore {
    /// Construct a facade from an existing shared state.
    pub(crate) fn from_state(state: Arc<CertmeshState>) -> Self {
        Self { state }
    }

    /// The resolved filesystem paths this core operates on.
    ///
    /// The data root is resolved once at the composition root and injected
    /// via the `*_with_paths` constructors; every operation reads it from
    /// here. There is no ambient fallback.
    pub fn paths(&self) -> &CertmeshPaths {
        &self.state.paths
    }

    /// Create a new CertmeshCore with an unlocked CA and explicit paths.
    pub fn new_with_paths(
        ca: ca::CaState,
        roster: Roster,
        auth_state: Option<AuthState>,
        paths: CertmeshPaths,
    ) -> Self {
        let rate_limiter = load_rate_limiter(&paths);
        let posture_tx = initial_posture_tx(&paths);
        Self {
            state: Arc::new(CertmeshState {
                paths,
                ca: tokio::sync::Mutex::new(Some(ca)),
                roster: tokio::sync::Mutex::new(roster),
                auth: tokio::sync::Mutex::new(auth_state),
                pending_challenge: tokio::sync::Mutex::new(None),
                rate_limiter: tokio::sync::Mutex::new(rate_limiter),
                approval_tx: tokio::sync::Mutex::new(None),
                event_tx: koi_common::events::event_channel().0,
                posture_tx,
            }),
        }
    }

    /// Create a CertmeshCore in locked state with explicit paths.
    pub fn locked_with_paths(roster: Roster, paths: CertmeshPaths) -> Self {
        let rate_limiter = load_rate_limiter(&paths);
        let posture_tx = initial_posture_tx(&paths);
        Self {
            state: Arc::new(CertmeshState {
                paths,
                ca: tokio::sync::Mutex::new(None),
                roster: tokio::sync::Mutex::new(roster),
                auth: tokio::sync::Mutex::new(None),
                pending_challenge: tokio::sync::Mutex::new(None),
                rate_limiter: tokio::sync::Mutex::new(rate_limiter),
                approval_tx: tokio::sync::Mutex::new(None),
                event_tx: koi_common::events::event_channel().0,
                posture_tx,
            }),
        }
    }

    /// Create a CertmeshCore in uninitialized state with explicit paths.
    ///
    /// HTTP routes are still mounted so `/create` is reachable on a fresh install.
    /// All operations that require an initialized CA will return `CaNotInitialized`.
    pub fn uninitialized_with_paths(paths: CertmeshPaths) -> Self {
        let rate_limiter = load_rate_limiter(&paths);
        let posture_tx = initial_posture_tx(&paths);
        Self {
            state: Arc::new(CertmeshState {
                paths,
                ca: tokio::sync::Mutex::new(None),
                roster: tokio::sync::Mutex::new(Roster::empty()),
                auth: tokio::sync::Mutex::new(None),
                pending_challenge: tokio::sync::Mutex::new(None),
                rate_limiter: tokio::sync::Mutex::new(rate_limiter),
                approval_tx: tokio::sync::Mutex::new(None),
                event_tx: koi_common::events::event_channel().0,
                posture_tx,
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

    /// Build the inter-node router for the mTLS listener.
    ///
    /// Contains only routes that require mutual TLS between mesh members:
    /// promote, health, renew, roster, set-hook.
    pub fn inter_node_routes(&self) -> Router {
        http::inter_node_routes(Arc::clone(&self.state))
    }

    /// Set the approval channel used for enrollment approvals.
    pub async fn set_approval_channel(&self, tx: mpsc::Sender<ApprovalRequest>) {
        *self.state.approval_tx.lock().await = Some(tx);
    }

    /// Subscribe to certmesh events.
    pub fn subscribe(&self) -> broadcast::Receiver<CertmeshEvent> {
        self.state.event_tx.subscribe()
    }

    /// Watch this node's posture (ADR-020 §5). The receiver always holds the
    /// current [`Posture`] (so a new subscriber reads it immediately) and is
    /// notified on every Open↔Authenticated transition — the signal a listener
    /// supervisor uses to flip plain↔mTLS without polling. Transitions are also
    /// surfaced as `KoiEvent::PostureChanged` by the embedded facade.
    pub fn watch_posture(&self) -> watch::Receiver<Posture> {
        self.state.posture_tx.subscribe()
    }

    /// Build the RFC 8555 ACME server state over this CA.
    ///
    /// The binary calls this when starting the dedicated server-auth TLS
    /// listener, passing the ACME base URL, the Koi DNS zone, and the
    /// `AcmeDnsSolver` bridge. The returned `AcmeState` shares this core's CA and
    /// roster (so ACME issuance lands in the same roster as TOTP enrollment), and
    /// is mounted via [`acme::routes`].
    pub fn acme_state(&self, config: acme::AcmeStateConfig) -> std::sync::Arc<acme::AcmeState> {
        acme::AcmeState::new(Arc::clone(&self.state), config)
    }

    /// Initialize a new CA and self-enroll this node as the primary member.
    ///
    /// Full CA-initialization orchestration: decode entropy, create the CA,
    /// generate the TOTP auth credential, create and persist the roster,
    /// self-enroll the CA node, install the CA cert in the OS trust store
    /// (best-effort), configure auto-unlock, and update in-memory state.
    ///
    /// This is the single source of truth for CA creation; the HTTP
    /// `create_handler` is a thin delegate over this method.
    pub async fn create(
        &self,
        req: protocol::CreateCaRequest,
    ) -> Result<protocol::CreateCaResponse, CertmeshError> {
        let state = &self.state;

        // Decode hex entropy (must be exactly 32 bytes)
        let entropy = match decode_hex(&req.entropy_hex) {
            Some(bytes) if bytes.len() == 32 => bytes,
            Some(bytes) => {
                return Err(CertmeshError::InvalidPayload(format!(
                    "entropy must be exactly 32 bytes, got {}",
                    bytes.len()
                )));
            }
            None => {
                return Err(CertmeshError::InvalidPayload(
                    "invalid hex entropy".to_string(),
                ));
            }
        };

        // Reject if CA already initialized
        if state.paths.is_ca_initialized() {
            return Err(CertmeshError::Conflict(
                "CA is already initialized".to_string(),
            ));
        }

        // Create CA (blocking I/O: key gen, file writes, slot table save)
        let passphrase_clone = req.passphrase.clone();
        let paths_clone = state.paths.clone();
        let (ca_state, _master_key) = tokio::task::spawn_blocking(move || {
            ca::create_ca(&passphrase_clone, &entropy, &paths_clone)
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("CA creation task: {e}")))
        .and_then(|r| r)?;
        let ca_fingerprint = ca::ca_fingerprint(&ca_state);

        // Generate auth credential (default=TOTP).
        // If the client provided a ceremony-verified secret, use it;
        // otherwise generate a fresh one.
        let totp_secret = if let Some(ref hex) = req.totp_secret_hex {
            match koi_common::encoding::hex_decode(hex) {
                Ok(bytes) => koi_crypto::totp::TotpSecret::from_bytes(bytes),
                Err(_) => {
                    return Err(CertmeshError::InvalidPayload(
                        "totp_secret_hex: invalid hex encoding".into(),
                    ));
                }
            }
        } else {
            koi_crypto::totp::generate_secret()
        };
        let stored = koi_crypto::auth::store_totp(&totp_secret, &req.passphrase)
            .map_err(|e| CertmeshError::Internal(format!("auth store: {e}")))?;
        let auth_json = serde_json::to_string_pretty(&stored)
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?;
        {
            let auth_path = state.paths.auth_path();
            let auth_json_clone = auth_json.clone();
            tokio::task::spawn_blocking(move || std::fs::write(&auth_path, &auth_json_clone))
                .await
                .map_err(|e| std::io::Error::other(format!("file I/O: {e}")))
                .and_then(|r| r)
                .map_err(CertmeshError::Io)?;
        }

        let totp_uri = koi_crypto::totp::build_totp_uri(&totp_secret, "Koi Certmesh", "enrollment");

        // Create roster from the two posture booleans (the named preset, if any,
        // was already resolved to these by the ceremony/CLI).
        let mut new_roster = roster::Roster::new(
            req.enrollment_open,
            req.requires_approval,
            req.operator.clone(),
        );
        let roster_path = state.paths.roster_path();
        roster::persist_roster(&new_roster, &roster_path).await?;

        // Self-enroll the CA node as the first (primary) member.
        // This issues a certificate for the local hostname so applications
        // on this machine can use TLS immediately.
        let local_hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "localhost".to_string());
        let sans = vec![
            local_hostname.clone(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ];
        match ca::issue_certificate(
            &ca_state,
            &local_hostname,
            &sans,
            new_roster.metadata.policy.leaf_lifetime_days,
        ) {
            Ok(issued) => {
                let cert_dir_base = state.paths.certs_dir().join(&local_hostname);
                let cert_dir_base_clone = cert_dir_base.clone();
                let issued_for_write = issued.clone();
                let cert_dir = match tokio::task::spawn_blocking(move || {
                    certfiles::write_cert_files_to(&cert_dir_base_clone, &issued_for_write)
                })
                .await
                {
                    Ok(Ok(dir)) => dir,
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "Could not write CA node cert files");
                        cert_dir_base
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Cert file write task panicked");
                        cert_dir_base
                    }
                };
                let ca_fp = ca::ca_fingerprint(&ca_state);
                let member = roster::RosterMember {
                    hostname: local_hostname.clone(),
                    role: roster::MemberRole::Primary,
                    enrolled_at: chrono::Utc::now(),
                    enrolled_by: req.operator.clone(),
                    cert_fingerprint: issued.fingerprint,
                    cert_expires: issued.expires,
                    cert_sans: sans,
                    cert_path: cert_dir.display().to_string(),
                    status: roster::MemberStatus::Active,
                    reload_hook: None,
                    last_seen: Some(chrono::Utc::now()),
                    pinned_ca_fingerprint: Some(ca_fp),
                    proxy_entries: Vec::new(),
                };
                new_roster.members.push(member);
                // Persist updated roster with the self-enrolled member
                if let Err(e) = roster::persist_roster(&new_roster, &roster_path).await {
                    tracing::warn!(error = %e, "Could not save roster after self-enrollment");
                }
                let _ = audit::append_entry_to(
                    &state.paths.audit_log_path(),
                    "member_joined",
                    &[
                        ("hostname", local_hostname.as_str()),
                        ("role", "primary"),
                        ("approved_by", "self-enroll"),
                    ],
                );
                tracing::info!(hostname = %local_hostname, "CA node self-enrolled as primary");
            }
            Err(e) => {
                tracing::warn!(error = %e, "Could not self-enroll CA node - roster will be empty");
            }
        }

        // Install CA cert in OS trust store (best-effort)
        if let Err(e) = os_truststore::Cert::from_pem(&ca_state.cert_pem)
            .and_then(|cert| os_truststore::install(&cert).map(drop))
        {
            tracing::warn!(error = %e, "Could not install CA cert in trust store");
        }

        // Configure auto-unlock from the create-time decision (single source of
        // truth: CertmeshCore::configure_auto_unlock). When `auto_unlock` is true,
        // the passphrase is saved to the koi-crypto vault so the daemon boots
        // unlocked; the slot table is marked. This is what keeps the boot-unlocked
        // path (koi-compose init_certmesh_core) working.
        if let Err(e) = self.configure_auto_unlock(req.auto_unlock, &req.passphrase) {
            tracing::warn!(error = %e, "Could not configure auto-unlock");
        }

        // Record this machine's fingerprint (ADR-017 F11) so a later boot can
        // detect a VM clone / disk restore onto different hardware and refuse to
        // auto-unlock. Best-effort: if the machine-id is unreadable, the CA is
        // simply not machine-checked.
        match koi_crypto::vault::machine_fingerprint() {
            Some(fp) => {
                let path = state.paths.machine_bind_path();
                let r = tokio::task::spawn_blocking(move || write_machine_binding(&path, &fp))
                    .await
                    .map_err(|e| std::io::Error::other(format!("machine-bind task: {e}")))
                    .and_then(|r| r);
                if let Err(e) = r {
                    tracing::warn!(error = %e, "Could not record machine binding");
                }
            }
            None => tracing::debug!(
                "machine-id unavailable; machine binding not recorded (auto-unlock unchecked)"
            ),
        }

        // Update in-memory state
        *state.ca.lock().await = Some(ca_state);
        *state.auth.lock().await = Some(koi_crypto::auth::AuthState::Totp(totp_secret));
        *state.roster.lock().await = new_roster;

        let _ = audit::append_entry_to(
            &state.paths.audit_log_path(),
            "ca_initialized",
            &[
                (
                    "enrollment_open",
                    if req.enrollment_open {
                        "open"
                    } else {
                        "closed"
                    },
                ),
                (
                    "requires_approval",
                    if req.requires_approval { "yes" } else { "no" },
                ),
                ("operator", req.operator.as_deref().unwrap_or("none")),
            ],
        );

        tracing::info!(
            enrollment_open = req.enrollment_open,
            requires_approval = req.requires_approval,
            auto_unlock = req.auto_unlock,
            "CA initialized via service"
        );

        // The CA node self-enrolled a leaf above → Open→Authenticated.
        state.republish_posture();

        Ok(protocol::CreateCaResponse {
            auth_setup: koi_crypto::auth::AuthSetup::Totp { totp_uri },
            ca_fingerprint,
        })
    }

    /// Read the audit log entries.
    pub fn read_audit_log(&self) -> Result<String, CertmeshError> {
        audit::read_log_from(&self.state.paths.audit_log_path()).map_err(CertmeshError::Io)
    }

    /// Destroy all certmesh state - CA key, certs, roster, and audit log.
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
    /// The joining machine’s hostname comes from the request - not from
    /// `hostname::get()` which would return the CA server’s hostname.
    pub async fn enroll(
        &self,
        request: &protocol::JoinRequest,
    ) -> Result<protocol::JoinResponse, CertmeshError> {
        let hostname = &request.hostname;
        validate_hostname(hostname)?;
        // Default SANs: hostname + hostname.local, plus any extras the joiner sent.
        // Every extra SAN is validated (F15): IP literals pass through; everything
        // else must be a valid RFC 1123 hostname — so a joiner can't slip a wildcard
        // or junk DNS name into its cert. Capped to bound the SAN list.
        const MAX_EXTRA_SANS: usize = 16;
        let mut sans = vec![hostname.clone(), format!("{hostname}.local")];
        for extra in request.sans.iter().take(MAX_EXTRA_SANS) {
            if extra.parse::<std::net::IpAddr>().is_err() {
                validate_hostname(extra)?;
            }
            if !sans.contains(extra) {
                sans.push(extra.clone());
            }
        }

        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let roster = self.state.roster.lock().await;
        let auth_guard = self.state.auth.lock().await;
        // The enrollment auth credential may be absent when the CA was unlocked
        // via a non-passphrase slot (TOTP/auto-unlock master key). Invite-token
        // enrollment (ADR-015 F2) does not need it; the TOTP branch inside
        // `process_enrollment` fails closed (CaLocked) when it does.
        let auth_state = auth_guard.as_ref();
        let challenge_guard = self.state.pending_challenge.lock().await;
        let challenge = challenge_guard
            .as_ref()
            .cloned()
            .unwrap_or(koi_crypto::auth::AuthChallenge::Totp);
        let mut rate_limiter = self.state.rate_limiter.lock().await;
        let requires_approval = roster.requires_approval();
        let fallback_operator = roster.metadata.operator.clone();
        drop(roster);

        let approved_by = if requires_approval {
            request_approval(&self.state, hostname, requires_approval).await?
        } else {
            fallback_operator
        };

        // Single-writer commit (ADR-017 F8): process_enrollment validates, signs,
        // and pushes the member under the lock; commit_roster bumps `seq` and
        // persists atomically. On any error it errors *before* mutating, so the
        // roster is left unchanged and nothing is persisted.
        let result = self
            .state
            .commit_roster(|roster| {
                enrollment::process_enrollment(
                    ca,
                    roster,
                    auth_state,
                    &challenge,
                    &mut rate_limiter,
                    request,
                    hostname,
                    &sans,
                    approved_by,
                    &self.state.paths,
                )
            })
            .await;

        // Persist the rate-limiter regardless of outcome (ADR-017 F7): a failed
        // TOTP attempt advances a lockout that must survive a restart. Snapshot +
        // drop the guard before the blocking write (no lock held across I/O).
        // Invite joins never consult the limiter, so this is a no-op for them.
        let limiter_snapshot = rate_limiter.clone();
        drop(rate_limiter);
        if let Err(e) = persist_rate_limiter(&self.state.paths, &limiter_snapshot) {
            tracing::warn!(error = %e, "Could not persist rate-limiter state");
        }

        let (response, _issued) = result?;

        let _ = self.state.event_tx.send(CertmeshEvent::MemberJoined {
            hostname: response.hostname.clone(),
            fingerprint: response.ca_fingerprint.clone(),
        });

        Ok(response)
    }

    /// Self-enroll the daemon as a certmesh member.
    ///
    /// Called automatically after CA creation (and on every daemon start) to get
    /// the server leaf the mTLS + ACME listeners use. This is the **one** issuance
    /// path that key-gens on the CA (the CA's own identity, [`ca::issue_certificate`]
    /// — ADR-017 P3); member leaves only ever come from a member CSR.
    ///
    /// Idempotent **except** when the on-disk leaf is within the CA policy's
    /// `renew_threshold_days`: then it re-issues, so a restart refreshes the
    /// listener cert (the CA self-renews — no live mTLS reload yet; the restart is
    /// the reload point).
    pub async fn self_enroll(&self) -> Result<SelfEnrollment, CertmeshError> {
        let hostname = hostname::get()
            .ok()
            .and_then(|os| os.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        // Validate hostname before using as certificate SAN (RFC 1123, F15).
        validate_hostname(&hostname)?;

        let sans = vec![
            hostname.clone(),
            format!("{hostname}.local"),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ];

        // Read the CA-held policy (self-leaf lifetime + restart-renewal threshold).
        let policy = {
            let roster = self.state.roster.lock().await;
            roster.metadata.policy.clone()
        };

        // The self leaf always lives at certs_dir()/<hostname> — derived, not read
        // from the roster (cert_path is no longer persisted, F13). Reuse the on-disk
        // leaf unless it is within the renewal threshold.
        {
            let cert_dir = self.state.paths.certs_dir().join(&hostname);
            let on_disk = (
                std::fs::read_to_string(cert_dir.join("cert.pem")).ok(),
                std::fs::read_to_string(cert_dir.join("key.pem")).ok(),
            );
            if let (Some(cert_pem), Some(key_pem)) = on_disk {
                let due = leaf_not_after_utc(&cert_pem)
                    .map(|na| {
                        chrono::Utc::now()
                            + chrono::Duration::days(i64::from(policy.renew_threshold_days))
                            >= na
                    })
                    .unwrap_or(true); // unparseable → re-issue to be safe
                if !due {
                    let ca_guard = self.state.ca.lock().await;
                    let ca = ca_guard.as_ref().ok_or_else(|| {
                        if self.state.paths.is_ca_initialized() {
                            CertmeshError::CaLocked
                        } else {
                            CertmeshError::CaNotInitialized
                        }
                    })?;
                    let ca_cert_pem = ca.cert_pem.clone();
                    drop(ca_guard);
                    tracing::debug!(hostname = %hostname, "already self-enrolled, reusing existing cert");
                    return Ok(SelfEnrollment {
                        cert_pem,
                        key_pem,
                        ca_cert_pem,
                    });
                }
                tracing::info!(hostname = %hostname, "CA self-cert within renewal threshold; re-issuing");
            }
        }

        // Issue a fresh (or renewed) self leaf at the policy lifetime.
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;
        let issued = ca::issue_certificate(ca, &hostname, &sans, policy.leaf_lifetime_days)?;
        let ca_cert_pem = ca.cert_pem.clone();
        drop(ca_guard);

        // Write cert files to the standard path (blocking I/O)
        let cert_path = self.state.paths.certs_dir().join(&hostname);
        let issued_clone = issued.clone();
        let cert_dir = tokio::task::spawn_blocking(move || {
            certfiles::write_cert_files_to(&cert_path, &issued_clone)
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("cert write task: {e}")))??;

        // Update the existing self entry in place, or insert as primary, then
        // commit (ADR-017 F8). The update path covers both restart-renewal and
        // concurrent self_enroll.
        if let Err(e) = self
            .state
            .commit_roster(|roster| {
                if let Some(member) = roster.find_member_mut(&hostname) {
                    member.cert_fingerprint = issued.fingerprint.clone();
                    member.cert_expires = issued.expires;
                    member.cert_path = cert_dir.display().to_string();
                } else {
                    roster.members.push(roster::RosterMember {
                        hostname: hostname.clone(),
                        role: roster::MemberRole::Primary,
                        enrolled_at: chrono::Utc::now(),
                        enrolled_by: Some("self-enrollment".to_string()),
                        cert_fingerprint: issued.fingerprint.clone(),
                        cert_expires: issued.expires,
                        cert_sans: sans.clone(),
                        cert_path: cert_dir.display().to_string(),
                        status: roster::MemberStatus::Active,
                        reload_hook: None,
                        last_seen: Some(chrono::Utc::now()),
                        pinned_ca_fingerprint: None,
                        proxy_entries: Vec::new(),
                    });
                }
                Ok(())
            })
            .await
        {
            tracing::warn!(error = %e, "Failed to save roster after self-enrollment");
        }

        tracing::info!(hostname = %hostname, "Daemon self-enrolled as certmesh member");

        // Audit the self-enroll issuance (ADR-017 F14) — the one issuance path that
        // key-gens on the CA must leave a trail like any other trust decision.
        let _ = audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "self_enroll",
            &[
                ("hostname", hostname.as_str()),
                ("fingerprint", issued.fingerprint.as_str()),
            ],
        );

        let _ = self.state.event_tx.send(CertmeshEvent::MemberJoined {
            hostname,
            fingerprint: issued.fingerprint,
        });

        // A leaf is now on disk → posture may have flipped Open→Authenticated.
        self.state.republish_posture();

        Ok(SelfEnrollment {
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
            ca_cert_pem,
        })
    }

    /// The CA certificate fingerprint, or `None` when no CA is initialized.
    ///
    /// Reads the in-memory CA when unlocked, else derives it from the on-disk CA
    /// cert (the fingerprint is public). Used by the daemon to advertise the CA's
    /// fingerprint in the `_certmesh._tcp` mDNS TXT (ADR-017 F12) and as a cheap
    /// preflight datum.
    pub async fn ca_fingerprint(&self) -> Option<String> {
        // In-memory path: compute under the lock, but drop the guard before any I/O
        // (never hold the CA mutex across disk reads).
        let in_memory = {
            let ca_guard = self.state.ca.lock().await;
            ca_guard.as_ref().map(ca::ca_fingerprint)
        };
        if in_memory.is_some() {
            return in_memory;
        }
        // Locked CA: derive from the on-disk cert off the async executor.
        let paths = self.state.paths.clone();
        tokio::task::spawn_blocking(move || ca::ca_fingerprint_from_disk(&paths).ok())
            .await
            .ok()
            .flatten()
    }

    /// Get the current certmesh status.
    pub async fn certmesh_status(&self) -> protocol::CertmeshStatus {
        let ca_guard = self.state.ca.lock().await;
        let roster = self.state.roster.lock().await;
        let auth_guard = self.state.auth.lock().await;
        let auth_method = auth_guard.as_ref().map(|a| a.method_name());
        build_status(self.paths(), &ca_guard, &roster, auth_method)
    }

    /// This node's current trust posture — the mode oracle every
    /// mode-transparent primitive consults (ADR-020 §0).
    ///
    /// `signed` is true when this node holds a usable cryptographic identity: its
    /// CA-signed leaf (`cert.pem`/`key.pem`) is on disk *and* the node is anchored
    /// to a mesh (the CA is initialized here, or a `member.json` records the mesh
    /// it joined — so an orphaned leaf left after `destroy` does not read as
    /// secure). A cheap filesystem check, safe to call from any primitive.
    /// `encrypted` (the Confidential rung) stays false until the `seal`/`open`
    /// encryption rung lands (ADR-020 §4).
    ///
    /// Posture answers "do I have an identity", not "is it fresh" — identity
    /// *health* (expiry, renewal status) is reported separately by
    /// `ensure_identity` / `diagnose` (later ADR-020 phases).
    pub fn posture(&self) -> Posture {
        Posture {
            signed: self.has_local_identity(),
            encrypted: false,
        }
    }

    /// Whether this node holds a usable local identity (a CA-signed leaf on disk,
    /// anchored to a mesh). Backs [`posture`](Self::posture).
    fn has_local_identity(&self) -> bool {
        node_has_identity(self.paths())
    }

    /// Load this node's live identity from disk, or `None` if it has none.
    ///
    /// Read-only: loads the on-disk leaf (cert/key) for the local hostname plus
    /// the CA anchor it chains to, derives the pinned CA fingerprint, and computes
    /// the leaf's renewal/expiry health from the CA-held policy. Returns `None`
    /// when the node is Open — consistent with [`posture`](Self::posture)`.signed`.
    /// Does not renew or enroll (that is `ensure_identity`'s job).
    pub async fn local_identity(&self) -> Option<Identity> {
        if !self.has_local_identity() {
            return None;
        }
        let hostname = Self::local_hostname()?;
        let leaf = self.paths().certs_dir().join(&hostname);
        let cert_pem = std::fs::read_to_string(leaf.join("cert.pem")).ok()?;
        let key_pem = std::fs::read_to_string(leaf.join("key.pem")).ok()?;
        // CA anchor: the leaf-local ca.pem, falling back to the CA dir (CA node).
        let ca_cert_pem = std::fs::read_to_string(leaf.join("ca.pem"))
            .ok()
            .or_else(|| std::fs::read_to_string(self.paths().ca_cert_path()).ok())?;
        let ca_fingerprint =
            koi_crypto::pinning::fingerprint_sha256(pem::parse(&ca_cert_pem).ok()?.contents());
        let policy = self.local_policy().await;
        let renewal = RenewalHealth::from_leaf(&cert_pem, &policy)?;
        Some(Identity {
            hostname,
            cert_pem,
            key_pem,
            ca_cert_pem,
            ca_fingerprint,
            renewal,
        })
    }

    /// The CA-held cert lifecycle policy this node follows: from `member.json`
    /// if it joined a mesh, else the local roster's (CA node), else the default.
    async fn local_policy(&self) -> roster::CertPolicy {
        if let Some(ms) = member::load(&self.paths().member_state_path()) {
            return ms.policy;
        }
        self.state.roster.lock().await.metadata.policy.clone()
    }

    /// Ensure this node holds a current identity, then return it (`None` if it
    /// cannot — the node is Open with no way to enroll). ADR-020 §7.
    ///
    /// Mode-transparent + idempotent — the consumer calls this without branching:
    /// - **Open** (no CA, not a member): returns `None`.
    /// - **CA node** (CA unlocked): self-enrolls if needed and re-issues a self
    ///   leaf that is within the renewal threshold (local, no network).
    /// - **Joined member**: pull-renews from the CA when the leaf is due
    ///   (`renew_self_if_due`); best-effort — on a network/CA failure it logs and
    ///   returns the current (un-renewed) identity rather than erroring.
    ///
    /// First-join identity acquisition that needs out-of-band authorization (an
    /// invite/TOTP) is *not* performed here — that is the explicit `join` flow.
    pub async fn ensure_identity(&self) -> Option<Identity> {
        if self.paths().is_ca_initialized() {
            // CA node: self-enroll is idempotent (reuses a fresh leaf, re-issues
            // one within the renewal threshold). Requires the CA unlocked.
            let unlocked = self.state.ca.lock().await.is_some();
            if unlocked {
                if let Err(e) = self.self_enroll().await {
                    tracing::warn!(error = %e, "ensure_identity: self-enroll failed");
                }
            }
        } else if member::load(&self.paths().member_state_path()).is_some() {
            // Joined member: renew if due (network pull to the CA). Best-effort.
            if let Err(e) = self.renew_self_if_due().await {
                tracing::warn!(error = %e, "ensure_identity: renewal check failed");
            }
        }
        self.local_identity().await
    }

    /// Sign `bytes` into an [`Envelope`](koi_common::envelope::Envelope) (ADR-020 §3).
    ///
    /// Mode-transparent: Open posture → a freshness-stamped passthrough (no
    /// signature); Authenticated → ES256-signed, carrying this node's leaf cert so
    /// any holder of the CA can verify it. The consumer calls this identically in
    /// both postures.
    pub async fn sign(&self, bytes: &[u8]) -> koi_common::envelope::Envelope {
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        let ts = chrono::Utc::now().timestamp();
        let identity = self.local_identity().await;
        let signer = identity
            .as_ref()
            .map(|id| (id.key_pem.as_str(), id.cert_pem.as_str()));
        envelope::build_envelope(signer, bytes, &nonce, ts)
    }

    /// Verify an [`Envelope`](koi_common::envelope::Envelope) → an
    /// [`Assurance`](koi_common::envelope::Assurance) (ADR-020 §3).
    ///
    /// Self-contained (carry-cert): validates the carried leaf against this node's
    /// pinned CA + checks freshness + best-effort revocation. Read a trusted
    /// identity only via `Assurance::identity()`. On an Open node (no anchor) any
    /// envelope verifies as `Anonymous`.
    pub async fn verify(
        &self,
        env: &koi_common::envelope::Envelope,
    ) -> koi_common::envelope::Assurance {
        let ca_cert_pem = self.local_ca_cert_pem().await;
        let revoked = self.revoked_fingerprints().await;
        let now = chrono::Utc::now().timestamp();
        envelope::verify_envelope(env, ca_cert_pem.as_deref(), &revoked, now)
    }

    /// Seal `bytes` into a [`Sealed`](koi_common::sealed::Sealed) (ADR-020 §4).
    ///
    /// The confidentiality rung, shipped today as **passthrough**: the bytes are
    /// signed (integrity + freshness) but **not encrypted**. Reuses [`sign`](Self::sign)'s
    /// machinery — a `Sealed` is a signed [`Envelope`](koi_common::envelope::Envelope)
    /// plus a confidentiality version tag. The consumer codes against the final API
    /// now; the group-key rung lands later with no consumer change. A one-time
    /// `warn!` makes the passthrough (un-encrypted) state loud, not silent.
    pub async fn seal(&self, bytes: &[u8]) -> koi_common::sealed::Sealed {
        static PASSTHROUGH_WARNED: std::sync::Once = std::sync::Once::new();
        PASSTHROUGH_WARNED.call_once(|| {
            tracing::warn!(
                "seal(): running in passthrough mode — messages are signed but NOT \
                 encrypted (group-key confidentiality is not yet available)"
            );
        });
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        let ts = chrono::Utc::now().timestamp();
        let identity = self.local_identity().await;
        let signer = identity
            .as_ref()
            .map(|id| (id.key_pem.as_str(), id.cert_pem.as_str()));
        sealed::seal_passthrough(signer, bytes, &nonce, ts)
    }

    /// Open a [`Sealed`](koi_common::sealed::Sealed) → [`Opened`](koi_common::sealed::Opened)
    /// (ADR-020 §4): the recovered bytes plus the trust state they arrived with.
    ///
    /// Self-contained (carry-cert), reusing [`verify`](Self::verify)'s machinery. A
    /// tampered / unknown-signer / expired / revoked message yields an `Err`, never
    /// bytes — read a trusted identity via `opened.assurance.identity()`.
    pub async fn open(
        &self,
        sealed: &koi_common::sealed::Sealed,
    ) -> Result<koi_common::sealed::Opened, CertmeshError> {
        let ca_cert_pem = self.local_ca_cert_pem().await;
        let revoked = self.revoked_fingerprints().await;
        let now = chrono::Utc::now().timestamp();
        sealed::open_sealed(sealed, ca_cert_pem.as_deref(), &revoked, now)
    }

    /// Run the trust-doctor (ADR-020 §13) → a structured [`TrustDiagnosis`].
    ///
    /// Aggregates this node's real trust state — posture, identity + renewal health
    /// (reusing [`local_identity`](Self::local_identity)), on-disk-leaf integrity
    /// (chains to its CA), self-revocation, and the CA trust-install limitation —
    /// into distinct, named checks each carrying an exact remedy. The rollup exits
    /// non-zero only when something is RED (`TrustDiagnosis::exit_code`).
    pub async fn diagnose(&self) -> koi_common::diagnosis::TrustDiagnosis {
        let posture = self.posture();
        let identity = self.local_identity().await;
        let now = chrono::Utc::now();
        let (integrity_ok, self_revoked) = match &identity {
            Some(id) => {
                let integrity = diagnosis::leaf_chains_to_ca(&id.cert_pem, &id.ca_cert_pem);
                // Is this node's own leaf in the (best-effort) revoked set?
                let self_fp = pem::parse(&id.cert_pem)
                    .ok()
                    .map(|p| koi_crypto::pinning::fingerprint_sha256(p.contents()));
                let revoked = self.revoked_fingerprints().await;
                let self_revoked = self_fp
                    .as_ref()
                    .map(|fp| {
                        revoked
                            .iter()
                            .any(|r| koi_crypto::pinning::fingerprints_match(r, fp))
                    })
                    .unwrap_or(false);
                (Some(integrity), self_revoked)
            }
            None => (None, false),
        };
        diagnosis::build_diagnosis(posture, identity.as_ref(), integrity_ok, self_revoked, now)
    }

    /// The CA certificate this node trusts as its verification anchor: the leaf's
    /// `ca.pem` (member or CA node), falling back to the CA cert on disk. `None`
    /// on an Open node with no anchor.
    async fn local_ca_cert_pem(&self) -> Option<String> {
        if let Some(hostname) = Self::local_hostname() {
            let leaf_ca = self.paths().certs_dir().join(&hostname).join("ca.pem");
            if let Ok(pem) = std::fs::read_to_string(&leaf_ca) {
                return Some(pem);
            }
        }
        std::fs::read_to_string(self.paths().ca_cert_path()).ok()
    }

    /// Best-effort revoked-leaf fingerprints from the local roster. A CA node holds
    /// the full roster; a pure member's roster is empty, so revocation there is
    /// eventual-consistent — the CA chain remains the hard gate (ADR-020 §3).
    async fn revoked_fingerprints(&self) -> Vec<String> {
        let roster = self.state.roster.lock().await;
        roster
            .members
            .iter()
            .filter(|m| m.status == roster::MemberStatus::Revoked)
            .map(|m| m.cert_fingerprint.clone())
            .collect()
    }

    /// Gate `router`'s routes by authentication (ADR-020 §6 `require_auth`).
    ///
    /// Mode-transparent: a **no-op in Open posture** (homelab-open); in secure
    /// posture every request must carry an authenticated client CN (the mTLS
    /// `ClientCn` the listener / same-port dial injects) or it is rejected with
    /// 401. Apply once to your *write* routes — no per-handler boilerplate, and the
    /// same consumer code runs green in both postures.
    ///
    /// (P2 gates on the mTLS client identity; an optional CN/role policy hook and a
    /// signed-envelope-header path are planned refinements.)
    pub fn require_auth(&self, router: Router) -> Router {
        router.layer(axum::middleware::from_fn_with_state(
            Arc::clone(&self.state),
            http::require_auth_mw,
        ))
    }

    /// Set the post-renewal reload hook for a member.
    pub async fn set_reload_hook(&self, hostname: &str, hook: &str) -> Result<(), CertmeshError> {
        // Validate at domain boundary — all callers (HTTP, embedded, CLI) are
        // protected by the single source of truth in `validate_reload_hook`.
        validate_reload_hook(hook)?;
        // touch_roster: reload_hook is not bundle content, so no seq bump — but
        // the write still serializes behind the single writer (F8).
        self.state
            .touch_roster(|roster| {
                let member = roster.find_member_mut(hostname).ok_or_else(|| {
                    CertmeshError::NotFound(format!("member not found: {hostname}"))
                })?;
                member.reload_hook = Some(hook.to_string());
                Ok(())
            })
            .await?;

        tracing::info!(hostname, hook, "Reload hook set");
        Ok(())
    }

    /// Set the role of a member in the roster.
    pub async fn set_member_role(
        &self,
        hostname: &str,
        role: roster::MemberRole,
    ) -> Result<(), CertmeshError> {
        self.state
            .touch_roster(|roster| {
                let member = roster.find_member_mut(hostname).ok_or_else(|| {
                    CertmeshError::Internal(format!("member not found: {hostname}"))
                })?;
                member.role = role.clone();
                Ok(())
            })
            .await?;

        tracing::info!(hostname, role = ?role, "Member role updated");
        Ok(())
    }

    /// Unlock the CA with a passphrase.
    pub async fn unlock(&self, passphrase: &str) -> Result<(), CertmeshError> {
        let ca_state = match ca::load_ca(passphrase, &self.state.paths) {
            Ok(ca) => ca,
            Err(e) => {
                // Audit the failed unlock before returning (ADR-017 F9/F14).
                let _ = audit::append_entry_to(
                    &self.state.paths.audit_log_path(),
                    "unlock_failed",
                    &[("via", "passphrase")],
                );
                return Err(e);
            }
        };

        // Load auth credential from auth.json
        let auth_path = self.state.paths.auth_path();
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

    /// Unlock the CA with a pre-unwrapped master key (TOTP or auto-unlock).
    ///
    /// This bypasses passphrase-based auth.json decryption. The auth
    /// credential (for API gating) is not loaded - callers should use
    /// the slot table's embedded TOTP shared_secret for verification
    /// if auth gating is needed.
    pub async fn unlock_with_master_key(&self, master_key: &[u8; 32]) -> Result<(), CertmeshError> {
        let ca_state = ca::load_ca_with_master_key(master_key, &self.state.paths)?;
        *self.state.ca.lock().await = Some(ca_state);
        tracing::info!("CA unlocked via master key (non-passphrase slot)");
        Ok(())
    }

    /// Unlock the CA using a TOTP code against the unlock slot table.
    ///
    /// Loads the slot table, verifies the TOTP code, unwraps the master
    /// key, and decrypts the CA key.
    pub async fn unlock_with_totp(&self, code: &str) -> Result<(), CertmeshError> {
        let slot_table =
            ca::load_slot_table(&self.state.paths.slot_table_path())?.ok_or_else(|| {
                CertmeshError::NoSlotFound(
                    "no slot table found - CA may use legacy passphrase format".into(),
                )
            })?;

        if !slot_table.has_totp_slot() {
            return Err(CertmeshError::NoSlotFound(
                "TOTP unlock is not configured for this CA".into(),
            ));
        }

        let master_key = slot_table.unwrap_with_totp(code).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("invalid TOTP code") {
                CertmeshError::InvalidAuth
            } else {
                CertmeshError::Crypto(msg)
            }
        })?;

        self.unlock_with_master_key(&master_key).await
    }

    // ── Auto-unlock key management ──────────────────────────────────

    /// Vault key under which the auto-unlock passphrase is stored.
    const VAULT_AUTO_UNLOCK_KEY: &'static str = "certmesh-auto-unlock";

    /// Save a passphrase for automatic unlock on reboot, rooted at explicit
    /// paths so the vault is co-located with the CA it unlocks.
    ///
    /// Uses the koi-crypto vault which automatically selects the strongest
    /// available backend: platform credential store (DPAPI, Keychain,
    /// Secret Service) first, machine-bound Argon2id derivation as fallback.
    /// The counterpart reader is [`Self::read_auto_unlock_key`].
    pub fn save_auto_unlock_key_at(
        paths: &CertmeshPaths,
        passphrase: &str,
    ) -> Result<(), CertmeshError> {
        let vault = koi_crypto::vault::Vault::open(paths.data_dir())?;
        vault.store(Self::VAULT_AUTO_UNLOCK_KEY, passphrase)?;
        tracing::info!(
            backend = vault.backend_name(),
            "Auto-unlock key saved to vault"
        );
        // Remove any legacy file/credential store entries
        let _ = std::fs::remove_file(paths.auto_unlock_key_path());
        let _ = koi_crypto::tpm::delete_key_material("koi-auto-unlock");
        Ok(())
    }

    /// Read the stored auto-unlock passphrase from the vault, if any.
    ///
    /// The auto-unlock passphrase lives in the koi-crypto vault (written by
    /// [`Self::save_auto_unlock_key_at`], which deletes any legacy plaintext
    /// file). This is the **single source of truth** for that location:
    /// boot paths that need to unlock the CA at construction time call this
    /// instead of reading a plaintext file that no longer exists.
    ///
    /// Returns `Ok(None)` when no key is stored, `Ok(Some(pp))` when one is
    /// found, and `Err` when the vault cannot be opened or read.
    pub fn read_auto_unlock_key(
        paths: &CertmeshPaths,
    ) -> Result<Option<Zeroizing<String>>, CertmeshError> {
        let vault = koi_crypto::vault::Vault::open(paths.data_dir())?;
        Ok(match vault.retrieve(Self::VAULT_AUTO_UNLOCK_KEY)? {
            Some(pp) if !pp.is_empty() => Some(Zeroizing::new(pp)),
            _ => None,
        })
    }

    /// Try to auto-unlock the CA from the vault.
    ///
    /// Returns `Ok(true)` if the CA was unlocked, `Ok(false)` if no
    /// stored key exists, and `Err` if the key exists but decryption
    /// failed (corrupt key, changed passphrase, etc.).
    pub async fn try_auto_unlock(&self) -> Result<bool, CertmeshError> {
        // F11: refuse auto-unlock if the machine fingerprint changed since the CA
        // was created (a VM clone / disk restore onto new hardware). Fail-safe —
        // boot LOCKED and require a manual passphrase. Checked BEFORE touching the
        // vault so a cloned host can't auto-unlock with the copied vault key.
        // `machine_binding_ok` shells out on Windows/macOS, so run it off the
        // executor. (The real daemon boot path is `koi_compose::init_certmesh_core`,
        // which gates auto-unlock with the same free function — this method mirrors
        // it for embedded/programmatic callers.)
        let paths = self.state.paths.clone();
        let bound_ok = tokio::task::spawn_blocking(move || machine_binding_ok(&paths))
            .await
            .unwrap_or(true);
        if !bound_ok {
            let _ = audit::append_entry_to(
                &self.state.paths.audit_log_path(),
                "auto_unlock_refused_machine_changed",
                &[],
            );
            tracing::error!(
                "machine fingerprint changed since CA creation (clone/restore?) — refusing \
                 auto-unlock. Run `koi certmesh unlock` to unlock manually on this host."
            );
            return Ok(false);
        }

        let passphrase = match Self::read_auto_unlock_key(&self.state.paths)? {
            Some(pp) => pp,
            None => return Ok(false),
        };
        self.unlock(&passphrase).await?;
        tracing::info!("CA auto-unlocked via vault");
        Ok(true)
    }

    /// Configure auto-unlock from the create-time `auto_unlock` decision.
    ///
    /// This is the **single source of truth** for the unlock-on-boot decision.
    /// When `auto_unlock` is true and a passphrase is present, the passphrase
    /// is saved to the koi-crypto vault (read back at boot by
    /// [`Self::read_auto_unlock_key`]) and the slot table is marked. Call it
    /// after CA creation from any init path (direct API or ceremony).
    pub fn configure_auto_unlock(
        &self,
        auto_unlock: bool,
        passphrase: &str,
    ) -> Result<(), CertmeshError> {
        if auto_unlock && !passphrase.is_empty() {
            let paths = self.paths();
            Self::save_auto_unlock_key_at(paths, passphrase)?;

            // Mark auto-unlock in the slot table (if it exists)
            let slot_path = paths.slot_table_path();
            if let Some(mut table) = ca::load_slot_table(&slot_path)? {
                table.add_auto_unlock();
                ca::save_slot_table(&table, &slot_path)?;
            }
        }
        Ok(())
    }

    // ── Enrollment toggle ───────────────────────────────────────────

    /// Open the enrollment window. Stays open until explicitly closed.
    pub async fn open_enrollment(&self) -> Result<(), CertmeshError> {
        // Posture change → single-writer commit so a concurrent enroll can't
        // overwrite it with a stale snapshot (F8). Not bundle content → no bump.
        self.state
            .touch_roster(|roster| {
                roster.open_enrollment();
                Ok(())
            })
            .await?;

        tracing::info!("Enrollment window opened");
        let _ =
            audit::append_entry_to(&self.state.paths.audit_log_path(), "enrollment_opened", &[]);
        Ok(())
    }

    /// Close the enrollment window.
    pub async fn close_enrollment(&self) -> Result<(), CertmeshError> {
        self.state
            .touch_roster(|roster| {
                roster.close_enrollment();
                Ok(())
            })
            .await?;

        tracing::info!("Enrollment window closed");
        let _ =
            audit::append_entry_to(&self.state.paths.audit_log_path(), "enrollment_closed", &[]);
        Ok(())
    }

    /// Mint a single-use, hostname-bound enrollment invite (ADR-015 F2).
    ///
    /// Returns the one-time plaintext token plus its absolute expiry. The CA
    /// stores only a hash; the joining host presents the token once via
    /// `POST /join` (`invite_token`). The mesh must be initialized — the invite
    /// is an authorization to enroll into an existing CA. Posture booleans are
    /// unchanged: the token replaces the credential, not the `enrollment_open` /
    /// `requires_approval` gates.
    pub async fn mint_invite(
        &self,
        hostname: &str,
        ttl_mins: i64,
    ) -> Result<protocol::InviteResponse, CertmeshError> {
        if !self.state.paths.is_ca_initialized() {
            return Err(CertmeshError::CaNotInitialized);
        }
        // Validate the hostname the same way enrollment will (it becomes the
        // single host this token authorizes — and a certificate SAN at join, F15).
        validate_hostname(hostname)?;

        // The CA fingerprint the joiner will pin (ADR-017 F3). `is_ca_initialized`
        // was checked above, so `ca_fingerprint()` (in-memory or on-disk, never
        // holding a lock across I/O) yields the public CA fingerprint here.
        let ca_fingerprint = self
            .ca_fingerprint()
            .await
            .ok_or(CertmeshError::CaNotInitialized)?;

        let minted = invite::mint(&self.state.paths.invites_path(), hostname, ttl_mins)?;
        let expires_at = minted.expires_at.to_rfc3339();
        // The operator-facing code carries the pinned CA fingerprint (F3) so the
        // joiner can preflight + pin before sending its CSR.
        let code = invite::encode_code(&minted.token, &ca_fingerprint);

        let _ = audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "invite_minted",
            &[("hostname", hostname), ("expires_at", &expires_at)],
        );
        tracing::info!(hostname, "Enrollment invite minted");

        Ok(protocol::InviteResponse {
            token: code,
            hostname: hostname.to_string(),
            expires_at,
            ca_fingerprint,
        })
    }

    // ── Member-side key custody (ADR-015 F1) ────────────────────────

    /// Generate this member's keypair + CSR and persist the **private key** locally.
    ///
    /// The daemon generates the keypair, writes the private key to
    /// `certs/<hostname>/key.pem` (0600 on Unix), and returns only the CSR. The
    /// key never leaves the daemon; the CLI carries only the public CSR to the
    /// remote CA. Paired with [`Self::install_member_cert`].
    pub async fn prepare_member_csr(
        &self,
        hostname: &str,
        sans: &[String],
    ) -> Result<String, CertmeshError> {
        validate_hostname(hostname)?;
        let (key_pem, csr_pem) = csr::generate_keypair_and_csr(hostname, sans)?;

        let cert_dir = self.state.paths.certs_dir().join(hostname);
        let key_path = cert_dir.join("key.pem");
        tokio::task::spawn_blocking(move || -> Result<(), CertmeshError> {
            std::fs::create_dir_all(&cert_dir)?;
            std::fs::write(&key_path, key_pem.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("write member key task: {e}")))??;

        tracing::info!(
            hostname,
            "Member keypair generated; CSR prepared (key kept local)"
        );
        Ok(csr_pem)
    }

    /// Install a CA-signed leaf next to the member key from [`Self::prepare_member_csr`].
    ///
    /// Writes `cert.pem`, `ca.pem`, and `fullchain.pem` into `certs/<hostname>/`
    /// (the key is already there) and installs the CA root in the OS trust store
    /// (best-effort). Returns the cert directory path.
    ///
    /// When `ca_endpoint` + `ca_fingerprint` are supplied (the normal join flow),
    /// it also writes the **member renewal state** (`certmesh/member.json`) so the
    /// background loop can later pull a rotate-key renewal from the CA over mTLS
    /// (ADR-017 F6). The pinned `ca_fingerprint` is verified against the supplied
    /// `ca_pem` before arming, so a mismatched pair never arms renewal.
    #[allow(clippy::too_many_arguments)]
    pub async fn install_member_cert(
        &self,
        hostname: &str,
        cert_pem: &str,
        ca_pem: &str,
        ca_endpoint: Option<&str>,
        ca_fingerprint: Option<&str>,
        sans: &[String],
        policy: Option<roster::CertPolicy>,
    ) -> Result<String, CertmeshError> {
        validate_hostname(hostname)?;

        // Enforce the pin BEFORE writing anything (ADR-017 F3). When the caller
        // supplied a pinned fingerprint (the out-of-band-trusted one from the
        // invite), the CA cert we are about to install + trust MUST match it, or we
        // refuse — a MITM that intercepted the plain-HTTP join and substituted its
        // own CA is rejected here, before any file is written or any root is
        // trusted. Without a pin (TOTP join), this is a documented TOFU install.
        if let Some(expected_fp) = ca_fingerprint {
            let der = pem::parse(ca_pem).map_err(|e| {
                CertmeshError::InvalidPayload(format!("CA cert is not valid PEM: {e}"))
            })?;
            let actual_fp = koi_crypto::pinning::fingerprint_sha256(der.contents());
            if !koi_crypto::pinning::fingerprints_match(&actual_fp, expected_fp) {
                return Err(CertmeshError::InvalidPayload(format!(
                    "installed CA cert fingerprint {actual_fp} does not match the pinned \
                     fingerprint {expected_fp} (possible MITM) — refusing to install"
                )));
            }
        }

        let cert_dir = self.state.paths.certs_dir().join(hostname);
        let cert_owned = cert_pem.to_string();
        let ca_owned = ca_pem.to_string();
        let fullchain = format!("{cert_owned}{ca_owned}");
        let dir = cert_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<(), CertmeshError> {
            std::fs::create_dir_all(&dir)?;
            write_file_atomic(&dir.join("cert.pem"), cert_owned.as_bytes(), false)?;
            write_file_atomic(&dir.join("ca.pem"), ca_owned.as_bytes(), false)?;
            write_file_atomic(&dir.join("fullchain.pem"), fullchain.as_bytes(), false)?;
            Ok(())
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("write member cert task: {e}")))??;

        // Trust the CA root so this node can verify the mesh (best-effort).
        if let Err(e) = os_truststore::Cert::from_pem(ca_pem)
            .and_then(|cert| os_truststore::install(&cert).map(drop))
        {
            tracing::warn!(error = %e, "Could not install CA cert in trust store");
        }

        // Arm member-pull renewal when the join supplied the CA coordinates. The
        // pinned fingerprint was already verified against `ca_pem` above, so the
        // MemberState records a fingerprint we have confirmed matches the installed
        // CA root.
        if let (Some(endpoint), Some(fingerprint)) = (ca_endpoint, ca_fingerprint) {
            let state = member::MemberState {
                hostname: hostname.to_string(),
                ca_host: member::host_from_endpoint(endpoint),
                ca_mtls_port: member::DEFAULT_CA_MTLS_PORT,
                ca_http_port: member::port_from_endpoint(endpoint),
                ca_fingerprint: fingerprint.to_string(),
                sans: sans.to_vec(),
                policy: policy.unwrap_or_default(),
                last_bundle_seq: 0,
                reload_hook: None,
            };
            if let Err(e) = member::save(&self.state.paths.member_state_path(), &state) {
                tracing::warn!(error = %e, "Could not persist member renewal state");
            } else {
                tracing::info!(hostname, ca_host = %state.ca_host, "Member renewal state armed");
            }
        }

        tracing::info!(hostname, "Member certificate installed locally");

        // Leaf (and possibly member.json) now on disk → Open→Authenticated.
        self.state.republish_posture();

        Ok(cert_dir.display().to_string())
    }

    /// Rotate the auth credential - generates new credential, persists, returns setup info.
    ///
    /// If `method` is `None`, keeps the current method. If `Some("totp")`,
    /// switches to that method.
    pub async fn rotate_auth(
        &self,
        passphrase: &str,
        method: Option<&str>,
    ) -> Result<koi_crypto::auth::AuthSetup, CertmeshError> {
        // Verify CA is unlocked
        let ca_guard = self.state.ca.lock().await;
        if ca_guard.is_none() {
            return Err(if self.state.paths.is_ca_initialized() {
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
            other => {
                return Err(CertmeshError::Internal(format!(
                    "unknown auth method: {other}"
                )));
            }
        };

        let json = serde_json::to_string_pretty(&stored)
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?;
        let auth_path = self.state.paths.auth_path();
        tokio::task::spawn_blocking(move || std::fs::write(&auth_path, &json))
            .await
            .map_err(|e| CertmeshError::Internal(format!("file I/O: {e}")))?
            .map_err(CertmeshError::Io)?;
        *self.state.auth.lock().await = Some(new_state);

        tracing::info!(method = target, "auth credential rotated");
        let _ = audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "auth_rotated",
            &[("method", target)],
        );
        Ok(setup)
    }

    // ── Phase 5 - Backup/Restore/Revocation ───────────────────────

    /// Create an encrypted backup bundle for the certmesh state.
    pub async fn backup(
        &self,
        ca_passphrase: &str,
        backup_passphrase: &str,
    ) -> Result<Vec<u8>, CertmeshError> {
        if !self.state.paths.is_ca_initialized() {
            return Err(CertmeshError::CaNotInitialized);
        }

        let ca_state = ca::load_ca(ca_passphrase, &self.state.paths)?;

        // Load auth state for backup
        let auth_path = self.state.paths.auth_path();
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

        let audit_log =
            audit::read_log_from(&self.state.paths.audit_log_path()).map_err(CertmeshError::Io)?;

        let ca_key_pem = ca_state
            .key
            .private_key_pem()
            .map_err(|e| CertmeshError::Crypto(e.to_string()))?
            .to_string();
        let payload = backup::BackupPayload::new(
            ca_key_pem,
            ca_state.cert_pem.clone(),
            auth_state.method_name().to_string(),
            auth_state.to_backup_bytes(),
            roster_json,
            audit_log,
        );

        let bundle = backup::encode_backup(&payload, backup_passphrase)?;
        let _ = audit::append_entry_to(&self.state.paths.audit_log_path(), "backup_created", &[]);
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
        let ca_key_der = koi_crypto::keys::ca_keypair_to_der(&ca_key)?;
        let (encrypted_key, slot_table, _master_key) =
            koi_crypto::unlock_slots::envelope_encrypt_new(&ca_key_der, new_passphrase)?;
        std::fs::create_dir_all(self.state.paths.ca_dir())?;
        koi_crypto::keys::save_encrypted_key(&self.state.paths.ca_key_path(), &encrypted_key)?;
        slot_table.save(&self.state.paths.slot_table_path())?;
        std::fs::write(self.state.paths.ca_cert_path(), &payload.ca_cert_pem)?;

        let auth_state = AuthState::from_backup(&payload.auth_method, payload.auth_data)
            .map_err(|e| CertmeshError::Internal(format!("auth restore failed: {e}")))?;

        // Persist restored auth credential
        let AuthState::Totp(secret) = &auth_state;
        let stored = koi_crypto::auth::store_totp(secret, new_passphrase)?;
        let auth_json = serde_json::to_string_pretty(&stored)
            .map_err(|e| CertmeshError::Internal(format!("auth serialize: {e}")))?;
        std::fs::write(self.state.paths.auth_path(), auth_json)?;

        if let Some(parent) = self.state.paths.roster_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(self.state.paths.roster_path(), &payload.roster_json)?;
        if let Some(parent) = self.state.paths.audit_log_path().parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(self.state.paths.audit_log_path(), &payload.audit_log)?;

        let restored_roster: Roster = serde_json::from_str(&payload.roster_json)
            .map_err(|e| CertmeshError::Internal(format!("roster deserialization failed: {e}")))?;

        let ca_state = ca::load_ca(new_passphrase, &self.state.paths)?;
        *self.state.ca.lock().await = Some(ca_state);
        *self.state.auth.lock().await = Some(auth_state);
        *self.state.roster.lock().await = restored_roster;

        let _ = audit::append_entry_to(&self.state.paths.audit_log_path(), "backup_restored", &[]);
        Ok(())
    }

    /// Revoke a member and persist the revocation list.
    pub async fn revoke_member(
        &self,
        hostname: &str,
        operator: Option<String>,
        reason: Option<String>,
    ) -> Result<(), CertmeshError> {
        // Membership change → commit_roster bumps `seq` so the revocation
        // propagates in the next trust bundle (ADR-017 F4/F8).
        self.state
            .commit_roster(|roster| {
                roster
                    .revoke_member(hostname, operator.clone(), reason.clone())
                    .map_err(CertmeshError::NotFound)
            })
            .await?;

        let _ = self.state.event_tx.send(CertmeshEvent::MemberRevoked {
            hostname: hostname.to_string(),
        });

        let _ = audit::append_entry_to(
            &self.state.paths.audit_log_path(),
            "member_revoked",
            &[
                ("hostname", hostname),
                ("operator", operator.as_deref().unwrap_or("unknown")),
                ("reason", reason.as_deref().unwrap_or("none")),
            ],
        );
        Ok(())
    }

    // ── Phase 3 - Lifecycle ────────────────────────────────────────

    /// Member-initiated, rotate-key renewal (ADR-017 F6).
    ///
    /// A no-op ([`RenewOutcome::NotApplicable`]) unless this node has a persisted
    /// [`member::MemberState`] (i.e. it *joined* a mesh). When its local leaf is
    /// within the CA policy's `renew_threshold_days`, it:
    ///
    /// 1. generates a **fresh** keypair + CSR (rotate-on-renewal — the new private
    ///    key is held in memory until the install succeeds, never on the CA),
    /// 2. POSTs only the CSR to the CA's mTLS `/v1/certmesh/renew`, presenting its
    ///    **current** (still-valid) leaf as the client identity,
    /// 3. verifies the returned CA fingerprint matches its pin (anti-CA-swap),
    /// 4. installs the new key + signed leaf locally and runs its reload hook.
    ///
    /// The CA never generates or receives a member private key — on enroll *or*
    /// renew. If the network call fails (CA down, cert lapsed past mTLS validity)
    /// the local files are left untouched and the loop retries next tick.
    pub async fn renew_self_if_due(&self) -> Result<RenewOutcome, CertmeshError> {
        let Some(state) = member::load(&self.state.paths.member_state_path()) else {
            return Ok(RenewOutcome::NotApplicable);
        };

        let cert_dir = self.state.paths.certs_dir().join(&state.hostname);
        // Read the current key + cert + pinned CA off the blocking pool.
        let read_dir = cert_dir.clone();
        let (current_cert, current_key, pinned_ca_pem) =
            tokio::task::spawn_blocking(move || -> std::io::Result<(String, String, String)> {
                Ok((
                    std::fs::read_to_string(read_dir.join("cert.pem"))?,
                    std::fs::read_to_string(read_dir.join("key.pem"))?,
                    std::fs::read_to_string(read_dir.join("ca.pem"))?,
                ))
            })
            .await
            .map_err(|e| CertmeshError::Internal(format!("read member cert task: {e}")))??;

        // Due? Compare the local leaf's not_after against the renew threshold.
        let not_after = leaf_not_after_utc(&current_cert).ok_or_else(|| {
            CertmeshError::Internal("cannot parse local leaf expiry for renewal".into())
        })?;
        let threshold = chrono::Duration::days(i64::from(state.policy.renew_threshold_days));
        if chrono::Utc::now() + threshold < not_after {
            return Ok(RenewOutcome::NotDue { not_after });
        }

        // Rotate: fresh keypair + CSR. The new key lives only in memory until the
        // CA-signed leaf is in hand, so a failed renewal never discards the
        // working key.
        let (new_key_pem, csr_pem) = csr::generate_keypair_and_csr(&state.hostname, &state.sans)?;
        let req_body = serde_json::to_string(&protocol::RenewRequest {
            hostname: state.hostname.clone(),
            csr: csr_pem,
        })
        .map_err(|e| CertmeshError::Internal(format!("serialize renew request: {e}")))?;

        let (host, port) = state.ca_mtls_authority();
        // Bound the network call: a black-holed CA must not stall the loop (or
        // daemon shutdown) for the OS TCP timeout.
        let (status, body) = tokio::time::timeout(
            RENEWAL_REQUEST_TIMEOUT,
            mtls::post_json(
                &host,
                port,
                http::paths::RENEW,
                &req_body,
                &current_cert,
                &current_key,
                &pinned_ca_pem,
            ),
        )
        .await
        .map_err(|_| CertmeshError::RenewalFailed {
            hostname: state.hostname.clone(),
            reason: format!(
                "renewal request to {host}:{port} timed out after {}s",
                RENEWAL_REQUEST_TIMEOUT.as_secs()
            ),
        })??;

        if status != 200 {
            return Err(CertmeshError::RenewalFailed {
                hostname: state.hostname.clone(),
                reason: format!("CA returned HTTP {status}: {body}"),
            });
        }
        let resp: protocol::RenewResponse =
            serde_json::from_str(&body).map_err(|e| CertmeshError::RenewalFailed {
                hostname: state.hostname.clone(),
                reason: format!("malformed renew response: {e}"),
            })?;

        // Anti-CA-swap: derive the fingerprint from the RETURNED CA cert (the one
        // we are about to install as our new pin) and require it to match the pin.
        // Deriving locally — rather than trusting the asserted `ca_fingerprint`
        // string — is the authoritative check.
        let returned_ca_fp = pem::parse(&resp.ca_cert)
            .map(|der| koi_crypto::pinning::fingerprint_sha256(der.contents()))
            .map_err(|e| CertmeshError::RenewalFailed {
                hostname: state.hostname.clone(),
                reason: format!("returned ca_cert is not valid PEM: {e}"),
            })?;
        if !koi_crypto::pinning::fingerprints_match(&returned_ca_fp, &state.ca_fingerprint) {
            return Err(CertmeshError::RenewalFailed {
                hostname: state.hostname.clone(),
                reason: "returned CA cert does not match the pinned CA fingerprint".into(),
            });
        }

        // Install the new key + leaf atomically (temp → rename per file).
        let new_cert = resp.service_cert.clone();
        let new_ca = resp.ca_cert.clone();
        let fullchain = format!("{new_cert}{new_ca}");
        let dir = cert_dir.clone();
        tokio::task::spawn_blocking(move || -> Result<(), CertmeshError> {
            std::fs::create_dir_all(&dir)?;
            write_file_atomic(&dir.join("key.pem"), new_key_pem.as_bytes(), true)?;
            write_file_atomic(&dir.join("cert.pem"), new_cert.as_bytes(), false)?;
            write_file_atomic(&dir.join("ca.pem"), new_ca.as_bytes(), false)?;
            write_file_atomic(&dir.join("fullchain.pem"), fullchain.as_bytes(), false)?;
            Ok(())
        })
        .await
        .map_err(|e| CertmeshError::Internal(format!("write renewed cert task: {e}")))??;

        tracing::info!(hostname = %state.hostname, expires = %resp.expires, "Member certificate renewed (rotated key)");

        // Run the local reload hook, if configured.
        let hook = state
            .reload_hook
            .as_deref()
            .map(lifecycle::execute_reload_hook);

        Ok(RenewOutcome::Renewed {
            expires: resp.expires,
            hook,
        })
    }

    /// Pull, verify, and apply the CA's signed trust bundle (ADR-017 P1/F4).
    ///
    /// A no-op ([`BundleOutcome::NotApplicable`]) unless this node joined a mesh.
    /// Fetches the self-verifying bundle over plain HTTP, verifies the ES256
    /// signature against the **pinned** CA fingerprint, and rejects a strictly
    /// older `seq` (anti-rollback). On a newer bundle it refreshes the member's
    /// cached `policy` and `last_bundle_seq`, and flags whether this node has been
    /// revoked mesh-wide.
    pub async fn pull_trust_bundle(&self) -> Result<BundleOutcome, CertmeshError> {
        let member_path = self.state.paths.member_state_path();
        let Some(mut state) = member::load(&member_path) else {
            return Ok(BundleOutcome::NotApplicable);
        };

        let (host, port) = (state.ca_host.clone(), state.ca_http_port);
        let (status, body) = tokio::time::timeout(
            RENEWAL_REQUEST_TIMEOUT,
            mtls::get(&host, port, http::paths::TRUST_BUNDLE),
        )
        .await
        .map_err(|_| {
            CertmeshError::Internal(format!("trust-bundle pull from {host}:{port} timed out"))
        })??;

        if status != 200 {
            return Err(CertmeshError::Internal(format!(
                "CA returned HTTP {status} for trust-bundle"
            )));
        }
        let signed: bundle::SignedBundle = serde_json::from_str(&body)
            .map_err(|e| CertmeshError::Internal(format!("malformed trust bundle: {e}")))?;

        // Verify signature against the pinned CA + anti-rollback floor.
        if let Err(e) = bundle::verify(&signed, &state.ca_fingerprint, Some(state.last_bundle_seq))
        {
            // F5 fail-safe: a bundle whose CA fingerprint differs from our pin is
            // rejected, and we KEEP the old pin. There is no supported live CA
            // re-key path today, so a fingerprint change is treated as hostile; an
            // intentional CA replacement is recovered by re-enrolling with a fresh
            // invite (which carries the new fingerprint, F3).
            if matches!(e, bundle::BundleError::PinMismatch) {
                tracing::error!(
                    host = %state.hostname,
                    "Trust bundle CA fingerprint does NOT match the pinned CA — rejecting \
                     (fail-safe). Re-enroll with a fresh invite if the CA was intentionally replaced."
                );
            }
            return Err(CertmeshError::Internal(format!(
                "trust bundle rejected: {e}"
            )));
        }

        // F5 anchor self-heal: the bundle's `ca_cert_pem` provably hashes to our pin
        // (verify enforced it), so writing it keeps the on-disk `ca.pem` — the trust
        // root the mTLS renewal client loads — in sync and repairs drift/corruption.
        // Done on every verified pull (even an unchanged seq) so a wiped anchor is
        // restored promptly; the write is skipped when the file already matches.
        {
            let anchor = self
                .state
                .paths
                .certs_dir()
                .join(&state.hostname)
                .join("ca.pem");
            let want = signed.bundle.ca_cert_pem.clone();
            // Best-effort: the closure logs its own write error, and any JoinError
            // (task panic) is intentionally dropped. A write failure is harmless —
            // the bundle was already pin-verified, and because this heal runs on
            // every verified pull (before the seq short-circuit below) the next pull
            // simply retries it.
            let _ = tokio::task::spawn_blocking(move || {
                let current = std::fs::read_to_string(&anchor).ok();
                if current.as_deref() != Some(want.as_str()) {
                    match write_file_atomic(&anchor, want.as_bytes(), false) {
                        Ok(()) => tracing::info!(
                            path = %anchor.display(),
                            "Refreshed on-disk CA anchor from the verified trust bundle"
                        ),
                        Err(e) => tracing::warn!(error = %e, "Could not refresh on-disk CA anchor"),
                    }
                }
            })
            .await;
        }

        let seq = signed.bundle.seq;
        if seq == state.last_bundle_seq {
            return Ok(BundleOutcome::NoChange { seq });
        }

        let hostname = state.hostname.clone();
        let self_revoked = signed.bundle.is_revoked(&hostname);
        state.last_bundle_seq = seq;
        state.policy = signed.bundle.policy.clone();
        tokio::task::spawn_blocking(move || member::save(&member_path, &state))
            .await
            .map_err(|e| CertmeshError::Internal(format!("member state save task: {e}")))??;

        if self_revoked {
            tracing::error!(
                %hostname,
                "This node has been REVOKED in the mesh trust bundle (seq {seq}); renewal will be refused by the CA"
            );
        } else {
            tracing::debug!(seq, "Trust bundle updated");
        }
        Ok(BundleOutcome::Updated { seq, self_revoked })
    }

    /// Validate a member's health heartbeat.
    pub async fn health_check(
        &self,
        request: &protocol::HealthRequest,
    ) -> Result<protocol::HealthResponse, CertmeshError> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let current_fp = ca::ca_fingerprint(ca);
        let valid =
            health::validate_pinned_fingerprint(&current_fp, &request.pinned_ca_fingerprint);
        drop(ca_guard); // release the CA lock before the roster commit (no lock held across disk I/O)

        // Touch last_seen (no seq bump — liveness is not in the bundle); reject a
        // revoked member at the boundary before recording the heartbeat.
        self.state
            .touch_roster(|roster| {
                if roster.is_revoked(&request.hostname) {
                    return Err(CertmeshError::Revoked(request.hostname.clone()));
                }
                roster.touch_member(&request.hostname);
                Ok(())
            })
            .await?;

        Ok(protocol::HealthResponse {
            valid,
            ca_fingerprint: current_fp,
        })
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

    /// Promote the local member to primary and demote any existing primary.
    /// Returns true if the roster was updated.
    pub async fn promote_self_to_primary(&self) -> Result<bool, CertmeshError> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .map_err(|_| CertmeshError::Internal("hostname unavailable".to_string()))?;

        // Role changes are not bundle content → touch_roster (no seq bump), but the
        // write still serializes behind the single writer (F8).
        self.state
            .touch_roster(|roster| {
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
                Ok(true)
            })
            .await
    }

    /// Demote the local member to standby. Returns true if the roster changed.
    pub async fn demote_self_to_standby(&self) -> Result<bool, CertmeshError> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .map_err(|_| CertmeshError::Internal("hostname unavailable".to_string()))?;

        self.state
            .touch_roster(|roster| {
                let member = roster
                    .find_member_mut(&hostname)
                    .ok_or_else(|| CertmeshError::NotFound(hostname.clone()))?;
                if member.role == roster::MemberRole::Standby {
                    return Ok(false);
                }
                member.role = roster::MemberRole::Standby;
                Ok(true)
            })
            .await
    }

    /// Add alias SANs to a member's roster entry (used by DNS alias feedback).
    ///
    /// Returns true if any SANs were added.
    pub async fn add_alias_sans(
        &self,
        hostname: &str,
        sans: &[String],
    ) -> Result<bool, CertmeshError> {
        self.state
            .touch_roster(|roster| {
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
                Ok(changed)
            })
            .await
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
    /// Uses DH key agreement to encrypt the CA key for wire transfer.
    pub async fn promote(
        &self,
        client_public_key: &[u8; 32],
    ) -> Result<protocol::PromoteResponse, CertmeshError> {
        let ca_guard = self.state.ca.lock().await;
        let ca = ca_guard.as_ref().ok_or_else(|| {
            if self.state.paths.is_ca_initialized() {
                CertmeshError::CaLocked
            } else {
                CertmeshError::CaNotInitialized
            }
        })?;

        let auth_guard = self.state.auth.lock().await;
        let auth_state = auth_guard.as_ref().ok_or(CertmeshError::CaLocked)?;

        let roster = self.state.roster.lock().await;
        failover::prepare_promotion(ca, auth_state, &roster, client_public_key)
    }
}

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
/// Whether a node rooted at `paths` holds a usable local identity: a CA-signed
/// leaf (`cert.pem`/`key.pem`) for the local hostname on disk, anchored to a mesh
/// (the CA is initialized here, or a `member.json` records the joined mesh — so an
/// orphaned leaf left by `destroy` does not read as secure). Backs
/// [`CertmeshCore::posture`] and the [`CertmeshCore::require_auth`] gate.
pub(crate) fn node_has_identity(paths: &CertmeshPaths) -> bool {
    let Some(hostname) = CertmeshCore::local_hostname() else {
        return false;
    };
    let leaf = paths.certs_dir().join(&hostname);
    let leaf_present = leaf.join("cert.pem").exists() && leaf.join("key.pem").exists();
    let anchored = paths.is_ca_initialized() || paths.member_state_path().exists();
    leaf_present && anchored
}

fn leaf_not_after_utc(cert_pem: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use x509_parser::prelude::FromDer;
    let der = pem::parse(cert_pem).ok()?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.contents()).ok()?;
    chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
}

/// Write `bytes` to `path` atomically (temp file → rename), 0600 on Unix when
/// `private` is set. Used by the member-pull renewal install so a crash mid-write
/// can never leave a half-written key or cert in place. The temp name carries the
/// pid so concurrent writers (different processes) never collide on it.
fn write_file_atomic(path: &std::path::Path, bytes: &[u8], private: bool) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    std::fs::rename(&tmp, path)?;
    Ok(())
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

/// Write the machine-binding fingerprint atomically (0600 on Unix), creating the
/// parent directory if needed (ADR-017 F11). The value is a non-secret hash.
fn write_machine_binding(path: &std::path::Path, fingerprint: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_file_atomic(path, fingerprint.as_bytes(), true)
}

/// Load the persisted TOTP rate-limiter state, or a fresh one (ADR-017 F7).
///
/// A missing or unparseable file yields a fresh limiter; the live check still
/// fails closed, and a real lockout is re-persisted on the next failed attempt.
fn load_rate_limiter(paths: &CertmeshPaths) -> RateLimiter {
    match std::fs::read(paths.rate_limiter_path()) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Could not parse persisted rate-limiter; starting fresh");
            RateLimiter::new()
        }),
        Err(_) => RateLimiter::new(),
    }
}

/// Persist the TOTP rate-limiter state atomically (0600) so a daemon restart can't
/// reset an active lockout (ADR-017 F7). Best-effort — callers log any error.
/// `pub(crate)` so the http promote handler can persist after its own check.
pub(crate) fn persist_rate_limiter(
    paths: &CertmeshPaths,
    limiter: &RateLimiter,
) -> std::io::Result<()> {
    let path = paths.rate_limiter_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(limiter).map_err(std::io::Error::other)?;
    write_file_atomic(&path, &json, true)
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
        .await
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

#[async_trait::async_trait]
impl Capability for CertmeshCore {
    fn name(&self) -> &str {
        "certmesh"
    }

    async fn status(&self) -> CapabilityStatus {
        // Use try_lock for sync Capability trait - best effort
        let ca_initialized = self.state.paths.is_ca_initialized();
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

        let (summary, healthy) = if !ca_initialized {
            ("ready \u{2014} run certmesh create".to_string(), true)
        } else if ca_locked {
            ("CA locked".to_string(), false)
        } else {
            (
                format!(
                    "active ({} member{})",
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
    paths: &CertmeshPaths,
    ca_guard: &Option<ca::CaState>,
    roster: &Roster,
    auth_method: Option<&str>,
) -> protocol::CertmeshStatus {
    let ca_fingerprint = match ca_guard {
        Some(ca) => Some(ca::ca_fingerprint(ca)),
        None => ca::ca_fingerprint_from_disk(paths).ok(),
    };

    protocol::CertmeshStatus {
        ca_initialized: paths.is_ca_initialized(),
        ca_locked: ca_guard.is_none(),
        ca_fingerprint,
        enrollment_open: roster.metadata.enrollment_open,
        requires_approval: roster.metadata.requires_approval,
        enrollment_state: roster.enrollment_state(),
        auth_method: auth_method.map(|s| s.to_string()),
        member_count: roster.active_count(),
        seq: roster.metadata.seq,
        policy: roster.metadata.policy.clone(),
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

    // ── ADR-020 P1: posture oracle ──────────────────────────────────

    // Each posture test gets its OWN isolated data dir. We deliberately do NOT
    // use `koi_common::test::ensure_data_dir` here: that returns a process-wide
    // `OnceLock` dir shared by every test in this binary, so wiping it (to get a
    // clean slate) would destroy sibling tests' CA/vault/roster state. posture()
    // reads only the injected `CertmeshPaths`, so an isolated dir is sufficient.
    fn isolated_posture_paths(tag: &str) -> CertmeshPaths {
        let dir = std::env::temp_dir().join(format!("koi-cm-posture-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        CertmeshPaths::with_data_dir(dir)
    }

    fn posture_member_state(hostname: &str) -> crate::member::MemberState {
        crate::member::MemberState {
            hostname: hostname.to_string(),
            ca_host: "ca-host".to_string(),
            ca_mtls_port: 5642,
            ca_http_port: 5641,
            ca_fingerprint: "fp".to_string(),
            sans: vec![hostname.to_string()],
            policy: crate::roster::CertPolicy::default(),
            last_bundle_seq: 0,
            reload_hook: None,
        }
    }

    fn write_posture_leaf(paths: &CertmeshPaths, hostname: &str) {
        let leaf = paths.certs_dir().join(hostname);
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("cert.pem"), b"leaf-cert").unwrap();
        std::fs::write(leaf.join("key.pem"), b"leaf-key").unwrap();
    }

    #[test]
    fn posture_is_open_without_identity() {
        let paths = isolated_posture_paths("open");
        let core = CertmeshCore::uninitialized_with_paths(paths);
        assert_eq!(core.posture(), koi_common::posture::Posture::OPEN);
    }

    #[test]
    fn posture_is_authenticated_with_member_identity() {
        let paths = isolated_posture_paths("auth");
        let hostname = CertmeshCore::local_hostname().expect("local hostname");
        crate::member::save(&paths.member_state_path(), &posture_member_state(&hostname)).unwrap();
        write_posture_leaf(&paths, &hostname);
        let core = CertmeshCore::uninitialized_with_paths(paths);
        let p = core.posture();
        assert!(p.signed);
        assert!(!p.encrypted);
        assert_eq!(p.level(), koi_common::posture::PostureLevel::Authenticated);
    }

    #[test]
    fn posture_ignores_orphan_leaf_without_anchor() {
        let paths = isolated_posture_paths("orphan");
        let hostname = CertmeshCore::local_hostname().expect("local hostname");
        // Leaf present but no CA and no member.json — an unanchored orphan.
        write_posture_leaf(&paths, &hostname);
        let core = CertmeshCore::uninitialized_with_paths(paths);
        assert_eq!(core.posture(), koi_common::posture::Posture::OPEN);
    }

    #[tokio::test]
    async fn local_identity_is_none_when_open() {
        let paths = isolated_posture_paths("local-id-open");
        let core = CertmeshCore::uninitialized_with_paths(paths);
        assert!(core.local_identity().await.is_none());
    }

    #[tokio::test]
    async fn local_identity_loads_after_self_enroll() {
        std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
        let paths = isolated_posture_paths("local-id");
        let ca = ca::create_ca("test-pass", &[7u8; 32], &paths).unwrap().0;
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let core = CertmeshCore::new_with_paths(ca, roster, None, paths);
        core.self_enroll().await.expect("self-enroll");

        let id = core.local_identity().await.expect("identity present");
        assert_eq!(id.hostname, CertmeshCore::local_hostname().unwrap());
        assert!(id.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(id.key_pem.contains("BEGIN"));
        assert_eq!(id.ca_fingerprint.len(), 64); // sha256 hex
                                                 // A fresh 90-day leaf (renew at 30 days remaining) is healthy.
        assert!(!id.renewal.expired);
        assert!(!id.renewal.renew_overdue);
        assert!(id.renewal.expires_in_days > 30);
        // Redacted Debug must never leak key material.
        assert!(!format!("{id:?}").contains("BEGIN"));
    }

    #[tokio::test]
    async fn ensure_identity_none_when_open() {
        let paths = isolated_posture_paths("ensure-open");
        let core = CertmeshCore::uninitialized_with_paths(paths);
        assert!(core.ensure_identity().await.is_none());
    }

    #[tokio::test]
    async fn ensure_identity_self_enrolls_ca_node() {
        std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
        let paths = isolated_posture_paths("ensure-ca");
        let ca = ca::create_ca("test-pass", &[9u8; 32], &paths).unwrap().0;
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let core = CertmeshCore::new_with_paths(ca, roster, None, paths);

        // No leaf yet → Open.
        assert!(!core.posture().signed);
        // ensure_identity self-enrolls the CA node and returns a live identity.
        let id = core.ensure_identity().await.expect("identity after ensure");
        assert_eq!(id.hostname, CertmeshCore::local_hostname().unwrap());
        assert!(core.posture().signed);
        // Idempotent: a second call reuses the fresh leaf (no re-issue).
        let id2 = core
            .ensure_identity()
            .await
            .expect("identity still present");
        assert_eq!(id2.cert_pem, id.cert_pem);
    }

    #[tokio::test]
    async fn posture_watch_observes_transitions_and_coalesces() {
        std::env::set_var("KOI_NO_CREDENTIAL_STORE", "1");
        let paths = isolated_posture_paths("watch");
        let ca = ca::create_ca("test-pass", &[5u8; 32], &paths).unwrap().0;
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let core = CertmeshCore::new_with_paths(ca, roster, None, paths);

        let mut rx = core.watch_posture();
        assert!(!rx.borrow_and_update().signed, "no leaf yet → Open");

        // self_enroll writes the leaf and publishes → Open→Authenticated observed.
        core.self_enroll().await.expect("self-enroll");
        assert!(rx.has_changed().unwrap(), "self-enroll must notify");
        assert!(rx.borrow_and_update().signed);

        // A second self_enroll re-issues the leaf but the posture is unchanged →
        // the watch coalesces (no spurious PostureChanged — silence is correct here,
        // an upgrade is not).
        core.self_enroll().await.expect("re-enroll");
        assert!(
            !rx.has_changed().unwrap(),
            "an unchanged posture must not notify"
        );

        // destroy tears the identity down → Authenticated→Open observed (a degrade
        // is as loud as the upgrade, ADR-020 §13).
        core.destroy().await.expect("destroy");
        assert!(rx.has_changed().unwrap(), "destroy must notify");
        assert!(!rx.borrow_and_update().signed);
    }

    fn test_paths() -> CertmeshPaths {
        CertmeshPaths::with_data_dir(koi_common::test::ensure_data_dir("koi-certmesh-core-tests"))
    }

    fn make_test_ca() -> ca::CaState {
        ca::create_ca("test-pass", &[42u8; 32], &test_paths())
            .unwrap()
            .0
    }

    // Posture booleans for the named presets (UX labels only).
    // Just Me = (open, no approval); My Organization = (closed, approval).
    const JUST_ME: (bool, bool) = (true, false);
    const MY_ORG: (bool, bool) = (false, true);

    fn make_test_roster_with_member(hostname: &str, role: MemberRole) -> Roster {
        let mut r = Roster::new(JUST_ME.0, JUST_ME.1, None);
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
        let totp = koi_crypto::totp::generate_secret();
        let auth_state = koi_crypto::auth::AuthState::Totp(totp);
        CertmeshCore::new_with_paths(ca, roster, Some(auth_state), test_paths())
    }

    fn make_locked_core(roster: Roster) -> CertmeshCore {
        CertmeshCore::locked_with_paths(roster, test_paths())
    }

    // ── auto-unlock vault round-trip ─────────────────────────────────
    #[test]
    fn auto_unlock_key_round_trips_through_vault() {
        // `save_auto_unlock_key_at` persists the passphrase in the koi-crypto
        // vault and deletes the legacy plaintext file; `read_auto_unlock_key`
        // must read it back from that same vault. This is the contract the
        // embedded boot path relies on. Regression guard: the boot reader
        // used to read the (now deleted) plaintext file and boot LOCKED.
        let base = koi_common::test::ensure_data_dir("koi-certmesh-autounlock-tests");
        let paths = CertmeshPaths::with_data_dir(base.join("autounlock-roundtrip"));

        CertmeshCore::save_auto_unlock_key_at(&paths, "test-secret-pass").unwrap();

        // The plaintext key file must not be the source of truth.
        assert!(
            !paths.auto_unlock_key_path().exists(),
            "save_auto_unlock_key_at must not leave a plaintext key file behind"
        );

        let recovered = CertmeshCore::read_auto_unlock_key(&paths).unwrap();
        assert_eq!(
            recovered.as_ref().map(|z| z.as_str()),
            Some("test-secret-pass"),
            "the auto-unlock passphrase must round-trip through the vault"
        );

        // A data dir with no stored key reads back as None (boots locked).
        let empty = CertmeshPaths::with_data_dir(base.join("autounlock-empty"));
        assert!(CertmeshCore::read_auto_unlock_key(&empty)
            .unwrap()
            .is_none());
    }

    // ── renew_self_if_due ─────────────────────────────────────────────

    #[tokio::test]
    async fn renew_self_if_due_is_noop_without_member_state() {
        // A node that never joined a mesh (no member.json) has nothing to pull.
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        let outcome = core.renew_self_if_due().await.expect("no-op succeeds");
        assert!(matches!(outcome, RenewOutcome::NotApplicable));
    }

    /// End-to-end member-pull renewal over a real mTLS connection (ADR-017 F6).
    ///
    /// Proves the whole loop without the test host: a member enrolls (CSR), then
    /// pulls a rotate-key renewal from the CA's mTLS `/renew` — the request carries
    /// ONLY a CSR, the member's key ROTATES locally, and the CA records the new
    /// fingerprint. The key-custody invariant holds across renewal.
    #[tokio::test]
    async fn member_pull_renewal_round_trip() {
        use crate::roster::CertPolicy;

        // `ensure_data_dir` returns a process-wide shared base (OnceLock, prefix is
        // only honored on the first call), so carve a test-unique subdir — otherwise
        // this test's `remove_dir_all` races other e2e tests sharing `base/ca`.
        let base = koi_common::test::ensure_data_dir("koi-certmesh-renew-e2e").join("renew-e2e");
        let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
        let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
        let _ = std::fs::remove_dir_all(ca_paths.data_dir());
        let _ = std::fs::remove_dir_all(member_paths.data_dir());

        // ── CA side: create CA, self-enroll (server leaf for the mTLS listener) ──
        let (ca_state, _master) = ca::create_ca("e2e-pass", &[7u8; 32], &ca_paths).unwrap();
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
        let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());
        let server_leaf = ca_core.self_enroll().await.expect("CA self-enroll");

        // ── Member side: generate keypair+CSR, enroll via invite, install cert ──
        let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());
        let csr = member_core
            .prepare_member_csr("renew-host", &["renew-host".to_string()])
            .await
            .expect("member CSR");
        let invite = ca_core
            .mint_invite("renew-host", 60)
            .await
            .expect("invite")
            .token;
        let join = ca_core
            .enroll(&protocol::JoinRequest {
                hostname: "renew-host".to_string(),
                auth: None,
                invite_token: Some(invite),
                csr: Some(csr),
                sans: vec!["renew-host".to_string()],
            })
            .await
            .expect("enroll");
        assert!(join.service_key.is_empty(), "enroll must not return a key");
        member_core
            .install_member_cert(
                "renew-host",
                &join.service_cert,
                &join.ca_cert,
                Some("http://127.0.0.1:5641"),
                Some(&join.ca_fingerprint),
                &["renew-host".to_string()],
                Some(join.policy.clone()),
            )
            .await
            .expect("install");

        // ── Stand up the CA's mTLS inter-node listener ──
        let config = mtls::build_server_config(
            &server_leaf.cert_pem,
            &server_leaf.key_pem,
            &server_leaf.ca_cert_pem,
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let cancel = tokio_util::sync::CancellationToken::new();
        // Mirror the binary's mTLS adapter, which nests the inter-node router under
        // the crate prefix so the served path is `/v1/certmesh/renew`.
        let app = Router::new().nest("/v1/certmesh", ca_core.inter_node_routes());
        let server = tokio::spawn(mtls::serve(app, listener, config, cancel.clone()));

        // Point the armed member state at the ephemeral test port and force "due".
        let mut st = member::load(&member_paths.member_state_path()).expect("renewal armed");
        assert_eq!(st.ca_host, "127.0.0.1");
        st.ca_mtls_port = port;
        st.policy = CertPolicy {
            leaf_lifetime_days: 90,
            renew_threshold_days: 365, // > leaf lifetime → always due
            grace_days: 14,
        };
        member::save(&member_paths.member_state_path(), &st).unwrap();

        let cert_dir = member_paths.certs_dir().join("renew-host");
        let old_key = std::fs::read_to_string(cert_dir.join("key.pem")).unwrap();
        let old_cert = std::fs::read_to_string(cert_dir.join("cert.pem")).unwrap();

        // ── Member pulls the renewal over mTLS ──
        let outcome = member_core.renew_self_if_due().await.expect("renewal ok");
        assert!(
            matches!(outcome, RenewOutcome::Renewed { .. }),
            "expected Renewed, got {outcome:?}"
        );

        let new_key = std::fs::read_to_string(cert_dir.join("key.pem")).unwrap();
        let new_cert = std::fs::read_to_string(cert_dir.join("cert.pem")).unwrap();
        assert_ne!(
            old_key, new_key,
            "renewal must ROTATE the member private key"
        );
        assert_ne!(old_cert, new_cert, "renewal must install a fresh leaf");
        assert!(new_cert.contains("BEGIN CERTIFICATE"));
        assert!(new_key.contains("PRIVATE KEY"));

        // The CA roster recorded the rotated leaf's fingerprint.
        let new_fp =
            koi_crypto::pinning::fingerprint_sha256(pem::parse(&new_cert).unwrap().contents());
        {
            let roster = ca_core.state.roster.lock().await;
            let member = roster
                .find_member("renew-host")
                .expect("member in CA roster");
            assert_eq!(
                member.cert_fingerprint, new_fp,
                "CA roster must record the rotated leaf fingerprint"
            );
        }

        cancel.cancel();
        let _ = server.await;
        let _ = std::fs::remove_dir_all(base.join("ca"));
        let _ = std::fs::remove_dir_all(base.join("member"));
    }

    /// End-to-end trust-bundle pull (ADR-017 P1/F4): the CA serves a signed bundle
    /// over HTTP; a member pulls it, verifies the signature against its pin,
    /// accepts a newer `seq`, no-ops on an unchanged one, rejects a rollback, and
    /// detects its own revocation.
    #[tokio::test]
    async fn trust_bundle_pull_round_trip() {
        // Test-unique subdir under the shared base (see renew test note).
        let base = koi_common::test::ensure_data_dir("koi-certmesh-bundle-e2e").join("bundle-e2e");
        let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
        let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
        let _ = std::fs::remove_dir_all(ca_paths.data_dir());
        let _ = std::fs::remove_dir_all(member_paths.data_dir());

        // CA with one enrolled member (enroll bumps seq to >= 1).
        let (ca_state, _m) = ca::create_ca("be2e", &[5u8; 32], &ca_paths).unwrap();
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
        let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());
        let (_k, csr) =
            csr::generate_keypair_and_csr("bundle-host", &["bundle-host".to_string()]).unwrap();
        let invite = ca_core.mint_invite("bundle-host", 60).await.unwrap().token;
        ca_core
            .enroll(&protocol::JoinRequest {
                hostname: "bundle-host".to_string(),
                auth: None,
                invite_token: Some(invite),
                csr: Some(csr),
                sans: vec!["bundle-host".to_string()],
            })
            .await
            .unwrap();
        let pin = ca::ca_fingerprint_from_disk(&ca_paths).unwrap();

        // Serve the certmesh routes (incl. GET /trust-bundle) over plain HTTP,
        // nested under the crate prefix exactly as the binary mounts them.
        let app = Router::new().nest("/v1/certmesh", crate::http::routes(ca_core.state.clone()));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        // Arm the member with a pin and a fresh (seq 0) anti-rollback floor.
        member::save(
            &member_paths.member_state_path(),
            &member::MemberState {
                hostname: "bundle-host".to_string(),
                ca_host: "127.0.0.1".to_string(),
                ca_mtls_port: 5642,
                ca_http_port: port,
                ca_fingerprint: pin.clone(),
                sans: vec!["bundle-host".to_string()],
                policy: crate::roster::CertPolicy::default(),
                last_bundle_seq: 0,
                reload_hook: None,
            },
        )
        .unwrap();
        let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());

        // First pull → Updated (the CA's seq is >= 1 after the enroll).
        match member_core.pull_trust_bundle().await.expect("pull ok") {
            BundleOutcome::Updated { seq, self_revoked } => {
                assert!(seq >= 1, "expected a bumped seq, got {seq}");
                assert!(!self_revoked);
            }
            other => panic!("expected Updated, got {other:?}"),
        }
        let stored = member::load(&member_paths.member_state_path()).unwrap();
        assert!(
            stored.last_bundle_seq >= 1,
            "member persisted the bundle seq"
        );

        // Second pull, no roster change → NoChange (idempotent).
        assert!(matches!(
            member_core.pull_trust_bundle().await.unwrap(),
            BundleOutcome::NoChange { .. }
        ));

        // Revoke the member on the CA → next pull sees self_revoked + a higher seq.
        ca_core
            .revoke_member("bundle-host", Some("op".into()), Some("test".into()))
            .await
            .unwrap();
        match member_core.pull_trust_bundle().await.expect("pull ok") {
            BundleOutcome::Updated { self_revoked, .. } => {
                assert!(
                    self_revoked,
                    "member must detect its own revocation in the bundle"
                );
            }
            other => panic!("expected Updated(self_revoked), got {other:?}"),
        }

        server.abort();
        let _ = std::fs::remove_dir_all(base.join("ca"));
        let _ = std::fs::remove_dir_all(base.join("member"));
    }

    // ── F3 install pin enforcement ───────────────────────────────────

    /// F3: when a pinned fingerprint is supplied, `install_member_cert` must
    /// hard-fail (writing nothing, arming nothing) if the CA cert does not match
    /// it — a MITM that substituted its own CA at join is rejected before any file
    /// is written or any root is trusted. The correct pin installs and arms.
    #[tokio::test]
    async fn install_member_cert_rejects_pin_mismatch() {
        // Test-unique subdir under the shared base (see renew test note).
        let base = koi_common::test::ensure_data_dir("koi-certmesh-installpin").join("installpin");
        let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
        let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
        let _ = std::fs::remove_dir_all(ca_paths.data_dir());
        let _ = std::fs::remove_dir_all(member_paths.data_dir());

        let (ca_state, _m) = ca::create_ca("ip", &[3u8; 32], &ca_paths).unwrap();
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
        let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());

        let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());
        let csr = member_core
            .prepare_member_csr("pin-host", &["pin-host".to_string()])
            .await
            .unwrap();
        let invite = ca_core.mint_invite("pin-host", 60).await.unwrap();
        // The invite code embeds the real CA fingerprint (F3).
        let (secret, real_fp) = invite::decode_code(&invite.token);
        let real_fp = real_fp
            .expect("invite code carries the CA fingerprint")
            .to_string();
        assert_eq!(real_fp, invite.ca_fingerprint);
        let join = ca_core
            .enroll(&protocol::JoinRequest {
                hostname: "pin-host".to_string(),
                auth: None,
                invite_token: Some(secret.to_string()),
                csr: Some(csr),
                sans: vec!["pin-host".to_string()],
            })
            .await
            .unwrap();

        // Wrong pin → hard-fail; no cert written, renewal not armed.
        let wrong_fp = "0".repeat(64);
        let err = member_core
            .install_member_cert(
                "pin-host",
                &join.service_cert,
                &join.ca_cert,
                Some("http://127.0.0.1:5641"),
                Some(&wrong_fp),
                &["pin-host".to_string()],
                Some(join.policy.clone()),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, CertmeshError::InvalidPayload(_)),
            "got {err:?}"
        );
        let cert_dir = member_paths.certs_dir().join("pin-host");
        assert!(
            !cert_dir.join("cert.pem").exists(),
            "no cert must be written on pin mismatch"
        );
        assert!(
            member::load(&member_paths.member_state_path()).is_none(),
            "renewal must not be armed on pin mismatch"
        );

        // Correct pin (the one embedded in the invite) → installs + arms.
        let dir = member_core
            .install_member_cert(
                "pin-host",
                &join.service_cert,
                &join.ca_cert,
                Some("http://127.0.0.1:5641"),
                Some(&real_fp),
                &["pin-host".to_string()],
                Some(join.policy.clone()),
            )
            .await
            .unwrap();
        assert!(std::path::Path::new(&dir).join("cert.pem").exists());
        assert!(
            member::load(&member_paths.member_state_path()).is_some(),
            "correct pin arms renewal"
        );

        let _ = std::fs::remove_dir_all(base.join("ca"));
        let _ = std::fs::remove_dir_all(base.join("member"));
    }

    /// F5: a verified trust-bundle pull restores a corrupted on-disk `ca.pem`
    /// (the trust anchor the mTLS renewal client loads), keeping it in sync with
    /// the signed mesh truth.
    #[tokio::test]
    async fn pull_trust_bundle_self_heals_ca_anchor() {
        // Test-unique subdir under the shared base (see renew test note).
        let base =
            koi_common::test::ensure_data_dir("koi-certmesh-anchor-heal").join("anchor-heal");
        let ca_paths = CertmeshPaths::with_data_dir(base.join("ca"));
        let member_paths = CertmeshPaths::with_data_dir(base.join("member"));
        let _ = std::fs::remove_dir_all(ca_paths.data_dir());
        let _ = std::fs::remove_dir_all(member_paths.data_dir());

        let (ca_state, _m) = ca::create_ca("heal", &[6u8; 32], &ca_paths).unwrap();
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let auth = koi_crypto::auth::AuthState::Totp(koi_crypto::totp::generate_secret());
        let ca_core = CertmeshCore::new_with_paths(ca_state, roster, Some(auth), ca_paths.clone());

        let member_core = CertmeshCore::uninitialized_with_paths(member_paths.clone());
        let csr = member_core
            .prepare_member_csr("heal-host", &["heal-host".to_string()])
            .await
            .unwrap();
        let invite = ca_core.mint_invite("heal-host", 60).await.unwrap();
        let (secret, fp) = invite::decode_code(&invite.token);
        let pin = fp.unwrap().to_string();
        let join = ca_core
            .enroll(&protocol::JoinRequest {
                hostname: "heal-host".to_string(),
                auth: None,
                invite_token: Some(secret.to_string()),
                csr: Some(csr),
                sans: vec!["heal-host".to_string()],
            })
            .await
            .unwrap();
        member_core
            .install_member_cert(
                "heal-host",
                &join.service_cert,
                &join.ca_cert,
                Some("http://127.0.0.1:5641"),
                Some(&pin),
                &["heal-host".to_string()],
                Some(join.policy.clone()),
            )
            .await
            .unwrap();

        // Serve the certmesh routes (incl. GET /trust-bundle) over plain HTTP.
        let app = Router::new().nest("/v1/certmesh", crate::http::routes(ca_core.state.clone()));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        // Point the armed member's HTTP port at the ephemeral test server.
        let mut st = member::load(&member_paths.member_state_path()).unwrap();
        st.ca_http_port = port;
        member::save(&member_paths.member_state_path(), &st).unwrap();

        // Corrupt the on-disk anchor, then pull → it is healed from the bundle.
        let anchor = member_paths.certs_dir().join("heal-host").join("ca.pem");
        std::fs::write(&anchor, b"-----BEGIN CERTIFICATE-----\nGARBAGE\n").unwrap();
        member_core.pull_trust_bundle().await.expect("pull ok");

        let restored = std::fs::read_to_string(&anchor).unwrap();
        assert!(
            !restored.contains("GARBAGE"),
            "anchor must be self-healed from the verified bundle"
        );
        assert_eq!(
            restored, join.ca_cert,
            "anchor now matches the signed CA cert"
        );

        server.abort();
        let _ = std::fs::remove_dir_all(base.join("ca"));
        let _ = std::fs::remove_dir_all(base.join("member"));
    }

    // ── health_check ─────────────────────────────────────────────────

    #[tokio::test]
    async fn health_check_returns_error_when_ca_locked() {
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let request = protocol::HealthRequest {
            hostname: "node-01".to_string(),
            pinned_ca_fingerprint: "some-fp".to_string(),
        };
        let result = core.health_check(&request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn health_check_validates_matching_fingerprint() {
        let ca = make_test_ca();
        let ca_fp = ca::ca_fingerprint(&ca);
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let request = protocol::HealthRequest {
            hostname: "node-01".to_string(),
            pinned_ca_fingerprint: ca_fp,
        };
        let result = core.health_check(&request).await.unwrap();
        assert!(result.valid);
        assert!(!result.ca_fingerprint.is_empty());
    }

    #[tokio::test]
    async fn health_check_rejects_mismatched_fingerprint() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let request = protocol::HealthRequest {
            hostname: "node-01".to_string(),
            pinned_ca_fingerprint: "wrong-fingerprint".to_string(),
        };
        let result = core.health_check(&request).await.unwrap();
        assert!(!result.valid);
    }

    #[tokio::test]
    async fn health_check_updates_last_seen() {
        let ca = make_test_ca();
        let ca_fp = ca::ca_fingerprint(&ca);
        let mut roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        // Ensure last_seen is None initially
        roster.members[0].last_seen = None;
        let core = make_unlocked_core(ca, roster);

        let request = protocol::HealthRequest {
            hostname: "node-01".to_string(),
            pinned_ca_fingerprint: ca_fp,
        };
        core.health_check(&request).await.unwrap();

        // Verify last_seen was updated via the roster state
        let roster = core.state.roster.lock().await;
        assert!(roster.members[0].last_seen.is_some());
    }

    // ── promote ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn promote_returns_error_when_ca_locked() {
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let dummy_pk = [0u8; 32];
        let result = core.promote(&dummy_pk).await;
        assert!(matches!(result, Err(CertmeshError::CaLocked)));
    }

    #[tokio::test]
    async fn promote_returns_encrypted_material() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let client_pub = client_kp.public_key_bytes();

        let response = core.promote(&client_pub).await.unwrap();
        assert!(!response.encrypted_ca_key.ciphertext.is_empty());
        assert!(!response.auth_data.is_null());
        assert!(!response.roster_json.is_empty());
        assert!(response.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(response.ephemeral_public.is_some());
    }

    #[tokio::test]
    async fn promote_response_can_be_accepted_with_dh() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);

        let client_kp = koi_crypto::key_agreement::EphemeralKeyPair::generate();
        let client_pub = client_kp.public_key_bytes();

        let response = core.promote(&client_pub).await.unwrap();
        assert!(response.ephemeral_public.is_some());

        // Accept the promotion on the standby side using DH
        let (ca_key, accepted_auth, accepted_roster) =
            failover::accept_promotion(&response, client_kp).unwrap();
        assert!(!ca_key.public_key_pem().unwrap().is_empty());
        assert_eq!(accepted_auth.method_name(), "totp");
        assert_eq!(accepted_roster.members.len(), 1);
    }

    // ── local_hostname ───────────────────────────────────────────────

    #[test]
    fn local_hostname_returns_some() {
        let hostname = CertmeshCore::local_hostname();
        assert!(hostname.is_some());
        assert!(!hostname.unwrap().is_empty());
    }

    // ── validate_hostname (F15, RFC 1123) ────────────────────────────

    #[test]
    fn validate_hostname_rfc1123() {
        let label63 = "a".repeat(63);
        for ok in [
            "web-01",
            "node-granite-spring",
            "a",
            "a.b.c",
            "x1.local",
            label63.as_str(),
        ] {
            assert!(validate_hostname(ok).is_ok(), "{ok:?} should be valid");
        }

        let label64 = "a".repeat(64);
        let over253 = vec!["a"; 200].join(".");
        for bad in [
            "",           // empty
            " ",          // space
            "host name",  // embedded space
            "host/name",  // path separator
            "host\\name", // path separator
            "host:1",     // colon (Windows drive / ADS)
            "..",         // empty labels
            "host..name", // empty interior label
            "-host",      // leading hyphen
            "host-",      // trailing hyphen
            "host_name",  // underscore is not RFC 1123
            label64.as_str(),
            over253.as_str(),
        ] {
            assert!(
                validate_hostname(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    // ── F11 machine binding ──────────────────────────────────────────

    #[test]
    fn machine_binding_detects_change() {
        let paths = CertmeshPaths::with_data_dir(
            koi_common::test::ensure_data_dir("koi-certmesh-core-tests").join("machinebind"),
        );
        let _ = std::fs::remove_dir_all(paths.data_dir());
        let bind = paths.machine_bind_path();
        std::fs::create_dir_all(bind.parent().unwrap()).unwrap();

        // No recorded binding → not machine-checked (pre-F11 CA) → ok.
        assert!(machine_binding_ok(&paths));

        // A binding that matches this host → ok (when a machine-id is available).
        if let Some(current) = koi_crypto::vault::machine_fingerprint() {
            std::fs::write(&bind, current.as_bytes()).unwrap();
            assert!(machine_binding_ok(&paths), "matching binding must pass");
        }

        // A binding that no longer matches (a clone/restore) → fail safe.
        std::fs::write(
            &bind,
            b"0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert!(
            !machine_binding_ok(&paths),
            "a changed machine fingerprint must refuse auto-unlock"
        );

        let _ = std::fs::remove_dir_all(paths.data_dir());
    }

    // ── F7 persisted rate limiter ────────────────────────────────────

    #[test]
    fn rate_limiter_lockout_survives_reload() {
        let paths = CertmeshPaths::with_data_dir(
            koi_common::test::ensure_data_dir("koi-certmesh-core-tests").join("ratelimit"),
        );
        let _ = std::fs::remove_dir_all(paths.data_dir());

        // No persisted file yet → fresh limiter, not locked.
        let mut rl = load_rate_limiter(&paths);
        assert!(!rl.is_locked());

        // Drive it into lockout, then persist.
        for _ in 0..3 {
            let _ = rl.check_and_record(false);
        }
        assert!(rl.is_locked(), "limiter must lock after MAX_FAILURES");
        persist_rate_limiter(&paths, &rl).unwrap();

        // A fresh load (simulating a daemon restart) must still be locked (F7).
        let reloaded = load_rate_limiter(&paths);
        assert!(
            reloaded.is_locked(),
            "persisted lockout must survive a restart"
        );

        let _ = std::fs::remove_dir_all(paths.data_dir());
    }

    // ── build_status ─────────────────────────────────────────────────

    #[test]
    fn build_status_locked_ca() {
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let status = build_status(&test_paths(), &None, &roster, None);
        assert!(status.ca_locked);
        assert_eq!(status.member_count, 1);
        assert_eq!(status.members.len(), 1);
        assert_eq!(status.members[0].hostname, "node-01");
        assert_eq!(status.members[0].role, "primary");
    }

    #[test]
    fn build_status_unlocked_ca() {
        let ca = make_test_ca();
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let status = build_status(&test_paths(), &Some(ca), &roster, None);
        assert!(!status.ca_locked);
        assert_eq!(status.member_count, 0);
    }

    #[test]
    fn build_status_member_roles_lowercase() {
        let mut roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
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
        let status = build_status(&test_paths(), &None, &roster, None);
        assert_eq!(status.members[0].role, "standby");
        assert_eq!(status.members[0].status, "active");
    }

    // ── Enrollment toggle facade tests ──────────────────────────────

    #[tokio::test]
    async fn open_enrollment_changes_state() {
        let ca = make_test_ca();
        let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".into()));
        let core = make_unlocked_core(ca, roster);

        // Initially closed (My Organization)
        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Closed);
        assert!(!status.enrollment_open);

        // Open
        core.open_enrollment().await.unwrap();
        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Open);
        assert!(status.enrollment_open);
    }

    #[tokio::test]
    async fn close_enrollment_changes_state() {
        let ca = make_test_ca();
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let core = make_unlocked_core(ca, roster);

        // Initially open for Just Me
        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Open);

        // Close
        core.close_enrollment().await.unwrap();
        let status = core.certmesh_status().await;
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Closed);
        assert!(!status.enrollment_open);
    }

    #[tokio::test]
    async fn rotate_auth_fails_when_ca_locked() {
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let core = make_locked_core(roster);
        let result = core.rotate_auth("test-pass", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn build_status_reports_posture_booleans() {
        let ca = make_test_ca();
        let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".into()));
        let status = build_status(&test_paths(), &Some(ca), &roster, None);
        assert!(!status.enrollment_open);
        assert!(status.requires_approval);
        assert_eq!(status.enrollment_state, roster::EnrollmentState::Closed);
    }

    // ── CertmeshCore::uninitialized_with_paths(test_paths()) state ─────────────────────────

    #[tokio::test]
    async fn uninitialized_core_status_shows_empty_roster() {
        let core = CertmeshCore::uninitialized_with_paths(test_paths());
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
        let core = CertmeshCore::uninitialized_with_paths(test_paths());
        let request = protocol::JoinRequest {
            hostname: "node-05".to_string(),
            auth: Some(koi_crypto::auth::AuthResponse::Totp {
                code: "123456".to_string(),
            }),
            invite_token: None,
            csr: None,
            sans: vec![],
        };
        let result = core.enroll(&request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn uninitialized_core_promote_returns_error() {
        let core = CertmeshCore::uninitialized_with_paths(test_paths());
        let dummy_pk = [0u8; 32];
        let result = core.promote(&dummy_pk).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn uninitialized_core_renew_self_is_noop() {
        let core = CertmeshCore::uninitialized_with_paths(test_paths());
        let outcome = core.renew_self_if_due().await.expect("no-op succeeds");
        assert!(matches!(outcome, RenewOutcome::NotApplicable));
    }

    #[tokio::test]
    async fn uninitialized_core_rotate_auth_returns_error() {
        let core = CertmeshCore::uninitialized_with_paths(test_paths());
        let result = core.rotate_auth("passphrase", None).await;
        assert!(result.is_err());
    }

    // ── node_role ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn node_role_returns_none_for_empty_roster() {
        let ca = make_test_ca();
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let core = make_unlocked_core(ca, roster);
        // Empty roster has no members, so node_role returns None
        // (regardless of local hostname)
        let role = core.node_role().await;
        // May or may not match the local hostname - depends on environment
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
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
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

    // ── Capability::status() ───────────────────────────────────────────

    #[tokio::test]
    async fn capability_status_uninitialised() {
        let core = CertmeshCore::uninitialized_with_paths(test_paths());
        let status = core.status().await;
        assert_eq!(status.name, "certmesh");
        // When no CA files exist on disk this is a healthy "ready" state.
        // On a dev machine with existing CA files it appears as "CA locked"
        // because the filesystem check sees them but the core has no loaded CA.
        if test_paths().is_ca_initialized() {
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

    #[tokio::test]
    async fn capability_status_locked() {
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_locked_core(roster);
        let status = core.status().await;
        assert_eq!(status.name, "certmesh");
        assert!(!status.healthy);
    }

    #[tokio::test]
    async fn capability_status_unlocked() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        let status = core.status().await;
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
    async fn certmesh_status_reports_posture() {
        let ca = make_test_ca();
        let roster = Roster::new(MY_ORG.0, MY_ORG.1, Some("ops".to_string()));
        let totp = koi_crypto::totp::generate_secret();
        let auth = koi_crypto::auth::AuthState::Totp(totp);
        let core = CertmeshCore::new_with_paths(ca, roster, Some(auth), test_paths());
        let status = core.certmesh_status().await;
        // My Organization posture: closed enrollment, approval required.
        assert!(!status.enrollment_open);
        assert!(status.requires_approval);
    }

    // ── set_reload_hook facade ─────────────────────────────────────────

    /// An absolute reload-hook command valid for the host platform.
    const ABS_HOOK: &str = if cfg!(windows) {
        "C:\\Windows\\System32\\cmd.exe"
    } else {
        "/usr/bin/systemctl"
    };

    #[tokio::test]
    async fn set_reload_hook_unknown_member_returns_error() {
        let ca = make_test_ca();
        let roster = Roster::new(JUST_ME.0, JUST_ME.1, None);
        let core = make_unlocked_core(ca, roster);
        let result = core.set_reload_hook("nonexistent", ABS_HOOK).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn set_reload_hook_sets_hook_for_known_member() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        core.set_reload_hook("node-01", ABS_HOOK).await.unwrap();
        let roster = core.state.roster.lock().await;
        assert_eq!(roster.members[0].reload_hook.as_deref(), Some(ABS_HOOK));
    }

    /// The domain method (not just the HTTP facade) must reject a relative-path
    /// hook. This is the intended strengthening: a direct library caller that
    /// bypasses HTTP still gets the absolute-path check.
    #[tokio::test]
    async fn set_reload_hook_rejects_relative_path() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        // A bare command name with no path separator is PATH-relative.
        let result = core
            .set_reload_hook("node-01", "systemctl restart nginx")
            .await;
        assert!(
            result.is_err(),
            "relative-path hook must be rejected by the core method"
        );
        // And the member's hook must remain unset (validation runs before mutation).
        let roster = core.state.roster.lock().await;
        assert!(roster.members[0].reload_hook.is_none());
    }

    /// Forbidden shell metacharacters are rejected by the core method.
    #[tokio::test]
    async fn set_reload_hook_rejects_shell_metacharacters() {
        let ca = make_test_ca();
        let roster = make_test_roster_with_member("node-01", MemberRole::Primary);
        let core = make_unlocked_core(ca, roster);
        let malicious = format!("{ABS_HOOK}; rm -rf /");
        let result = core.set_reload_hook("node-01", &malicious).await;
        assert!(result.is_err());
    }

    // ── decode_hex (moved from http.rs) ──────────────────────────────

    #[test]
    fn decode_hex_valid() {
        assert_eq!(decode_hex("0011ff"), Some(vec![0x00, 0x11, 0xff]));
    }

    #[test]
    fn decode_hex_invalid() {
        assert_eq!(decode_hex("zz"), None);
    }

    #[test]
    fn decode_hex_odd_length() {
        assert_eq!(decode_hex("abc"), None);
    }

    // ── CertmeshCore::create happy path ──────────────────────────────

    /// Direct unit coverage of the relocated CA-creation orchestration
    /// (previously only reachable via the HTTP create_handler). Verifies a
    /// fresh, uninitialized CA becomes initialized, unlocked, and
    /// self-enrolls the CA node as the primary member.
    #[tokio::test]
    async fn create_initializes_ca_and_self_enrolls_primary() {
        // Isolated, uninitialized data dir so is_ca_initialized() starts false.
        let base = koi_common::test::ensure_data_dir("koi-certmesh-create-tests");
        let paths = CertmeshPaths::with_data_dir(base.join("create-happy-path"));
        // Ensure a clean slate even if a prior run left artifacts behind.
        let _ = std::fs::remove_dir_all(paths.data_dir());
        assert!(
            !paths.is_ca_initialized(),
            "precondition: CA must not be initialized before create()"
        );

        let core = CertmeshCore::uninitialized_with_paths(paths.clone());

        let req = protocol::CreateCaRequest {
            passphrase: "test-pass-strong".to_string(),
            entropy_hex: koi_common::encoding::hex_encode(&[7u8; 32]),
            operator: Some("ops".to_string()),
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: false,
            totp_secret_hex: None,
        };

        let resp = core.create(req).await.expect("create should succeed");
        assert!(
            !resp.ca_fingerprint.is_empty(),
            "create should return a CA fingerprint"
        );

        // CA is now initialized on disk and unlocked in memory.
        assert!(paths.is_ca_initialized());
        let status = core.certmesh_status().await;
        assert!(status.ca_initialized);
        assert!(!status.ca_locked, "CA should be unlocked after create");

        // The CA node self-enrolled as the primary member.
        assert_eq!(status.member_count, 1, "CA node should self-enroll");
        assert_eq!(status.members.len(), 1);
        assert_eq!(status.members[0].role, "primary");
    }

    /// create() rejects a second initialization with a Conflict (→ 409).
    #[tokio::test]
    async fn create_on_initialized_ca_returns_conflict() {
        let base = koi_common::test::ensure_data_dir("koi-certmesh-create-tests");
        let paths = CertmeshPaths::with_data_dir(base.join("create-conflict"));
        let _ = std::fs::remove_dir_all(paths.data_dir());
        let core = CertmeshCore::uninitialized_with_paths(paths.clone());

        let mk_req = || protocol::CreateCaRequest {
            passphrase: "test-pass-strong".to_string(),
            entropy_hex: koi_common::encoding::hex_encode(&[9u8; 32]),
            operator: None,
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: false,
            totp_secret_hex: None,
        };

        core.create(mk_req()).await.expect("first create succeeds");
        let err = core
            .create(mk_req())
            .await
            .expect_err("second create must fail");
        assert!(
            matches!(err, CertmeshError::Conflict(_)),
            "expected Conflict, got {err:?}"
        );
        assert_eq!(koi_common::error::ErrorCode::from(&err).http_status(), 409);
    }

    /// create() rejects malformed entropy with InvalidPayload (→ 400).
    #[tokio::test]
    async fn create_with_bad_entropy_returns_invalid_payload() {
        let base = koi_common::test::ensure_data_dir("koi-certmesh-create-tests");
        let paths = CertmeshPaths::with_data_dir(base.join("create-bad-entropy"));
        let _ = std::fs::remove_dir_all(paths.data_dir());
        let core = CertmeshCore::uninitialized_with_paths(paths);

        let req = protocol::CreateCaRequest {
            passphrase: "test-pass-strong".to_string(),
            entropy_hex: "bad".to_string(),
            operator: None,
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: false,
            totp_secret_hex: None,
        };
        let err = core.create(req).await.expect_err("bad entropy must fail");
        assert!(
            matches!(err, CertmeshError::InvalidPayload(_)),
            "expected InvalidPayload, got {err:?}"
        );
        assert_eq!(koi_common::error::ErrorCode::from(&err).http_status(), 400);
    }
}
