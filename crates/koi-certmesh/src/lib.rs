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
    /// Tracks consecutive renewal failures so `CertRenewalFailed` can report the
    /// streak to consumers. Reset to zero on each successful renewal.
    pub(crate) renewal_failure_count: std::sync::atomic::AtomicU32,
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
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

// impl CertmeshCore is split across cohesive submodules (certmesh M2).
// Each child module does 'use super::*' to inherit lib.rs's imports, sibling
// modules, and crate-private state + helpers.
mod core_admin;
mod core_auth;
mod core_enroll;
mod core_identity;
mod core_lifecycle;
mod core_member;
mod core_renewal;
mod core_setup;

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
/// leaf (`cert.pem`/`key.pem`) for the local hostname on disk, anchored to a mesh.
///
/// "Anchored" is any of:
/// - the CA is initialized here (this node *is* the CA), or
/// - a `member.json` records the joined mesh (the mTLS-pull-renewal consumer), or
/// - the leaf's CA anchor (`ca.pem`) sits alongside it — a leaf installed *with*
///   the CA it chains to. This recognizes an **embedded consumer that holds a
///   CA-signed leaf but deliberately does not arm `member.json`** (it drives its
///   own renewal over a non-mTLS plane, ADR-020/ADR-022): its leaf is a real
///   identity, not a stray cert. `install_member_cert`/`self_enroll` only write
///   `ca.pem` beside a deliberately-installed leaf, and `destroy` removes the whole
///   `certs/` tree, so this does not resurrect an orphaned leaf as secure.
///
/// Backs [`CertmeshCore::posture`] and the [`CertmeshCore::require_auth`] gate.
pub(crate) fn node_has_identity(paths: &CertmeshPaths) -> bool {
    let Some(hostname) = CertmeshCore::local_hostname() else {
        return false;
    };
    let leaf = paths.certs_dir().join(&hostname);
    let leaf_present = leaf.join("cert.pem").exists() && leaf.join("key.pem").exists();
    let anchored = paths.is_ca_initialized()
        || paths.member_state_path().exists()
        || leaf.join("ca.pem").exists();
    leaf_present && anchored
}

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
/// [`mtls::extract_cn`](crate::mtls::extract_cn) with a PEM entry point.
pub fn leaf_cn(cert_pem: &str) -> Option<String> {
    let der = pem::parse(cert_pem).ok()?;
    crate::mtls::extract_cn(der.contents())
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
mod core_tests;
