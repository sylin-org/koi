//! Construction, wiring, and route/subscription accessors for CertmeshCore.
//!
//! Part of the inherent impl CertmeshCore, split from lib.rs (certmesh M2).
//! As a child module of the crate root, 'use super::*' inherits lib.rs's
//! imports, sibling modules, and crate-private state/helpers as in the original.
use super::*;

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
}
