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

    /// Replace the standalone `.internal` default with the composition root's
    /// configured DNS zone. This consumes a freshly constructed core so the
    /// immutable shared state cannot be reconfigured after publication.
    pub fn with_dns_zone(mut self, zone: &str) -> Result<Self, CertmeshError> {
        let issuance_names = IssuanceNames::new(zone)?;
        let state = Arc::get_mut(&mut self.state).ok_or_else(|| {
            CertmeshError::Internal(
                "certificate naming cannot change after the certmesh core is shared".into(),
            )
        })?;
        let domain = Arc::get_mut(&mut state.domain).ok_or_else(|| {
            CertmeshError::Internal(
                "certificate naming cannot change after the certmesh core is shared".into(),
            )
        })?;
        domain.issuance_names = issuance_names;
        Ok(self)
    }

    /// Inject the immutable machine identity accepted by the application root.
    ///
    /// This consumes an unshared core so a running Certmesh generation cannot
    /// change certificate identity underneath its status or listeners.
    pub fn with_local_hostname(mut self, hostname: &str) -> Result<Self, CertmeshError> {
        let hostname = hostname.trim().trim_end_matches('.');
        validate_hostname(hostname)?;
        let state = Arc::get_mut(&mut self.state).ok_or_else(|| {
            CertmeshError::Internal(
                "local hostname cannot change after the certmesh core is shared".into(),
            )
        })?;
        let domain = Arc::get_mut(&mut state.domain).ok_or_else(|| {
            CertmeshError::Internal(
                "local hostname cannot change after the certmesh core is shared".into(),
            )
        })?;
        domain.local_hostname = Some(Arc::from(hostname));
        domain.refresh_status_under_transition();
        Ok(self)
    }

    /// Apply all immutable launch inputs before the core can arm retained work.
    fn with_boot_configuration(
        self,
        dns_zone: &str,
        local_hostname: &str,
    ) -> Result<Self, CertmeshError> {
        self.with_dns_zone(dns_zone)?
            .with_local_hostname(local_hostname)
    }

    /// The normalized configured zone used for certmesh-issued FQDNs.
    pub fn dns_zone(&self) -> &str {
        self.state.issuance_names.zone()
    }

    /// Arm the one durable post-certificate integration only after immutable
    /// bootstrap configuration has been applied. The retained reload executor
    /// owns settlement independently from the startup caller.
    fn reconcile_pending_reload(self) -> Self {
        self.state.reloads.reconcile(Arc::clone(&self.state.domain));
        self
    }

    /// Load Certmesh's persisted aggregate and select its boot state.
    ///
    /// This is the sole persistence-aware bootstrap boundary. Composition owns
    /// only path resolution and configuration; roster, CA, auth, machine-binding,
    /// and vault semantics remain private to the Certmesh domain.
    pub fn load_with_paths(
        paths: CertmeshPaths,
        dns_zone: &str,
        local_hostname: &str,
    ) -> Result<Self, CertmeshError> {
        let dns_zone = dns_zone.to_string();
        let local_hostname = local_hostname.to_string();
        koi_common::blocking::run_to_completion(move || {
            Self::load_with_paths_inner(paths, &dns_zone, &local_hostname)
        })
    }

    /// Load Certmesh without blocking an async executor.
    ///
    /// Bootstrap can recover durable transactions and consult platform-backed
    /// credentials. Its joinable one-shot owner finishes and reaps that work if
    /// the awaiting startup future is cancelled.
    pub async fn load_with_paths_async(
        paths: CertmeshPaths,
        dns_zone: &str,
        local_hostname: &str,
    ) -> Result<Self, CertmeshError> {
        bootstrap::CertmeshBootstrapJob::start(
            paths,
            dns_zone.to_string(),
            local_hostname.to_string(),
        )?
        .await
    }

    fn load_with_paths_inner(
        paths: CertmeshPaths,
        dns_zone: &str,
        local_hostname: &str,
    ) -> Result<Self, CertmeshError> {
        // Reject invalid launch input before repository recovery or credential
        // cleanup can have durable effects.
        validate_hostname(local_hostname.trim().trim_end_matches('.'))?;
        // A process may have stopped between artifact replacements. Recovery is
        // domain-owned and happens before any aggregate generation is read.
        let repository = repository::CertmeshRepository::new(paths.data_dir().to_path_buf());
        repository.recover()?;
        retry_credential_cleanups(&paths, &repository);
        let acme_accounts = acme::account::AccountStore::load(&paths.acme_accounts_path())?;
        let rate_limiter = load_rate_limiter(&paths)?;
        if !paths.is_ca_initialized() {
            tracing::info!("Certmesh: CA not initialized - routes mounted for /create");
            return Self::uninitialized_with_boot_state(paths, acme_accounts, rate_limiter)
                .with_boot_configuration(dns_zone, local_hostname)
                .map(Self::reconcile_pending_reload);
        }

        let roster_path = paths.roster_path();
        let roster = match roster::load_roster(&roster_path) {
            Ok(roster) => roster,
            Err(error) => {
                // Keep the authority relationship fail-closed even when its
                // private roster is unavailable. status::build derives role from
                // the durable CA marker, independently from this empty fallback.
                tracing::warn!(%error, "Failed to load Certmesh roster; booting locked");
                return Self::locked_with_boot_state(
                    Roster::empty(),
                    paths,
                    acme_accounts,
                    rate_limiter,
                )
                .with_boot_configuration(dns_zone, local_hostname)
                .map(Self::reconcile_pending_reload);
            }
        };

        // The durable slot marker is the sole desired-state authority. A stale
        // vault value without that marker is inert and must never unlock a CA.
        let auto_unlock_desired = match ca::load_slot_table(&paths.slot_table_path()) {
            Ok(Some(table)) => Some(table.has_auto_unlock()),
            Ok(None) => Some(false),
            Err(error) => {
                tracing::warn!(%error, "Could not read Certmesh unlock slots; booting locked");
                None
            }
        };
        if auto_unlock_desired == Some(false) {
            // The slot marker is authoritative, so any legacy credential is
            // inert. Vault owns a cross-process transaction fence; retiring the
            // exact Certmesh key cannot overwrite unrelated application keys.
            match koi_crypto::vault::Vault::delete_persisted_entry(
                paths.data_dir(),
                Self::VAULT_AUTO_UNLOCK_KEY,
            ) {
                Ok(true) => tracing::info!("Retired inert Certmesh auto-unlock credential"),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(%error, "Could not retire inert Certmesh auto-unlock credential")
                }
            }
        }
        if auto_unlock_desired == Some(true) {
            // Refuse copied auto-unlock material before touching the vault. A
            // manual unlock remains available for a legitimate migration.
            let machine_ok = machine_binding_ok(&paths);
            if !machine_ok {
                let mut transaction = repository::ArtifactTransaction::new();
                transaction.append(
                    paths.audit_log_path(),
                    audit::render_entry("auto_unlock_refused_machine_changed", &[]),
                    true,
                )?;
                repository.commit_durable(transaction)?;
                tracing::error!(
                    "Certmesh: machine fingerprint changed since CA creation; booting locked"
                );
            } else {
                match Self::read_auto_unlock_key(&paths) {
                    Ok(Some(passphrase)) => match ca::load_ca(&passphrase, &paths) {
                        Ok(ca_state) => {
                            // Re-read at the moment the unlocked aggregate is built so
                            // the in-memory model cannot lag a concurrent durable write.
                            match roster::load_roster(&roster_path) {
                                Ok(fresh_roster) => {
                                    let auth = load_auth_for_boot(&paths, &passphrase);
                                    tracing::info!("Certmesh CA auto-unlocked at init from vault");
                                    return Self::new_with_boot_state(
                                        ca_state,
                                        fresh_roster,
                                        auth,
                                        paths,
                                        acme_accounts,
                                        rate_limiter,
                                    )
                                    .with_boot_configuration(dns_zone, local_hostname)
                                    .map(Self::reconcile_pending_reload);
                                }
                                Err(error) => tracing::warn!(
                                    %error,
                                    "Certmesh roster changed or became unreadable during auto-unlock"
                                ),
                            }
                        }
                        Err(error) => tracing::warn!(
                            %error,
                            "Auto-unlock key exists in vault but CA decryption failed"
                        ),
                    },
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(%error, "Could not read Certmesh auto-unlock vault")
                    }
                }
            }
        }

        tracing::info!("Certmesh: CA initialized (locked; manual unlock required)");
        Self::locked_with_boot_state(roster, paths, acme_accounts, rate_limiter)
            .with_boot_configuration(dns_zone, local_hostname)
            .map(Self::reconcile_pending_reload)
    }

    /// Create a fresh CertmeshCore with explicit aggregate material and paths.
    ///
    /// This constructor is intentionally persistence-free and starts with an
    /// empty ACME account model. Use [`Self::load_with_paths`] (or its async
    /// variant) when opening an existing data root.
    pub fn new_with_paths(
        ca: ca::CaState,
        roster: Roster,
        auth_state: Option<AuthState>,
        paths: CertmeshPaths,
    ) -> Self {
        Self::new_with_boot_state(
            ca,
            roster,
            auth_state,
            paths,
            acme::account::AccountStore::default(),
            RateLimiter::new(),
        )
    }

    fn new_with_boot_state(
        ca: ca::CaState,
        roster: Roster,
        auth_state: Option<AuthState>,
        paths: CertmeshPaths,
        acme_accounts: acme::account::AccountStore,
        rate_limiter: RateLimiter,
    ) -> Self {
        let local_hostname = initial_local_hostname();
        let (initial_status, initial_tls_material) = status::build_with_tls(
            &paths,
            local_hostname.as_deref(),
            true,
            Some(ca::ca_fingerprint(&ca)),
            &roster,
            auth_state
                .as_ref()
                .map(|auth| auth.method_name().to_string()),
            0,
        );
        let initial_roster_snapshot = koi_common::integration::CertmeshRosterSnapshot {
            revision: 0,
            active_members: status::active_members(&initial_status),
        };
        let initial_ca_anchor =
            status::build_ca_anchor(&paths, local_hostname.as_deref(), initial_status.role, 0);
        let repository = Arc::new(repository::CertmeshRepository::new(
            paths.data_dir().to_path_buf(),
        ));
        Self {
            state: Arc::new(CertmeshState::own(CertmeshDomain {
                paths,
                local_hostname,
                issuance_names: IssuanceNames::default(),
                ca: ModelCell::new(Some(ca)),
                roster: ModelCell::new(roster),
                auth: ModelCell::new(auth_state),
                acme_accounts,
                pending_challenge: ModelCell::new(None),
                rate_limiter: ModelCell::new(rate_limiter),
                approval_tx: ModelCell::new(None),
                pending_promotion: ModelCell::new(None),
                event_tx: koi_common::events::event_channel().0,
                status: koi_common::status::StatusFeed::new(initial_status),
                roster_snapshot: koi_common::status::StatusFeed::new(initial_roster_snapshot),
                tls_identity: koi_common::status::StatusFeed::new(
                    koi_common::integration::TlsIdentitySnapshot {
                        revision: 0,
                        material: initial_tls_material,
                    },
                ),
                ca_anchor: koi_common::status::StatusFeed::new(initial_ca_anchor),
                transition: Arc::new(tokio::sync::Mutex::new(())),
                repository,
                renewal: ModelCell::new(CertmeshRenewalStatus::default()),
                repository_settlement_error: ModelCell::new(None),
            })),
        }
    }

    /// Create a fresh locked CertmeshCore with explicit paths.
    ///
    /// Existing persistence must be opened through [`Self::load_with_paths`].
    pub fn locked_with_paths(roster: Roster, paths: CertmeshPaths) -> Self {
        Self::locked_with_boot_state(
            roster,
            paths,
            acme::account::AccountStore::default(),
            RateLimiter::new(),
        )
    }

    fn locked_with_boot_state(
        roster: Roster,
        paths: CertmeshPaths,
        acme_accounts: acme::account::AccountStore,
        rate_limiter: RateLimiter,
    ) -> Self {
        let local_hostname = initial_local_hostname();
        let (initial_status, initial_tls_material) = status::build_with_tls(
            &paths,
            local_hostname.as_deref(),
            false,
            None,
            &roster,
            None,
            0,
        );
        let initial_roster_snapshot = koi_common::integration::CertmeshRosterSnapshot {
            revision: 0,
            active_members: status::active_members(&initial_status),
        };
        let initial_ca_anchor =
            status::build_ca_anchor(&paths, local_hostname.as_deref(), initial_status.role, 0);
        let repository = Arc::new(repository::CertmeshRepository::new(
            paths.data_dir().to_path_buf(),
        ));
        Self {
            state: Arc::new(CertmeshState::own(CertmeshDomain {
                paths,
                local_hostname,
                issuance_names: IssuanceNames::default(),
                ca: ModelCell::new(None),
                roster: ModelCell::new(roster),
                auth: ModelCell::new(None),
                acme_accounts,
                pending_challenge: ModelCell::new(None),
                rate_limiter: ModelCell::new(rate_limiter),
                approval_tx: ModelCell::new(None),
                pending_promotion: ModelCell::new(None),
                event_tx: koi_common::events::event_channel().0,
                status: koi_common::status::StatusFeed::new(initial_status),
                roster_snapshot: koi_common::status::StatusFeed::new(initial_roster_snapshot),
                tls_identity: koi_common::status::StatusFeed::new(
                    koi_common::integration::TlsIdentitySnapshot {
                        revision: 0,
                        material: initial_tls_material,
                    },
                ),
                ca_anchor: koi_common::status::StatusFeed::new(initial_ca_anchor),
                transition: Arc::new(tokio::sync::Mutex::new(())),
                repository,
                renewal: ModelCell::new(CertmeshRenewalStatus::default()),
                repository_settlement_error: ModelCell::new(None),
            })),
        }
    }

    /// Create a fresh CertmeshCore in uninitialized state with explicit paths.
    ///
    /// HTTP routes are still mounted so `/create` is reachable on a fresh install.
    /// All operations that require an initialized CA will return `CaNotInitialized`.
    /// Existing persistence must be opened through [`Self::load_with_paths`].
    pub fn uninitialized_with_paths(paths: CertmeshPaths) -> Self {
        Self::uninitialized_with_boot_state(
            paths,
            acme::account::AccountStore::default(),
            RateLimiter::new(),
        )
    }

    fn uninitialized_with_boot_state(
        paths: CertmeshPaths,
        acme_accounts: acme::account::AccountStore,
        rate_limiter: RateLimiter,
    ) -> Self {
        let roster = Roster::empty();
        let local_hostname = initial_local_hostname();
        let (initial_status, initial_tls_material) = status::build_with_tls(
            &paths,
            local_hostname.as_deref(),
            false,
            None,
            &roster,
            None,
            0,
        );
        let initial_roster_snapshot = koi_common::integration::CertmeshRosterSnapshot {
            revision: 0,
            active_members: status::active_members(&initial_status),
        };
        let initial_ca_anchor =
            status::build_ca_anchor(&paths, local_hostname.as_deref(), initial_status.role, 0);
        let repository = Arc::new(repository::CertmeshRepository::new(
            paths.data_dir().to_path_buf(),
        ));
        Self {
            state: Arc::new(CertmeshState::own(CertmeshDomain {
                paths,
                local_hostname,
                issuance_names: IssuanceNames::default(),
                ca: ModelCell::new(None),
                roster: ModelCell::new(roster),
                auth: ModelCell::new(None),
                acme_accounts,
                pending_challenge: ModelCell::new(None),
                rate_limiter: ModelCell::new(rate_limiter),
                approval_tx: ModelCell::new(None),
                pending_promotion: ModelCell::new(None),
                event_tx: koi_common::events::event_channel().0,
                status: koi_common::status::StatusFeed::new(initial_status),
                roster_snapshot: koi_common::status::StatusFeed::new(initial_roster_snapshot),
                tls_identity: koi_common::status::StatusFeed::new(
                    koi_common::integration::TlsIdentitySnapshot {
                        revision: 0,
                        material: initial_tls_material,
                    },
                ),
                ca_anchor: koi_common::status::StatusFeed::new(initial_ca_anchor),
                transition: Arc::new(tokio::sync::Mutex::new(())),
                repository,
                renewal: ModelCell::new(CertmeshRenewalStatus::default()),
                repository_settlement_error: ModelCell::new(None),
            })),
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
        *self.state.approval_tx.lock() = Some(tx);
    }

    /// Subscribe to certmesh events.
    pub fn subscribe(&self) -> broadcast::Receiver<CertmeshEvent> {
        self.state.event_tx.subscribe()
    }

    /// Read the current immutable Certmesh status in constant time.
    pub fn status(&self) -> Arc<CertmeshStatus> {
        self.state.status.current()
    }

    /// Subscribe to the latest Certmesh status. The receiver is seeded with the
    /// same allocation returned by [`Self::status`]. Updates coalesce; audit and
    /// semantic events remain the history-bearing surfaces.
    pub fn watch_status(&self) -> tokio::sync::watch::Receiver<Arc<CertmeshStatus>> {
        self.state.status.subscribe()
    }

    /// Current active-member projection for cross-domain consumers. This is a
    /// constant-time read and intentionally excludes private Certmesh status.
    pub fn roster_snapshot(&self) -> Arc<koi_common::integration::CertmeshRosterSnapshot> {
        self.state.roster_snapshot.current()
    }

    /// Capture primary status and the active-roster projection from one completed
    /// Certmesh transition.
    ///
    /// The roster is published before primary status. Comparing through Certmesh's
    /// own projection function closes that narrow publication window without making
    /// composition duplicate the meaning of an active member.
    pub fn status_with_roster(
        &self,
    ) -> (
        Arc<CertmeshStatus>,
        Arc<koi_common::integration::CertmeshRosterSnapshot>,
    ) {
        loop {
            let before = self.status();
            let roster = self.roster_snapshot();
            let after = self.status();
            let active_members = crate::status::active_members(after.as_ref());
            if Arc::ptr_eq(&before, &after)
                && active_members.as_slice() == roster.active_members.as_slice()
            {
                return (after, roster);
            }
            std::hint::spin_loop();
        }
    }

    /// Observe active-member additions, removals, renewal facts, and metadata
    /// changes without polling Certmesh persistence or rebuilding a cache.
    pub fn watch_roster_snapshot(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<koi_common::integration::CertmeshRosterSnapshot>> {
        self.state.roster_snapshot.subscribe()
    }

    /// Current usable local TLS identity. Private material stays in-process and
    /// is absent whenever Certmesh cannot safely authenticate this node.
    pub fn tls_identity(&self) -> Arc<koi_common::integration::TlsIdentitySnapshot> {
        self.state.tls_identity.current()
    }

    /// Observe local TLS identity install, rotation, revocation, expiry, and
    /// destruction without watching Certmesh-owned files.
    pub fn watch_tls_identity(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<koi_common::integration::TlsIdentitySnapshot>> {
        self.state.tls_identity.subscribe()
    }

    /// Current Certmesh verification anchor for trusted in-process consumers.
    /// The raw PEM is deliberately absent from serializable [`CertmeshStatus`].
    pub fn ca_anchor(&self) -> Arc<CertmeshCaAnchorSnapshot> {
        self.state.ca_anchor.current()
    }

    /// Observe authoritative anchor creation, replacement, and destruction.
    pub fn watch_ca_anchor(&self) -> tokio::sync::watch::Receiver<Arc<CertmeshCaAnchorSnapshot>> {
        self.state.ca_anchor.subscribe()
    }

    /// Build the RFC 8555 ACME server state over this CA.
    ///
    /// The binary calls this when starting the dedicated server-auth TLS
    /// listener, passing the ACME base URL, the Koi DNS zone, and the
    /// `AcmeDnsResolver` bridge. The returned `AcmeState` shares this core's CA and
    /// roster (so ACME issuance lands in the same roster as TOTP enrollment), and
    /// is mounted via [`acme::routes`].
    pub fn acme_state(&self, config: acme::AcmeStateConfig) -> std::sync::Arc<acme::AcmeState> {
        acme::AcmeState::new(Arc::clone(&self.state), config)
    }
}

fn load_auth_for_boot(paths: &CertmeshPaths, passphrase: &str) -> Option<AuthState> {
    let auth_path = paths.auth_path();
    if !auth_path.exists() {
        return None;
    }
    let result = std::fs::read_to_string(&auth_path)
        .map_err(|error| error.to_string())
        .and_then(|json| {
            serde_json::from_str::<koi_crypto::auth::StoredAuth>(&json)
                .map_err(|error| error.to_string())
        })
        .and_then(|stored| stored.unlock(passphrase).map_err(|error| error.to_string()));
    match result {
        Ok(auth) => Some(auth),
        Err(error) => {
            tracing::warn!(%error, path = %auth_path.display(), "Could not load Certmesh auth credential");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coherent_status_capture_retries_a_projection_publication_window() {
        let temp = tempfile::tempdir().expect("temporary Certmesh root");
        let core = CertmeshCore::uninitialized_with_paths(CertmeshPaths::with_data_dir(
            temp.path().to_path_buf(),
        ));
        let status = core.status();
        core.state
            .roster_snapshot
            .publish(koi_common::integration::CertmeshRosterSnapshot {
                revision: 1,
                active_members: vec![koi_common::integration::MemberSummary {
                    hostname: "future.internal".to_string(),
                    sans: Vec::new(),
                    cert_expires: None,
                    last_seen: None,
                    status: "active".to_string(),
                    proxy_entries: Vec::new(),
                }],
            });

        let worker = core.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx.send(worker.status_with_roster()).unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("capture thread started");
        assert!(matches!(
            result_rx.recv_timeout(std::time::Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        core.state
            .roster_snapshot
            .publish(koi_common::integration::CertmeshRosterSnapshot {
                revision: 2,
                active_members: crate::status::active_members(status.as_ref()),
            });
        let (captured_status, captured_roster) = result_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("coherent pair");
        thread.join().expect("capture thread");
        assert_eq!(captured_status.as_ref(), status.as_ref());
        assert_eq!(
            captured_roster.active_members,
            crate::status::active_members(captured_status.as_ref())
        );
    }
}
