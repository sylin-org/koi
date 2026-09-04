//! OS trust-store domain boundary.
//!
//! `TrustCore` is the sole owner of Koi-managed root state and platform-store
//! effects. Commands are journaled before the external effect, serialized across
//! processes, and acknowledged only after status has been refreshed and the
//! semantic event emitted. Consumers read the cheap immutable status or subscribe;
//! they never reconstruct trust truth from `trust.json`.

pub mod http;
mod platform;
mod repository;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::JoinHandle;

use koi_common::persist::AtomicCommit;
use platform::{InstallOutcome, PlatformTrustStore, TrustStore};
use repository::{Repository, TrustEntry, TrustState, TrustTransition};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};

const TRUST_COMMAND_CAPACITY: usize = 64;

/// Desired Koi-managed root supplied to a Trust command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InstallRoot {
    pub name: String,
    pub source: String,
    pub certificate_pem: String,
}

/// What the real platform adapter can truthfully observe.
///
/// This deliberately says `Present`, not `Trusted`: some platforms can confirm
/// store membership but cannot prove that every application accepts the anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TrustPresence {
    Present,
    Missing,
    Unavailable { reason: String },
}

/// One Koi-owned root in the authoritative public read model. Raw certificate
/// material is persistence/replay data and never crosses this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TrustRootStatus {
    pub name: String,
    pub installed_at: String,
    pub fingerprint: String,
    pub source: String,
    pub presence: TrustPresence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustOperation {
    Install,
    Uninstall,
    Ensure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TrustPendingStatus {
    pub operation: TrustOperation,
    pub name: String,
    pub fingerprint: String,
}

/// Cheap immutable Trust-domain truth.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TrustStatus {
    /// Process-local monotonic semantic revision.
    pub revision: u64,
    pub roots: Vec<TrustRootStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<TrustPendingStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Best-effort transition history. Current truth is always [`TrustStatus`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEvent {
    RootInstalled {
        name: String,
        fingerprint: String,
    },
    RootRemoved {
        name: String,
        fingerprint: String,
    },
    TransitionRecovered {
        operation: TrustOperation,
        name: String,
        fingerprint: String,
    },
    PresenceChanged {
        name: String,
        fingerprint: String,
        presence: TrustPresence,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TrustMutation {
    pub name: String,
    pub fingerprint: Option<String>,
    pub changed: bool,
    /// A platform-specific qualification such as macOS reporting that the
    /// certificate is present but application trust could not be confirmed.
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TrustRecovery {
    Clean,
    Recovered {
        operation: TrustOperation,
        name: String,
        fingerprint: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("trust persistence: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid CA certificate: {0}")]
    InvalidCertificate(String),
    #[error("OS trust store: {0}")]
    Platform(String),
    #[error("trust ownership conflict: {0}")]
    Conflict(String),
    #[error("no Koi-installed CA root named \"{0}\"")]
    NotFound(String),
    #[error("trust transition durability is uncertain: {0}")]
    DurabilityUncertain(String),
    #[error("trust worker stopped unexpectedly: {0}")]
    Worker(String),
    #[error("trust domain is shut down")]
    ShutDown,
}

#[derive(Clone)]
pub struct TrustCore {
    inner: Arc<Inner>,
}

struct Inner {
    status: koi_common::status::StatusFeed<TrustStatus>,
    events: broadcast::Sender<TrustEvent>,
    worker: TrustWorker,
}

/// Serialized owner of Trust's persistence, platform adapter, status, and
/// semantic events. A command accepted into this worker is completed even if
/// its caller stops waiting, so cancellation cannot split the domain invariant.
struct TrustDomain {
    repository: Repository,
    store: Arc<dyn TrustStore>,
    status: koi_common::status::StatusFeed<TrustStatus>,
    events: broadcast::Sender<TrustEvent>,
}

type TrustWork = Box<dyn FnOnce(&TrustDomain) + Send + 'static>;

enum TrustMessage {
    Run(TrustWork),
    Shutdown,
}

struct TrustAdmission {
    sender: Option<mpsc::Sender<TrustMessage>>,
}

/// The one blocking execution boundary owned by a Trust facade.
///
/// `os-truststore` and durable filesystem transitions are synchronous and may
/// not be abandoned once admitted. The dedicated thread keeps that work away
/// from async executors, while its queue is the local serialization boundary.
/// Last-owner drop closes the queue, drains already accepted commands, and
/// joins the thread rather than detaching platform effects.
struct TrustWorker {
    admission: Mutex<TrustAdmission>,
    completion: watch::Receiver<bool>,
    thread: StdMutex<Option<JoinHandle<()>>>,
}

impl TrustWorker {
    async fn start(
        data_dir: PathBuf,
        store: Arc<dyn TrustStore>,
    ) -> Result<
        (
            Self,
            koi_common::status::StatusFeed<TrustStatus>,
            broadcast::Sender<TrustEvent>,
        ),
        TrustError,
    > {
        let (work_tx, mut work_rx) = mpsc::channel::<TrustMessage>(TRUST_COMMAND_CAPACITY);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (completion_tx, completion_rx) = watch::channel(false);
        let thread = std::thread::Builder::new()
            .name("koi-trust".into())
            .spawn(move || {
                let repository = Repository::new(data_dir);
                // Construction is observation-only. Atomic state reads need no
                // mutation lock, and an absent Trust domain must not create a
                // directory merely because a query opened it. The long-lived
                // composition owner explicitly reconciles after construction;
                // mutations also recover durable intent before their effect.
                let initial = repository
                    .load()
                    .map(|state| status_from_state(&state, store.as_ref(), None, 0));
                let initial = match initial {
                    Ok(initial) => initial,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                let status = koi_common::status::StatusFeed::new(initial);
                let events = koi_common::events::event_channel().0;
                let domain = TrustDomain {
                    repository,
                    store,
                    status: status.clone(),
                    events: events.clone(),
                };
                if ready_tx.send(Ok((status, events))).is_err() {
                    return;
                }
                while let Some(message) = work_rx.blocking_recv() {
                    match message {
                        TrustMessage::Run(work) => {
                            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                work(&domain);
                            }))
                            .is_err()
                            {
                                // The admitted caller observes a closed reply.
                                // Durable intent was already published before
                                // any platform effect, so the next command can
                                // recover it. Keep the domain owner alive.
                                tracing::error!("trust command panicked; worker remains available");
                            }
                        }
                        TrustMessage::Shutdown => break,
                    }
                }
                completion_tx.send_replace(true);
            })?;
        // Own the thread before awaiting its initialization handshake. If the
        // opening future is cancelled here, `TrustWorker::drop` closes and
        // joins it; there is never a detached initialization effect.
        let worker = Self {
            admission: Mutex::new(TrustAdmission {
                sender: Some(work_tx),
            }),
            completion: completion_rx,
            thread: StdMutex::new(Some(thread)),
        };
        let (status, events) = ready_rx.await.map_err(|error| {
            TrustError::Worker(format!("initialization ended without a result: {error}"))
        })??;
        Ok((worker, status, events))
    }

    async fn submit<R: Send + 'static>(
        &self,
        action: impl FnOnce(&TrustDomain) -> Result<R, TrustError> + Send + 'static,
    ) -> Result<R, TrustError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let work = Box::new(move |domain: &TrustDomain| {
            // Completing the invariant does not depend on the receiver still
            // existing; a cancelled caller merely declines its acknowledgement.
            let _ = reply_tx.send(action(domain));
        });
        {
            // Holding admission through the bounded send linearizes this work
            // against terminal shutdown. Cancellation before send completion
            // admits nothing; after completion the worker owns the command.
            let mut admission = self.admission.lock().await;
            let Some(sender) = admission.sender.as_ref() else {
                return Err(TrustError::ShutDown);
            };
            if sender.send(TrustMessage::Run(work)).await.is_err() {
                admission.sender.take();
                return Err(TrustError::Worker("worker command channel closed".into()));
            }
        }
        reply_rx
            .await
            .map_err(|_| TrustError::Worker("worker ended before acknowledgement".into()))?
    }

    async fn shutdown(&self) -> Result<(), TrustError> {
        let admission_result = {
            let mut admission = self.admission.lock().await;
            if let Some(sender) = admission.sender.as_ref() {
                // Every accepted Run message precedes this marker because all
                // sends share this gate. Do not publish the terminal admission
                // state until the bounded send itself succeeds: cancellation
                // while waiting for capacity can then be retried cleanly.
                if sender.send(TrustMessage::Shutdown).await.is_err() {
                    admission.sender.take();
                    Err(TrustError::Worker(
                        "worker stopped before terminal command admission".into(),
                    ))
                } else {
                    admission.sender.take();
                    Ok(())
                }
            } else {
                Ok(())
            }
        };

        let mut completion = self.completion.clone();
        let completion_result = loop {
            if *completion.borrow() {
                break Ok(());
            }
            if completion.changed().await.is_err() {
                break Err(TrustError::Worker(
                    "worker exited without shutdown completion".into(),
                ));
            }
        };
        // Once completion is observed this is non-cancellable synchronous
        // bookkeeping. If waiting above is cancelled, the handle remains in
        // the shared slot for a later shutdown call or the Drop fallback.
        let join_result = self.join_thread();
        admission_result?;
        completion_result?;
        join_result
    }

    fn join_thread(&self) -> Result<(), TrustError> {
        let mut slot = self
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(thread) = slot.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| TrustError::Worker("worker panicked during shutdown".into()))
    }
}

impl Drop for TrustWorker {
    fn drop(&mut self) {
        // Close first. The receiver drains everything accepted before closure,
        // then exits; joining is the ownership fence for real platform work.
        drop(self.admission.get_mut().sender.take());
        let thread = self
            .thread
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(thread) = thread {
            if thread.join().is_err() {
                tracing::error!("trust worker panicked while shutting down");
            }
        }
    }
}

impl TrustCore {
    /// Open the Trust aggregate below `data_dir` using the real platform store.
    ///
    /// Construction loads durable intent and observes platform presence, but
    /// deliberately does not replay a pending effect. A long-lived application
    /// owner calls [`Self::reconcile`] during startup; mutation commands recover
    /// before applying their own effect. This keeps one-shot status/list reads
    /// side-effect free.
    pub async fn open(data_dir: impl Into<PathBuf>) -> Result<Self, TrustError> {
        Self::open_with_store(data_dir.into(), Arc::new(PlatformTrustStore)).await
    }

    async fn open_with_store(
        data_dir: PathBuf,
        store: Arc<dyn TrustStore>,
    ) -> Result<Self, TrustError> {
        let (worker, status, events) = TrustWorker::start(data_dir, store).await?;
        let inner = Arc::new(Inner {
            status,
            events,
            worker,
        });
        Ok(Self { inner })
    }

    /// Current immutable status in constant time.
    pub fn status(&self) -> Arc<TrustStatus> {
        self.inner.status.current()
    }

    pub fn watch_status(&self) -> watch::Receiver<Arc<TrustStatus>> {
        self.inner.status.subscribe()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TrustEvent> {
        self.inner.events.subscribe()
    }

    /// Build the typed HTTP adapter for this Trust owner.
    ///
    /// The serving layer mounts it at [`http::paths::PREFIX`] and supplies the
    /// machine-owner authentication policy; handlers never open another core.
    pub fn routes(&self) -> axum::Router {
        http::routes(Arc::new(self.clone()))
    }

    /// Operator command: install one root. Reusing a name for a different
    /// certificate remains an explicit conflict.
    pub async fn install(&self, request: InstallRoot) -> Result<TrustMutation, TrustError> {
        self.run(move |inner, state| inner.install_locked(state, request, false))
            .await
    }

    /// Desired-state command used by composition. It may replace only a root
    /// already owned under the same `name` and `source`; operator-owned roots are
    /// never displaced.
    pub async fn ensure_installed(
        &self,
        request: InstallRoot,
    ) -> Result<TrustMutation, TrustError> {
        self.run(move |inner, state| inner.install_locked(state, request, true))
            .await
    }

    /// Operator command: remove a Koi-tracked root by name.
    pub async fn remove(&self, name: &str) -> Result<TrustMutation, TrustError> {
        let name = name.to_string();
        self.run(move |inner, state| inner.remove_locked(state, &name, None, false))
            .await
    }

    /// Desired-state removal. A different source under the same name is an
    /// untracked/operator root from this automation's perspective and is left
    /// untouched. Absence is a successful no-op.
    pub async fn ensure_removed(
        &self,
        name: &str,
        source: &str,
    ) -> Result<TrustMutation, TrustError> {
        let name = name.to_string();
        let source = source.to_string();
        self.run(move |inner, state| inner.remove_locked(state, &name, Some(&source), true))
            .await
    }

    /// Query one concrete certificate through the real platform adapter.
    pub async fn inspect(&self, certificate_pem: &str) -> Result<TrustPresence, TrustError> {
        let pem = certificate_pem.to_string();
        self.inner
            .worker
            .submit(move |domain| {
                let certificate = parse_certificate(&pem)?;
                Ok(match domain.store.is_present(&certificate) {
                    Ok(true) => TrustPresence::Present,
                    Ok(false) => TrustPresence::Missing,
                    Err(error) => TrustPresence::Unavailable {
                        reason: error.to_string(),
                    },
                })
            })
            .await
    }

    /// Retry pending work and refresh cross-process/platform truth.
    pub async fn reconcile(&self) -> Result<TrustRecovery, TrustError> {
        self.run(|inner, state| inner.reconcile_locked(state)).await
    }

    /// Permanently close command admission, drain every accepted Trust
    /// transition, and join the platform worker.
    ///
    /// The terminal transaction is idempotent. If a caller is cancelled after
    /// shutdown admission, a later caller waits for and acknowledges that same
    /// worker completion; no second terminal sequence is created.
    pub async fn shutdown(&self) -> Result<(), TrustError> {
        self.inner.worker.shutdown().await
    }

    async fn run<R: Send + 'static>(
        &self,
        action: impl FnOnce(&TrustDomain, &mut TrustState) -> Result<R, TrustError> + Send + 'static,
    ) -> Result<R, TrustError> {
        self.inner
            .worker
            .submit(move |domain| {
                domain
                    .repository
                    .with_locked_state(|state| action(domain, state))
            })
            .await
    }

    #[cfg(test)]
    async fn with_test_store(
        data_dir: PathBuf,
        store: Arc<dyn TrustStore>,
    ) -> Result<Self, TrustError> {
        Self::open_with_store(data_dir, store).await
    }

    #[cfg(test)]
    async fn inject_next_final_commit_uncertainty(&self) -> Result<(), TrustError> {
        self.inner
            .worker
            .submit(|domain| {
                domain.repository.inject_next_final_commit_uncertainty();
                Ok(())
            })
            .await
    }

    #[cfg(test)]
    async fn inject_next_final_commit_failure(&self) -> Result<(), TrustError> {
        self.inner
            .worker
            .submit(|domain| {
                domain.repository.inject_next_final_commit_failure();
                Ok(())
            })
            .await
    }
}

impl TrustDomain {
    fn install_locked(
        &self,
        state: &mut TrustState,
        request: InstallRoot,
        desired_state: bool,
    ) -> Result<TrustMutation, TrustError> {
        self.recover_before_command(state)?;
        let certificate = parse_certificate(&request.certificate_pem)?;
        let fingerprint = certificate.fingerprint_hex();
        let same_name = state
            .roots
            .iter()
            .find(|entry| entry.name == request.name)
            .cloned();

        if let Some(existing) = &same_name {
            if existing.fingerprint != fingerprint && !desired_state {
                return Err(TrustError::Conflict(format!(
                    "a different CA is already tracked as \"{}\" (sha256: {}); remove it before reusing that name",
                    request.name, existing.fingerprint
                )));
            }
            if desired_state && existing.source != request.source {
                return Err(TrustError::Conflict(format!(
                    "\"{}\" is owned by source \"{}\", not automation source \"{}\"",
                    request.name, existing.source, request.source
                )));
            }
        }
        if let Some(existing) = state
            .roots
            .iter()
            .find(|entry| entry.fingerprint == fingerprint && entry.name != request.name)
        {
            return Err(TrustError::Conflict(format!(
                "sha256 {fingerprint} is already tracked as \"{}\"; one platform certificate cannot have two independent Koi owners",
                existing.name
            )));
        }

        if same_name
            .as_ref()
            .is_some_and(|entry| entry.fingerprint == fingerprint)
            && self.store.is_present(&certificate)?
        {
            self.publish_state(state, None);
            return Ok(TrustMutation {
                name: request.name,
                fingerprint: Some(fingerprint),
                changed: false,
                warning: same_name.and_then(|entry| entry.warning),
            });
        }

        let installed_at = same_name
            .as_ref()
            .filter(|entry| entry.fingerprint == fingerprint)
            .map_or_else(
                || chrono::Utc::now().to_rfc3339(),
                |entry| entry.installed_at.clone(),
            );
        let desired = TrustEntry {
            name: request.name.clone(),
            installed_at,
            fingerprint: fingerprint.clone(),
            source: request.source,
            certificate_pem: Some(certificate.pem().to_string()),
            warning: None,
        };
        let transition = if desired_state
            && same_name.as_ref().is_some_and(|entry| {
                entry.fingerprint != fingerprint && entry.source == desired.source
            }) {
            TrustTransition::Ensure {
                desired,
                displaced: same_name,
            }
        } else {
            TrustTransition::Install { entry: desired }
        };
        let warning = self.apply_transition(state, transition.clone(), false)?;
        let (operation, entry) = transition_primary(&transition);
        debug_assert!(matches!(
            operation,
            TrustOperation::Install | TrustOperation::Ensure
        ));
        self.publish_state(state, None);
        let _ = self.events.send(TrustEvent::RootInstalled {
            name: entry.name.clone(),
            fingerprint: entry.fingerprint.clone(),
        });
        Ok(TrustMutation {
            name: entry.name.clone(),
            fingerprint: Some(entry.fingerprint.clone()),
            changed: true,
            warning,
        })
    }

    fn remove_locked(
        &self,
        state: &mut TrustState,
        name: &str,
        required_source: Option<&str>,
        absent_is_ok: bool,
    ) -> Result<TrustMutation, TrustError> {
        self.recover_before_command(state)?;
        let Some(mut entry) = state.roots.iter().find(|entry| entry.name == name).cloned() else {
            self.publish_state(state, None);
            if absent_is_ok {
                return Ok(TrustMutation {
                    name: name.to_string(),
                    fingerprint: None,
                    changed: false,
                    warning: None,
                });
            }
            return Err(TrustError::NotFound(name.to_string()));
        };
        if required_source.is_some_and(|source| source != entry.source) {
            self.publish_state(state, None);
            return Ok(TrustMutation {
                name: name.to_string(),
                fingerprint: None,
                changed: false,
                warning: None,
            });
        }
        hydrate_entry(&mut entry)?;
        let transition = TrustTransition::Uninstall {
            entry: entry.clone(),
        };
        self.apply_transition(state, transition, false)?;
        self.publish_state(state, None);
        let _ = self.events.send(TrustEvent::RootRemoved {
            name: entry.name.clone(),
            fingerprint: entry.fingerprint.clone(),
        });
        Ok(TrustMutation {
            name: entry.name,
            fingerprint: Some(entry.fingerprint),
            changed: true,
            warning: None,
        })
    }

    fn reconcile_locked(&self, state: &mut TrustState) -> Result<TrustRecovery, TrustError> {
        let previous = self.status.current();
        let recovery = match state.pending.clone() {
            Some(transition) => {
                if let Err(error) = self.apply_transition(state, transition.clone(), true) {
                    self.publish_state(state, Some(error.to_string()));
                    return Err(error);
                }
                let (operation, entry) = transition_primary(&transition);
                let recovery = TrustRecovery::Recovered {
                    operation,
                    name: entry.name.clone(),
                    fingerprint: entry.fingerprint.clone(),
                };
                self.publish_state(state, None);
                let _ = self.events.send(TrustEvent::TransitionRecovered {
                    operation,
                    name: entry.name.clone(),
                    fingerprint: entry.fingerprint.clone(),
                });
                recovery
            }
            None => {
                self.publish_state(state, None);
                TrustRecovery::Clean
            }
        };
        self.emit_presence_changes(previous.as_ref(), self.status.current().as_ref());
        Ok(recovery)
    }

    fn recover_before_command(&self, state: &mut TrustState) -> Result<(), TrustError> {
        let Some(transition) = state.pending.clone() else {
            return Ok(());
        };
        if let Err(error) = self.apply_transition(state, transition.clone(), true) {
            self.publish_state(state, Some(error.to_string()));
            return Err(error);
        }
        let (operation, entry) = transition_primary(&transition);
        self.publish_state(state, None);
        let _ = self.events.send(TrustEvent::TransitionRecovered {
            operation,
            name: entry.name.clone(),
            fingerprint: entry.fingerprint.clone(),
        });
        Ok(())
    }

    fn apply_transition(
        &self,
        state: &mut TrustState,
        transition: TrustTransition,
        rearm: bool,
    ) -> Result<Option<String>, TrustError> {
        if !rearm {
            state.pending = Some(transition.clone());
        }
        if let Err(error) = self.repository.arm(state) {
            if let Ok(durable) = self.repository.load() {
                *state = durable;
            }
            self.publish_state(state, Some(error.to_string()));
            return Err(error);
        }

        // The durable intent is now accepted Trust truth. Publish it before
        // entering the potentially slow platform effect so every observer sees
        // the same pending transition that crash recovery would replay.
        self.publish_state(state, None);

        let warning = match self.reconcile_platform(&transition) {
            Ok(warning) => warning,
            Err(error) => {
                self.publish_state(state, Some(error.to_string()));
                return Err(error);
            }
        };
        let replay = transition_with_warning(transition, warning.clone());
        let mut completed = state.clone();
        complete_state(&mut completed, &replay);
        match self.repository.commit(&completed) {
            Ok(AtomicCommit::Durable) => {
                *state = completed;
            }
            Ok(AtomicCommit::DurabilityUncertain(error)) => {
                // The completed file and platform effect are visible, so keep
                // that generation in the live model. Its crash durability is
                // not proven, however: attach the exact idempotent transition
                // again and re-arm it. The status therefore reports current
                // roots plus pending/error truth rather than either reverting
                // behind the visible state or publishing unqualified success.
                let mut recoverable = completed;
                recoverable.pending = Some(replay);
                let mut reason = format!(
                    "completed trust transition is visible but crash durability is unconfirmed ({error})"
                );
                if let Err(rearm_error) = self.repository.arm(&recoverable) {
                    reason.push_str(&format!(
                        "; re-arming the accepted transition was also not confirmed ({rearm_error})"
                    ));
                }
                *state = recoverable;
                let error = TrustError::DurabilityUncertain(reason);
                self.publish_state(state, Some(error.to_string()));
                return Err(error);
            }
            Err(error) => {
                // An ordinary error occurred before replacement, so the prior
                // pending generation remains the visible state. Preserve the
                // platform adapter's qualification in that replay intent when
                // possible, but never accept the uncommitted completed model.
                let mut recoverable = state.clone();
                recoverable.pending = Some(replay);
                let rearm_error = self.repository.arm(&recoverable).err();
                if rearm_error.is_none() {
                    *state = recoverable;
                } else if let Ok(durable) = self.repository.load() {
                    *state = durable;
                }
                let mut reason = error.to_string();
                if let Some(rearm_error) = rearm_error {
                    reason.push_str(&format!(
                        "; preserving the qualified replay intent also failed ({rearm_error})"
                    ));
                }
                self.publish_state(state, Some(reason));
                return Err(error);
            }
        }
        Ok(warning)
    }

    fn reconcile_platform(
        &self,
        transition: &TrustTransition,
    ) -> Result<Option<String>, TrustError> {
        let warning = match transition {
            TrustTransition::Install { entry } => self.ensure_entry_present(entry)?,
            TrustTransition::Uninstall { entry } => {
                self.ensure_entry_absent(entry)?;
                None
            }
            TrustTransition::Ensure { desired, displaced } => {
                // Availability-first replacement: the new anchor is confirmed
                // present before the prior managed generation is removed.
                let warning = self.ensure_entry_present(desired)?;
                if let Some(displaced) = displaced {
                    if displaced.fingerprint != desired.fingerprint {
                        self.ensure_entry_absent(displaced)?;
                    }
                }
                warning
            }
        };
        Ok(warning)
    }

    fn ensure_entry_present(&self, entry: &TrustEntry) -> Result<Option<String>, TrustError> {
        let certificate = entry_certificate(entry)?;
        let warning = if self.store.is_present(&certificate)? {
            entry.warning.clone()
        } else {
            match self.store.install(&certificate, &entry.name)? {
                InstallOutcome::Present => None,
                InstallOutcome::PresentButTrustUnconfirmed { reason } => Some(reason),
            }
        };
        if !self.store.is_present(&certificate)? {
            return Err(TrustError::Platform(format!(
                "install for {} completed without a verifiable store entry; the transition remains pending",
                entry.name
            )));
        }
        Ok(warning)
    }

    fn ensure_entry_absent(&self, entry: &TrustEntry) -> Result<(), TrustError> {
        let certificate = entry_certificate(entry)?;
        if self.store.is_present(&certificate)? {
            self.store.uninstall(&certificate)?;
        }
        if self.store.is_present(&certificate)? {
            return Err(TrustError::Platform(format!(
                "removal for {} completed but the store entry remains; the transition remains pending",
                entry.name
            )));
        }
        Ok(())
    }

    fn publish_state(&self, state: &TrustState, last_error: Option<String>) {
        let current = self.status.current();
        let next = status_from_state(state, self.store.as_ref(), last_error, current.revision);
        self.status.update(|current| {
            if same_status_generation(current, &next) {
                None
            } else {
                let mut next = next;
                next.revision = current.revision.saturating_add(1);
                Some(next)
            }
        });
    }

    fn emit_presence_changes(&self, previous: &TrustStatus, next: &TrustStatus) {
        for root in &next.roots {
            let changed = previous
                .roots
                .iter()
                .find(|prior| prior.fingerprint == root.fingerprint)
                .is_some_and(|prior| prior.presence != root.presence);
            if changed {
                let _ = self.events.send(TrustEvent::PresenceChanged {
                    name: root.name.clone(),
                    fingerprint: root.fingerprint.clone(),
                    presence: root.presence.clone(),
                });
            }
        }
    }
}

fn status_from_state(
    state: &TrustState,
    store: &dyn TrustStore,
    last_error: Option<String>,
    revision: u64,
) -> TrustStatus {
    let mut roots = state
        .roots
        .iter()
        .map(|entry| {
            let presence = entry_certificate_for_status(entry)
                .and_then(|certificate| store.is_present(&certificate))
                .map_or_else(
                    |error| TrustPresence::Unavailable {
                        reason: error.to_string(),
                    },
                    |present| {
                        if present {
                            TrustPresence::Present
                        } else {
                            TrustPresence::Missing
                        }
                    },
                );
            TrustRootStatus {
                name: entry.name.clone(),
                installed_at: entry.installed_at.clone(),
                fingerprint: entry.fingerprint.clone(),
                source: entry.source.clone(),
                presence,
                warning: entry.warning.clone(),
            }
        })
        .collect::<Vec<_>>();
    roots.sort_by(|left, right| left.name.cmp(&right.name));
    TrustStatus {
        revision,
        roots,
        pending: state.pending.as_ref().map(|transition| {
            let (operation, entry) = transition_primary(transition);
            TrustPendingStatus {
                operation,
                name: entry.name.clone(),
                fingerprint: entry.fingerprint.clone(),
            }
        }),
        last_error,
    }
}

fn same_status_generation(left: &TrustStatus, right: &TrustStatus) -> bool {
    left.roots == right.roots
        && left.pending == right.pending
        && left.last_error == right.last_error
}

fn parse_certificate(pem: &str) -> Result<os_truststore::Cert, TrustError> {
    os_truststore::Cert::from_pem(pem)
        .map_err(|error| TrustError::InvalidCertificate(error.to_string()))
}

fn hydrate_entry(entry: &mut TrustEntry) -> Result<(), TrustError> {
    let pem = match entry.certificate_pem.as_deref() {
        Some(pem) => pem.to_string(),
        None => std::fs::read_to_string(Path::new(&entry.source)).map_err(TrustError::Io)?,
    };
    let certificate = parse_certificate(&pem)?;
    let fingerprint = certificate.fingerprint_hex();
    if fingerprint != entry.fingerprint {
        return Err(TrustError::Conflict(format!(
            "refusing to remove {}: certificate material is sha256 {fingerprint}, but Koi tracked {}",
            entry.name, entry.fingerprint
        )));
    }
    entry.certificate_pem = Some(certificate.pem().to_string());
    Ok(())
}

fn entry_certificate(entry: &TrustEntry) -> Result<os_truststore::Cert, TrustError> {
    let pem = entry.certificate_pem.as_deref().ok_or_else(|| {
        TrustError::InvalidCertificate(format!(
            "pending transition for {} has no replay certificate material",
            entry.name
        ))
    })?;
    let certificate = parse_certificate(pem)?;
    let actual = certificate.fingerprint_hex();
    if actual != entry.fingerprint {
        return Err(TrustError::Conflict(format!(
            "pending transition for {} names sha256 {}, but its certificate is {actual}",
            entry.name, entry.fingerprint
        )));
    }
    Ok(certificate)
}

fn entry_certificate_for_status(entry: &TrustEntry) -> Result<os_truststore::Cert, TrustError> {
    if entry.certificate_pem.is_some() {
        return entry_certificate(entry);
    }
    let pem = std::fs::read_to_string(Path::new(&entry.source)).map_err(TrustError::Io)?;
    let certificate = parse_certificate(&pem)?;
    let actual = certificate.fingerprint_hex();
    if actual != entry.fingerprint {
        return Err(TrustError::Conflict(format!(
            "tracked root {} names sha256 {}, but its legacy source is {actual}",
            entry.name, entry.fingerprint
        )));
    }
    Ok(certificate)
}

fn transition_primary(transition: &TrustTransition) -> (TrustOperation, &TrustEntry) {
    match transition {
        TrustTransition::Install { entry } => (TrustOperation::Install, entry),
        TrustTransition::Uninstall { entry } => (TrustOperation::Uninstall, entry),
        TrustTransition::Ensure { desired, .. } => (TrustOperation::Ensure, desired),
    }
}

fn transition_with_warning(
    mut transition: TrustTransition,
    warning: Option<String>,
) -> TrustTransition {
    match &mut transition {
        TrustTransition::Install { entry } => entry.warning = warning,
        TrustTransition::Ensure { desired, .. } => desired.warning = warning,
        TrustTransition::Uninstall { .. } => debug_assert!(warning.is_none()),
    }
    transition
}

fn complete_state(state: &mut TrustState, transition: &TrustTransition) {
    match transition {
        TrustTransition::Install { entry } | TrustTransition::Ensure { desired: entry, .. } => {
            let entry = entry.clone();
            state
                .roots
                .retain(|root| root.name != entry.name && root.fingerprint != entry.fingerprint);
            state.roots.push(entry);
        }
        TrustTransition::Uninstall { entry } => {
            state
                .roots
                .retain(|root| root.fingerprint != entry.fingerprint);
        }
    }
    state.pending = None;
}

/// Deterministic adapter available only to tests of composition consumers.
#[cfg(any(test, feature = "test-util"))]
pub mod test_support {
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use super::{InstallOutcome, TrustCore, TrustError, TrustStore};

    #[derive(Default)]
    struct MemoryStore {
        present: Mutex<HashSet<String>>,
        fail_next_install: Mutex<bool>,
    }

    #[derive(Clone)]
    pub struct MemoryStoreControl {
        store: Arc<MemoryStore>,
    }

    impl MemoryStoreControl {
        pub fn fail_next_install(&self) {
            *self
                .store
                .fail_next_install
                .lock()
                .expect("memory store lock") = true;
        }
    }

    impl TrustStore for MemoryStore {
        fn is_present(&self, certificate: &os_truststore::Cert) -> Result<bool, TrustError> {
            Ok(self
                .present
                .lock()
                .expect("memory store lock")
                .contains(&certificate.fingerprint_hex()))
        }

        fn install(
            &self,
            certificate: &os_truststore::Cert,
            _label: &str,
        ) -> Result<InstallOutcome, TrustError> {
            if std::mem::take(&mut *self.fail_next_install.lock().expect("memory store lock")) {
                return Err(TrustError::Platform("injected install failure".into()));
            }
            self.present
                .lock()
                .expect("memory store lock")
                .insert(certificate.fingerprint_hex());
            Ok(InstallOutcome::Present)
        }

        fn uninstall(&self, certificate: &os_truststore::Cert) -> Result<(), TrustError> {
            self.present
                .lock()
                .expect("memory store lock")
                .remove(&certificate.fingerprint_hex());
            Ok(())
        }
    }

    impl TrustCore {
        pub async fn open_memory(
            data_dir: PathBuf,
        ) -> Result<(Self, MemoryStoreControl), TrustError> {
            let store = Arc::new(MemoryStore::default());
            let control = MemoryStoreControl {
                store: Arc::clone(&store),
            };
            let core = Self::open_with_store(data_dir, store).await?;
            Ok((core, control))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    use super::*;

    #[test]
    fn trust_status_wire_round_trips_and_ignores_additive_fields() {
        let expected = TrustStatus {
            revision: 9,
            roots: vec![TrustRootStatus {
                name: "local root".to_string(),
                installed_at: "2026-09-03T12:00:00Z".to_string(),
                fingerprint: "0123456789abcdef".to_string(),
                source: "certmesh".to_string(),
                presence: TrustPresence::Unavailable {
                    reason: "platform observation unavailable".to_string(),
                },
                warning: Some("membership is known; application trust is not".to_string()),
            }],
            pending: Some(TrustPendingStatus {
                operation: TrustOperation::Ensure,
                name: "local root".to_string(),
                fingerprint: "0123456789abcdef".to_string(),
            }),
            last_error: Some("observation deferred".to_string()),
        };

        let encoded = serde_json::to_string(&expected).expect("serialize Trust status");
        assert_eq!(
            serde_json::from_str::<TrustStatus>(&encoded).expect("round-trip Trust status"),
            expected
        );

        let mut additive = serde_json::to_value(&expected).expect("encode Trust status value");
        additive
            .as_object_mut()
            .expect("Trust status is an object")
            .insert(
                "future_domain_fact".to_string(),
                serde_json::json!({"available": true}),
            );
        additive["roots"][0]
            .as_object_mut()
            .expect("Trust root status is an object")
            .insert("future_root_fact".to_string(), serde_json::json!(42));
        additive["pending"]
            .as_object_mut()
            .expect("Trust pending status is an object")
            .insert(
                "future_command_fact".to_string(),
                serde_json::json!("queued"),
            );
        assert_eq!(
            serde_json::from_value::<TrustStatus>(additive)
                .expect("ignore additive Trust status fields"),
            expected
        );
    }

    #[derive(Default)]
    struct FakeStore {
        present: StdMutex<HashSet<String>>,
        calls: StdMutex<Vec<String>>,
        fail_install: StdMutex<bool>,
        fail_uninstall: StdMutex<bool>,
        next_install_warning: StdMutex<Option<String>>,
    }

    impl TrustStore for FakeStore {
        fn is_present(&self, certificate: &os_truststore::Cert) -> Result<bool, TrustError> {
            Ok(self
                .present
                .lock()
                .unwrap()
                .contains(&certificate.fingerprint_hex()))
        }

        fn install(
            &self,
            certificate: &os_truststore::Cert,
            _label: &str,
        ) -> Result<InstallOutcome, TrustError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("install:{}", certificate.fingerprint_hex()));
            if std::mem::take(&mut *self.fail_install.lock().unwrap()) {
                return Err(TrustError::Platform("injected install failure".into()));
            }
            self.present
                .lock()
                .unwrap()
                .insert(certificate.fingerprint_hex());
            Ok(match self.next_install_warning.lock().unwrap().take() {
                Some(reason) => InstallOutcome::PresentButTrustUnconfirmed { reason },
                None => InstallOutcome::Present,
            })
        }

        fn uninstall(&self, certificate: &os_truststore::Cert) -> Result<(), TrustError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("remove:{}", certificate.fingerprint_hex()));
            if std::mem::take(&mut *self.fail_uninstall.lock().unwrap()) {
                return Err(TrustError::Platform("injected uninstall failure".into()));
            }
            self.present
                .lock()
                .unwrap()
                .remove(&certificate.fingerprint_hex());
            Ok(())
        }
    }

    struct BlockingInstallStore {
        present: StdMutex<HashSet<String>>,
        entered: tokio::sync::Notify,
        block_next_effect: AtomicBool,
        release: AtomicBool,
        effect_count: AtomicUsize,
        active_effects: AtomicUsize,
        max_active_effects: AtomicUsize,
        fail_next_effect: AtomicBool,
        panic_next_effect: AtomicBool,
    }

    impl Default for BlockingInstallStore {
        fn default() -> Self {
            Self {
                present: StdMutex::default(),
                entered: tokio::sync::Notify::new(),
                block_next_effect: AtomicBool::new(false),
                release: AtomicBool::new(false),
                effect_count: AtomicUsize::new(0),
                active_effects: AtomicUsize::new(0),
                max_active_effects: AtomicUsize::new(0),
                fail_next_effect: AtomicBool::new(false),
                panic_next_effect: AtomicBool::new(false),
            }
        }
    }

    impl BlockingInstallStore {
        fn arm_effect(&self) {
            self.release.store(false, Ordering::Release);
            self.block_next_effect.store(true, Ordering::Release);
        }

        fn release_effect(&self) {
            self.release.store(true, Ordering::Release);
        }

        fn begin_effect(&self) {
            let active = self.active_effects.fetch_add(1, Ordering::AcqRel) + 1;
            self.max_active_effects.fetch_max(active, Ordering::AcqRel);
            self.effect_count.fetch_add(1, Ordering::AcqRel);
            if self.block_next_effect.swap(false, Ordering::AcqRel) {
                self.entered.notify_one();
                while !self.release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            }
        }

        fn end_effect(&self) {
            self.active_effects.fetch_sub(1, Ordering::AcqRel);
        }
    }

    impl TrustStore for BlockingInstallStore {
        fn is_present(&self, certificate: &os_truststore::Cert) -> Result<bool, TrustError> {
            Ok(self
                .present
                .lock()
                .unwrap()
                .contains(&certificate.fingerprint_hex()))
        }

        fn install(
            &self,
            certificate: &os_truststore::Cert,
            _label: &str,
        ) -> Result<InstallOutcome, TrustError> {
            self.begin_effect();
            if self.panic_next_effect.swap(false, Ordering::AcqRel) {
                self.end_effect();
                panic!("injected platform panic");
            }
            if self.fail_next_effect.swap(false, Ordering::AcqRel) {
                self.end_effect();
                return Err(TrustError::Platform("injected effect failure".into()));
            }
            self.present
                .lock()
                .unwrap()
                .insert(certificate.fingerprint_hex());
            self.end_effect();
            Ok(InstallOutcome::Present)
        }

        fn uninstall(&self, certificate: &os_truststore::Cert) -> Result<(), TrustError> {
            self.begin_effect();
            self.present
                .lock()
                .unwrap()
                .remove(&certificate.fingerprint_hex());
            self.end_effect();
            Ok(())
        }
    }

    #[derive(Default)]
    struct PresenceProbe {
        entered: tokio::sync::Notify,
        block_next: AtomicBool,
        release: AtomicBool,
        completed: AtomicUsize,
    }

    impl PresenceProbe {
        fn arm(&self) {
            self.release.store(false, Ordering::Release);
            self.block_next.store(true, Ordering::Release);
        }

        fn release(&self) {
            self.release.store(true, Ordering::Release);
        }
    }

    #[derive(Default)]
    struct BlockingPresenceStore {
        present: StdMutex<HashSet<String>>,
        installs: AtomicUsize,
        probe: Arc<PresenceProbe>,
    }

    impl TrustStore for BlockingPresenceStore {
        fn is_present(&self, certificate: &os_truststore::Cert) -> Result<bool, TrustError> {
            if self.probe.block_next.swap(false, Ordering::AcqRel) {
                self.probe.entered.notify_one();
                while !self.probe.release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            }
            self.probe.completed.fetch_add(1, Ordering::AcqRel);
            Ok(self
                .present
                .lock()
                .unwrap()
                .contains(&certificate.fingerprint_hex()))
        }

        fn install(
            &self,
            certificate: &os_truststore::Cert,
            _label: &str,
        ) -> Result<InstallOutcome, TrustError> {
            self.installs.fetch_add(1, Ordering::AcqRel);
            self.present
                .lock()
                .unwrap()
                .insert(certificate.fingerprint_hex());
            Ok(InstallOutcome::Present)
        }

        fn uninstall(&self, certificate: &os_truststore::Cert) -> Result<(), TrustError> {
            self.present
                .lock()
                .unwrap()
                .remove(&certificate.fingerprint_hex());
            Ok(())
        }
    }

    fn test_dir(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "koi-trust-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn certificate(name: &str) -> String {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    fn request(name: &str, source: &str, pem: String) -> InstallRoot {
        InstallRoot {
            name: name.into(),
            source: source.into(),
            certificate_pem: pem,
        }
    }

    #[tokio::test]
    async fn opening_an_absent_domain_is_observation_only() {
        let dir = test_dir("observation-only-open");
        let _ = std::fs::remove_dir_all(&dir);

        let core = TrustCore::with_test_store(dir.clone(), Arc::new(FakeStore::default()))
            .await
            .unwrap();

        assert!(!dir.exists(), "a status read must not create Trust storage");
        assert_eq!(core.status().as_ref(), &TrustStatus::default());
        core.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn command_ack_is_fenced_by_status_then_event() {
        let dir = test_dir("causal");
        let store = Arc::new(FakeStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store)
            .await
            .unwrap();
        let mut status = core.watch_status();
        let mut events = core.subscribe();
        let result = core
            .install(request("root", "test", certificate("root")))
            .await
            .unwrap();
        assert!(result.changed);
        let event = events
            .try_recv()
            .expect("event published before acknowledgement");
        assert!(matches!(event, TrustEvent::RootInstalled { .. }));
        assert!(status.has_changed().unwrap());
        status.borrow_and_update();
        assert_eq!(status.borrow().roots.len(), 1);
        assert!(matches!(
            status.borrow().roots[0].presence,
            TrustPresence::Present
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_command_cannot_split_platform_disk_status_and_event() {
        let dir = test_dir("cancelled-command");
        let store = Arc::new(BlockingInstallStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut events = core.subscribe();
        store.arm_effect();
        let installing_core = core.clone();
        let installing = tokio::spawn(async move {
            installing_core
                .install(request("root", "test", certificate("root")))
                .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), store.entered.notified())
            .await
            .expect("platform install started");
        let in_flight = core.status();
        assert!(in_flight.roots.is_empty());
        assert!(in_flight.pending.is_some());
        assert!(Repository::new(dir.clone())
            .load()
            .unwrap()
            .pending
            .is_some());
        assert!(events.try_recv().is_err());
        installing.abort();
        store.release_effect();
        let _ = installing.await;

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("completed transition event")
            .expect("event channel");
        assert!(matches!(event, TrustEvent::RootInstalled { .. }));
        let status = core.status();
        assert_eq!(status.roots.len(), 1);
        assert!(status.pending.is_none());
        assert!(status.last_error.is_none());
        assert!(matches!(status.roots[0].presence, TrustPresence::Present));

        let reopened = TrustCore::with_test_store(dir.clone(), store)
            .await
            .expect("durable transition reopens");
        assert_eq!(reopened.status().roots, status.roots);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn last_owner_drop_drains_an_accepted_transition_before_joining() {
        let dir = test_dir("drop-drains");
        let store = Arc::new(BlockingInstallStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut status = core.watch_status();
        let mut events = core.subscribe();
        store.arm_effect();

        // The task owns the last facade. Aborting it drops that owner, whose
        // worker fence must wait for the already admitted platform effect.
        let mut installing = tokio::spawn(async move {
            core.install(request("root", "test", certificate("root")))
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), store.entered.notified())
            .await
            .expect("platform install started");
        installing.abort();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut installing)
                .await
                .is_err(),
            "last-owner drop must not detach an admitted effect"
        );

        store.release_effect();
        let cancelled = tokio::time::timeout(std::time::Duration::from_secs(1), installing)
            .await
            .expect("worker joined after its effect completed")
            .expect_err("aborted command task");
        assert!(cancelled.is_cancelled());
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("completion event")
            .expect("event channel");
        assert!(matches!(event, TrustEvent::RootInstalled { .. }));
        status.changed().await.expect("completion status");
        let completed = status.borrow_and_update().clone();
        assert_eq!(completed.roots.len(), 1);
        assert!(completed.pending.is_none());

        let reopened = TrustCore::with_test_store(dir.clone(), store)
            .await
            .expect("completed transition is durable");
        assert_eq!(reopened.status().roots, completed.roots);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_inspection_stays_owned_and_serialized_before_mutation() {
        let dir = test_dir("cancelled-inspect");
        let store = Arc::new(BlockingPresenceStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let inspected_pem = certificate("inspected");
        store.probe.arm();
        let inspecting_core = core.clone();
        let inspecting = tokio::spawn(async move { inspecting_core.inspect(&inspected_pem).await });
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            store.probe.entered.notified(),
        )
        .await
        .expect("platform inspection started");
        inspecting.abort();

        let mut installing = {
            let core = core.clone();
            tokio::spawn(async move {
                core.install(request("root", "test", certificate("root")))
                    .await
            })
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut installing)
                .await
                .is_err(),
            "a mutation cannot pass an abandoned inspection in the Trust queue"
        );
        assert_eq!(store.installs.load(Ordering::Acquire), 0);

        store.probe.release();
        installing
            .await
            .expect("install task")
            .expect("serialized install");
        let cancelled = inspecting.await.expect_err("inspection task was aborted");
        assert!(cancelled.is_cancelled());
        assert!(store.probe.completed.load(Ordering::Acquire) >= 1);
        assert_eq!(store.installs.load(Ordering::Acquire), 1);
        assert_eq!(core.status().roots.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_open_cannot_orphan_its_initial_platform_inspection() {
        let dir = test_dir("cancelled-open");
        let pem = certificate("root");
        let seeded = TrustCore::with_test_store(dir.clone(), Arc::new(FakeStore::default()))
            .await
            .unwrap();
        seeded
            .install(request("root", "test", pem.clone()))
            .await
            .unwrap();
        drop(seeded);

        let fingerprint = parse_certificate(&pem).unwrap().fingerprint_hex();
        let store = Arc::new(BlockingPresenceStore::default());
        store.present.lock().unwrap().insert(fingerprint);
        let probe = Arc::clone(&store.probe);
        let weak_store = Arc::downgrade(&store);
        probe.arm();
        let mut opening = tokio::spawn(TrustCore::with_test_store(dir.clone(), store));
        tokio::time::timeout(std::time::Duration::from_secs(1), probe.entered.notified())
            .await
            .expect("initial platform inspection started");
        opening.abort();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut opening)
                .await
                .is_err(),
            "construction cannot detach its initializing worker"
        );

        probe.release();
        match tokio::time::timeout(std::time::Duration::from_secs(1), opening)
            .await
            .expect("initializing worker settled")
        {
            Ok(Ok(core)) => drop(core),
            Ok(Err(error)) => panic!("initialization failed after release: {error}"),
            Err(cancelled) => assert!(cancelled.is_cancelled()),
        }
        assert!(
            weak_store.upgrade().is_none(),
            "worker retained after owner exit"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_remove_and_concurrent_install_remain_one_serial_history() {
        let dir = test_dir("serialized-history");
        let store = Arc::new(BlockingInstallStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        core.install(request("old", "test", certificate("old")))
            .await
            .unwrap();
        let effects_before = store.effect_count.load(Ordering::Acquire);
        let mut events = core.subscribe();
        store.arm_effect();

        let removing_core = core.clone();
        let removing = tokio::spawn(async move { removing_core.remove("old").await });
        tokio::time::timeout(std::time::Duration::from_secs(1), store.entered.notified())
            .await
            .expect("remove effect started");
        removing.abort();
        let mut installing = {
            let core = core.clone();
            tokio::spawn(async move {
                core.install(request("new", "test", certificate("new")))
                    .await
            })
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut installing)
                .await
                .is_err(),
            "install escaped while remove still owned the worker"
        );
        assert_eq!(
            store.effect_count.load(Ordering::Acquire),
            effects_before + 1,
            "only the in-flight remove reached the platform"
        );

        store.release_effect();
        installing
            .await
            .expect("install task")
            .expect("install after remove");
        assert!(removing
            .await
            .expect_err("remove caller was aborted")
            .is_cancelled());
        assert_eq!(store.max_active_effects.load(Ordering::Acquire), 1);
        assert!(matches!(
            events.recv().await.unwrap(),
            TrustEvent::RootRemoved { ref name, .. } if name == "old"
        ));
        assert!(matches!(
            events.recv().await.unwrap(),
            TrustEvent::RootInstalled { ref name, .. } if name == "new"
        ));
        let status = core.status();
        assert_eq!(status.roots.len(), 1);
        assert_eq!(status.roots[0].name, "new");
        assert!(status.pending.is_none());

        drop(core);
        let reopened = TrustCore::with_test_store(dir.clone(), store)
            .await
            .expect("serialized history is durable");
        assert_eq!(reopened.status().roots, status.roots);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_failed_effect_publishes_only_durable_pending_truth() {
        let dir = test_dir("cancelled-fault");
        let store = Arc::new(BlockingInstallStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut status = core.watch_status();
        let mut events = core.subscribe();
        store.fail_next_effect.store(true, Ordering::Release);
        store.arm_effect();

        let installing_core = core.clone();
        let installing = tokio::spawn(async move {
            installing_core
                .install(request("root", "test", certificate("root")))
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), store.entered.notified())
            .await
            .expect("platform effect started");
        installing.abort();
        store.release_effect();
        assert!(installing.await.unwrap_err().is_cancelled());

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                status.changed().await.expect("status feed");
                status.borrow_and_update();
                if status.borrow().last_error.is_some() {
                    break;
                }
            }
        })
        .await
        .expect("failed transition status");
        let failed = status.borrow_and_update().clone();
        assert!(failed.roots.is_empty());
        assert!(failed.pending.is_some());
        assert!(failed.last_error.is_some());
        assert!(events.try_recv().is_err(), "failure is not a success event");
        let durable = Repository::new(dir.clone()).load().unwrap();
        assert!(durable.roots.is_empty());
        assert!(durable.pending.is_some());

        assert!(matches!(
            core.reconcile().await.unwrap(),
            TrustRecovery::Recovered { .. }
        ));
        assert!(core.status().pending.is_none());
        assert_eq!(core.status().roots.len(), 1);
        assert!(matches!(
            events.try_recv(),
            Ok(TrustEvent::TransitionRecovered { .. })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn panicking_effect_keeps_worker_and_durable_recovery_available() {
        let dir = test_dir("panicking-effect");
        let store = Arc::new(BlockingInstallStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        store.panic_next_effect.store(true, Ordering::Release);

        let error = core
            .install(request("root", "test", certificate("root")))
            .await
            .expect_err("panic closes only this command reply");
        assert!(matches!(error, TrustError::Worker(_)));
        let pending = core.status();
        assert!(pending.roots.is_empty());
        assert!(pending.pending.is_some());
        assert!(Repository::new(dir.clone())
            .load()
            .unwrap()
            .pending
            .is_some());

        assert!(matches!(
            core.reconcile().await.unwrap(),
            TrustRecovery::Recovered { .. }
        ));
        assert_eq!(core.status().roots.len(), 1);
        assert!(core.status().pending.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_while_backpressured_admits_no_command() {
        let dir = test_dir("bounded-admission");
        let store = Arc::new(BlockingInstallStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        store.arm_effect();
        let first = {
            let core = core.clone();
            tokio::spawn(async move {
                core.install(request("accepted", "test", certificate("accepted")))
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), store.entered.notified())
            .await
            .expect("first effect started");

        let mut queued = Vec::with_capacity(TRUST_COMMAND_CAPACITY);
        for _ in 0..TRUST_COMMAND_CAPACITY {
            let core = core.clone();
            queued.push(tokio::spawn(async move { core.reconcile().await }));
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let remaining = core
                    .inner
                    .worker
                    .admission
                    .lock()
                    .await
                    .sender
                    .as_ref()
                    .expect("live worker")
                    .capacity();
                if remaining == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker queue filled");

        let rejected = {
            let core = core.clone();
            tokio::spawn(async move {
                core.install(request("not-admitted", "test", certificate("not-admitted")))
                    .await
            })
        };
        tokio::task::yield_now().await;
        rejected.abort();
        assert!(rejected.await.unwrap_err().is_cancelled());

        store.release_effect();
        first.await.expect("first task").expect("first command");
        for command in queued {
            command.await.expect("queued task").expect("queued command");
        }
        let status = core.status();
        assert_eq!(status.roots.len(), 1);
        assert_eq!(status.roots[0].name, "accepted");
        assert_eq!(store.effect_count.load(Ordering::Acquire), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_shutdown_waiter_retries_the_same_terminal_transaction() {
        let dir = test_dir("shutdown-retry");
        let store = Arc::new(BlockingInstallStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut events = core.subscribe();
        store.arm_effect();
        let installing = {
            let core = core.clone();
            tokio::spawn(async move {
                core.install(request("root", "test", certificate("root")))
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), store.entered.notified())
            .await
            .expect("platform effect started");

        let shutting_down = {
            let core = core.clone();
            tokio::spawn(async move { core.shutdown().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if core.inner.worker.admission.lock().await.sender.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal command admitted");
        assert!(matches!(core.reconcile().await, Err(TrustError::ShutDown)));
        shutting_down.abort();
        assert!(shutting_down.await.unwrap_err().is_cancelled());

        store.release_effect();
        core.shutdown()
            .await
            .expect("retry observes shared completion");
        installing
            .await
            .expect("install task")
            .expect("accepted install drained");
        assert!(matches!(
            events.try_recv(),
            Ok(TrustEvent::RootInstalled { .. })
        ));
        assert_eq!(core.status().roots.len(), 1);
        assert!(core.inner.worker.thread.lock().unwrap().is_none());
        core.shutdown().await.expect("shutdown remains idempotent");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_command_and_shutdown_have_one_linearized_winner() {
        for _ in 0..16 {
            let dir = test_dir("shutdown-race");
            let core =
                TrustCore::with_test_store(dir.clone(), Arc::new(BlockingInstallStore::default()))
                    .await
                    .unwrap();
            let barrier = Arc::new(tokio::sync::Barrier::new(3));
            let command = {
                let core = core.clone();
                let barrier = Arc::clone(&barrier);
                tokio::spawn(async move {
                    barrier.wait().await;
                    core.install(request("racing-root", "test", certificate("racing-root")))
                        .await
                })
            };
            let shutdown = {
                let core = core.clone();
                let barrier = Arc::clone(&barrier);
                tokio::spawn(async move {
                    barrier.wait().await;
                    core.shutdown().await
                })
            };
            barrier.wait().await;

            shutdown
                .await
                .expect("shutdown task")
                .expect("terminal shutdown");
            match command.await.expect("command task") {
                Ok(mutation) => {
                    assert!(mutation.changed);
                    assert_eq!(core.status().roots.len(), 1);
                }
                Err(TrustError::ShutDown) => assert!(core.status().roots.is_empty()),
                Err(error) => panic!("unexpected admission result: {error}"),
            }
            assert!(core.inner.worker.thread.lock().unwrap().is_none());
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[tokio::test]
    async fn commands_are_rejected_after_terminal_shutdown() {
        let dir = test_dir("post-shutdown");
        let core = TrustCore::with_test_store(dir.clone(), Arc::new(FakeStore::default()))
            .await
            .unwrap();
        let pem = certificate("root");
        core.shutdown().await.unwrap();

        assert!(matches!(
            core.install(request("root", "test", pem.clone())).await,
            Err(TrustError::ShutDown)
        ));
        assert!(matches!(
            core.ensure_installed(request("root", "test", pem.clone()))
                .await,
            Err(TrustError::ShutDown)
        ));
        assert!(matches!(
            core.remove("root").await,
            Err(TrustError::ShutDown)
        ));
        assert!(matches!(
            core.ensure_removed("root", "test").await,
            Err(TrustError::ShutDown)
        ));
        assert!(matches!(
            core.inspect(&pem).await,
            Err(TrustError::ShutDown)
        ));
        assert!(matches!(core.reconcile().await, Err(TrustError::ShutDown)));
        core.shutdown().await.expect("idempotent terminal boundary");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn shutdown_reaps_worker_while_facade_and_status_remain_retained() {
        let dir = test_dir("retained-facade");
        let core = TrustCore::with_test_store(dir.clone(), Arc::new(FakeStore::default()))
            .await
            .unwrap();
        let retained = core.clone();
        let before = retained.status();
        assert!(core.inner.worker.thread.lock().unwrap().is_some());

        core.shutdown().await.unwrap();
        assert!(core.inner.worker.thread.lock().unwrap().is_none());
        assert!(Arc::ptr_eq(&before, &retained.status()));
        drop(core);
        assert!(Arc::ptr_eq(&before, &retained.status()));
        retained
            .shutdown()
            .await
            .expect("retained facade sees completion");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn semantic_noop_keeps_revision_and_emits_nothing() {
        let dir = test_dir("noop");
        let store = Arc::new(FakeStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store)
            .await
            .unwrap();
        let pem = certificate("root");
        core.install(request("root", "test", pem.clone()))
            .await
            .unwrap();
        let revision = core.status().revision;
        let mut events = core.subscribe();
        let result = core.install(request("root", "test", pem)).await.unwrap();
        assert!(!result.changed);
        assert_eq!(core.status().revision, revision);
        assert!(events.try_recv().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn managed_replacement_installs_new_before_removing_old() {
        let dir = test_dir("replace");
        let store = Arc::new(FakeStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        core.ensure_installed(request("koi-certmesh-ca", "certmesh", certificate("old")))
            .await
            .unwrap();
        store.calls.lock().unwrap().clear();
        core.ensure_installed(request("koi-certmesh-ca", "certmesh", certificate("new")))
            .await
            .unwrap();
        let calls = store.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with("install:"));
        assert!(calls[1].starts_with("remove:"));
        assert_eq!(core.status().roots.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn managed_replacement_recovers_after_new_is_present_but_old_removal_failed() {
        let dir = test_dir("replace-recovery");
        let store = Arc::new(FakeStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        core.ensure_installed(request("koi-certmesh-ca", "certmesh", certificate("old")))
            .await
            .unwrap();
        *store.fail_uninstall.lock().unwrap() = true;
        let new_pem = certificate("new");
        assert!(core
            .ensure_installed(request("koi-certmesh-ca", "certmesh", new_pem.clone(),))
            .await
            .is_err());
        assert_eq!(core.status().roots.len(), 1, "accepted state remains old");
        assert!(core.status().pending.is_some());

        // A fresh process/core observes durable intent without replaying it.
        // The application startup owner then explicitly reconciles, finishing
        // old-root removal and committing the accepted replacement.
        store.calls.lock().unwrap().clear();
        let recovered = TrustCore::with_test_store(dir.clone(), store)
            .await
            .unwrap();
        assert!(recovered.status().pending.is_some());
        assert_eq!(
            recovered.status().roots[0].fingerprint,
            core.status().roots[0].fingerprint
        );
        assert!(matches!(
            recovered.reconcile().await.unwrap(),
            TrustRecovery::Recovered { .. }
        ));
        assert!(recovered.status().pending.is_none());
        let new_fingerprint = os_truststore::Cert::from_pem(new_pem)
            .unwrap()
            .fingerprint_hex();
        assert_eq!(recovered.status().roots[0].fingerprint, new_fingerprint);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn desired_absence_never_removes_another_sources_root() {
        let dir = test_dir("ownership");
        let store = Arc::new(FakeStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        core.install(request(
            "koi-certmesh-ca",
            "operator",
            certificate("operator"),
        ))
        .await
        .unwrap();
        store.calls.lock().unwrap().clear();
        let result = core
            .ensure_removed("koi-certmesh-ca", "certmesh")
            .await
            .unwrap();
        assert!(!result.changed);
        assert!(store.calls.lock().unwrap().is_empty());
        assert_eq!(core.status().roots[0].source, "operator");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failed_effect_leaves_durable_intent_and_no_success_event() {
        let dir = test_dir("failure");
        let store = Arc::new(FakeStore::default());
        *store.fail_install.lock().unwrap() = true;
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut events = core.subscribe();
        let result = core
            .install(request("root", "test", certificate("root")))
            .await;
        assert!(result.is_err());
        assert!(core.status().pending.is_some());
        assert!(core.status().last_error.is_some());
        assert!(events.try_recv().is_err());

        let recovered = core.reconcile().await.unwrap();
        assert!(matches!(recovered, TrustRecovery::Recovered { .. }));
        assert!(core.status().pending.is_none());
        assert!(matches!(
            events.try_recv(),
            Ok(TrustEvent::TransitionRecovered { .. })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn uncertain_final_commit_accepts_visible_state_and_recovers_qualified_intent() {
        let dir = test_dir("uncertain-final-commit");
        let store = Arc::new(FakeStore::default());
        let warning = "certificate is present but application trust is unconfirmed";
        *store.next_install_warning.lock().unwrap() = Some(warning.into());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut events = core.subscribe();
        core.inject_next_final_commit_uncertainty().await.unwrap();

        let error = core
            .install(request("root", "test", certificate("root")))
            .await
            .expect_err("an unconfirmed final settlement is not acknowledged");
        assert!(matches!(error, TrustError::DurabilityUncertain(_)));
        let pending = core.status();
        assert_eq!(pending.roots.len(), 1);
        assert_eq!(pending.roots[0].warning.as_deref(), Some(warning));
        assert!(matches!(pending.roots[0].presence, TrustPresence::Present));
        assert!(pending.pending.is_some());
        assert!(pending
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("crash durability is unconfirmed")));
        assert!(events.try_recv().is_err(), "uncertainty is not success");
        let durable = Repository::new(dir.clone()).load().unwrap();
        assert_eq!(durable.roots.len(), 1);
        assert_eq!(durable.roots[0].warning.as_deref(), Some(warning));
        assert!(matches!(
            durable.pending.as_ref(),
            Some(TrustTransition::Install { entry })
                if entry.warning.as_deref() == Some(warning)
        ));

        core.shutdown().await.unwrap();
        drop(core);
        let reopened = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut recovery_events = reopened.subscribe();
        assert_eq!(reopened.status().roots[0].warning.as_deref(), Some(warning));
        assert!(reopened.status().pending.is_some());

        assert!(matches!(
            reopened.reconcile().await.unwrap(),
            TrustRecovery::Recovered { .. }
        ));
        let completed = reopened.status();
        assert_eq!(completed.roots.len(), 1);
        assert_eq!(completed.roots[0].warning.as_deref(), Some(warning));
        assert!(completed.pending.is_none());
        assert!(completed.last_error.is_none());
        assert!(matches!(
            completed.roots[0].presence,
            TrustPresence::Present
        ));
        assert!(matches!(
            recovery_events.try_recv(),
            Ok(TrustEvent::TransitionRecovered { .. })
        ));
        assert!(recovery_events.try_recv().is_err());
        let durable = Repository::new(dir.clone()).load().unwrap();
        assert_eq!(durable.roots.len(), 1);
        assert_eq!(durable.roots[0].warning.as_deref(), Some(warning));
        assert!(durable.pending.is_none());
        let install_calls = store
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("install:"))
            .count();
        assert_eq!(install_calls, 1, "recovery observes the idempotent effect");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn failed_final_commit_keeps_prior_state_and_recovers_qualified_intent() {
        let dir = test_dir("failed-final-commit");
        let store = Arc::new(FakeStore::default());
        let warning = "certificate is present but application trust is unconfirmed";
        *store.next_install_warning.lock().unwrap() = Some(warning.into());
        let core = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut events = core.subscribe();
        core.inject_next_final_commit_failure().await.unwrap();

        let error = core
            .install(request("root", "test", certificate("root")))
            .await
            .expect_err("a pre-replacement final commit failure is not acknowledged");
        assert!(matches!(error, TrustError::Io(_)));
        let pending = core.status();
        assert!(pending.roots.is_empty());
        assert!(pending.pending.is_some());
        assert!(pending.last_error.is_some());
        assert!(events.try_recv().is_err(), "failure is not success");
        let durable = Repository::new(dir.clone()).load().unwrap();
        assert!(durable.roots.is_empty());
        assert!(matches!(
            durable.pending.as_ref(),
            Some(TrustTransition::Install { entry })
                if entry.warning.as_deref() == Some(warning)
        ));

        core.shutdown().await.unwrap();
        drop(core);
        let reopened = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let mut recovery_events = reopened.subscribe();
        assert!(reopened.status().roots.is_empty());
        assert!(reopened.status().pending.is_some());
        assert!(matches!(
            reopened.reconcile().await.unwrap(),
            TrustRecovery::Recovered { .. }
        ));
        let completed = reopened.status();
        assert_eq!(completed.roots.len(), 1);
        assert_eq!(completed.roots[0].warning.as_deref(), Some(warning));
        assert!(completed.pending.is_none());
        assert!(completed.last_error.is_none());
        assert!(matches!(
            recovery_events.try_recv(),
            Ok(TrustEvent::TransitionRecovered { .. })
        ));
        assert!(recovery_events.try_recv().is_err());
        let install_calls = store
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("install:"))
            .count();
        assert_eq!(install_calls, 1, "recovery observes the idempotent effect");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn two_cores_reload_under_cross_process_lock() {
        let dir = test_dir("two-cores");
        let store = Arc::new(FakeStore::default());
        let first = TrustCore::with_test_store(dir.clone(), store.clone())
            .await
            .unwrap();
        let second = TrustCore::with_test_store(dir.clone(), store)
            .await
            .unwrap();
        first
            .install(request("one", "test", certificate("one")))
            .await
            .unwrap();
        second
            .install(request("two", "test", certificate("two")))
            .await
            .unwrap();
        first.reconcile().await.unwrap();
        let status = first.status();
        let names = status
            .roots
            .iter()
            .map(|root| root.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["one", "two"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn public_status_and_events_never_serialize_pem() {
        let dir = test_dir("redaction");
        let store = Arc::new(FakeStore::default());
        let core = TrustCore::with_test_store(dir.clone(), store)
            .await
            .unwrap();
        let pem = certificate("secret-marker");
        core.install(request("root", "test", pem.clone()))
            .await
            .unwrap();
        let json = serde_json::to_string(core.status().as_ref()).unwrap();
        assert!(!json.contains("BEGIN CERTIFICATE"));
        assert!(!json.contains(&pem));
        let _ = std::fs::remove_dir_all(dir);
    }
}
