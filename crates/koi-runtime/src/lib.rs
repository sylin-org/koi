//! Koi Runtime Adapter — container/service lifecycle integration.
//!
//! Watches container runtime APIs (Docker, Podman) for lifecycle events and
//! drives Koi capabilities: mDNS announce, DNS entry, health check, proxy
//! configuration.
//!
//! The adapter uses a trait-based backend system. Each runtime implements
//! [`RuntimeBackend`] to provide normalized lifecycle events and instance
//! metadata. The [`RuntimeCore`] facade orchestrates the mapping from
//! runtime events to Koi API calls.
//!
//! The `docker` feature (default-on) compiles the bollard-backed Docker/Podman backend.
//! With it off, the runtime capability stays available but Docker/Podman/Auto resolve to
//! [`RuntimeError::BackendUnavailable`]. The selectable backends are Auto/Docker/Podman;
//! other runtimes can be added by implementing [`RuntimeBackend`].
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod backend;
#[cfg(feature = "docker")]
pub mod docker;
pub mod error;
pub mod heuristics;
pub mod http;
pub mod instance;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use axum::Router;
use koi_common::status::StatusFeed;
use tokio::sync::{broadcast, mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use backend::{RuntimeBackend, RuntimeBackendKind, RuntimeEvent, RuntimeObservation};
pub use error::RuntimeError;
pub use instance::{Instance, InstanceState, KoiMetadata, PortMapping};

/// Runtime discovery is optional and must never hold every serving surface
/// hostage. Local Engine API operations should complete quickly; these bounds
/// turn a stale socket or hung desktop runtime into an unavailable capability.
const RUNTIME_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RUNTIME_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(10);
const RUNTIME_STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// Configuration for the runtime adapter.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Which backend to use.
    pub backend_kind: RuntimeBackendKind,
    /// Custom socket path (overrides default for the selected backend).
    pub socket_path: Option<String>,
}

/// Authoritative latest-value snapshot of runtime-backend and inventory state.
///
/// This contains the complete normalized inventory so a consumer that lags the semantic
/// event stream can recover from one cheap status read.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct RuntimeStatus {
    /// Monotonic semantic status revision.
    #[serde(default)]
    pub revision: u64,
    /// Whether the backend watch is active.
    pub active: bool,
    /// Exact lifecycle of the owned backend watch.
    #[serde(default)]
    pub state: RuntimeWatchState,
    /// Connected or most recently attempted backend name.
    pub backend: Option<String>,
    /// Most recent backend failure, cleared by a successful connection/reconnection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_error: Option<String>,
    /// Number of entries in `instances` (retained for compact status consumers).
    pub instance_count: usize,
    /// Complete normalized inventory, sorted by runtime ID.
    #[serde(default)]
    pub instances: Vec<Instance>,
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeWatchState {
    #[default]
    Stopped,
    Connecting,
    Reconciling,
    Running,
    Waiting,
    Stopping,
    Failed,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            backend_kind: RuntimeBackendKind::Auto,
            socket_path: None,
        }
    }
}

async fn connect_backend(
    backend: &mut dyn RuntimeBackend,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    let name = backend.name();
    tokio::time::timeout(timeout, backend.connect())
        .await
        .map_err(|_| {
            RuntimeError::Connection(format!(
                "{name} connection timed out after {}s",
                timeout.as_secs()
            ))
        })?
}

async fn begin_backend_observation(
    backend: Arc<dyn RuntimeBackend>,
    tx: mpsc::Sender<RuntimeEvent>,
    cancel: CancellationToken,
    timeout: Duration,
) -> Result<RuntimeObservation, RuntimeError> {
    let name = backend.name();
    tokio::time::timeout(timeout, backend.begin_observation(tx, cancel))
        .await
        .map_err(|_| {
            RuntimeError::Connection(format!(
                "{name} initial observation timed out after {}s",
                timeout.as_secs()
            ))
        })?
}

// ── Internal state ──────────────────────────────────────────────────

#[derive(Default)]
struct RuntimeModel {
    generation: u64,
    /// Tracked instances by runtime ID.
    instances: HashMap<String, Instance>,
    /// Backend name (set after connect).
    backend_name: Option<String>,
    /// Whether the watcher is active.
    active: bool,
    state: RuntimeWatchState,
    /// Most recent backend/watch error.
    backend_error: Option<String>,
}

struct RuntimeState {
    /// One short, synchronous transition boundary for generation checks, the
    /// authoritative snapshot, and its corresponding semantic event.
    model: StdMutex<RuntimeModel>,
    status: StatusFeed<RuntimeStatus>,
    /// Event broadcast channel.
    event_tx: broadcast::Sender<RuntimeEvent>,
}

impl RuntimeState {
    fn lock_model(&self) -> std::sync::MutexGuard<'_, RuntimeModel> {
        self.model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn publish_status(&self, model: &RuntimeModel) {
        let mut instances = model.instances.values().cloned().collect::<Vec<_>>();
        instances.sort_by(|left, right| left.id.cmp(&right.id));
        let mut next = RuntimeStatus {
            revision: 0,
            active: model.active,
            state: model.state,
            backend: model.backend_name.clone(),
            backend_error: model.backend_error.clone(),
            instance_count: instances.len(),
            instances,
        };
        self.status.update(move |current| {
            next.revision = current.revision;
            if current == &next {
                return None;
            }
            next.revision = current.revision.saturating_add(1);
            Some(next)
        });
    }

    /// Apply one normalized backend event to inventory, then publish the same
    /// event to every downstream consumer. Keeping both effects here prevents
    /// real backends and embedded/custom producers from drifting.
    #[cfg(test)]
    fn ingest(&self, event: RuntimeEvent) {
        let mut model = self.lock_model();
        self.ingest_locked(&mut model, event);
    }

    fn ingest_locked(&self, model: &mut RuntimeModel, event: RuntimeEvent) {
        match &event {
            RuntimeEvent::Started(instance) | RuntimeEvent::Updated(instance) => {
                let unchanged = model
                    .instances
                    .get(&instance.id)
                    .is_some_and(|current| current.has_same_operational_facts(instance));
                if !unchanged {
                    model
                        .instances
                        .insert(instance.id.clone(), instance.clone());
                }
                tracing::debug!(
                    name = %instance.name,
                    id = %instance.id,
                    "Instance tracked"
                );
            }
            RuntimeEvent::Stopped { id, name } => {
                model.instances.remove(id.as_str());
                tracing::debug!(name, id, "Instance untracked");
            }
            RuntimeEvent::BackendDisconnected { backend, reason } => {
                model.backend_name = Some(backend.clone());
                model.active = false;
                model.state = RuntimeWatchState::Waiting;
                model.backend_error = Some(reason.clone());
                tracing::warn!(backend, reason, "Backend disconnected");
            }
            RuntimeEvent::BackendReconnected { backend } => {
                model.backend_name = Some(backend.clone());
                model.active = true;
                model.state = RuntimeWatchState::Running;
                model.backend_error = None;
                tracing::info!(backend, "Backend reconnected");
            }
            RuntimeEvent::BackendStopped { backend } => {
                model.backend_name = Some(backend.clone());
                model.active = false;
                model.state = RuntimeWatchState::Stopped;
                model.backend_error = None;
            }
        }
        self.publish_status(model);
        let _ = self.event_tx.send(event);
    }

    fn begin_generation(&self, generation: u64, backend: String) {
        let mut model = self.lock_model();
        model.generation = generation;
        model.backend_name = Some(backend);
        model.active = false;
        model.state = RuntimeWatchState::Connecting;
        model.backend_error = None;
        self.publish_status(&model);
    }

    fn mark_reconciling(&self, generation: u64) -> bool {
        let mut model = self.lock_model();
        if model.generation != generation {
            return false;
        }
        model.state = RuntimeWatchState::Reconciling;
        self.publish_status(&model);
        true
    }

    fn reconcile(&self, generation: u64, backend: String, existing: &[Instance]) -> bool {
        let mut model = self.lock_model();
        if model.generation != generation {
            return false;
        }
        let instances = existing
            .iter()
            .map(|instance| {
                let stable = model
                    .instances
                    .get(&instance.id)
                    .filter(|current| current.has_same_operational_facts(instance))
                    .cloned()
                    .unwrap_or_else(|| instance.clone());
                (stable.id.clone(), stable)
            })
            .collect();
        model.instances = instances;
        model.backend_name = Some(backend);
        model.active = true;
        model.state = RuntimeWatchState::Running;
        model.backend_error = None;
        self.publish_status(&model);

        // The Running snapshot is already visible when its initial semantic facts cross the
        // boundary. Holding the same tiny transition lock prevents a concurrent stop fence from
        // landing between the snapshot and these events.
        for instance in existing {
            let _ = self.event_tx.send(RuntimeEvent::Started(instance.clone()));
        }
        true
    }

    fn ingest_generation(&self, generation: u64, event: RuntimeEvent) {
        let mut model = self.lock_model();
        if model.generation != generation {
            return;
        }
        self.ingest_locked(&mut model, event);
    }

    fn backend_stopped(&self, generation: u64, backend: String, error: Option<String>) {
        let mut model = self.lock_model();
        if model.generation != generation {
            return;
        }
        let state = if error.is_some() {
            RuntimeWatchState::Failed
        } else {
            RuntimeWatchState::Stopped
        };
        let changed = model.backend_name.as_deref() != Some(backend.as_str())
            || model.active
            || model.state != state
            || model.backend_error != error;
        model.backend_name = Some(backend.clone());
        model.active = false;
        model.state = state;
        model.backend_error = error.clone();
        self.publish_status(&model);
        if !changed {
            return;
        }
        let event = match error {
            Some(reason) => RuntimeEvent::BackendDisconnected { backend, reason },
            None => RuntimeEvent::BackendStopped { backend },
        };
        let _ = self.event_tx.send(event);
    }

    /// Publish one terminal fact only after the retiring worker was reaped.
    /// A release failure is retained in the cheap snapshot; it must never be
    /// overwritten by an unconditional clean `Stopped` transition.
    fn settle_stop_generation(
        &self,
        generation: u64,
        backend: Option<String>,
        outcome: &Result<(), RuntimeError>,
    ) {
        let mut model = self.lock_model();
        let backend = backend.or_else(|| model.backend_name.clone());
        let error = outcome.as_ref().err().map(ToString::to_string);
        let state = if error.is_some() {
            RuntimeWatchState::Failed
        } else {
            RuntimeWatchState::Stopped
        };
        let changed = model.active
            || model.state != state
            || model.backend_error != error
            || model.backend_name != backend;
        model.generation = generation;
        model.backend_name = backend.clone();
        model.active = false;
        model.state = state;
        model.backend_error = error.clone();
        self.publish_status(&model);
        if changed {
            if let Some(backend) = backend {
                let event = match error {
                    Some(reason) => RuntimeEvent::BackendDisconnected { backend, reason },
                    None => RuntimeEvent::BackendStopped { backend },
                };
                let _ = self.event_tx.send(event);
            } else {
                tracing::error!(
                    generation,
                    "Runtime reached a changed terminal state without an identified backend"
                );
            }
        }
    }

    /// Fence the retiring generation without claiming its worker is gone. Once
    /// this returns, queued observations from that generation are stale, while
    /// the authoritative status truthfully remains active/Stopping.
    fn begin_stop_generation(&self, generation: u64, backend: Option<String>) -> bool {
        let mut model = self.lock_model();
        model.generation = generation;
        model.backend_name = backend;
        if !model.active
            && matches!(
                model.state,
                RuntimeWatchState::Stopped | RuntimeWatchState::Failed
            )
        {
            return true;
        }
        model.active = true;
        model.state = RuntimeWatchState::Stopping;
        model.backend_error = None;
        self.publish_status(&model);
        false
    }
}

struct ActiveWatch {
    generation: u64,
    backend: String,
    cancel: CancellationToken,
    task: JoinHandle<Result<(), RuntimeError>>,
}

struct WatchCompletion {
    generation: u64,
    backend: String,
    result: Result<Result<(), RuntimeError>, tokio::task::JoinError>,
    forced_abort: bool,
}

#[derive(Default)]
struct RuntimeLifecycle {
    generation: u64,
    active: Option<ActiveWatch>,
}

/// One self-owned Runtime lifecycle transition.
///
/// The outer supervisor contains an operation panic and always breaks its
/// temporary owner → handle → task → owner cycle. Callers own only cheap
/// waiters, so cancellation cannot detach the admitted transition or strand
/// every later waiter.
#[derive(Default)]
struct RuntimeOwnedCompletion {
    state: StdMutex<RuntimeCompletionState>,
    completed: tokio::sync::Notify,
}

#[derive(Default)]
struct RuntimeCompletionState {
    outcome: Option<Result<bool, RuntimeError>>,
    task: Option<JoinHandle<()>>,
}

impl RuntimeOwnedCompletion {
    fn start<F>(operation: F, phase: &'static str) -> Arc<Self>
    where
        F: std::future::Future<Output = Result<bool, RuntimeError>> + Send + 'static,
    {
        let completion = Arc::new(Self::default());
        let retained = Arc::clone(&completion);
        let mut state = completion
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.task = Some(tokio::spawn(async move {
            let outcome = match tokio::spawn(operation).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    tracing::error!(%error, phase, "Runtime lifecycle transition panicked");
                    Err(RuntimeError::Worker(format!(
                        "{phase} transition panicked: {error}"
                    )))
                }
            };
            let mut state = retained
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.outcome = Some(outcome);
            state.task.take();
            drop(state);
            retained.completed.notify_waiters();
        }));
        drop(state);
        completion
    }

    async fn wait(&self) -> Result<bool, RuntimeError> {
        loop {
            let completed = self.completed.notified();
            if let Some(outcome) = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .outcome
                .clone()
            {
                return outcome;
            }
            completed.await;
        }
    }

    fn is_complete(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .outcome
            .is_some()
    }
}

/// One self-owned terminal transaction for the Runtime domain.
///
/// Admission is synchronous so dropping the returned waiter cannot undo the
/// terminal decision. The transaction retains its own JoinHandle only until
/// the active backend generation has been cancelled and reaped.
#[derive(Default)]
struct RuntimeShutdown {
    admitted: AtomicBool,
    state: StdMutex<RuntimeBoundaryState>,
}

#[derive(Default)]
struct RuntimeBoundaryState {
    stops: Vec<Arc<RuntimeOwnedCompletion>>,
    terminal: Option<Arc<RuntimeOwnedCompletion>>,
}

impl RuntimeShutdown {
    fn is_admitted(&self) -> bool {
        self.admitted.load(Ordering::Acquire)
    }

    fn start_stop(&self, core: RuntimeCore, timeout: Duration) -> Arc<RuntimeOwnedCompletion> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(completion) = state.terminal.as_ref() {
            return Arc::clone(completion);
        }
        state.stops.retain(|completion| !completion.is_complete());
        let completion = RuntimeOwnedCompletion::start(
            async move { core.stop_watching_inner(timeout).await },
            "restartable stop",
        );
        state.stops.push(Arc::clone(&completion));
        completion
    }

    fn start_terminal(&self, core: RuntimeCore, timeout: Duration) -> Arc<RuntimeOwnedCompletion> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(completion) = state.terminal.as_ref() {
            return Arc::clone(completion);
        }

        // This lock is the command-admission linearization point. Publish the
        // cheap atomic marker before releasing it so later starts fail closed
        // and later stops join this same terminal completion.
        self.admitted.store(true, Ordering::Release);
        let admitted_stops = std::mem::take(&mut state.stops);
        let completion = RuntimeOwnedCompletion::start(
            async move {
                let mut stopped = false;
                let mut failure = None;
                for stop in admitted_stops {
                    match stop.wait().await {
                        Ok(changed) => stopped |= changed,
                        Err(error) if failure.is_none() => failure = Some(error),
                        Err(error) => {
                            tracing::error!(%error, "Additional Runtime stop failure during shutdown");
                        }
                    }
                }
                match core.stop_watching_inner(timeout).await {
                    Ok(changed) => stopped |= changed,
                    Err(error) if failure.is_none() => failure = Some(error),
                    Err(error) => {
                        tracing::error!(%error, "Additional Runtime shutdown failure");
                    }
                }
                match failure {
                    Some(error) => Err(error),
                    None => Ok(stopped),
                }
            },
            "terminal shutdown",
        );
        state.terminal = Some(Arc::clone(&completion));
        completion
    }
}

impl Drop for RuntimeLifecycle {
    fn drop(&mut self) {
        if let Some(active) = &mut self.active {
            active.cancel.cancel();
            active.task.abort();
        }
    }
}

/// Synchronous cancellation edge for a dropped startup caller.
///
/// Status finalization remains the owned supervisor's responsibility; Drop never spawns work.
struct StartupCancellationGuard {
    cancel: Option<CancellationToken>,
}

impl StartupCancellationGuard {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            cancel: Some(cancel),
        }
    }

    fn disarm(&mut self) {
        self.cancel = None;
    }
}

impl Drop for StartupCancellationGuard {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
    }
}

fn startup_cancelled() -> RuntimeError {
    RuntimeError::EventStream("runtime startup was cancelled".to_string())
}

fn finish_failed_startup(
    state: &RuntimeState,
    generation: u64,
    backend: String,
    started: oneshot::Sender<Result<(), RuntimeError>>,
    error: RuntimeError,
) -> RuntimeError {
    state.backend_stopped(generation, backend, Some(error.to_string()));
    let retained = error.clone();
    let _ = started.send(Err(error));
    retained
}

/// Own one complete backend generation in one task.
///
/// The observation future is polled directly beside its event receiver. There is no child watch
/// task to detach if this supervisor must be aborted during bounded teardown.
async fn supervise_watch_generation(
    state: Arc<RuntimeState>,
    generation: u64,
    backend_name: String,
    mut backend: Box<dyn RuntimeBackend>,
    cancel: CancellationToken,
    started: oneshot::Sender<Result<(), RuntimeError>>,
) -> Result<(), RuntimeError> {
    let connected = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(startup_cancelled()),
        result = connect_backend(backend.as_mut(), RUNTIME_CONNECT_TIMEOUT) => result,
    };
    if let Err(error) = connected {
        let cancelled = cancel.is_cancelled();
        let error = finish_failed_startup(&state, generation, backend_name, started, error);
        return if cancelled { Ok(()) } else { Err(error) };
    }

    if !state.mark_reconciling(generation) {
        let _ = started.send(Err(startup_cancelled()));
        return Ok(());
    }

    // The adapter owns the snapshot-to-stream boundary. Docker captures an inclusive replay
    // cursor before listing; other adapters may buffer or use their native cursor. This one
    // supervisor begins draining only after it has published the reconciled snapshot and its
    // initial semantic facts, preserving their causal order.
    let (event_tx, mut event_rx) = mpsc::channel(256);
    let backend: Arc<dyn RuntimeBackend> = backend.into();
    let observation = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(startup_cancelled()),
        result = begin_backend_observation(
            backend,
            event_tx,
            cancel.clone(),
            RUNTIME_OBSERVATION_TIMEOUT,
        ) => result,
    };
    let observation = match observation {
        Ok(observation) => observation,
        Err(error) => {
            let cancelled = cancel.is_cancelled();
            let error = finish_failed_startup(&state, generation, backend_name, started, error);
            return if cancelled { Ok(()) } else { Err(error) };
        }
    };
    let (existing, mut watch) = observation.into_parts();

    if cancel.is_cancelled() || !state.reconcile(generation, backend_name.clone(), &existing) {
        finish_failed_startup(
            &state,
            generation,
            backend_name,
            started,
            startup_cancelled(),
        );
        return Ok(());
    }

    tracing::info!(
        backend = backend_name,
        instances = existing.len(),
        "Runtime adapter started, lossless initial observation armed"
    );

    // If the startup caller disappeared after reconciliation, its synchronous Drop guard has
    // already cancelled this token. A failed send closes the remaining race before the guard ran.
    if started.send(Ok(())).is_err() {
        cancel.cancel();
    }

    let mut receiving = true;
    let watch_result = loop {
        tokio::select! {
            biased;
            event = event_rx.recv(), if receiving => match event {
                Some(event) => state.ingest_generation(generation, event),
                None => receiving = false,
            },
            result = watch.as_mut() => break result,
        }
    };

    // Completion drops the adapter-owned sender. Drain everything it accepted before publishing
    // the terminal state so snapshot and semantic history converge at the boundary.
    drop(watch);
    while let Some(event) = event_rx.recv().await {
        state.ingest_generation(generation, event);
    }

    let outcome = match watch_result {
        Ok(()) if cancel.is_cancelled() => Ok(()),
        Ok(()) => Err(RuntimeError::EventStream(
            "backend watch ended unexpectedly".to_string(),
        )),
        Err(error) => {
            tracing::error!(error = %error, "Runtime watch loop exited with error");
            Err(error)
        }
    };
    state.backend_stopped(
        generation,
        backend_name,
        outcome.as_ref().err().map(ToString::to_string),
    );
    tracing::info!(generation, "Runtime watch generation stopped");
    outcome
}

// ── RuntimeCore facade ──────────────────────────────────────────────

/// Runtime adapter domain facade.
///
/// Wraps the backend and tracked instance state, exposes commands,
/// status, events, and HTTP routes.
#[derive(Clone)]
pub struct RuntimeCore {
    state: Arc<RuntimeState>,
    lifecycle: Arc<Mutex<RuntimeLifecycle>>,
    shutdown: Arc<RuntimeShutdown>,
    config: RuntimeConfig,
}

impl RuntimeCore {
    /// Create a new RuntimeCore with the given configuration.
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            state: Arc::new(RuntimeState {
                model: StdMutex::new(RuntimeModel::default()),
                status: StatusFeed::default(),
                event_tx: koi_common::events::event_channel().0,
            }),
            lifecycle: Arc::new(Mutex::new(RuntimeLifecycle::default())),
            shutdown: Arc::new(RuntimeShutdown::default()),
            config,
        }
    }

    /// Build the HTTP router for this domain.
    pub fn routes(&self) -> Router {
        http::routes(Arc::new(RuntimeCore {
            state: Arc::clone(&self.state),
            lifecycle: Arc::clone(&self.lifecycle),
            shutdown: Arc::clone(&self.shutdown),
            config: self.config.clone(),
        }))
    }

    /// Subscribe to runtime events.
    pub fn subscribe(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.state.event_tx.subscribe()
    }

    /// Test-only direct transition hook. Production producers enter through
    /// [`Self::start_with_backend`], which preserves the adapter's snapshot,
    /// observation, cancellation, and terminal ownership contract.
    #[cfg(test)]
    async fn ingest_test_event(&self, event: RuntimeEvent) -> Result<(), RuntimeError> {
        let _lifecycle = self.lifecycle.lock().await;
        if self.shutdown.is_admitted() {
            return Err(RuntimeError::ShutDown);
        }
        self.state.ingest(event);
        Ok(())
    }

    /// Return the current immutable status in constant time.
    pub fn status(&self) -> Arc<RuntimeStatus> {
        self.state.status.current()
    }

    /// Subscribe to the current snapshot and future coalesced status changes.
    pub fn watch_status(&self) -> watch::Receiver<Arc<RuntimeStatus>> {
        self.state.status.subscribe()
    }

    /// List all tracked instances.
    pub async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
        Ok(self.status().instances.clone())
    }

    /// Start watching the runtime backend for lifecycle events.
    ///
    /// This spawns a background task that:
    /// 1. Connects to the runtime backend
    /// 2. Arms an adapter-owned lossless observation and takes its snapshot
    /// 3. Reconciles and publishes Running, then drains lifecycle events
    /// 4. Updates tracked state and broadcasts normalized changes
    ///
    /// Returns after the initial observation has reconciled. The core-owned supervisor then runs
    /// until the cancel token fires or [`Self::stop_watching`] retires it.
    pub async fn start_watching(&self, cancel: CancellationToken) -> Result<(), RuntimeError> {
        self.start_with_factory(cancel, || self.create_backend())
            .await
    }

    /// Start an explicitly composed runtime backend.
    ///
    /// This is the provider port for embedded hosts and additional adapters.
    /// The backend must arm one lossless snapshot-to-stream observation; Koi
    /// owns that generation until cancellation or [`Self::stop_watching`].
    /// Producers cannot bypass reconciliation by writing aggregate state.
    pub async fn start_with_backend(
        &self,
        cancel: CancellationToken,
        backend: Box<dyn RuntimeBackend>,
    ) -> Result<(), RuntimeError> {
        self.start_with_factory(cancel, || Ok(backend)).await
    }

    async fn start_with_factory<F>(
        &self,
        cancel: CancellationToken,
        factory: F,
    ) -> Result<(), RuntimeError>
    where
        F: FnOnce() -> Result<Box<dyn RuntimeBackend>, RuntimeError>,
    {
        if self.shutdown.is_admitted() {
            return Err(RuntimeError::ShutDown);
        }
        let (generation, watch_cancel, started) = {
            let mut lifecycle = self.lifecycle.lock().await;

            if self.shutdown.is_admitted() {
                return Err(RuntimeError::ShutDown);
            }

            // A live generation makes start idempotent. A completed or already-cancelled
            // generation is reaped under this same gate before any successor is constructed.
            let active_state = lifecycle
                .active
                .as_ref()
                .map(|active| (active.task.is_finished(), active.cancel.is_cancelled()));
            match active_state {
                Some((true, _)) => {
                    if let Some(completion) = self
                        .reap_active_locked(
                            &mut lifecycle,
                            RUNTIME_STOP_TIMEOUT,
                            "completed runtime generation",
                        )
                        .await
                    {
                        let outcome =
                            self.reconcile_join_result(&completion, "completed runtime generation");
                        if let Err(error) = outcome {
                            self.state.backend_stopped(
                                completion.generation,
                                completion.backend,
                                Some(error.to_string()),
                            );
                        }
                    }
                }
                Some((false, true)) => {
                    if let Err(error) = self
                        .stop_active_locked(&mut lifecycle, RUNTIME_STOP_TIMEOUT)
                        .await
                    {
                        tracing::warn!(%error, "Retiring cancelled Runtime generation before restart");
                    }
                }
                Some((false, false)) => return Ok(()),
                None => {}
            }

            lifecycle.generation = lifecycle.generation.wrapping_add(1);
            let generation = lifecycle.generation;
            let backend = match factory() {
                Ok(backend) => backend,
                Err(error) => {
                    let backend = self.config.backend_kind.to_string();
                    self.state.begin_generation(generation, backend.clone());
                    self.state
                        .backend_stopped(generation, backend, Some(error.to_string()));
                    return Err(error);
                }
            };
            let backend_name = backend.name().to_string();
            self.state
                .begin_generation(generation, backend_name.clone());

            let watch_cancel = cancel.child_token();
            let (started_tx, started_rx) = oneshot::channel();
            let task = tokio::spawn(supervise_watch_generation(
                Arc::clone(&self.state),
                generation,
                backend_name.clone(),
                backend,
                watch_cancel.clone(),
                started_tx,
            ));
            lifecycle.active = Some(ActiveWatch {
                generation,
                backend: backend_name,
                cancel: watch_cancel.clone(),
                task,
            });
            (generation, watch_cancel, started_rx)
        };

        let mut startup = StartupCancellationGuard::new(watch_cancel.clone());
        let mut result = started.await.unwrap_or_else(|_| {
            Err(RuntimeError::EventStream(
                "runtime startup task ended without a result".to_string(),
            ))
        });
        if result.is_err() {
            watch_cancel.cancel();
            let mut lifecycle = self.lifecycle.lock().await;
            if lifecycle
                .active
                .as_ref()
                .is_some_and(|active| active.generation == generation)
            {
                if let Some(completion) = self
                    .reap_active_locked(
                        &mut lifecycle,
                        RUNTIME_STOP_TIMEOUT,
                        "failed runtime startup",
                    )
                    .await
                {
                    if let Err(error) =
                        self.reconcile_join_result(&completion, "failed runtime startup")
                    {
                        self.state.backend_stopped(
                            completion.generation,
                            completion.backend,
                            Some(error.to_string()),
                        );
                        result = Err(error);
                    }
                }
            }
        }
        startup.disarm();
        result
    }

    /// Stop the owned backend generation and acknowledge that its task has been reaped.
    ///
    /// The operation is idempotent and internally bounded. A self-owned stop
    /// transaction is created synchronously, so caller cancellation cannot
    /// interrupt the cancel/abort/reap sequence or require a later retry.
    /// `Ok(false)` means there was no active or unsettled generation to stop.
    pub fn stop_watching(&self) -> impl std::future::Future<Output = Result<bool, RuntimeError>> {
        self.stop_watching_with_timeout(RUNTIME_STOP_TIMEOUT)
    }

    /// Permanently close command admission and reap the owned backend watcher.
    ///
    /// The terminal decision and its self-owned transaction are created before
    /// this method returns its waiter. Cancelling or never polling that waiter
    /// cannot cancel shutdown; repeated calls observe the same completion.
    /// The retained result is shared by every caller. `Ok(bool)` reports
    /// whether this terminal transaction released a watch generation.
    pub fn shutdown(&self) -> impl std::future::Future<Output = Result<bool, RuntimeError>> {
        self.shutdown_with_timeout(RUNTIME_STOP_TIMEOUT)
    }

    fn shutdown_with_timeout(
        &self,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<bool, RuntimeError>> {
        let completion = self.shutdown.start_terminal(self.clone(), timeout);
        async move { completion.wait().await }
    }

    fn stop_watching_with_timeout(
        &self,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Result<bool, RuntimeError>> {
        let completion = self.shutdown.start_stop(self.clone(), timeout);
        async move { completion.wait().await }
    }

    async fn stop_watching_inner(&self, timeout: Duration) -> Result<bool, RuntimeError> {
        let mut lifecycle = self.lifecycle.lock().await;
        if lifecycle.active.is_some() {
            self.stop_active_locked(&mut lifecycle, timeout).await?;
            return Ok(true);
        }

        let current = self.status();
        if current.state == RuntimeWatchState::Failed {
            let diagnostic = current.backend_error.as_deref().unwrap_or(
                "runtime lifecycle worker failed: runtime watch failed without a retained diagnostic",
            );
            let detail = diagnostic
                .strip_prefix("runtime lifecycle worker failed: ")
                .unwrap_or(diagnostic);
            return Err(RuntimeError::Worker(detail.to_string()));
        }
        if current.active
            || current.state != RuntimeWatchState::Stopped
            || current.backend_error.is_some()
        {
            lifecycle.generation = lifecycle.generation.wrapping_add(1);
            self.state.settle_stop_generation(
                lifecycle.generation,
                current.backend.clone(),
                &Ok(()),
            );
            return Ok(true);
        }
        Ok(false)
    }

    async fn stop_active_locked(
        &self,
        lifecycle: &mut RuntimeLifecycle,
        timeout: Duration,
    ) -> Result<(), RuntimeError> {
        let backend = lifecycle
            .active
            .as_ref()
            .map(|active| active.backend.clone());
        lifecycle.generation = lifecycle.generation.wrapping_add(1);
        let retiring_generation = lifecycle.generation;
        let terminal_already_published = self
            .state
            .begin_stop_generation(retiring_generation, backend.clone());
        if let Some(active) = lifecycle.active.as_ref() {
            active.cancel.cancel();
        }
        let outcome = if let Some(completion) = self
            .reap_active_locked(lifecycle, timeout, "runtime stop")
            .await
        {
            self.reconcile_join_result(&completion, "runtime stop")
        } else {
            Err(RuntimeError::Worker(
                "runtime stop lost ownership of its admitted watch generation".to_string(),
            ))
        };
        let current_matches_outcome = terminal_already_published && {
            let current = self.status();
            match &outcome {
                Ok(()) => {
                    current.state == RuntimeWatchState::Stopped && current.backend_error.is_none()
                }
                Err(error) => {
                    let diagnostic = error.to_string();
                    current.state == RuntimeWatchState::Failed
                        && current.backend_error.as_deref() == Some(diagnostic.as_str())
                }
            }
        };
        if !current_matches_outcome {
            self.state
                .settle_stop_generation(retiring_generation, backend, &outcome);
        }
        outcome
    }

    async fn reap_active_locked(
        &self,
        lifecycle: &mut RuntimeLifecycle,
        timeout: Duration,
        phase: &'static str,
    ) -> Option<WatchCompletion> {
        let active = lifecycle.active.as_mut()?;
        let generation = active.generation;
        let backend = active.backend.clone();
        let task = &mut active.task;
        let (result, forced_abort) = if task.is_finished() {
            ((&mut *task).await, false)
        } else {
            match tokio::time::timeout(timeout, &mut *task).await {
                Ok(result) => (result, false),
                Err(_) => {
                    tracing::warn!(
                        phase,
                        timeout_ms = timeout.as_millis(),
                        "Runtime generation did not stop after cancellation; aborting it"
                    );
                    task.abort();
                    ((&mut *task).await, true)
                }
            }
        };
        lifecycle.active.take();
        Some(WatchCompletion {
            generation,
            backend,
            result,
            forced_abort,
        })
    }

    fn reconcile_join_result(
        &self,
        completion: &WatchCompletion,
        phase: &'static str,
    ) -> Result<(), RuntimeError> {
        if completion.forced_abort {
            return Err(RuntimeError::Worker(format!(
                "{phase}: {} watch missed its cancellation deadline and was force-aborted",
                completion.backend
            )));
        }
        match &completion.result {
            Ok(outcome) => outcome.clone(),
            Err(error) => {
                let failure = if error.is_cancelled() {
                    format!(
                        "{phase}: {} watch owner was cancelled before acknowledgement: {error}",
                        completion.backend
                    )
                } else {
                    format!(
                        "{phase}: {} watch owner panicked before acknowledgement: {error}",
                        completion.backend
                    )
                };
                tracing::error!(phase, backend = %completion.backend, %error, "Runtime generation task failed");
                Err(RuntimeError::Worker(failure))
            }
        }
    }

    /// Create a backend based on the configured kind.
    fn create_backend(&self) -> Result<Box<dyn RuntimeBackend>, RuntimeError> {
        match self.config.backend_kind {
            #[cfg(feature = "docker")]
            RuntimeBackendKind::Docker => {
                let backend = if let Some(ref path) = self.config.socket_path {
                    docker::DockerBackend::with_socket(path.clone())
                } else {
                    docker::DockerBackend::new()
                };
                Ok(Box::new(backend))
            }
            #[cfg(feature = "docker")]
            RuntimeBackendKind::Podman => {
                let backend = if let Some(ref path) = self.config.socket_path {
                    docker::DockerBackend::with_socket(path.clone())
                } else {
                    docker::DockerBackend::podman()
                };
                Ok(Box::new(backend))
            }
            RuntimeBackendKind::Auto => self.auto_detect_backend(),
            // When the `docker` feature is off, Docker/Podman join the same
            // not-compiled-in bucket as the stubbed backends below.
            #[cfg(not(feature = "docker"))]
            RuntimeBackendKind::Docker | RuntimeBackendKind::Podman => {
                Err(RuntimeError::BackendUnavailable(
                    "docker backend not compiled in — rebuild with the `docker` feature \
                     (koi-embedded: features = [\"docker\"]); the koi binary ships it by default"
                        .into(),
                ))
            }
        }
    }

    /// Auto-detect the best available backend.
    fn auto_detect_backend(&self) -> Result<Box<dyn RuntimeBackend>, RuntimeError> {
        #[cfg(all(feature = "docker", windows))]
        {
            // Windows named pipes have no reliable non-blocking stat operation.
            // Probe the Engine API directly under `RUNTIME_CONNECT_TIMEOUT` rather
            // than spawning an unbounded `docker info` child process.
            tracing::debug!("Probing Docker runtime through the local named pipe");
            Ok(Box::new(docker::DockerBackend::new()))
        }

        #[cfg(all(feature = "docker", unix))]
        {
            if docker::is_docker_available() {
                tracing::info!("Auto-detected Docker runtime");
                return Ok(Box::new(docker::DockerBackend::new()));
            }

            if docker::is_podman_available() {
                tracing::info!("Auto-detected Podman runtime");
                return Ok(Box::new(docker::DockerBackend::podman()));
            }

            Err(RuntimeError::BackendUnavailable(
                "no supported runtime detected (checked: Docker, Podman)".into(),
            ))
        }

        #[cfg(not(feature = "docker"))]
        {
            Err(RuntimeError::BackendUnavailable(
                "no runtime backend compiled in (build without the `docker` feature)".into(),
            ))
        }

        #[cfg(all(feature = "docker", not(any(unix, windows))))]
        {
            Err(RuntimeError::BackendUnavailable(
                "no supported runtime detected on this platform".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Clone, Copy)]
    enum HangAt {
        Connect,
        List,
    }

    struct HangingBackend(HangAt);

    #[async_trait::async_trait]
    impl RuntimeBackend for HangingBackend {
        fn name(&self) -> &'static str {
            "hanging-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            match self.0 {
                HangAt::Connect => std::future::pending().await,
                HangAt::List => Ok(()),
            }
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            match self.0 {
                HangAt::Connect => Ok(Vec::new()),
                HangAt::List => std::future::pending().await,
            }
        }

        async fn begin_observation(
            self: Arc<Self>,
            _tx: mpsc::Sender<RuntimeEvent>,
            cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            let instances = self.list_instances().await?;
            Ok(RuntimeObservation::new(instances, async move {
                cancel.cancelled().await;
                Ok(())
            }))
        }
    }

    struct ControlledBackend {
        watches: Arc<AtomicUsize>,
    }

    struct PanickingWatchBackend;

    #[async_trait::async_trait]
    impl RuntimeBackend for PanickingWatchBackend {
        fn name(&self) -> &'static str {
            "panicking-watch-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            Ok(Vec::new())
        }

        async fn begin_observation(
            self: Arc<Self>,
            _tx: mpsc::Sender<RuntimeEvent>,
            _cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            Ok(RuntimeObservation::new(Vec::new(), async move {
                panic!("injected backend watch panic")
            }))
        }
    }

    #[async_trait::async_trait]
    impl RuntimeBackend for ControlledBackend {
        fn name(&self) -> &'static str {
            "controlled-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            Ok(Vec::new())
        }

        async fn begin_observation(
            self: Arc<Self>,
            _tx: mpsc::Sender<RuntimeEvent>,
            cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            self.watches.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeObservation::new(Vec::new(), async move {
                cancel.cancelled().await;
                Ok(())
            }))
        }
    }

    struct BootstrapWindowBackend {
        armed: Arc<AtomicBool>,
        replayed: Instance,
    }

    #[async_trait::async_trait]
    impl RuntimeBackend for BootstrapWindowBackend {
        fn name(&self) -> &'static str {
            "bootstrap-window-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            Ok(Vec::new())
        }

        async fn begin_observation(
            self: Arc<Self>,
            tx: mpsc::Sender<RuntimeEvent>,
            cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            // The adapter establishes its replay boundary before acknowledging
            // the snapshot. The queued fact models a lifecycle change that
            // occurred after that boundary but before the empty snapshot ended.
            self.armed.store(true, Ordering::SeqCst);
            let replayed = self.replayed.clone();
            Ok(RuntimeObservation::new(Vec::new(), async move {
                if tx.send(RuntimeEvent::Started(replayed)).await.is_err() {
                    return Ok(());
                }
                cancel.cancelled().await;
                Ok(())
            }))
        }
    }

    struct GatedObservationBackend {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        armed: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RuntimeBackend for GatedObservationBackend {
        fn name(&self) -> &'static str {
            "gated-observation-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            Ok(Vec::new())
        }

        async fn begin_observation(
            self: Arc<Self>,
            _tx: mpsc::Sender<RuntimeEvent>,
            cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            self.entered.notify_one();
            self.release.notified().await;
            self.armed.store(true, Ordering::SeqCst);
            Ok(RuntimeObservation::new(Vec::new(), async move {
                cancel.cancelled().await;
                Ok(())
            }))
        }
    }

    struct WatchLease {
        live: Arc<AtomicUsize>,
    }

    impl WatchLease {
        fn acquire(live: Arc<AtomicUsize>, maximum: &AtomicUsize) -> Self {
            let current = live.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(current, Ordering::SeqCst);
            Self { live }
        }
    }

    impl Drop for WatchLease {
        fn drop(&mut self) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct TrackedBackend {
        starts: Arc<AtomicUsize>,
        live: Arc<AtomicUsize>,
        maximum: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl RuntimeBackend for TrackedBackend {
        fn name(&self) -> &'static str {
            "tracked-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            Ok(Vec::new())
        }

        async fn begin_observation(
            self: Arc<Self>,
            _tx: mpsc::Sender<RuntimeEvent>,
            cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            let live = Arc::clone(&self.live);
            let maximum = Arc::clone(&self.maximum);
            Ok(RuntimeObservation::new(Vec::new(), async move {
                let _lease = WatchLease::acquire(live, &maximum);
                cancel.cancelled().await;
                Ok(())
            }))
        }
    }

    struct WatchDropMarker(Arc<AtomicBool>);

    impl Drop for WatchDropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct UncooperativeBackend {
        entered: Arc<tokio::sync::Notify>,
        dropped: Arc<AtomicBool>,
    }

    struct ReleaseGatedBackend {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dropped: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RuntimeBackend for ReleaseGatedBackend {
        fn name(&self) -> &'static str {
            "release-gated-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            Ok(Vec::new())
        }

        async fn begin_observation(
            self: Arc<Self>,
            _tx: mpsc::Sender<RuntimeEvent>,
            _cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            let dropped = Arc::clone(&self.dropped);
            Ok(RuntimeObservation::new(Vec::new(), async move {
                let _drop_marker = WatchDropMarker(dropped);
                entered.notify_one();
                release.notified().await;
                Ok(())
            }))
        }
    }

    #[async_trait::async_trait]
    impl RuntimeBackend for UncooperativeBackend {
        fn name(&self) -> &'static str {
            "uncooperative-test"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<Instance>, RuntimeError> {
            Ok(Vec::new())
        }

        async fn begin_observation(
            self: Arc<Self>,
            _tx: mpsc::Sender<RuntimeEvent>,
            _cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            let entered = Arc::clone(&self.entered);
            let dropped = Arc::clone(&self.dropped);
            Ok(RuntimeObservation::new(Vec::new(), async move {
                let _drop_marker = WatchDropMarker(dropped);
                entered.notify_one();
                std::future::pending::<Result<(), RuntimeError>>().await
            }))
        }
    }

    async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while counter.load(Ordering::SeqCst) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("counter did not settle");
    }

    #[tokio::test]
    async fn backend_connection_is_bounded_at_the_runtime_boundary() {
        let mut backend = HangingBackend(HangAt::Connect);
        let error = connect_backend(&mut backend, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(matches!(error, RuntimeError::Connection(_)));
        assert!(error.to_string().contains("connection timed out"));
    }

    #[tokio::test]
    async fn initial_observation_is_bounded_at_the_runtime_boundary() {
        let backend: Arc<dyn RuntimeBackend> = Arc::new(HangingBackend(HangAt::List));
        let result = begin_backend_observation(
            backend,
            mpsc::channel(1).0,
            CancellationToken::new(),
            Duration::from_millis(10),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("hanging observation unexpectedly completed"),
            Err(error) => error,
        };
        assert!(matches!(error, RuntimeError::Connection(_)));
        assert!(error.to_string().contains("observation timed out"));
    }

    #[tokio::test]
    async fn runtime_core_default_status_is_inactive() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let status = core.status();
        assert!(!status.active);
        assert_eq!(status.state, RuntimeWatchState::Stopped);
        assert_eq!(status.instance_count, 0);
        assert!(status.backend.is_none());
        assert!(status.instances.is_empty());
    }

    #[tokio::test]
    async fn stop_noop_and_terminal_noop_have_stable_typed_acknowledgements() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let revision = core.status().revision;

        assert!(!core.stop_watching().await.unwrap());
        assert_eq!(core.status().revision, revision);

        assert!(!core.shutdown().await.unwrap());
        assert!(!core.shutdown().await.unwrap());
        assert_eq!(core.status().revision, revision);
        assert!(matches!(
            core.start_watching(CancellationToken::new()).await,
            Err(RuntimeError::ShutDown)
        ));
    }

    #[tokio::test]
    async fn panicking_lifecycle_operation_breaks_self_ownership_and_releases_waiters() {
        let completion = RuntimeOwnedCompletion::start(
            async { panic!("injected runtime transition panic") },
            "injected test",
        );
        let error = tokio::time::timeout(Duration::from_secs(1), completion.wait())
            .await
            .expect("contained transition released its waiter")
            .expect_err("panicking transition cannot acknowledge success");
        assert!(matches!(error, RuntimeError::Worker(_)));
        assert!(error.to_string().contains("panicked"));
        let repeated = completion
            .wait()
            .await
            .expect_err("every waiter observes the retained failure");
        assert_eq!(repeated.to_string(), error.to_string());
        let state = completion
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(state.outcome.is_some());
        assert!(state.task.is_none());
        drop(state);

        let weak = Arc::downgrade(&completion);
        drop(completion);
        assert!(weak.upgrade().is_none(), "temporary self-cycle was broken");
    }

    #[tokio::test]
    async fn panicking_backend_owner_returns_worker_error_and_retains_failed_status() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let mut events = core.subscribe();
        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(PanickingWatchBackend) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let finished = core
                    .lifecycle
                    .lock()
                    .await
                    .active
                    .as_ref()
                    .is_some_and(|active| active.task.is_finished());
                if finished {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("panicking backend owner did not finish");

        let error = core
            .stop_watching()
            .await
            .expect_err("panicking backend owner cannot acknowledge a clean stop");
        assert!(matches!(error, RuntimeError::Worker(_)));
        assert!(error.to_string().contains("panicked"));
        let status = core.status();
        assert_eq!(status.state, RuntimeWatchState::Failed);
        assert!(!status.active);
        assert!(status
            .backend_error
            .as_deref()
            .is_some_and(|reason| reason.contains("panicked")));
        assert!(matches!(
            events.recv().await.unwrap(),
            RuntimeEvent::BackendDisconnected { ref backend, ref reason }
                if backend == "panicking-watch-test" && reason.contains("panicked")
        ));

        let repeated = core
            .stop_watching()
            .await
            .expect_err("repeated stop observes retained worker failure");
        assert_eq!(repeated.to_string(), error.to_string());
        assert_eq!(core.status().revision, status.revision);
    }

    #[tokio::test]
    async fn one_owned_watch_generation_stops_with_status_before_event_and_can_restart() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let watches = Arc::new(AtomicUsize::new(0));
        let constructed = Arc::new(AtomicUsize::new(0));
        let mut events = core.subscribe();
        let cancel = CancellationToken::new();

        let factory = || {
            constructed.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(ControlledBackend {
                watches: Arc::clone(&watches),
            }) as Box<dyn RuntimeBackend>)
        };
        core.start_with_factory(cancel.clone(), factory)
            .await
            .unwrap();
        assert!(core.status().active);
        assert_eq!(core.status().state, RuntimeWatchState::Running);
        assert_eq!(watches.load(Ordering::SeqCst), 1);

        // A duplicate arm is a no-op and does not even construct a provider.
        core.start_with_factory(cancel.clone(), || {
            constructed.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(ControlledBackend {
                watches: Arc::clone(&watches),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        assert_eq!(constructed.load(Ordering::SeqCst), 1);

        tokio::time::timeout(Duration::from_secs(1), async {
            while watches.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancel.cancel();

        let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            RuntimeEvent::BackendStopped { ref backend } if backend == "controlled-test"
        ));
        assert!(!core.status().active);
        assert_eq!(core.status().state, RuntimeWatchState::Stopped);
        assert!(core.status().backend_error.is_none());
        let terminal_revision = core.status().revision;
        assert!(core.stop_watching().await.unwrap());
        assert_eq!(core.status().revision, terminal_revision);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), events.recv())
                .await
                .is_err(),
            "reaping an already-published clean completion must not emit it twice"
        );

        let second_cancel = CancellationToken::new();
        core.start_with_factory(second_cancel.clone(), || {
            Ok(Box::new(ControlledBackend {
                watches: Arc::clone(&watches),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        assert!(core.status().active);
        assert!(core.stop_watching().await.unwrap());
    }

    #[tokio::test]
    async fn bootstrap_window_event_is_replayed_after_running_is_armed() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let armed = Arc::new(AtomicBool::new(false));
        let replayed = Instance {
            id: "during-bootstrap".into(),
            name: "replayed-service".into(),
            ports: vec![],
            ips: vec!["127.0.0.1".into()],
            metadata: KoiMetadata::default(),
            backend: "bootstrap-window-test".into(),
            state: InstanceState::Running,
            discovered_at: chrono::Utc::now(),
            image: None,
        };
        let mut events = core.subscribe();
        let cancel = CancellationToken::new();

        core.start_with_factory(cancel.clone(), || {
            Ok(Box::new(BootstrapWindowBackend {
                armed: Arc::clone(&armed),
                replayed: replayed.clone(),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();

        assert!(armed.load(Ordering::SeqCst));
        assert_eq!(core.status().state, RuntimeWatchState::Running);
        let event = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("replayed bootstrap event timeout")
            .unwrap();
        assert!(matches!(
            event,
            RuntimeEvent::Started(ref instance) if instance.id == "during-bootstrap"
        ));
        let status = core.status();
        assert_eq!(status.instance_count, 1);
        assert_eq!(status.instances[0].id, "during-bootstrap");

        assert!(core.stop_watching().await.unwrap());
    }

    #[tokio::test]
    async fn running_is_not_published_before_the_observation_handshake() {
        let core = Arc::new(RuntimeCore::new(RuntimeConfig::default()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let armed = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let starting_core = Arc::clone(&core);
        let backend_entered = Arc::clone(&entered);
        let backend_release = Arc::clone(&release);
        let backend_armed = Arc::clone(&armed);
        let start_cancel = cancel.clone();
        let start = tokio::spawn(async move {
            starting_core
                .start_with_factory(start_cancel, || {
                    Ok(Box::new(GatedObservationBackend {
                        entered: backend_entered,
                        release: backend_release,
                        armed: backend_armed,
                    }) as Box<dyn RuntimeBackend>)
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("observation handshake was not entered");
        assert_eq!(core.status().state, RuntimeWatchState::Reconciling);
        assert!(!core.status().active);
        assert!(!armed.load(Ordering::SeqCst));

        release.notify_one();
        start.await.unwrap().unwrap();
        assert!(armed.load(Ordering::SeqCst));
        assert_eq!(core.status().state, RuntimeWatchState::Running);
        assert!(core.status().active);

        assert!(core.stop_watching().await.unwrap());
    }

    #[tokio::test]
    async fn aborted_startup_publishes_terminal_status_and_can_restart() {
        let core = Arc::new(RuntimeCore::new(RuntimeConfig::default()));
        let mut status = core.watch_status();
        let mut events = core.subscribe();
        let starting_core = Arc::clone(&core);
        let task = tokio::spawn(async move {
            starting_core
                .start_with_factory(CancellationToken::new(), || {
                    Ok(Box::new(HangingBackend(HangAt::Connect)) as Box<dyn RuntimeBackend>)
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), status.changed())
            .await
            .expect("connecting status timeout")
            .unwrap();
        assert_eq!(
            status.borrow_and_update().state,
            RuntimeWatchState::Connecting
        );
        task.abort();
        let _ = task.await;

        tokio::time::timeout(Duration::from_secs(1), status.changed())
            .await
            .expect("cancelled startup status timeout")
            .unwrap();
        assert_eq!(status.borrow_and_update().state, RuntimeWatchState::Failed);
        assert!(core
            .status()
            .backend_error
            .as_deref()
            .is_some_and(|reason| reason.contains("cancelled")));
        assert!(matches!(
            events.recv().await.unwrap(),
            RuntimeEvent::BackendDisconnected { ref reason, .. } if reason.contains("cancelled")
        ));

        let cancel = CancellationToken::new();
        core.start_with_factory(cancel.clone(), || {
            Ok(Box::new(ControlledBackend {
                watches: Arc::new(AtomicUsize::new(0)),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        assert_eq!(core.status().state, RuntimeWatchState::Running);
        assert!(core.stop_watching().await.unwrap());
    }

    #[tokio::test]
    async fn stopped_truth_is_published_only_after_the_watcher_is_reaped() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(ReleaseGatedBackend {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                dropped: Arc::clone(&dropped),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("watch was not polled");
        let mut status = core.watch_status();
        status.borrow_and_update();

        let stop = core.stop_watching_with_timeout(Duration::from_secs(1));
        tokio::pin!(stop);
        tokio::time::timeout(Duration::from_secs(1), status.changed())
            .await
            .expect("stopping status timeout")
            .unwrap();
        let stopping = status.borrow_and_update().clone();
        assert_eq!(stopping.state, RuntimeWatchState::Stopping);
        assert!(stopping.active);
        assert!(!dropped.load(Ordering::SeqCst));

        release.notify_one();
        assert!(stop.await.unwrap());
        assert!(dropped.load(Ordering::SeqCst));
        let stopped = core.status();
        assert_eq!(stopped.state, RuntimeWatchState::Stopped);
        assert!(!stopped.active);
    }

    #[tokio::test]
    async fn bounded_stop_aborts_and_reaps_an_uncooperative_watch() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let mut events = core.subscribe();

        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(UncooperativeBackend {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("uncooperative watch was not polled");

        let error = core
            .stop_watching_with_timeout(Duration::from_millis(10))
            .await
            .expect_err("forced abort cannot acknowledge a clean stop");
        assert!(matches!(error, RuntimeError::Worker(_)));
        assert!(error.to_string().contains("force-aborted"));

        let status = core.status();
        assert!(!status.active);
        assert_eq!(status.state, RuntimeWatchState::Failed);
        assert!(status
            .backend_error
            .as_deref()
            .is_some_and(|reason| reason.contains("force-aborted")));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(core.lifecycle.lock().await.active.is_none());
        assert!(matches!(
            events.recv().await.unwrap(),
            RuntimeEvent::BackendDisconnected { ref backend, ref reason }
                if backend == "uncooperative-test" && reason.contains("force-aborted")
        ));

        let stopped_revision = status.revision;
        let repeated = core
            .stop_watching_with_timeout(Duration::from_millis(10))
            .await
            .expect_err("a repeated stop observes the retained worker failure");
        assert!(repeated.to_string().contains("force-aborted"));
        assert_eq!(core.status().revision, stopped_revision);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), events.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn dropping_a_failed_stop_waiter_still_reaps_and_retains_failure_until_restart() {
        let core = Arc::new(RuntimeCore::new(RuntimeConfig::default()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));

        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(UncooperativeBackend {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("uncooperative watch was not polled");

        let waiter = core.stop_watching_with_timeout(Duration::from_millis(10));
        drop(waiter);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("self-owned stop did not reap the watcher");
        assert!(dropped.load(Ordering::SeqCst));
        assert!(core.lifecycle.lock().await.active.is_none());
        assert_eq!(core.status().state, RuntimeWatchState::Failed);
        assert!(core
            .status()
            .backend_error
            .as_deref()
            .is_some_and(|reason| reason.contains("force-aborted")));

        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(ControlledBackend {
                watches: Arc::new(AtomicUsize::new(0)),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .expect("restart after a completed stop");
        assert_eq!(core.status().state, RuntimeWatchState::Running);
        assert!(core.stop_watching().await.unwrap());
    }

    #[tokio::test]
    async fn dropping_a_shutdown_waiter_still_terminally_reaps_and_rejects_commands() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let watches = Arc::new(AtomicUsize::new(0));
        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(ControlledBackend {
                watches: Arc::clone(&watches),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();

        let waiter = core.shutdown();
        drop(waiter);
        tokio::time::timeout(Duration::from_secs(1), async {
            while core.lifecycle.lock().await.active.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("self-owned terminal transaction did not reap the watcher");
        let start = core
            .start_with_factory(CancellationToken::new(), || {
                Ok(Box::new(ControlledBackend {
                    watches: Arc::new(AtomicUsize::new(0)),
                }) as Box<dyn RuntimeBackend>)
            })
            .await;
        assert!(matches!(start, Err(RuntimeError::ShutDown)));
        assert!(matches!(
            core.ingest_test_event(RuntimeEvent::BackendReconnected {
                backend: "late".into(),
            })
            .await,
            Err(RuntimeError::ShutDown)
        ));

        // Repeated shutdown observes the same terminal completion.
        assert!(core.shutdown().await.unwrap());
    }

    #[tokio::test]
    async fn dropped_terminal_failure_waiter_preserves_one_outcome_for_later_callers() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(UncooperativeBackend {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("uncooperative watch was not polled");

        let waiter = core.shutdown_with_timeout(Duration::from_millis(10));
        drop(waiter);
        tokio::time::timeout(Duration::from_secs(1), async {
            while core.status().state != RuntimeWatchState::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal owner did not retain its failed settlement");

        assert!(dropped.load(Ordering::SeqCst));
        assert!(core.lifecycle.lock().await.active.is_none());
        let failed = core.status();
        assert!(failed
            .backend_error
            .as_deref()
            .is_some_and(|reason| reason.contains("force-aborted")));

        let error = core
            .shutdown_with_timeout(Duration::from_secs(1))
            .await
            .expect_err("later terminal waiter observes the retained failure");
        assert!(matches!(error, RuntimeError::Worker(_)));
        assert!(error.to_string().contains("force-aborted"));
        assert_eq!(core.status().revision, failed.revision);
        assert!(matches!(
            core.start_watching(CancellationToken::new()).await,
            Err(RuntimeError::ShutDown)
        ));
    }

    #[tokio::test]
    async fn terminal_shutdown_wins_a_concurrent_reconciling_start() {
        let core = Arc::new(RuntimeCore::new(RuntimeConfig::default()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let armed = Arc::new(AtomicBool::new(false));
        let starting_core = Arc::clone(&core);
        let backend_entered = Arc::clone(&entered);
        let backend_release = Arc::clone(&release);
        let backend_armed = Arc::clone(&armed);
        let starting = tokio::spawn(async move {
            starting_core
                .start_with_factory(CancellationToken::new(), || {
                    Ok(Box::new(GatedObservationBackend {
                        entered: backend_entered,
                        release: backend_release,
                        armed: backend_armed,
                    }) as Box<dyn RuntimeBackend>)
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("reconciling start was not admitted");
        assert!(core.shutdown().await.unwrap());
        assert!(starting.await.unwrap().is_err());
        assert!(!armed.load(Ordering::SeqCst));
        assert!(core.lifecycle.lock().await.active.is_none());
        assert!(matches!(
            core.start_watching(CancellationToken::new()).await,
            Err(RuntimeError::ShutDown)
        ));
    }

    #[tokio::test]
    async fn terminal_shutdown_drains_an_already_admitted_restartable_stop() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(ReleaseGatedBackend {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
                dropped: Arc::clone(&dropped),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("watch was not polled");

        let stop = core.stop_watching_with_timeout(Duration::from_secs(1));
        drop(stop);
        tokio::time::timeout(Duration::from_secs(1), async {
            while core.status().state != RuntimeWatchState::Stopping {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("restartable stop was not admitted");

        let shutdown = core.shutdown();
        tokio::pin!(shutdown);
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut shutdown)
                .await
                .is_err(),
            "terminal completion must wait for the admitted stop owner"
        );
        assert!(!dropped.load(Ordering::SeqCst));

        release.notify_one();
        assert!(tokio::time::timeout(Duration::from_secs(1), &mut shutdown)
            .await
            .expect("terminal completion after stop release")
            .unwrap());
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(core.status().state, RuntimeWatchState::Stopped);
    }

    #[tokio::test]
    async fn stop_and_restart_never_overlap_owned_watch_generations() {
        let core = Arc::new(RuntimeCore::new(RuntimeConfig::default()));
        let starts = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));

        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(TrackedBackend {
                starts: Arc::clone(&starts),
                live: Arc::clone(&live),
                maximum: Arc::clone(&maximum),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        wait_for_count(&live, 1).await;

        let mut status = core.watch_status();
        let stopping_core = Arc::clone(&core);
        let stopping = tokio::spawn(async move { stopping_core.stop_watching().await });
        tokio::time::timeout(Duration::from_secs(1), status.changed())
            .await
            .expect("stop transition status timeout")
            .unwrap();
        assert!(matches!(
            status.borrow_and_update().state,
            RuntimeWatchState::Stopping | RuntimeWatchState::Stopped
        ));

        let starting_core = Arc::clone(&core);
        let restart_starts = Arc::clone(&starts);
        let restart_live = Arc::clone(&live);
        let restart_maximum = Arc::clone(&maximum);
        let restarting = tokio::spawn(async move {
            starting_core
                .start_with_factory(CancellationToken::new(), || {
                    Ok(Box::new(TrackedBackend {
                        starts: restart_starts,
                        live: restart_live,
                        maximum: restart_maximum,
                    }) as Box<dyn RuntimeBackend>)
                })
                .await
        });

        assert!(stopping.await.unwrap().unwrap());
        restarting.await.unwrap().unwrap();
        wait_for_count(&live, 1).await;
        assert_eq!(starts.load(Ordering::SeqCst), 2);
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
        assert_eq!(core.status().state, RuntimeWatchState::Running);

        assert!(core.stop_watching().await.unwrap());
        wait_for_count(&live, 0).await;
    }

    #[tokio::test]
    async fn concurrent_starts_share_one_owned_watch_generation() {
        let core = Arc::new(RuntimeCore::new(RuntimeConfig::default()));
        let starts = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let constructed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut callers = Vec::new();

        for _ in 0..2 {
            let caller_core = Arc::clone(&core);
            let caller_starts = Arc::clone(&starts);
            let caller_live = Arc::clone(&live);
            let caller_maximum = Arc::clone(&maximum);
            let caller_constructed = Arc::clone(&constructed);
            let caller_barrier = Arc::clone(&barrier);
            callers.push(tokio::spawn(async move {
                caller_barrier.wait().await;
                caller_core
                    .start_with_factory(CancellationToken::new(), || {
                        caller_constructed.fetch_add(1, Ordering::SeqCst);
                        Ok(Box::new(TrackedBackend {
                            starts: caller_starts,
                            live: caller_live,
                            maximum: caller_maximum,
                        }) as Box<dyn RuntimeBackend>)
                    })
                    .await
            }));
        }

        barrier.wait().await;
        for caller in callers {
            caller.await.unwrap().unwrap();
        }
        wait_for_count(&live, 1).await;
        assert_eq!(constructed.load(Ordering::SeqCst), 1);
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
        assert_eq!(core.status().state, RuntimeWatchState::Running);

        assert!(core.stop_watching().await.unwrap());
        wait_for_count(&live, 0).await;
    }

    #[tokio::test]
    async fn aborted_reconciling_start_terminalizes_and_can_restart() {
        let core = Arc::new(RuntimeCore::new(RuntimeConfig::default()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let armed = Arc::new(AtomicBool::new(false));
        let starting_core = Arc::clone(&core);
        let backend_entered = Arc::clone(&entered);
        let backend_release = Arc::clone(&release);
        let backend_armed = Arc::clone(&armed);
        let starting = tokio::spawn(async move {
            starting_core
                .start_with_factory(CancellationToken::new(), || {
                    Ok(Box::new(GatedObservationBackend {
                        entered: backend_entered,
                        release: backend_release,
                        armed: backend_armed,
                    }) as Box<dyn RuntimeBackend>)
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("observation handshake was not entered");
        assert_eq!(core.status().state, RuntimeWatchState::Reconciling);
        starting.abort();
        let _ = starting.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            while core.status().state != RuntimeWatchState::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled reconciliation did not terminalize");
        assert!(!armed.load(Ordering::SeqCst));
        assert!(core
            .status()
            .backend_error
            .as_deref()
            .is_some_and(|reason| reason.contains("cancelled")));

        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(ControlledBackend {
                watches: Arc::new(AtomicUsize::new(0)),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        assert_eq!(core.status().state, RuntimeWatchState::Running);
        assert!(core.stop_watching().await.unwrap());
    }

    #[tokio::test]
    async fn explicit_stop_during_reconciliation_wins_without_a_stale_failure() {
        let core = Arc::new(RuntimeCore::new(RuntimeConfig::default()));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let armed = Arc::new(AtomicBool::new(false));
        let starting_core = Arc::clone(&core);
        let backend_entered = Arc::clone(&entered);
        let backend_release = Arc::clone(&release);
        let backend_armed = Arc::clone(&armed);
        let starting = tokio::spawn(async move {
            starting_core
                .start_with_factory(CancellationToken::new(), || {
                    Ok(Box::new(GatedObservationBackend {
                        entered: backend_entered,
                        release: backend_release,
                        armed: backend_armed,
                    }) as Box<dyn RuntimeBackend>)
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("observation handshake was not entered");
        assert_eq!(core.status().state, RuntimeWatchState::Reconciling);

        assert!(core
            .stop_watching_with_timeout(Duration::from_millis(10))
            .await
            .unwrap());
        assert!(starting.await.unwrap().is_err());
        assert!(!armed.load(Ordering::SeqCst));
        let status = core.status();
        assert_eq!(status.state, RuntimeWatchState::Stopped);
        assert!(status.backend_error.is_none());
        assert!(core.lifecycle.lock().await.active.is_none());

        core.start_with_factory(CancellationToken::new(), || {
            Ok(Box::new(ControlledBackend {
                watches: Arc::new(AtomicUsize::new(0)),
            }) as Box<dyn RuntimeBackend>)
        })
        .await
        .unwrap();
        assert_eq!(core.status().state, RuntimeWatchState::Running);
        assert!(core.stop_watching().await.unwrap());
    }

    // With the `docker` feature off, selecting Docker resolves to BackendUnavailable
    // (create_backend errors before any connect), naming the missing feature.
    #[cfg(not(feature = "docker"))]
    #[tokio::test]
    async fn docker_backend_unavailable_without_feature() {
        let core = RuntimeCore::new(RuntimeConfig {
            backend_kind: RuntimeBackendKind::Docker,
            ..Default::default()
        });
        let err = core
            .start_watching(CancellationToken::new())
            .await
            .expect_err("docker backend must be unavailable without the feature");
        assert!(matches!(err, RuntimeError::BackendUnavailable(_)));
        assert!(err.to_string().contains("docker"));
    }

    #[tokio::test]
    async fn list_instances_empty_by_default() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let instances = core.list_instances().await.unwrap();
        assert!(instances.is_empty());
    }

    #[tokio::test]
    async fn test_transition_hook_uses_the_single_inventory_and_fanout_path() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let mut events = core.subscribe();
        let mut instance = Instance {
            id: "synthetic-1".into(),
            name: "before".into(),
            ports: vec![],
            ips: vec![],
            metadata: KoiMetadata::default(),
            backend: "custom".into(),
            state: InstanceState::Running,
            discovered_at: chrono::Utc::now(),
            image: None,
        };

        core.ingest_test_event(RuntimeEvent::Started(instance.clone()))
            .await
            .unwrap();
        assert!(matches!(events.recv().await, Ok(RuntimeEvent::Started(_))));
        assert_eq!(core.list_instances().await.unwrap()[0].name, "before");

        instance.name = "after".into();
        core.ingest_test_event(RuntimeEvent::Updated(instance.clone()))
            .await
            .unwrap();
        assert!(matches!(events.recv().await, Ok(RuntimeEvent::Updated(_))));
        assert_eq!(core.list_instances().await.unwrap()[0].name, "after");

        core.ingest_test_event(RuntimeEvent::Stopped {
            id: instance.id,
            name: instance.name,
        })
        .await
        .unwrap();
        assert!(matches!(
            events.recv().await,
            Ok(RuntimeEvent::Stopped { .. })
        ));
        assert!(core.list_instances().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn backend_connectivity_events_drive_health_at_the_ingest_chokepoint() {
        let core = RuntimeCore::new(RuntimeConfig::default());

        core.ingest_test_event(RuntimeEvent::BackendDisconnected {
            backend: "docker".into(),
            reason: "event stream ended".into(),
        })
        .await
        .unwrap();
        assert!(!core.status().active);
        assert_eq!(core.status().backend.as_deref(), Some("docker"));
        assert_eq!(
            core.status().backend_error.as_deref(),
            Some("event stream ended")
        );

        core.ingest_test_event(RuntimeEvent::BackendReconnected {
            backend: "docker".into(),
        })
        .await
        .unwrap();
        assert!(core.status().active);
        assert!(core.status().backend_error.is_none());
    }

    #[tokio::test]
    async fn status_feed_contains_inventory_and_suppresses_duplicate_events() {
        let core = RuntimeCore::new(RuntimeConfig::default());
        let mut status_rx = core.watch_status();
        let initial = core.status();
        assert_eq!(initial.revision, 0);
        assert_eq!(status_rx.borrow().revision, 0);

        let instance = Instance {
            id: "b".into(),
            name: "worker".into(),
            ports: vec![],
            ips: vec!["127.0.0.1".into()],
            metadata: KoiMetadata::default(),
            backend: "custom".into(),
            state: InstanceState::Running,
            discovered_at: chrono::Utc::now(),
            image: Some("example/worker:latest".into()),
        };
        core.ingest_test_event(RuntimeEvent::Started(instance.clone()))
            .await
            .unwrap();
        status_rx.changed().await.unwrap();
        let started = status_rx.borrow_and_update().clone();
        assert_eq!(started.revision, 1);
        assert_eq!(started.instance_count, 1);
        assert_eq!(started.instances, vec![instance.clone()]);

        let mut replay = instance;
        replay.discovered_at += chrono::TimeDelta::seconds(1);
        core.ingest_test_event(RuntimeEvent::Started(replay))
            .await
            .unwrap();
        assert!(status_rx.has_changed().is_ok_and(|changed| !changed));

        core.ingest_test_event(RuntimeEvent::Stopped {
            id: "missing".into(),
            name: "missing".into(),
        })
        .await
        .unwrap();
        assert!(status_rx.has_changed().is_ok_and(|changed| !changed));
    }

    #[test]
    fn runtime_status_wire_round_trips() {
        let status = RuntimeStatus {
            revision: 4,
            active: false,
            state: RuntimeWatchState::Failed,
            backend: Some("docker".into()),
            backend_error: Some("socket closed".into()),
            instance_count: 0,
            instances: Vec::new(),
        };
        let encoded = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<RuntimeStatus>(&encoded).unwrap(),
            status
        );
    }

    #[test]
    fn auto_backend_kind_display() {
        assert_eq!(RuntimeBackendKind::Auto.to_string(), "auto");
        assert_eq!(RuntimeBackendKind::Docker.to_string(), "docker");
    }

    #[test]
    fn backend_kind_from_str() {
        assert_eq!(
            RuntimeBackendKind::from_str_loose("docker"),
            Some(RuntimeBackendKind::Docker)
        );
        assert_eq!(
            RuntimeBackendKind::from_str_loose("podman"),
            Some(RuntimeBackendKind::Podman)
        );
        assert_eq!(
            RuntimeBackendKind::from_str_loose("auto"),
            Some(RuntimeBackendKind::Auto)
        );
        // Removed stub backends are now rejected (no silent fallback).
        assert_eq!(RuntimeBackendKind::from_str_loose("k8s"), None);
        assert_eq!(RuntimeBackendKind::from_str_loose("systemd"), None);
        assert_eq!(RuntimeBackendKind::from_str_loose("incus"), None);
        assert_eq!(RuntimeBackendKind::from_str_loose("unknown"), None);
    }
}
