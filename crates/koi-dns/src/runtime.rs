use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures_util::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot, watch, Mutex, Notify};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::resolver::{DnsCatalogSnapshot, DnsCore, DnsEntryScope, DnsError, DnsLookupResult};
use crate::DnsEntry;

const RETRY_INTERVAL: Duration = Duration::from_secs(2);
const INTERFACE_PROBE_INTERVAL: Duration = Duration::from_secs(5);
const DNS_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IN_FLIGHT_LIFECYCLE_COMMANDS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsRuntimeState {
    Stopped,
    Reconciling,
    Running,
    Waiting,
}

/// Rich desired-state projection for operators and adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DnsRuntimeStatus {
    /// Monotonic snapshot revision. It advances only when another field changes.
    #[serde(default)]
    pub revision: u64,
    /// Causal fence for the domain's specialized catalog projection. It stays
    /// internal to the Rust boundary: wire consumers read the catalog itself,
    /// while composition uses it to capture a non-torn pair without waiting on
    /// the command/persistence lock.
    #[serde(skip)]
    #[schema(ignore)]
    pub(crate) catalog_revision: u64,
    /// Backward-compatible convenience field.
    pub running: bool,
    pub desired: bool,
    pub state: DnsRuntimeState,
    pub endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub zone: String,
    pub port: u16,
    pub records: DnsRecordSummary,
}

impl DnsRuntimeStatus {
    pub(crate) fn stopped(config: &crate::DnsConfig, records: DnsRecordSummary) -> Self {
        Self {
            revision: 0,
            catalog_revision: 0,
            running: false,
            desired: false,
            state: DnsRuntimeState::Stopped,
            endpoints: Vec::new(),
            reason: None,
            zone: config.zone.clone(),
            port: config.port,
            records,
        }
    }
}

/// Bounded summary of the effective DNS record sources.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DnsRecordSummary {
    pub static_entries: usize,
    pub certmesh_entries: usize,
    pub mdns_entries: usize,
    pub txt_names: usize,
}

struct RunHandle {
    generation: u64,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct BackgroundTask {
    name: &'static str,
    task: JoinHandle<()>,
}

struct DnsLifecycle {
    generation: u64,
    active: Option<RunHandle>,
    background: Vec<BackgroundTask>,
    shutting_down: bool,
}

/// Bounded owner for restartable lifecycle commands and the one terminal
/// transaction. Requesters own only reply waiters; admitted work retains the
/// runtime through settlement. Terminal election closes future admission and
/// publishes one shared completion to all shutdown callers.
struct DnsLifecycleTasks {
    tasks: std::sync::Mutex<Vec<JoinHandle<()>>>,
    admission: Arc<DnsLifecycleAdmission>,
    terminal: Arc<DnsTerminalState>,
}

struct DnsLifecycleAdmissionState {
    accepting: bool,
    in_flight: usize,
}

struct DnsLifecycleAdmission {
    capacity: Arc<tokio::sync::Semaphore>,
    state: std::sync::Mutex<DnsLifecycleAdmissionState>,
    idle: Notify,
}

struct DnsLifecyclePermit {
    admission: Arc<DnsLifecycleAdmission>,
    _capacity: tokio::sync::OwnedSemaphorePermit,
}

struct DnsTerminalState {
    outcome: std::sync::Mutex<Option<Option<String>>>,
    shutdown_changed: Notify,
}

impl DnsLifecycleTasks {
    fn new() -> Self {
        Self {
            tasks: std::sync::Mutex::new(Vec::new()),
            admission: Arc::new(DnsLifecycleAdmission {
                capacity: Arc::new(tokio::sync::Semaphore::new(
                    MAX_IN_FLIGHT_LIFECYCLE_COMMANDS,
                )),
                state: std::sync::Mutex::new(DnsLifecycleAdmissionState {
                    accepting: true,
                    in_flight: 0,
                }),
                idle: Notify::new(),
            }),
            terminal: Arc::new(DnsTerminalState {
                outcome: std::sync::Mutex::new(None),
                shutdown_changed: Notify::new(),
            }),
        }
    }

    async fn admit(&self) -> Option<DnsLifecyclePermit> {
        self.admission.clone().admit().await
    }

    fn begin_shutdown(&self) -> bool {
        self.admission.begin_shutdown()
    }

    fn is_shutting_down(&self) -> bool {
        self.admission.is_shutting_down()
    }

    fn retain(&self, task: JoinHandle<()>) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }

    fn abort_all(&self) {
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

impl DnsLifecycleAdmission {
    async fn admit(self: Arc<Self>) -> Option<DnsLifecyclePermit> {
        if !self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepting
        {
            return None;
        }
        let capacity = Arc::clone(&self.capacity).acquire_owned().await.ok()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.accepting {
            return None;
        }
        state.in_flight = state.in_flight.saturating_add(1);
        drop(state);
        Some(DnsLifecyclePermit {
            admission: self,
            _capacity: capacity,
        })
    }

    fn begin_shutdown(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.accepting {
            return false;
        }
        state.accepting = false;
        self.capacity.close();
        if state.in_flight == 0 {
            self.idle.notify_waiters();
        }
        true
    }

    fn is_shutting_down(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepting
    }

    async fn wait_idle(&self) {
        loop {
            let idle = self.idle.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .in_flight
                == 0
            {
                return;
            }
            idle.await;
        }
    }
}

impl Drop for DnsLifecyclePermit {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        if !state.accepting && state.in_flight == 0 {
            self.admission.idle.notify_waiters();
        }
    }
}

impl DnsTerminalState {
    fn finish(&self, failure: Option<String>) {
        let mut outcome = self
            .outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if outcome.is_none() {
            *outcome = Some(failure);
            drop(outcome);
            self.shutdown_changed.notify_waiters();
        }
    }

    async fn wait(&self) -> Option<String> {
        loop {
            let changed = self.shutdown_changed.notified();
            if let Some(outcome) = self
                .outcome
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
            {
                return outcome;
            }
            changed.await;
        }
    }
}

impl Drop for DnsLifecycleTasks {
    fn drop(&mut self) {
        self.abort_all();
    }
}

struct DnsRuntimeInner {
    core: Arc<DnsCore>,
    control: Mutex<DnsLifecycle>,
    generation_fence: Arc<AtomicU64>,
    infrastructure_cancel: CancellationToken,
    #[cfg(test)]
    panic_next_stop: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    panic_next_shutdown: std::sync::atomic::AtomicBool,
}

/// Desired-state DNS listener controller.
///
/// A requested listener remains armed through address contention and interface
/// changes. Manual stop is the only operation that clears desire and retry.
#[derive(Clone)]
pub struct DnsRuntime {
    inner: Arc<DnsRuntimeInner>,
    lifecycle_tasks: Arc<DnsLifecycleTasks>,
}

/// Process-local ownership of one exact ephemeral TXT value.
///
/// The DNS domain accepts the value before construction returns and removes it
/// synchronously on drop. Composition supervisors can therefore be aborted at
/// any await without leaking their descriptor into a still-running DNS core.
pub struct DnsTxtLease {
    core: Arc<DnsCore>,
    name: String,
    value: String,
}

impl Drop for DnsTxtLease {
    fn drop(&mut self) {
        self.core.remove_txt_value(&self.name, &self.value);
    }
}

impl DnsRuntime {
    pub fn new(mut core: DnsCore) -> Self {
        let alias_feedback = core.prepare_alias_feedback();
        let core = Arc::new(core);
        let infrastructure_cancel = CancellationToken::new();
        let mut background = Vec::new();

        if let Some(mdns) = core.mdns_input() {
            let mut input = mdns.watch_snapshot();
            // Subscribe before refreshing so no upstream transition can fall
            // between the initial projection and observer registration.
            core.accept_mdns_snapshot(input.borrow_and_update().clone());
            let weak = Arc::downgrade(&core);
            let cancel = infrastructure_cancel.child_token();
            background.push(BackgroundTask {
                name: "mDNS input observer",
                task: tokio::spawn(observe_mdns(weak, input, cancel)),
            });
        }
        if let Some(certmesh) = core.certmesh_input() {
            let mut input = certmesh.watch_snapshot();
            core.accept_certmesh_snapshot(input.borrow_and_update().clone());
            let weak = Arc::downgrade(&core);
            let cancel = infrastructure_cancel.child_token();
            background.push(BackgroundTask {
                name: "Certmesh input observer",
                task: tokio::spawn(observe_certmesh(weak, input, cancel)),
            });
        }
        if let Some(worker) = alias_feedback {
            let cancel = infrastructure_cancel.child_token();
            background.push(BackgroundTask {
                name: "alias feedback",
                task: tokio::spawn(worker.run(cancel)),
            });
        }

        Self {
            inner: Arc::new(DnsRuntimeInner {
                core,
                control: Mutex::new(DnsLifecycle {
                    generation: 0,
                    active: None,
                    background,
                    shutting_down: false,
                }),
                generation_fence: Arc::new(AtomicU64::new(0)),
                infrastructure_cancel,
                #[cfg(test)]
                panic_next_stop: std::sync::atomic::AtomicBool::new(false),
                #[cfg(test)]
                panic_next_shutdown: std::sync::atomic::AtomicBool::new(false),
            }),
            lifecycle_tasks: Arc::new(DnsLifecycleTasks::new()),
        }
    }

    pub fn core(&self) -> Arc<DnsCore> {
        Arc::clone(&self.inner.core)
    }

    /// Normalize a candidate name against this runtime's authoritative zone.
    pub fn normalize_name(&self, name: &str) -> Option<String> {
        self.inner.core.normalize_name(name)
    }

    /// Resolve from the effective local record model without exposing the core.
    pub fn resolve_local(
        &self,
        name: &str,
        record_type: hickory_proto::rr::RecordType,
    ) -> Option<DnsLookupResult> {
        self.inner.core.resolve_local(name, record_type)
    }

    /// Resolve through the full DNS policy without exposing the core.
    pub async fn lookup(
        &self,
        name: &str,
        record_type: hickory_proto::rr::RecordType,
    ) -> Result<Option<DnsLookupResult>, DnsError> {
        self.inner.core.lookup(name, record_type).await
    }

    /// Return the sorted effective DNS names through the runtime boundary.
    pub fn list_names(&self) -> Vec<String> {
        self.inner.core.list_names()
    }

    /// Return durable operator entries through the runtime boundary.
    pub fn list_entries(&self) -> Vec<DnsEntry> {
        self.inner.core.list_entries()
    }

    /// Capture the complete effective record model through the runtime boundary.
    pub fn records_snapshot(&self) -> crate::records::RecordsSnapshot {
        self.inner.core.snapshot()
    }

    /// Persist an operator-managed static entry.
    pub fn add_entry(&self, entry: DnsEntry) -> Result<Vec<DnsEntry>, DnsError> {
        self.inner.core.add_entry(entry)
    }

    /// Remove an operator-managed static entry.
    pub fn remove_entry(&self, name: &str) -> Result<Option<Vec<DnsEntry>>, DnsError> {
        self.inner.core.remove_entry(name)
    }

    /// Atomically replace one transient producer's complete static-entry set.
    pub fn replace_scoped_entries(
        &self,
        scope: DnsEntryScope,
        entries: Vec<DnsEntry>,
    ) -> Result<(), DnsError> {
        self.inner.core.replace_scoped_entries(scope, entries)
    }

    /// Validate one prospective transient entry using DNS-owned zone and
    /// address rules without mutating the accepted desired set.
    pub fn validate_scoped_entry(&self, entry: &DnsEntry) -> Result<(), DnsError> {
        self.inner
            .core
            .normalize_scoped_entries(vec![entry.clone()])
            .map(|_| ())
    }

    /// Read an exact ephemeral TXT owner through the runtime facade.
    pub fn get_txt(&self, name: &str) -> Vec<String> {
        self.inner.core.get_txt(name)
    }

    /// Publish a runtime-owned ephemeral TXT value. This command form remains
    /// live until an explicit matching removal or runtime teardown.
    pub fn set_txt(&self, name: &str, value: &str) {
        self.inner.core.add_txt(name, value);
    }

    /// Remove one exact runtime-owned ephemeral TXT value.
    pub fn remove_txt_value(&self, name: &str, value: &str) -> bool {
        self.inner.core.remove_txt_value(name, value)
    }

    /// Publish one exact ephemeral TXT value and return its synchronous owner.
    pub fn publish_txt(&self, name: impl Into<String>, value: impl Into<String>) -> DnsTxtLease {
        let name = name.into();
        let value = value.into();
        self.inner.core.add_txt(&name, &value);
        DnsTxtLease {
            core: Arc::clone(&self.inner.core),
            name,
            value,
        }
    }

    /// Arm DNS serving. Success means the desired-state reconciler is live;
    /// inspect [`Self::status`] to distinguish running from waiting.
    pub async fn start(&self) -> Result<bool, DnsError> {
        let mut control = self.inner.control.lock().await;
        if control.shutting_down || self.lifecycle_tasks.is_shutting_down() {
            return Err(DnsError::ShutDown);
        }

        let stale_active = control
            .active
            .as_ref()
            .is_some_and(|active| active.task.is_finished() || active.cancel.is_cancelled());
        if stale_active {
            Self::reap_active_locked(&mut control, DNS_STOP_TIMEOUT, "DNS restart").await;
        }
        if control.active.is_some() {
            return Ok(false);
        }
        control.generation = control.generation.wrapping_add(1);
        let generation = control.generation;
        self.inner
            .generation_fence
            .store(generation, Ordering::Release);

        self.inner.core.set_runtime_status(
            false,
            true,
            DnsRuntimeState::Reconciling,
            Vec::new(),
            None,
        );

        let cancel = self.inner.infrastructure_cancel.child_token();
        let (initial_tx, initial_rx) = oneshot::channel();
        let core = Arc::clone(&self.inner.core);
        let reconcile_core = Arc::clone(&core);
        let reconcile_cancel = cancel.clone();
        let completion_cancel = cancel.clone();
        let generation_fence = Arc::clone(&self.inner.generation_fence);
        let task = tokio::spawn(async move {
            let outcome = AssertUnwindSafe(reconcile(reconcile_core, reconcile_cancel, initial_tx))
                .catch_unwind()
                .await;
            if !completion_cancel.is_cancelled()
                && generation_fence.load(Ordering::Acquire) == generation
            {
                let reason = match outcome {
                    Ok(()) => "DNS reconciler ended unexpectedly".to_string(),
                    Err(_) => "DNS reconciler task panicked".to_string(),
                };
                core.set_runtime_status(
                    false,
                    true,
                    DnsRuntimeState::Waiting,
                    Vec::new(),
                    Some(reason),
                );
            }
        });
        control.active = Some(RunHandle {
            generation,
            cancel: cancel.clone(),
            task,
        });
        drop(control);

        let mut startup = StartupCancellationGuard::new(
            generation,
            cancel,
            Arc::clone(&self.inner.generation_fence),
            Arc::clone(&self.inner.core),
        );
        match initial_rx.await {
            Ok(()) => {
                startup.disarm();
                Ok(true)
            }
            Err(_) => Err(DnsError::Worker(
                "reconciler stopped during startup acknowledgement".to_string(),
            )),
        }
    }

    /// Disarm DNS serving and acknowledge release of the active generation.
    ///
    /// `Ok(false)` is reserved for an accepted command that found DNS already
    /// stopped. Terminal admission and loss of the retained command owner are
    /// explicit errors; neither can masquerade as that domain fact.
    pub async fn stop(&self) -> Result<bool, DnsError> {
        self.stop_with_timeout(DNS_STOP_TIMEOUT).await
    }

    async fn stop_with_timeout(&self, timeout: Duration) -> Result<bool, DnsError> {
        let Some(permit) = self.lifecycle_tasks.admit().await else {
            return Err(DnsError::ShutDown);
        };
        let (result_tx, result_rx) = oneshot::channel();
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            let _permit = permit;
            #[cfg(test)]
            if inner
                .panic_next_stop
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                panic!("injected DNS stop worker panic");
            }
            let result = Self::stop_owned(inner, timeout).await;
            let _ = result_tx.send(result);
        });
        self.lifecycle_tasks.retain(task);
        result_rx
            .await
            .map_err(|_| DnsError::Worker("stop ended before acknowledgement".into()))
    }

    async fn stop_owned(inner: Arc<DnsRuntimeInner>, timeout: Duration) -> bool {
        let mut control = inner.control.lock().await;
        if control.active.is_none() {
            return false;
        }
        Self::stop_active_locked(&inner, &mut control, timeout, "DNS stop").await;
        true
    }

    /// Permanently stop this runtime and reap every DNS-owned background task.
    ///
    /// Unlike [`Self::stop`], which only disarms the listener while preserving
    /// live cross-domain observation for a later restart, shutdown is terminal.
    /// It is idempotent and bounded. Once admitted, a runtime-owned worker
    /// completes it even if the caller stops waiting.
    pub async fn shutdown(&self) {
        self.shutdown_with_timeout(DNS_STOP_TIMEOUT).await;
    }

    async fn shutdown_with_timeout(&self, timeout: Duration) {
        if self.lifecycle_tasks.begin_shutdown() {
            // Election, cancellation, spawn, and retention contain no await.
            // Once the terminal decision is visible, caller cancellation can
            // discard only this method's acknowledgement waiter.
            self.inner.infrastructure_cancel.cancel();
            let inner = Arc::clone(&self.inner);
            let admission = Arc::clone(&self.lifecycle_tasks.admission);
            let terminal = Arc::clone(&self.lifecycle_tasks.terminal);
            let worker = tokio::spawn(async move {
                let completion =
                    DnsTerminalCompletion::new(Arc::clone(&inner), Arc::clone(&terminal));
                admission.wait_idle().await;
                #[cfg(test)]
                if inner
                    .panic_next_shutdown
                    .swap(false, std::sync::atomic::Ordering::AcqRel)
                {
                    panic!("injected DNS terminal-shutdown panic");
                }
                let failure = AssertUnwindSafe(Self::shutdown_owned(&inner, timeout))
                    .catch_unwind()
                    .await
                    .err()
                    .map(|_| "DNS terminal worker panicked".to_string());
                completion.settle(failure);
            });
            self.lifecycle_tasks.retain(worker);
        }
        if let Some(error) = self.lifecycle_tasks.terminal.wait().await {
            tracing::error!(%error, "DNS shutdown completed with a terminal worker failure");
        }
    }

    async fn shutdown_owned(inner: &DnsRuntimeInner, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut control = inner.control.lock().await;
        control.shutting_down = true;

        if control.active.is_some() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            Self::stop_active_locked(inner, &mut control, remaining, "DNS shutdown").await;
        } else {
            inner
                .core
                .set_runtime_status(false, false, DnsRuntimeState::Stopped, Vec::new(), None);
        }
        reap_background_locked(&mut control, deadline).await;
    }

    async fn stop_active_locked(
        inner: &DnsRuntimeInner,
        control: &mut DnsLifecycle,
        timeout: Duration,
        phase: &'static str,
    ) {
        // Fence the retiring generation before cancellation so it can no
        // longer publish. The externally visible Stopped status follows the
        // native listener's release acknowledgement below.
        control.generation = control.generation.wrapping_add(1);
        inner
            .generation_fence
            .store(control.generation, Ordering::Release);
        if let Some(active) = control.active.as_ref() {
            active.cancel.cancel();
        }
        Self::reap_active_locked(control, timeout, phase).await;
        inner
            .core
            .set_runtime_status(false, false, DnsRuntimeState::Stopped, Vec::new(), None);
    }

    async fn reap_active_locked(
        control: &mut DnsLifecycle,
        timeout: Duration,
        phase: &'static str,
    ) {
        let Some(active) = control.active.as_mut() else {
            return;
        };
        let generation = active.generation;
        let result = finish_task(&mut active.task, timeout).await;
        if let Err(error) = result {
            if !error.is_cancelled() {
                tracing::warn!(phase, generation, %error, "DNS lifecycle task failed");
            }
        }
        control.active = None;
    }

    /// Current immutable runtime status. This is a constant-time `Arc` clone.
    pub fn status(&self) -> Arc<DnsRuntimeStatus> {
        self.inner.core.status()
    }

    /// Subscribe to coalesced runtime status transitions.
    pub fn watch_status(&self) -> watch::Receiver<Arc<DnsRuntimeStatus>> {
        self.inner.core.watch_status()
    }

    /// Capture the primary DNS status and its specialized catalog at one causal
    /// fence without exposing the core implementation to composition.
    pub fn status_with_catalog(&self) -> (Arc<DnsRuntimeStatus>, Arc<DnsCatalogSnapshot>) {
        self.inner.core.status_with_catalog()
    }

    /// Return the current immutable DNS catalog projection.
    pub fn catalog_snapshot(&self) -> Arc<DnsCatalogSnapshot> {
        self.inner.core.catalog_snapshot()
    }

    /// Subscribe to coalesced DNS catalog changes.
    pub fn watch_catalog_snapshot(&self) -> watch::Receiver<Arc<DnsCatalogSnapshot>> {
        self.inner.core.watch_catalog_snapshot()
    }

    /// Subscribe to semantic DNS events through the runtime facade.
    ///
    /// Keeping all three domain faces on this boundary means consumers never
    /// need to reach through [`Self::core`] merely to observe occurrences.
    pub fn subscribe(&self) -> broadcast::Receiver<crate::DnsEvent> {
        self.inner.core.subscribe()
    }
}

struct DnsTerminalCompletion {
    inner: Arc<DnsRuntimeInner>,
    terminal: Arc<DnsTerminalState>,
    settled: bool,
}

impl DnsTerminalCompletion {
    fn new(inner: Arc<DnsRuntimeInner>, terminal: Arc<DnsTerminalState>) -> Self {
        Self {
            inner,
            terminal,
            settled: false,
        }
    }

    fn settle(mut self, failure: Option<String>) {
        if failure.is_some() {
            self.inner.fail_close();
        }
        self.terminal.finish(failure);
        self.settled = true;
    }
}

impl Drop for DnsTerminalCompletion {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        self.inner.fail_close();
        self.terminal.finish(Some(
            "DNS terminal worker stopped unexpectedly; resources were fail-closed".to_string(),
        ));
    }
}

impl DnsRuntimeInner {
    fn fail_close(&self) {
        self.infrastructure_cancel.cancel();
        self.generation_fence.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut control) = self.control.try_lock() {
            control.shutting_down = true;
            if let Some(active) = control.active.take() {
                active.cancel.cancel();
                active.task.abort();
            }
            for background in control.background.drain(..) {
                background.task.abort();
            }
        }
        self.core
            .set_runtime_status(false, false, DnsRuntimeState::Stopped, Vec::new(), None);
    }
}

impl Drop for DnsRuntime {
    fn drop(&mut self) {
        if Arc::strong_count(&self.lifecycle_tasks) == 1 {
            self.lifecycle_tasks.begin_shutdown();
            self.inner.fail_close();
            self.lifecycle_tasks.abort_all();
        }
    }
}

impl Drop for DnsRuntimeInner {
    fn drop(&mut self) {
        self.infrastructure_cancel.cancel();
        let control = self.control.get_mut();
        if let Some(active) = control.active.as_mut() {
            active.cancel.cancel();
            active.task.abort();
        }
        for background in &control.background {
            background.task.abort();
        }
    }
}

struct StartupCancellationGuard {
    generation: u64,
    cancel: CancellationToken,
    generation_fence: Arc<AtomicU64>,
    core: Arc<DnsCore>,
    armed: bool,
}

impl StartupCancellationGuard {
    fn new(
        generation: u64,
        cancel: CancellationToken,
        generation_fence: Arc<AtomicU64>,
        core: Arc<DnsCore>,
    ) -> Self {
        Self {
            generation,
            cancel,
            generation_fence,
            core,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StartupCancellationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let retired = self.generation.wrapping_add(1);
        if self
            .generation_fence
            .compare_exchange(
                self.generation,
                retired,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.cancel.cancel();
            self.core
                .set_runtime_status(false, false, DnsRuntimeState::Stopped, Vec::new(), None);
        }
    }
}

async fn finish_task(task: &mut JoinHandle<()>, timeout: Duration) -> Result<(), JoinError> {
    if task.is_finished() {
        return (&mut *task).await;
    }
    match tokio::time::timeout(timeout, &mut *task).await {
        Ok(result) => result,
        Err(_) => {
            task.abort();
            (&mut *task).await
        }
    }
}

async fn reap_background_locked(control: &mut DnsLifecycle, deadline: Instant) {
    while let Some(background) = control.background.last_mut() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let name = background.name;
        let result = finish_task(&mut background.task, remaining).await;
        if let Err(error) = result {
            if !error.is_cancelled() {
                tracing::warn!(task = name, %error, "DNS background task failed");
            }
        }
        control.background.pop();
    }
}

async fn observe_mdns(
    core: Weak<DnsCore>,
    mut input: watch::Receiver<Arc<koi_common::integration::MdnsDiscoverySnapshot>>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = input.changed() => {
                if changed.is_err() {
                    break;
                }
                let Some(core) = core.upgrade() else {
                    break;
                };
                core.accept_mdns_snapshot(input.borrow_and_update().clone());
            }
        }
    }
}

async fn observe_certmesh(
    core: Weak<DnsCore>,
    mut input: watch::Receiver<Arc<koi_common::integration::CertmeshRosterSnapshot>>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            changed = input.changed() => {
                if changed.is_err() {
                    break;
                }
                let Some(core) = core.upgrade() else {
                    break;
                };
                core.accept_certmesh_snapshot(input.borrow_and_update().clone());
            }
        }
    }
}

async fn reconcile(core: Arc<DnsCore>, cancel: CancellationToken, initial_tx: oneshot::Sender<()>) {
    let mut initial_tx = Some(initial_tx);
    loop {
        if cancel.is_cancelled() {
            break;
        }
        core.set_runtime_status(false, true, DnsRuntimeState::Reconciling, Vec::new(), None);

        match core.bind_server().await {
            Ok(server) => {
                let endpoints = server
                    .endpoints
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let reason = server.reason.clone();
                let observation = server.observation.clone();
                core.set_runtime_status(true, true, DnsRuntimeState::Running, endpoints, reason);
                signal_initial(&mut initial_tx);

                let server_cancel = CancellationToken::new();
                let server_done = server.serve(server_cancel.clone());
                tokio::pin!(server_done);
                let mut probe = tokio::time::interval(INTERFACE_PROBE_INTERVAL);
                let retry_reason = loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            server_cancel.cancel();
                            let _ = server_done.await;
                            return;
                        }
                        result = &mut server_done => {
                            break match result {
                                Ok(()) => "DNS listener ended unexpectedly".to_string(),
                                Err(error) => error.to_string(),
                            };
                        }
                        _ = probe.tick() => {
                            if observation.changed().await {
                                server_cancel.cancel();
                                let _ = server_done.await;
                                break "network interfaces changed; rebuilding DNS listeners".to_string();
                            }
                        }
                    }
                };
                set_waiting(&core, retry_reason);
            }
            Err(error) => {
                set_waiting(&core, error.to_string());
                signal_initial(&mut initial_tx);
            }
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(RETRY_INTERVAL) => {}
        }
    }
}

fn set_waiting(core: &DnsCore, reason: String) {
    core.set_runtime_status(
        false,
        true,
        DnsRuntimeState::Waiting,
        Vec::new(),
        Some(reason),
    );
}

fn signal_initial(sender: &mut Option<oneshot::Sender<()>>) {
    if let Some(sender) = sender.take() {
        let _ = sender.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RecordType;
    use koi_common::integration::{
        AliasFeedback, CertmeshRosterSnapshot, CertmeshSnapshot, MdnsDiscoverySnapshot,
        MdnsSnapshot, MemberSummary,
    };
    use koi_common::status::StatusFeed;
    use koi_common::types::ServiceRecord;
    use std::collections::HashMap;
    use std::future::pending;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    #[derive(Default)]
    struct RecordingAliasFeedback;

    #[async_trait::async_trait]
    impl AliasFeedback for RecordingAliasFeedback {
        async fn record_alias(
            &self,
            _hostname: &str,
            _alias: &str,
        ) -> Result<(), koi_common::integration::AliasFeedbackError> {
            Ok(())
        }
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, AtomicOrdering::SeqCst);
        }
    }

    struct MutableMdnsInput {
        feed: StatusFeed<MdnsDiscoverySnapshot>,
    }

    impl MutableMdnsInput {
        fn new(hosts: &[(&str, &str)]) -> Self {
            Self {
                feed: StatusFeed::new(mdns_snapshot(0, hosts)),
            }
        }

        fn replace(&self, hosts: &[(&str, &str)]) {
            let hosts = hosts
                .iter()
                .map(|(hostname, address)| ((*hostname).to_string(), (*address).to_string()))
                .collect::<Vec<_>>();
            self.feed.update(move |current| {
                let borrowed = hosts
                    .iter()
                    .map(|(hostname, address)| (hostname.as_str(), address.as_str()))
                    .collect::<Vec<_>>();
                Some(mdns_snapshot(current.revision.saturating_add(1), &borrowed))
            });
        }
    }

    impl MdnsSnapshot for MutableMdnsInput {
        fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot> {
            self.feed.current()
        }

        fn watch_snapshot(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>> {
            self.feed.subscribe()
        }
    }

    struct MutableCertmeshInput {
        feed: StatusFeed<CertmeshRosterSnapshot>,
    }

    impl MutableCertmeshInput {
        fn new(members: Vec<MemberSummary>) -> Self {
            Self {
                feed: StatusFeed::new(CertmeshRosterSnapshot {
                    revision: 0,
                    active_members: members,
                }),
            }
        }

        fn replace(&self, members: Vec<MemberSummary>) {
            self.feed.update(move |current| {
                Some(CertmeshRosterSnapshot {
                    revision: current.revision.saturating_add(1),
                    active_members: members,
                })
            });
        }
    }

    impl CertmeshSnapshot for MutableCertmeshInput {
        fn snapshot(&self) -> Arc<CertmeshRosterSnapshot> {
            self.feed.current()
        }

        fn watch_snapshot(&self) -> watch::Receiver<Arc<CertmeshRosterSnapshot>> {
            self.feed.subscribe()
        }
    }

    fn mdns_snapshot(revision: u64, hosts: &[(&str, &str)]) -> MdnsDiscoverySnapshot {
        MdnsDiscoverySnapshot {
            revision,
            service_types: vec!["_http._tcp.local.".to_string()],
            records: hosts
                .iter()
                .map(|(hostname, address)| ServiceRecord {
                    name: format!("{hostname}-http"),
                    service_type: "_http._tcp.local.".to_string(),
                    host: Some(format!("{hostname}.local.")),
                    ip: Some((*address).to_string()),
                    port: Some(80),
                    txt: HashMap::new(),
                })
                .collect(),
        }
    }

    fn member(hostname: &str, san: &str) -> MemberSummary {
        MemberSummary {
            hostname: hostname.to_string(),
            sans: vec![san.to_string()],
            cert_expires: None,
            last_seen: None,
            status: "active".to_string(),
            proxy_entries: Vec::new(),
        }
    }

    async fn runtime_with_inputs(
        mdns: Option<Arc<dyn MdnsSnapshot>>,
        certmesh: Option<Arc<dyn CertmeshSnapshot>>,
    ) -> DnsRuntime {
        let core = DnsCore::open(
            std::env::temp_dir().join(format!(
                "koi-dns-inputs-{}.json",
                koi_common::id::generate_short_id()
            )),
            crate::DnsConfig::default(),
            mdns,
            certmesh,
            None,
        )
        .await
        .expect("DNS core");
        DnsRuntime::new(core)
    }

    async fn runtime_on(port: u16) -> DnsRuntime {
        let core = DnsCore::open(
            std::env::temp_dir().join(format!(
                "koi-dns-runtime-{}-{port}.json",
                std::process::id()
            )),
            crate::DnsConfig {
                bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                ..Default::default()
            },
            None,
            None,
            None,
        )
        .await
        .unwrap();
        DnsRuntime::new(core)
    }

    #[tokio::test]
    async fn contention_is_waiting_and_recovers_without_another_start() {
        let blocker = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = blocker.local_addr().unwrap().port();
        let runtime = runtime_on(port).await;

        assert!(runtime.start().await.unwrap());
        let waiting = runtime.status();
        assert_eq!(waiting.state, DnsRuntimeState::Waiting);
        assert!(waiting.desired);
        assert!(!waiting.running);

        drop(blocker);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if runtime.status().running {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("runtime should recover after the incumbent leaves");
        assert!(runtime.stop().await.expect("stop DNS"));
        assert_eq!(runtime.status().state, DnsRuntimeState::Stopped);
    }

    #[tokio::test]
    async fn port_zero_reports_the_real_endpoint() {
        let runtime = runtime_on(0).await;
        assert!(runtime.start().await.unwrap());
        let status = runtime.status();
        assert_eq!(status.state, DnsRuntimeState::Running);
        assert_eq!(status.endpoints.len(), 1);
        assert!(!status.endpoints[0].ends_with(":0"));
        assert!(runtime.stop().await.expect("stop DNS"));
    }

    #[test]
    fn runtime_status_round_trips_with_revision() {
        let status = DnsRuntimeStatus {
            revision: 7,
            catalog_revision: 0,
            running: true,
            desired: true,
            state: DnsRuntimeState::Running,
            endpoints: vec!["127.0.0.1:5354".to_string()],
            reason: Some("loopback only".to_string()),
            zone: "internal".to_string(),
            port: 5354,
            records: DnsRecordSummary {
                static_entries: 1,
                certmesh_entries: 2,
                mdns_entries: 3,
                txt_names: 1,
            },
        };

        let json = serde_json::to_value(&status).expect("serialize DNS status");
        let decoded: DnsRuntimeStatus =
            serde_json::from_value(json).expect("deserialize DNS status");
        assert_eq!(decoded, status);
    }

    #[tokio::test]
    async fn status_feed_is_immediate_revisioned_and_suppresses_noop_start() {
        let runtime = runtime_on(0).await;
        let first = runtime.status();
        let second = runtime.status();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.revision, 0);

        let mut status_rx = runtime.watch_status();
        assert_eq!(status_rx.borrow().revision, 0);
        assert!(runtime.start().await.unwrap());
        status_rx
            .changed()
            .await
            .expect("start should publish status");
        let running = status_rx.borrow_and_update().clone();
        assert_eq!(running.state, DnsRuntimeState::Running);
        assert!(running.revision > first.revision);

        let before_noop = runtime.status();
        assert!(!runtime.start().await.unwrap());
        assert_eq!(runtime.status().revision, before_noop.revision);
        assert!(status_rx.has_changed().is_ok_and(|changed| !changed));

        assert!(runtime.stop().await.expect("stop DNS"));
        status_rx
            .changed()
            .await
            .expect("stop should publish status");
        let stopped = status_rx.borrow_and_update().clone();
        assert_eq!(stopped.state, DnsRuntimeState::Stopped);
        assert!(stopped.revision > running.revision);
    }

    #[tokio::test]
    async fn stop_reserves_false_for_an_accepted_already_stopped_command() {
        let runtime = runtime_on(0).await;

        assert!(!runtime.stop().await.expect("accepted DNS no-op"));

        runtime.shutdown().await;
        assert!(matches!(runtime.stop().await, Err(DnsError::ShutDown)));
    }

    #[tokio::test]
    async fn stop_surfaces_a_lost_owned_worker_acknowledgement() {
        let runtime = runtime_on(0).await;
        runtime
            .inner
            .panic_next_stop
            .store(true, std::sync::atomic::Ordering::Release);

        let error = runtime
            .stop()
            .await
            .expect_err("lost DNS owner must not look already stopped");
        assert!(matches!(
            error,
            DnsError::Worker(detail) if detail.contains("before acknowledgement")
        ));

        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn same_count_mdns_replacement_immediately_updates_effective_dns() {
        let mdns = Arc::new(MutableMdnsInput::new(&[("node", "10.0.0.10")]));
        let mdns_port: Arc<dyn MdnsSnapshot> = mdns.clone();
        let runtime = runtime_with_inputs(Some(mdns_port), None).await;
        let before = runtime.status();
        let mut status_rx = runtime.watch_status();

        mdns.replace(&[("node", "10.0.0.11")]);
        tokio::time::timeout(Duration::from_secs(2), status_rx.changed())
            .await
            .expect("mDNS watch propagation")
            .expect("DNS status feed open");
        let after = status_rx.borrow_and_update().clone();
        assert!(after.revision > before.revision);
        assert_eq!(after.records.mdns_entries, before.records.mdns_entries);
        assert_eq!(
            runtime
                .core()
                .resolve_mdns_local("node.local", RecordType::A)
                .expect("updated .local answer")
                .ips,
            vec!["10.0.0.11".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn same_count_certmesh_replacement_immediately_updates_effective_dns() {
        let mdns = Arc::new(MutableMdnsInput::new(&[
            ("first", "10.0.0.10"),
            ("second", "10.0.0.11"),
        ]));
        let certmesh = Arc::new(MutableCertmeshInput::new(vec![member(
            "first",
            "app.internal",
        )]));
        let runtime = runtime_with_inputs(
            Some(mdns as Arc<dyn MdnsSnapshot>),
            Some(certmesh.clone() as Arc<dyn CertmeshSnapshot>),
        )
        .await;
        let before = runtime.status();
        assert_eq!(before.records.certmesh_entries, 1);
        let mut status_rx = runtime.watch_status();

        certmesh.replace(vec![member("second", "app.internal")]);
        tokio::time::timeout(Duration::from_secs(2), status_rx.changed())
            .await
            .expect("Certmesh watch propagation")
            .expect("DNS status feed open");
        let after = status_rx.borrow_and_update().clone();
        assert!(after.revision > before.revision);
        assert_eq!(after.records.certmesh_entries, 1);
        assert_eq!(
            runtime
                .core()
                .resolve_local("app.internal", RecordType::A)
                .expect("updated Certmesh answer")
                .ips,
            vec!["10.0.0.11".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn newer_irrelevant_input_revision_does_not_wake_dns_status() {
        let mdns = Arc::new(MutableMdnsInput::new(&[("node", "10.0.0.10")]));
        let runtime = runtime_with_inputs(Some(mdns.clone() as Arc<dyn MdnsSnapshot>), None).await;
        let before = runtime.status();
        let mut next = (*mdns.snapshot()).clone();
        next.revision = next.revision.saturating_add(1);

        runtime.core().accept_mdns_snapshot(Arc::new(next));

        assert!(Arc::ptr_eq(&before, &runtime.status()));
    }

    #[tokio::test]
    async fn shutdown_reaps_every_background_worker_and_is_terminal_and_idempotent() {
        let mdns = Arc::new(MutableMdnsInput::new(&[("node", "10.0.0.10")]));
        let certmesh = Arc::new(MutableCertmeshInput::new(vec![member(
            "node",
            "app.internal",
        )]));
        let core = DnsCore::open(
            std::env::temp_dir().join(format!(
                "koi-dns-shutdown-{}.json",
                koi_common::id::generate_short_id()
            )),
            crate::DnsConfig::default(),
            Some(mdns.clone() as Arc<dyn MdnsSnapshot>),
            Some(certmesh as Arc<dyn CertmeshSnapshot>),
            Some(Arc::new(RecordingAliasFeedback)),
        )
        .await
        .expect("DNS core");
        let runtime = DnsRuntime::new(core);
        assert_eq!(runtime.inner.control.lock().await.background.len(), 3);

        runtime.shutdown().await;
        let stopped_revision = runtime.status().revision;
        {
            let control = runtime.inner.control.lock().await;
            assert!(control.shutting_down);
            assert!(control.active.is_none());
            assert!(control.background.is_empty());
        }
        assert_eq!(runtime.status().state, DnsRuntimeState::Stopped);
        assert!(runtime.start().await.is_err());

        mdns.replace(&[("node", "10.0.0.11")]);
        tokio::task::yield_now().await;
        assert_eq!(runtime.status().revision, stopped_revision);
        assert_eq!(
            runtime
                .core()
                .resolve_mdns_local("node.local", RecordType::A)
                .expect("last accepted .local answer")
                .ips,
            vec!["10.0.0.10".parse::<IpAddr>().unwrap()]
        );

        runtime.shutdown().await;
        assert_eq!(runtime.status().revision, stopped_revision);
    }

    #[tokio::test]
    async fn last_owner_drop_breaks_the_active_generation_cycle_and_aborts_workers() {
        let runtime = runtime_on(0).await;
        assert!(runtime.start().await.unwrap());
        let inner = Arc::downgrade(&runtime.inner);
        let dropped = Arc::new(AtomicBool::new(false));
        let worker_dropped = Arc::clone(&dropped);
        let worker = tokio::spawn(async move {
            let _drop = DropFlag(worker_dropped);
            pending::<()>().await;
        });
        tokio::task::yield_now().await;
        runtime
            .inner
            .control
            .lock()
            .await
            .background
            .push(BackgroundTask {
                name: "drop probe",
                task: worker,
            });

        drop(runtime);

        assert!(
            inner.upgrade().is_none(),
            "listener task retained its owner"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(AtomicOrdering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted worker future was not dropped");
    }

    #[tokio::test]
    async fn cancelled_stop_converges_without_retry_and_remains_restartable() {
        let runtime = runtime_on(0).await;
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let cancel = CancellationToken::new();
        let cancel_observer = cancel.clone();
        let task = tokio::spawn(async move {
            let _drop = DropFlag(task_dropped);
            pending::<()>().await;
        });
        tokio::task::yield_now().await;
        {
            let mut control = runtime.inner.control.lock().await;
            control.generation = 1;
            runtime.inner.generation_fence.store(1, Ordering::Release);
            control.active = Some(RunHandle {
                generation: 1,
                cancel,
                task,
            });
        }
        runtime.inner.core.set_runtime_status(
            true,
            true,
            DnsRuntimeState::Running,
            vec!["test".to_string()],
            None,
        );

        let stopping_runtime = runtime.clone();
        let stopping = tokio::spawn(async move {
            stopping_runtime
                .stop_with_timeout(Duration::from_millis(50))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancel_observer.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned stop did not reach native cancellation");

        stopping.abort();
        let _ = stopping.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if runtime.inner.control.lock().await.active.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned stop did not finish after requester cancellation");
        assert!(dropped.load(AtomicOrdering::SeqCst));
        assert_eq!(runtime.status().state, DnsRuntimeState::Stopped);

        assert!(runtime.start().await.expect("restart after completed stop"));
        assert!(runtime.stop().await.expect("stop DNS"));
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_terminal_shutdown_converges_without_retry() {
        let runtime = runtime_on(0).await;
        let active_dropped = Arc::new(AtomicBool::new(false));
        let active_drop = Arc::clone(&active_dropped);
        let active = tokio::spawn(async move {
            let _drop = DropFlag(active_drop);
            pending::<()>().await;
        });
        let background_dropped = Arc::new(AtomicBool::new(false));
        let background_drop = Arc::clone(&background_dropped);
        let background = tokio::spawn(async move {
            let _drop = DropFlag(background_drop);
            pending::<()>().await;
        });
        tokio::task::yield_now().await;
        {
            let mut control = runtime.inner.control.lock().await;
            control.generation = 1;
            runtime.inner.generation_fence.store(1, Ordering::Release);
            control.active = Some(RunHandle {
                generation: 1,
                cancel: CancellationToken::new(),
                task: active,
            });
            control.background.push(BackgroundTask {
                name: "terminal drop probe",
                task: background,
            });
        }
        runtime.inner.core.set_runtime_status(
            true,
            true,
            DnsRuntimeState::Running,
            vec!["test".to_string()],
            None,
        );

        let requester_runtime = runtime.clone();
        let requester = tokio::spawn(async move {
            requester_runtime
                .shutdown_with_timeout(Duration::from_millis(50))
                .await;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !runtime.inner.infrastructure_cancel.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal cancellation was not admitted");
        requester.abort();
        let _ = requester.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let settled = {
                    let control = runtime.inner.control.lock().await;
                    control.shutting_down
                        && control.active.is_none()
                        && control.background.is_empty()
                };
                if settled {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned terminal shutdown did not finish");
        assert!(active_dropped.load(AtomicOrdering::SeqCst));
        assert!(background_dropped.load(AtomicOrdering::SeqCst));
        assert_eq!(runtime.status().state, DnsRuntimeState::Stopped);
        assert!(runtime.start().await.is_err());
    }

    #[tokio::test]
    async fn panicked_terminal_owner_fail_closes_and_settles_waiters() {
        let runtime = Arc::new(runtime_on(0).await);
        let active_dropped = Arc::new(AtomicBool::new(false));
        let active_drop = Arc::clone(&active_dropped);
        let active = tokio::spawn(async move {
            let _drop = DropFlag(active_drop);
            pending::<()>().await;
        });
        {
            let mut control = runtime.inner.control.lock().await;
            control.active = Some(RunHandle {
                generation: 1,
                cancel: CancellationToken::new(),
                task: active,
            });
        }
        runtime.inner.core.set_runtime_status(
            true,
            true,
            DnsRuntimeState::Running,
            vec!["test".to_string()],
            None,
        );
        runtime
            .inner
            .panic_next_shutdown
            .store(true, std::sync::atomic::Ordering::Release);

        let first = {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.shutdown().await })
        };
        let second = {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.shutdown().await })
        };
        tokio::time::timeout(Duration::from_secs(2), first)
            .await
            .expect("first terminal waiter was stranded")
            .expect("first waiter task should not panic");
        tokio::time::timeout(Duration::from_secs(2), second)
            .await
            .expect("second terminal waiter was stranded")
            .expect("second waiter task should not panic");

        let failure = runtime
            .lifecycle_tasks
            .terminal
            .wait()
            .await
            .expect("terminal panic should be observable");
        assert!(failure.contains("stopped unexpectedly"));
        assert!(active_dropped.load(AtomicOrdering::SeqCst));
        assert!(runtime.inner.control.lock().await.active.is_none());
        assert_eq!(runtime.status().state, DnsRuntimeState::Stopped);
        assert!(runtime.start().await.is_err());
    }

    #[tokio::test]
    async fn last_facade_drop_breaks_an_admitted_stop_owner_chain() {
        let runtime = runtime_on(0).await;
        let inner = Arc::downgrade(&runtime.inner);
        let active_dropped = Arc::new(AtomicBool::new(false));
        let active_drop = Arc::clone(&active_dropped);
        let cancel = CancellationToken::new();
        let cancel_observer = cancel.clone();
        let active = tokio::spawn(async move {
            let _drop = DropFlag(active_drop);
            pending::<()>().await;
        });
        {
            let mut control = runtime.inner.control.lock().await;
            control.active = Some(RunHandle {
                generation: 1,
                cancel,
                task: active,
            });
        }

        let stopping =
            tokio::spawn(async move { runtime.stop_with_timeout(Duration::from_secs(30)).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancel_observer.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("admitted stop did not reach native cancellation");
        stopping.abort();
        let _ = stopping.await;

        tokio::time::timeout(Duration::from_secs(1), async {
            while inner.upgrade().is_some() || !active_dropped.load(AtomicOrdering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained command formed a last-owner cycle");
    }

    #[tokio::test]
    async fn restart_waits_until_the_retiring_generation_is_reaped() {
        let runtime = Arc::new(runtime_on(0).await);
        let task = tokio::spawn(pending::<()>());
        tokio::task::yield_now().await;
        {
            let mut control = runtime.inner.control.lock().await;
            control.generation = 1;
            runtime.inner.generation_fence.store(1, Ordering::Release);
            control.active = Some(RunHandle {
                generation: 1,
                cancel: CancellationToken::new(),
                task,
            });
        }
        runtime.inner.core.set_runtime_status(
            true,
            true,
            DnsRuntimeState::Running,
            vec!["test".to_string()],
            None,
        );

        let stopping_runtime = Arc::clone(&runtime);
        let stopping = tokio::spawn(async move {
            stopping_runtime
                .stop_with_timeout(Duration::from_millis(25))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while runtime.status().state != DnsRuntimeState::Stopped {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retiring generation did not publish its fence");

        let restarting_runtime = Arc::clone(&runtime);
        let restarting = tokio::spawn(async move { restarting_runtime.start().await });
        assert!(stopping.await.unwrap().expect("stop retiring DNS"));
        assert!(restarting.await.unwrap().unwrap());
        assert_eq!(runtime.status().state, DnsRuntimeState::Running);
        assert_eq!(runtime.inner.control.lock().await.generation, 3);

        assert!(runtime.stop().await.expect("stop DNS"));
        runtime.shutdown().await;
    }
}
