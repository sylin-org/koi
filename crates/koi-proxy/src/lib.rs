//! Koi Proxy - TLS-terminating reverse proxy (Phase 8).

mod config;
pub mod http;
mod listener;
mod safety;
mod tls;

#[cfg(test)]
mod data_plane_tests;

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use koi_common::integration::{ProxyEntriesSnapshot, ProxyEntrySummary, TlsIdentitySource};
use koi_common::status::StatusFeed;
use tokio::sync::{broadcast, watch, Mutex};

use listener::{spawn_listener_with_tls_observer, ConnectionTasks, ListenerHandle, ListenerStatus};

const PROXY_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IN_FLIGHT_COMMANDS: usize = 32;

pub use config::{ProxyConfig, ProxyEntry};
pub use safety::{ensure_backend_allowed, parse_backend};

/// Owner of a transient desired-entry set.
///
/// Scoped entries are process-derived facts. They participate in Proxy's one
/// effective model and status projection, but are deliberately never written to
/// the operator's `config.toml`. Replacing a scope is a complete desired-set
/// operation, so entries which disappear from the source disappear here too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProxyEntryScope {
    Runtime,
}

/// Events emitted by the proxy subsystem when entries change.
#[derive(Debug, Clone)]
pub enum ProxyEvent {
    /// Durable desired configuration was added or updated and its listener task
    /// was armed. This does not claim the asynchronous bind/TLS outcome.
    EntryUpdated { entry: ProxyEntry },
    /// A proxy entry was removed.
    EntryRemoved { name: String },
    /// One transient producer replaced its complete desired set.
    ScopedEntriesReplaced {
        scope: ProxyEntryScope,
        entries: Vec<ProxyEntry>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("proxy config error: {0}")]
    Config(String),

    #[error("proxy io error: {0}")]
    Io(String),

    #[error("proxy invalid config: {0}")]
    InvalidConfig(String),

    #[error("proxy entry not found: {0}")]
    NotFound(String),

    #[error("proxy runtime has already shut down")]
    ShutDown,

    #[error("proxy lifecycle worker stopped unexpectedly: {0}")]
    Worker(String),
}

/// Runtime status of a single proxy listener.
///
/// `state`/`error` reflect the listener task's real liveness (bind/accept outcome),
/// and `cert_source` records which certificate the listener is serving. This
/// replaces the old hardcoded `running: true`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ProxyStatus {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    pub allow_remote: bool,
    /// "override", "certmesh", or "self-signed" for an armed listener;
    /// "unresolved" before start.
    pub cert_source: String,
    /// Advances whenever the selected certificate bytes or provenance changes.
    #[serde(default)]
    pub cert_revision: u64,
    /// "starting" | "running" | "error" | "stopped".
    pub state: String,
    /// Error detail, present only when `state == "error"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Authoritative latest-value snapshot for the proxy runtime.
///
/// The listener list is sorted by name so equivalent runtime state has one stable
/// representation. `revision` advances only when that semantic representation changes.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct ProxyRuntimeStatus {
    #[serde(default)]
    pub revision: u64,
    /// Causal fence for [`ProxyEntriesSnapshot`]. The entries projection is
    /// published first; a primary status carrying this revision therefore
    /// guarantees that revision is already readable at its own boundary.
    #[serde(skip)]
    #[schema(ignore)]
    pub entries_revision: u64,
    pub proxies: Vec<ProxyStatus>,
}

#[derive(Default)]
struct ProxyDesiredModel {
    operator: Vec<ProxyEntry>,
    scoped: BTreeMap<ProxyEntryScope, Vec<ProxyEntry>>,
}

#[cfg(test)]
#[derive(Default)]
struct ConfigCommitPause {
    armed: AtomicBool,
    paused: AtomicBool,
    release: AtomicBool,
}

#[cfg(test)]
impl ConfigCommitPause {
    fn after_commit(&self) {
        if !self.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        self.paused.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        self.paused.store(false, Ordering::Release);
        self.release.store(false, Ordering::Release);
    }
}

impl ProxyDesiredModel {
    fn effective(&self) -> Vec<ProxyEntry> {
        let mut entries = BTreeMap::new();
        for scoped in self.scoped.values() {
            for entry in scoped {
                entries.insert(entry.name.clone(), entry.clone());
            }
        }
        // An explicit operator entry owns its name and overrides derived desire.
        for entry in &self.operator {
            entries.insert(entry.name.clone(), entry.clone());
        }
        entries.into_values().collect()
    }
}

pub struct ProxyCore {
    desired: Arc<std::sync::RwLock<ProxyDesiredModel>>,
    entries_status: StatusFeed<ProxyEntriesSnapshot>,
    operation: Arc<Mutex<()>>,
    event_tx: broadcast::Sender<ProxyEvent>,
    config_path: std::path::PathBuf,
    certificate_overrides_dir: std::path::PathBuf,
    #[cfg(test)]
    commit_pause: Arc<ConfigCommitPause>,
}

impl ProxyCore {
    /// Open the Proxy domain against its explicitly composed durable resources.
    pub fn open(
        config_path: std::path::PathBuf,
        certificate_overrides_dir: std::path::PathBuf,
    ) -> Result<Self, ProxyError> {
        let entries = config::load_entries(&config_path)?;
        validate_entries(&entries)?;
        let entries_status = StatusFeed::new(ProxyEntriesSnapshot {
            revision: 0,
            entries: summarize_entries(&entries),
        });
        Ok(Self {
            desired: Arc::new(std::sync::RwLock::new(ProxyDesiredModel {
                operator: entries,
                scoped: BTreeMap::new(),
            })),
            entries_status,
            operation: Arc::new(Mutex::new(())),
            event_tx: koi_common::events::event_channel().0,
            config_path,
            certificate_overrides_dir,
            #[cfg(test)]
            commit_pause: Arc::new(ConfigCommitPause::default()),
        })
    }

    pub async fn entries(&self) -> Vec<ProxyEntry> {
        self.configured_entries()
    }

    fn configured_entries(&self) -> Vec<ProxyEntry> {
        self.desired
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .effective()
    }

    fn operator_entries(&self) -> Vec<ProxyEntry> {
        self.desired
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .operator
            .clone()
    }

    /// Capture desired entries and their owning projection under one read
    /// fence. Writers publish the entries snapshot while holding the matching
    /// write lock, so a concurrent listener transition can observe either the
    /// old pair or the new pair, never mixed generations.
    fn configured_with_snapshot(&self) -> (Vec<ProxyEntry>, Arc<ProxyEntriesSnapshot>) {
        let desired = self
            .desired
            .read()
            .unwrap_or_else(|error| error.into_inner());
        (desired.effective(), self.entries_status.current())
    }

    fn publish_effective_locked(
        &self,
        model: &ProxyDesiredModel,
    ) -> (Vec<ProxyEntry>, Arc<ProxyEntriesSnapshot>) {
        let effective = model.effective();
        let summaries = summarize_entries(&effective);
        let snapshot = self.entries_status.update(move |current| {
            (current.entries != summaries).then_some(ProxyEntriesSnapshot {
                revision: current.revision.saturating_add(1),
                entries: summaries,
            })
        });
        (effective, snapshot)
    }

    fn accept_operator_entries(
        &self,
        entries: Vec<ProxyEntry>,
    ) -> (Vec<ProxyEntry>, Arc<ProxyEntriesSnapshot>) {
        let mut model = self
            .desired
            .write()
            .unwrap_or_else(|error| error.into_inner());
        model.operator = entries;
        self.publish_effective_locked(&model)
    }

    fn replace_scoped_entries(
        &self,
        scope: ProxyEntryScope,
        mut entries: Vec<ProxyEntry>,
    ) -> Result<(Vec<ProxyEntry>, bool), ProxyError> {
        validate_entries(&entries)?;
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let mut model = self
            .desired
            .write()
            .unwrap_or_else(|error| error.into_inner());
        let changed = model.scoped.get(&scope) != Some(&entries);
        if !changed {
            return Ok((model.effective(), false));
        }
        if entries.is_empty() {
            model.scoped.remove(&scope);
        } else {
            model.scoped.insert(scope, entries);
        }
        let (effective, _) = self.publish_effective_locked(&model);
        Ok((effective, true))
    }

    /// Current immutable desired-entry projection in constant time.
    fn entries_snapshot(&self) -> Arc<ProxyEntriesSnapshot> {
        self.entries_status.current()
    }

    /// Subscribe to desired-entry changes without polling the Proxy model.
    fn watch_entries(&self) -> watch::Receiver<Arc<ProxyEntriesSnapshot>> {
        self.entries_status.subscribe()
    }

    fn reload_model(&self) -> Result<Vec<ProxyEntry>, ProxyError> {
        let config_path = self.config_path.clone();
        let entries =
            koi_common::blocking::run_to_completion(move || config::load_entries(&config_path))?;
        validate_entries(&entries)?;
        Ok(self.accept_operator_entries(entries).0)
    }

    fn commit_upsert(&self, entry: ProxyEntry) -> Result<(Vec<ProxyEntry>, bool), ProxyError> {
        validate_entry(&entry)?;
        let mut entries = self.operator_entries();
        let changed = entries.iter().find(|existing| existing.name == entry.name) != Some(&entry);
        if !changed {
            return Ok((self.configured_entries(), false));
        }
        if let Some(existing) = entries
            .iter_mut()
            .find(|existing| existing.name == entry.name)
        {
            *existing = entry;
        } else {
            entries.push(entry);
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let config_path = self.config_path.clone();
        let persisted = entries.clone();
        #[cfg(test)]
        let commit_pause = Arc::clone(&self.commit_pause);
        let entries = koi_common::blocking::run_to_completion(move || {
            config::save_entries(&persisted, &config_path)?;
            #[cfg(test)]
            commit_pause.after_commit();
            Ok::<_, ProxyError>(persisted)
        })?;
        Ok((self.accept_operator_entries(entries).0, changed))
    }

    fn commit_remove(&self, name: &str) -> Result<Vec<ProxyEntry>, ProxyError> {
        let mut entries = self.operator_entries();
        let before = entries.len();
        entries.retain(|entry| entry.name != name);
        if entries.len() == before {
            return Err(ProxyError::NotFound(name.to_string()));
        }
        let config_path = self.config_path.clone();
        let persisted = entries.clone();
        #[cfg(test)]
        let commit_pause = Arc::clone(&self.commit_pause);
        let entries = koi_common::blocking::run_to_completion(move || {
            config::save_entries(&persisted, &config_path)?;
            #[cfg(test)]
            commit_pause.after_commit();
            Ok::<_, ProxyError>(persisted)
        })?;
        Ok(self.accept_operator_entries(entries).0)
    }

    /// Subscribe to proxy events.
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.event_tx.subscribe()
    }

    fn certificate_overrides_dir(&self) -> std::path::PathBuf {
        self.certificate_overrides_dir.clone()
    }

    #[cfg(test)]
    fn pause_next_commit_after_durable(&self) {
        self.commit_pause.release.store(false, Ordering::Release);
        self.commit_pause.armed.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn is_commit_paused(&self) -> bool {
        self.commit_pause.paused.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn release_commit(&self) {
        self.commit_pause.release.store(true, Ordering::Release);
    }
}

struct ProxyInstance {
    entry: ProxyEntry,
    generation: u64,
    listener: ListenerHandle,
}

#[derive(Clone)]
struct ProjectedListener {
    generation: u64,
    entry: ProxyEntry,
    status: ListenerStatus,
}

/// Proxy's single authoritative runtime projection.
///
/// Listener tasks report transitions directly into this cheap synchronous
/// boundary. There is no second status-monitor task and no polling read model.
struct ProxyProjection {
    listeners: std::sync::Mutex<HashMap<String, ProjectedListener>>,
    status: StatusFeed<ProxyRuntimeStatus>,
}

impl ProxyProjection {
    fn new(core: &ProxyCore) -> Self {
        let (configured, entries) = core.configured_with_snapshot();
        Self {
            listeners: std::sync::Mutex::new(HashMap::new()),
            status: StatusFeed::new(ProxyRuntimeStatus {
                revision: 0,
                entries_revision: entries.revision,
                proxies: stopped_proxies(&configured),
            }),
        }
    }

    fn arm(&self, core: &ProxyCore, entry: &ProxyEntry, generation: u64) {
        self.listeners
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(
                entry.name.clone(),
                ProjectedListener {
                    generation,
                    entry: entry.clone(),
                    status: ListenerStatus::starting(),
                },
            );
        self.publish(core);
    }

    fn accept(&self, core: &ProxyCore, name: &str, generation: u64, status: ListenerStatus) {
        let accepted = {
            let mut listeners = self
                .listeners
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let Some(current) = listeners.get_mut(name) else {
                return;
            };
            if current.generation != generation || current.status == status {
                return;
            }
            current.status = status;
            true
        };
        if accepted {
            self.publish(core);
        }
    }

    fn retire(&self, core: &ProxyCore, name: &str, generation: u64) {
        let removed = {
            let mut listeners = self
                .listeners
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if listeners
                .get(name)
                .is_some_and(|current| current.generation == generation)
            {
                listeners.remove(name);
                true
            } else {
                false
            }
        };
        if removed {
            self.publish(core);
        }
    }

    fn retire_all(&self, core: &ProxyCore) {
        self.listeners
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        self.publish(core);
    }

    fn publish(&self, core: &ProxyCore) {
        let (configured, entries_status) = core.configured_with_snapshot();
        let listeners = self
            .listeners
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let proxies = snapshot_proxies(&configured, &listeners);
        let entries_revision = entries_status.revision;
        self.status.update(move |current| {
            (current.proxies != proxies || current.entries_revision != entries_revision).then_some(
                ProxyRuntimeStatus {
                    revision: current.revision.saturating_add(1),
                    entries_revision,
                    proxies,
                },
            )
        });
    }
}

#[derive(Default)]
struct ProxyLifecycle {
    generation: u64,
    active: HashMap<String, ProxyInstance>,
    retiring: Vec<ProxyInstance>,
    draining: Vec<ConnectionTasks>,
    shutting_down: bool,
}

struct ProxyRuntimeInner {
    core: Arc<ProxyCore>,
    lifecycle: Mutex<ProxyLifecycle>,
    projection: Arc<ProxyProjection>,
    tls_identity: Option<Arc<dyn TlsIdentitySource>>,
    #[cfg(test)]
    panic_next_stop_all: AtomicBool,
    #[cfg(test)]
    panic_next_shutdown: AtomicBool,
}

/// Retains every admitted runtime command independently of its requester.
/// Dropping an HTTP/client future therefore drops only its acknowledgement;
/// persistence, reconciliation, primary status, and semantic event still finish.
struct ProxyCommandTasks {
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    permits: Arc<tokio::sync::Semaphore>,
    accepting: AtomicBool,
    shutdown_complete: AtomicBool,
    shutdown_changed: tokio::sync::Notify,
    shutdown_failure: std::sync::Mutex<Option<String>>,
}

impl ProxyCommandTasks {
    fn new() -> Self {
        Self {
            tasks: std::sync::Mutex::new(Vec::new()),
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_COMMANDS)),
            accepting: AtomicBool::new(true),
            shutdown_complete: AtomicBool::new(false),
            shutdown_changed: tokio::sync::Notify::new(),
            shutdown_failure: std::sync::Mutex::new(None),
        }
    }

    async fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ProxyError> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| ProxyError::ShutDown)?;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ProxyError::ShutDown);
        }
        Ok(permit)
    }

    /// Atomically elect the sole terminal-shutdown owner and close ordinary
    /// command admission. The elected caller must spawn retained completion
    /// before its next await.
    fn begin_shutdown(&self) -> bool {
        let elected = self
            .accepting
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if elected {
            self.permits.close();
        }
        elected
    }

    fn complete_shutdown(&self, failure: Option<String>) {
        *self
            .shutdown_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = failure;
        self.shutdown_complete.store(true, Ordering::Release);
        self.shutdown_changed.notify_waiters();
    }

    async fn wait_shutdown(&self) -> Option<String> {
        loop {
            let changed = self.shutdown_changed.notified();
            if self.shutdown_complete.load(Ordering::Acquire) {
                return self
                    .shutdown_failure
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone();
            }
            changed.await;
        }
    }

    fn retain(&self, task: tokio::task::JoinHandle<()>) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }
}

impl Drop for ProxyCommandTasks {
    fn drop(&mut self) {
        for task in self
            .tasks
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

/// Runtime controller for proxy listeners.
#[derive(Clone)]
pub struct ProxyRuntime {
    inner: Arc<ProxyRuntimeInner>,
    commands: Arc<ProxyCommandTasks>,
}

impl ProxyRuntime {
    pub fn new(core: Arc<ProxyCore>) -> Self {
        Self::with_tls_identity(core, None)
    }

    /// Construct a proxy runtime with an optional Certmesh-owned TLS identity.
    /// The port is injected by composition; Proxy never inspects Certmesh files.
    pub fn with_tls_identity(
        core: Arc<ProxyCore>,
        tls_identity: Option<Arc<dyn TlsIdentitySource>>,
    ) -> Self {
        let projection = Arc::new(ProxyProjection::new(&core));
        Self {
            inner: Arc::new(ProxyRuntimeInner {
                core,
                lifecycle: Mutex::new(ProxyLifecycle::default()),
                projection,
                tls_identity,
                #[cfg(test)]
                panic_next_stop_all: AtomicBool::new(false),
                #[cfg(test)]
                panic_next_shutdown: AtomicBool::new(false),
            }),
            commands: Arc::new(ProxyCommandTasks::new()),
        }
    }

    pub fn core(&self) -> Arc<ProxyCore> {
        Arc::clone(&self.inner.core)
    }

    /// Return Proxy's effective desired entries through the runtime boundary.
    pub async fn entries(&self) -> Vec<ProxyEntry> {
        self.inner.core.entries().await
    }

    /// Arm every desired listener.
    ///
    /// Success means any superseded sockets were released and each replacement
    /// task was armed. Initial bind/TLS settlement remains observable as
    /// `starting` followed by `running` or `error`; it is not disguised as
    /// configuration-command failure.
    pub async fn start_all(&self) -> Result<(), ProxyError> {
        self.submit(|runtime| async move { runtime.start_all_owned().await })
            .await
    }

    async fn start_all_owned(&self) -> Result<(), ProxyError> {
        let _operation = self.inner.core.operation.lock().await;
        self.ensure_live().await?;
        let entries = self.inner.core.configured_entries();
        self.apply_entries(entries).await
    }

    /// Reload durable desire and arm its listener tasks. As with [`Self::upsert`],
    /// success acknowledges replacement-socket teardown and task admission;
    /// status reports each asynchronous bind/TLS outcome.
    pub async fn reload(&self) -> Result<(), ProxyError> {
        self.submit(|runtime| async move { runtime.reload_owned().await })
            .await
    }

    async fn reload_owned(&self) -> Result<(), ProxyError> {
        let _operation = self.inner.core.operation.lock().await;
        self.ensure_live().await?;
        let entries = self.inner.core.reload_model()?;
        self.inner.projection.publish(&self.inner.core);
        self.apply_entries(entries).await
    }

    /// Persist an entry and immediately reconcile the listener data plane.
    ///
    /// Cross-domain producers use this chokepoint so a configuration mutation
    /// cannot be observed without its corresponding listener mutation.
    /// Success acknowledges durable desired state, release of a superseded
    /// listening socket, and arming of the replacement. The real initial
    /// `running`/`error` outcome is asynchronous and remains in status.
    pub async fn upsert(&self, entry: ProxyEntry) -> Result<(), ProxyError> {
        self.submit(move |runtime| async move { runtime.upsert_owned(entry).await })
            .await
    }

    async fn upsert_owned(&self, entry: ProxyEntry) -> Result<(), ProxyError> {
        let _operation = self.inner.core.operation.lock().await;
        self.ensure_live().await?;
        let (entries, changed) = self.inner.core.commit_upsert(entry.clone())?;
        // Specialized desired state is published by `commit_upsert`; primary
        // status is its immediate causal fence, before listener reconciliation.
        self.inner.projection.publish(&self.inner.core);
        self.apply_entries(entries).await?;
        if changed {
            let _ = self
                .inner
                .core
                .event_tx
                .send(ProxyEvent::EntryUpdated { entry });
        }
        Ok(())
    }

    /// Remove an entry and immediately reconcile the listener data plane.
    pub async fn remove(&self, name: &str) -> Result<(), ProxyError> {
        let name = name.to_string();
        self.submit(move |runtime| async move { runtime.remove_owned(name).await })
            .await
    }

    async fn remove_owned(&self, name: String) -> Result<(), ProxyError> {
        let _operation = self.inner.core.operation.lock().await;
        self.ensure_live().await?;
        let entries = self.inner.core.commit_remove(&name)?;
        self.inner.projection.publish(&self.inner.core);
        self.apply_entries(entries).await?;
        let _ = self
            .inner
            .core
            .event_tx
            .send(ProxyEvent::EntryRemoved { name });
        Ok(())
    }

    /// Persist a desired entry for the next daemon start without arming a
    /// listener in this short-lived process. Used only by explicit standalone
    /// CLI mode; normal live mutations use [`Self::upsert`].
    pub async fn configure_for_next_start(&self, entry: ProxyEntry) -> Result<(), ProxyError> {
        self.submit(
            move |runtime| async move { runtime.configure_for_next_start_owned(entry).await },
        )
        .await
    }

    async fn configure_for_next_start_owned(&self, entry: ProxyEntry) -> Result<(), ProxyError> {
        let _operation = self.inner.core.operation.lock().await;
        self.ensure_live().await?;
        let (_entries, changed) = self.inner.core.commit_upsert(entry.clone())?;
        self.inner.projection.publish(&self.inner.core);
        if changed {
            let _ = self
                .inner
                .core
                .event_tx
                .send(ProxyEvent::EntryUpdated { entry });
        }
        Ok(())
    }

    /// Remove persisted desire without arming listeners in this short-lived
    /// process. Used only by explicit standalone CLI mode.
    pub async fn remove_for_next_start(&self, name: &str) -> Result<(), ProxyError> {
        let name = name.to_string();
        self.submit(move |runtime| async move { runtime.remove_for_next_start_owned(name).await })
            .await
    }

    async fn remove_for_next_start_owned(&self, name: String) -> Result<(), ProxyError> {
        let _operation = self.inner.core.operation.lock().await;
        self.ensure_live().await?;
        self.inner.core.commit_remove(&name)?;
        self.inner.projection.publish(&self.inner.core);
        let _ = self
            .inner
            .core
            .event_tx
            .send(ProxyEvent::EntryRemoved { name });
        Ok(())
    }

    /// Validate one externally-derived entry with Proxy's own policy. Callers
    /// can discard a bad source item before replacing the complete scope, so a
    /// single invalid process cannot retain unrelated stale entries.
    pub fn validate_scoped_entry(entry: &ProxyEntry) -> Result<(), ProxyError> {
        validate_entry(entry)
    }

    /// Atomically replace one producer's transient desired set and reconcile
    /// the effective operator+derived data plane. Listener bind/TLS failures do
    /// not reject desire; they settle as truthful `error` status.
    pub async fn replace_scoped_entries(
        &self,
        scope: ProxyEntryScope,
        entries: Vec<ProxyEntry>,
    ) -> Result<(), ProxyError> {
        self.submit(move |runtime| async move {
            runtime.replace_scoped_entries_owned(scope, entries).await
        })
        .await
    }

    async fn replace_scoped_entries_owned(
        &self,
        scope: ProxyEntryScope,
        entries: Vec<ProxyEntry>,
    ) -> Result<(), ProxyError> {
        let _operation = self.inner.core.operation.lock().await;
        self.ensure_live().await?;
        let event_entries = entries.clone();
        let (effective, changed) = self.inner.core.replace_scoped_entries(scope, entries)?;
        if !changed {
            return Ok(());
        }
        self.inner.projection.publish(&self.inner.core);
        self.apply_entries(effective).await?;
        let _ = self
            .inner
            .core
            .event_tx
            .send(ProxyEvent::ScopedEntriesReplaced {
                scope,
                entries: event_entries,
            });
        Ok(())
    }

    async fn submit<R, F, Fut>(&self, command: F) -> Result<R, ProxyError>
    where
        R: Send + 'static,
        F: FnOnce(ProxyRuntime) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<R, ProxyError>> + Send + 'static,
    {
        // Admission is bounded before a task becomes runtime-owned. The task
        // intentionally retains this facade (and therefore its own JoinHandle)
        // until completion; the permit caps that temporary self-retention.
        let permit = self.commands.admit().await?;
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let runtime = self.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let result = command(runtime).await;
            let _ = result_tx.send(result);
        });
        self.commands.retain(task);
        result_rx
            .await
            .map_err(|_| ProxyError::Worker("command ended before acknowledgement".into()))?
    }

    async fn apply_entries(&self, entries: Vec<ProxyEntry>) -> Result<(), ProxyError> {
        let desired = entries
            .iter()
            .map(|entry| (entry.name.clone(), entry))
            .collect::<HashMap<_, _>>();

        // Move retirement under the lifecycle owner before the first await.
        // A cancelled command therefore leaves every handle available for the
        // next command or terminal shutdown to finish reaping.
        {
            let mut lifecycle = self.inner.lifecycle.lock().await;
            let names = lifecycle
                .active
                .iter()
                .filter(|(name, instance)| {
                    desired.get(*name).is_none_or(|entry| {
                        instance.entry != **entry || instance.listener.is_finished()
                    })
                })
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            for name in names {
                if let Some(instance) = lifecycle.active.remove(&name) {
                    self.inner
                        .projection
                        .retire(&self.inner.core, &name, instance.generation);
                    lifecycle.retiring.push(instance);
                }
            }
        }
        self.reap_retiring(PROXY_STOP_TIMEOUT).await;
        self.prune_draining().await;

        // Old sockets are now closed. Only then arm replacements/new entries.
        let mut lifecycle = self.inner.lifecycle.lock().await;
        if lifecycle.shutting_down {
            return Err(ProxyError::ShutDown);
        }
        for entry in entries {
            if lifecycle.active.contains_key(&entry.name) {
                continue;
            }
            lifecycle.generation = lifecycle.generation.wrapping_add(1);
            let generation = lifecycle.generation;
            self.inner
                .projection
                .arm(&self.inner.core, &entry, generation);
            let observer = listener_observer(
                &self.inner.projection,
                &self.inner.core,
                entry.name.clone(),
                generation,
            );
            let listener = spawn_listener_with_tls_observer(
                entry.clone(),
                self.inner.core.certificate_overrides_dir(),
                self.inner.tls_identity.clone(),
                Some(observer),
            );
            lifecycle.active.insert(
                entry.name.clone(),
                ProxyInstance {
                    entry,
                    generation,
                    listener,
                },
            );
        }

        Ok(())
    }

    /// Stop every listener and acknowledge their native release. Connections
    /// accepted before this boundary intentionally drain to completion.
    ///
    /// `Ok(false)` is reserved for an admitted command that found no listener
    /// generation to stop. Closed admission and loss of the retained command
    /// owner are explicit errors.
    pub async fn stop_all(&self) -> Result<bool, ProxyError> {
        self.submit(|runtime| async move { runtime.stop_all_owned().await })
            .await
    }

    async fn stop_all_owned(&self) -> Result<bool, ProxyError> {
        let _operation = self.inner.core.operation.lock().await;
        #[cfg(test)]
        if self.inner.panic_next_stop_all.swap(false, Ordering::AcqRel) {
            panic!("injected Proxy stop-all panic");
        }
        let stopped = {
            let lifecycle = self.inner.lifecycle.lock().await;
            !lifecycle.active.is_empty() || !lifecycle.retiring.is_empty()
        };
        self.retire_all_active().await;
        self.reap_retiring(PROXY_STOP_TIMEOUT).await;
        self.prune_draining().await;
        Ok(stopped)
    }

    /// Permanently stop Proxy and reap every listener and child task.
    ///
    /// Unlike [`Self::stop_all`], shutdown is terminal. It is bounded,
    /// idempotent, and safe to retry after caller cancellation.
    pub async fn shutdown(&self) -> Result<(), ProxyError> {
        if self.commands.begin_shutdown() {
            // Election, task spawn, and retention contain no await: once
            // admission closes, caller cancellation cannot strand the runtime
            // between a terminal decision and its native-release owner.
            let runtime = self.clone();
            let command_owner = Arc::clone(&self.commands);
            let task = tokio::spawn(async move {
                // A nested task contains an unexpected panic so it cannot
                // strand every present and future shutdown waiter forever.
                // Ordinary release remains in the retained outer owner.
                let worker = tokio::spawn(async move { runtime.shutdown_owned().await });
                let failure = worker
                    .await
                    .err()
                    .map(|error| format!("Proxy terminal worker failed: {error}"));
                command_owner.complete_shutdown(failure);
            });
            self.commands.retain(task);
        }
        match self.commands.wait_shutdown().await {
            Some(error) => Err(ProxyError::Worker(error)),
            None => Ok(()),
        }
    }

    #[cfg(test)]
    fn panic_next_stop_all(&self) {
        self.inner
            .panic_next_stop_all
            .store(true, Ordering::Release);
    }

    async fn shutdown_owned(&self) {
        // Acquiring the operation gate fences every command admitted before the
        // terminal election: it either completes first or observes shutdown.
        let _operation = self.inner.core.operation.lock().await;
        #[cfg(test)]
        if self.inner.panic_next_shutdown.swap(false, Ordering::AcqRel) {
            panic!("injected Proxy shutdown panic");
        }
        {
            let mut lifecycle = self.inner.lifecycle.lock().await;
            lifecycle.shutting_down = true;
        }
        self.retire_all_active().await;
        let deadline = tokio::time::Instant::now() + PROXY_STOP_TIMEOUT;
        self.reap_retiring_until(deadline).await;
        self.reap_draining_until(deadline).await;
    }

    #[cfg(test)]
    fn panic_next_shutdown(&self) {
        self.inner
            .panic_next_shutdown
            .store(true, Ordering::Release);
    }

    /// Return the current immutable runtime snapshot in constant time.
    pub fn status(&self) -> Arc<ProxyRuntimeStatus> {
        self.inner.projection.status.current()
    }

    /// Subscribe to the current snapshot and future coalesced status changes.
    pub fn watch_status(&self) -> watch::Receiver<Arc<ProxyRuntimeStatus>> {
        self.inner.projection.status.subscribe()
    }

    /// Current immutable desired-entry projection in constant time.
    pub fn entries_snapshot(&self) -> Arc<ProxyEntriesSnapshot> {
        self.inner.core.entries_snapshot()
    }

    /// Subscribe to Proxy-owned desired-entry changes.
    pub fn watch_entries(&self) -> watch::Receiver<Arc<ProxyEntriesSnapshot>> {
        self.inner.core.watch_entries()
    }

    /// Subscribe to Proxy's semantic configuration events without piercing
    /// the runtime facade to reach its core.
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyEvent> {
        self.inner.core.subscribe()
    }

    async fn ensure_live(&self) -> Result<(), ProxyError> {
        if self.inner.lifecycle.lock().await.shutting_down {
            Err(ProxyError::ShutDown)
        } else {
            Ok(())
        }
    }

    async fn retire_all_active(&self) {
        let mut lifecycle = self.inner.lifecycle.lock().await;
        let active = std::mem::take(&mut lifecycle.active);
        for (name, instance) in active {
            self.inner
                .projection
                .retire(&self.inner.core, &name, instance.generation);
            lifecycle.retiring.push(instance);
        }
    }

    async fn reap_retiring(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        self.reap_retiring_until(deadline).await;
    }

    async fn reap_retiring_until(&self, deadline: tokio::time::Instant) {
        let mut lifecycle = self.inner.lifecycle.lock().await;
        while let Some(instance) = lifecycle.retiring.last_mut() {
            instance.listener.shutdown_until(deadline).await;
            let connections = instance.listener.take_connections();
            lifecycle.retiring.pop();
            if !connections.is_empty() {
                lifecycle.draining.push(connections);
            }
        }
    }

    async fn prune_draining(&self) {
        let mut lifecycle = self.inner.lifecycle.lock().await;
        for connections in &mut lifecycle.draining {
            connections.prune_finished();
        }
        lifecycle
            .draining
            .retain(|connections| !connections.is_empty());
    }

    async fn reap_draining_until(&self, deadline: tokio::time::Instant) {
        let mut lifecycle = self.inner.lifecycle.lock().await;
        while let Some(connections) = lifecycle.draining.last_mut() {
            connections.shutdown_until(deadline).await;
            lifecycle.draining.pop();
        }
    }
}

impl Drop for ProxyRuntimeInner {
    fn drop(&mut self) {
        self.projection.retire_all(&self.core);
        let lifecycle = self.lifecycle.get_mut();
        // Dropping ListenerHandle cancels and aborts synchronously. The maps are
        // then dropped normally; Drop never spawns cleanup work.
        lifecycle.active.clear();
        lifecycle.retiring.clear();
        lifecycle.draining.clear();
    }
}

fn listener_observer(
    projection: &Arc<ProxyProjection>,
    core: &Arc<ProxyCore>,
    name: String,
    generation: u64,
) -> Arc<dyn Fn(ListenerStatus) + Send + Sync> {
    let projection: Weak<ProxyProjection> = Arc::downgrade(projection);
    let core: Weak<ProxyCore> = Arc::downgrade(core);
    Arc::new(move |status| {
        let (Some(projection), Some(core)) = (projection.upgrade(), core.upgrade()) else {
            return;
        };
        projection.accept(&core, &name, generation, status);
    })
}

fn stopped_proxy(entry: &ProxyEntry) -> ProxyStatus {
    ProxyStatus {
        name: entry.name.clone(),
        listen_port: entry.listen_port,
        backend: entry.backend.clone(),
        allow_remote: entry.allow_remote,
        cert_source: "unresolved".to_string(),
        cert_revision: 0,
        state: "stopped".to_string(),
        error: None,
    }
}

fn stopped_proxies(entries: &[ProxyEntry]) -> Vec<ProxyStatus> {
    let mut proxies = entries.iter().map(stopped_proxy).collect::<Vec<_>>();
    proxies.sort_by(|left, right| left.name.cmp(&right.name));
    proxies
}

fn snapshot_proxies(
    entries: &[ProxyEntry],
    listeners: &HashMap<String, ProjectedListener>,
) -> Vec<ProxyStatus> {
    let mut proxies = entries
        .iter()
        .map(|entry| {
            let Some(listener) = listeners
                .get(&entry.name)
                .filter(|listener| listener.entry == *entry)
            else {
                return stopped_proxy(entry);
            };
            ProxyStatus {
                name: entry.name.clone(),
                listen_port: entry.listen_port,
                backend: entry.backend.clone(),
                allow_remote: entry.allow_remote,
                cert_source: listener.status.cert_source.as_str().to_string(),
                cert_revision: listener.status.cert_revision,
                state: listener.status.state.as_str().to_string(),
                error: listener.status.error.clone(),
            }
        })
        .collect::<Vec<_>>();
    proxies.sort_by(|left, right| left.name.cmp(&right.name));
    proxies
}

fn summarize_entries(entries: &[ProxyEntry]) -> Vec<ProxyEntrySummary> {
    let mut summaries = entries
        .iter()
        .map(|entry| ProxyEntrySummary {
            name: entry.name.clone(),
            listen_port: entry.listen_port,
            backend: entry.backend.clone(),
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| left.name.cmp(&right.name));
    summaries
}

fn validate_entry(entry: &ProxyEntry) -> Result<(), ProxyError> {
    if entry.name.trim().is_empty() {
        return Err(ProxyError::InvalidConfig(
            "proxy name cannot be empty".to_string(),
        ));
    }
    ensure_backend_allowed(&entry.backend, entry.allow_remote)
}

fn validate_entries(entries: &[ProxyEntry]) -> Result<(), ProxyError> {
    let mut names = std::collections::HashSet::new();
    for entry in entries {
        validate_entry(entry)?;
        if !names.insert(&entry.name) {
            return Err(ProxyError::InvalidConfig(format!(
                "duplicate proxy entry: {}",
                entry.name
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "koi-proxy-test-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn open_test_core(dir: &std::path::Path) -> Result<ProxyCore, ProxyError> {
        ProxyCore::open(dir.join("config.toml"), dir.join("proxy-certs"))
    }

    /// Build a ProxyCore backed by a throwaway data dir so tests never touch the
    /// real on-disk proxy config.
    fn test_core() -> ProxyCore {
        let dir = test_dir();
        open_test_core(&dir).expect("core should build")
    }

    fn sample_entry(name: &str) -> ProxyEntry {
        ProxyEntry {
            name: name.to_string(),
            listen_port: 9090,
            backend: "http://127.0.0.1:8080".to_string(),
            allow_remote: false,
        }
    }

    fn free_tcp_port() -> u16 {
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("bind ephemeral listener")
            .local_addr()
            .expect("ephemeral listener address")
            .port()
    }

    async fn wait_for_proxy_state(
        runtime: &ProxyRuntime,
        name: &str,
        expected: &str,
    ) -> ProxyStatus {
        let mut status = runtime.watch_status();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(proxy) = status
                    .borrow_and_update()
                    .proxies
                    .iter()
                    .find(|proxy| proxy.name == name && proxy.state == expected)
                    .cloned()
                {
                    return proxy;
                }
                status
                    .changed()
                    .await
                    .expect("proxy status source remains live");
            }
        })
        .await
        .expect("proxy reaches expected state")
    }

    /// Drives the runtime-owned command path and asserts its converged event is broadcast
    /// through the core's channel. Fails if mutation/status/event ordering drifts.
    #[tokio::test]
    async fn upsert_emits_entry_updated_through_core() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut rx = core.subscribe();
        let mut entry = sample_entry("test-svc");
        entry.listen_port = 0;

        runtime.upsert(entry).await.expect("upsert should succeed");

        match rx.try_recv().expect("should receive event") {
            ProxyEvent::EntryUpdated { entry } => {
                assert_eq!(entry.name, "test-svc");
                assert_eq!(entry.listen_port, 0);
                assert_eq!(entry.backend, "http://127.0.0.1:8080");
            }
            other => panic!("expected EntryUpdated, got {other:?}"),
        }
        assert_eq!(runtime.status().proxies[0].name, "test-svc");
        runtime.stop_all().await.expect("stop Proxy listeners");
    }

    /// remove() on an existing entry emits EntryRemoved through the core.
    #[tokio::test]
    async fn remove_emits_entry_removed_through_core() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut entry = sample_entry("rm-svc");
        entry.listen_port = 0;
        runtime.upsert(entry).await.expect("upsert should succeed");

        let mut rx = core.subscribe();
        runtime
            .remove("rm-svc")
            .await
            .expect("remove should succeed");

        match rx.try_recv().expect("should receive event") {
            ProxyEvent::EntryRemoved { name } => assert_eq!(name, "rm-svc"),
            other => panic!("expected EntryRemoved, got {other:?}"),
        }
        assert!(runtime.status().proxies.is_empty());
    }

    /// Two subscribers to the same core each receive a core-emitted event.
    #[tokio::test]
    async fn multiple_subscribers_each_receive_core_event() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut rx1 = core.subscribe();
        let mut rx2 = core.subscribe();
        let mut entry = sample_entry("multi");
        entry.listen_port = 0;

        runtime.upsert(entry).await.expect("upsert should succeed");

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
        runtime.stop_all().await.expect("stop Proxy listeners");
    }

    #[tokio::test]
    async fn runtime_mutations_reconcile_listener_ownership() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut entry = sample_entry("runtime-owned");
        entry.listen_port = 0;

        runtime
            .upsert(entry)
            .await
            .expect("runtime upsert should persist and apply");
        let status = runtime.status();
        assert_eq!(status.proxies.len(), 1);
        assert_eq!(status.proxies[0].name, "runtime-owned");

        runtime
            .remove("runtime-owned")
            .await
            .expect("runtime remove should persist and apply");
        assert!(runtime.status().proxies.is_empty());
        assert!(core.entries().await.is_empty());
    }

    #[tokio::test]
    async fn same_port_replacement_waits_for_previous_listener_release() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(core);
        let listen_port = free_tcp_port();
        let mut entry = sample_entry("replace-in-place");
        entry.listen_port = listen_port;

        runtime.upsert(entry.clone()).await.unwrap();
        wait_for_proxy_state(&runtime, &entry.name, "running").await;

        entry.backend = "127.0.0.1:8081".to_string();
        runtime.upsert(entry.clone()).await.unwrap();
        let replaced = wait_for_proxy_state(&runtime, &entry.name, "running").await;
        assert_eq!(replaced.backend, entry.backend);
        assert!(replaced.error.is_none());

        runtime.stop_all().await.expect("stop Proxy listeners");
    }

    #[tokio::test]
    async fn upsert_accepts_desire_without_claiming_a_failed_bind_is_running() {
        let occupied = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let listen_port = occupied.local_addr().unwrap().port();
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut events = core.subscribe();
        let mut entry = sample_entry("contended");
        entry.listen_port = listen_port;

        runtime
            .upsert(entry.clone())
            .await
            .expect("durable desired-state acceptance succeeds");
        assert!(matches!(
            events.try_recv(),
            Ok(ProxyEvent::EntryUpdated { entry: accepted }) if accepted == entry
        ));
        assert_ne!(
            runtime.status().proxies[0].state,
            "running",
            "desired-state success must not invent listener liveness"
        );

        let settled = wait_for_proxy_state(&runtime, &entry.name, "error").await;
        assert_eq!(settled.error.as_deref(), Some("address in use"));
        runtime.stop_all().await.expect("stop Proxy listeners");
    }

    #[tokio::test]
    async fn remove_returns_only_after_listening_port_is_rebindable() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(core);
        let listen_port = free_tcp_port();
        let mut entry = sample_entry("remove-and-rebind");
        entry.listen_port = listen_port;

        runtime.upsert(entry.clone()).await.unwrap();
        wait_for_proxy_state(&runtime, &entry.name, "running").await;
        runtime.remove(&entry.name).await.unwrap();

        let rebound = std::net::TcpListener::bind(("0.0.0.0", listen_port))
            .expect("remove success acknowledges listening socket release");
        drop(rebound);
    }

    #[test]
    fn corrupt_persistence_fails_construction_instead_of_becoming_empty() {
        let dir = test_dir();
        std::fs::write(dir.join("config.toml"), "[proxy\nnot toml").unwrap();
        let error = match open_test_core(&dir) {
            Ok(_) => panic!("corrupt config must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, ProxyError::Config(_)));
    }

    #[test]
    fn initial_status_contains_persisted_entries_as_stopped() {
        let dir = test_dir();
        let entry = sample_entry("persisted");
        config::save_entries(std::slice::from_ref(&entry), &dir.join("config.toml")).unwrap();
        let runtime = ProxyRuntime::new(Arc::new(open_test_core(&dir).unwrap()));

        let status = runtime.status();
        assert_eq!(status.revision, 0);
        assert_eq!(status.proxies.len(), 1);
        assert_eq!(status.proxies[0].name, entry.name);
        assert_eq!(status.proxies[0].state, "stopped");
        assert_eq!(status.proxies[0].cert_source, "unresolved");
    }

    #[tokio::test]
    async fn failed_commit_changes_neither_model_status_nor_event() {
        let dir = test_dir();
        let core = Arc::new(open_test_core(&dir).unwrap());
        // A directory where the shared config file must be makes the durable
        // write fail deterministically on every supported platform.
        std::fs::create_dir(dir.join("config.toml")).unwrap();
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let before = runtime.status();
        let mut events = core.subscribe();

        assert!(runtime.upsert(sample_entry("rejected")).await.is_err());
        assert!(core.entries().await.is_empty());
        assert!(Arc::ptr_eq(&before, &runtime.status()));
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn concurrent_commands_preserve_both_durable_entries() {
        let core = Arc::new(test_core());
        let runtime = Arc::new(ProxyRuntime::new(Arc::clone(&core)));
        let mut first = sample_entry("alpha");
        first.listen_port = 0;
        let mut second = sample_entry("bravo");
        second.listen_port = 0;

        let left = {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.upsert(first).await })
        };
        let right = {
            let runtime = Arc::clone(&runtime);
            tokio::spawn(async move { runtime.upsert(second).await })
        };
        left.await.unwrap().unwrap();
        right.await.unwrap().unwrap();

        let entries = core.entries().await;
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "bravo"]
        );
        runtime.stop_all().await.expect("stop Proxy listeners");
    }

    #[tokio::test]
    async fn runtime_status_is_immediate_revisioned_and_suppresses_noops() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(core);
        let mut status_rx = runtime.watch_status();
        let mut event_rx = runtime.core().subscribe();
        let initial = runtime.status();
        assert_eq!(initial.revision, 0);
        assert!(Arc::ptr_eq(&initial, &status_rx.borrow()));

        let mut entry = sample_entry("observed");
        entry.listen_port = 0;
        runtime.upsert(entry.clone()).await.unwrap();
        assert!(matches!(
            event_rx.try_recv(),
            Ok(ProxyEvent::EntryUpdated { .. })
        ));
        status_rx.changed().await.unwrap();
        let mut settled = status_rx.borrow_and_update().clone();
        assert_eq!(settled.proxies.len(), 1);
        while settled.proxies[0].state == "starting" {
            tokio::time::timeout(std::time::Duration::from_secs(5), status_rx.changed())
                .await
                .expect("listener should settle")
                .unwrap();
            settled = status_rx.borrow_and_update().clone();
        }

        runtime.upsert(entry).await.unwrap();
        assert!(status_rx.has_changed().is_ok_and(|changed| !changed));
        assert!(matches!(
            event_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        runtime.stop_all().await.expect("stop Proxy listeners");
        status_rx.changed().await.unwrap();
        assert_eq!(
            status_rx.borrow_and_update().revision,
            settled.revision.saturating_add(1)
        );
    }

    #[tokio::test]
    async fn entries_projection_precedes_primary_status_and_suppresses_noops() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut entries_rx = runtime.watch_entries();
        let mut status_rx = runtime.watch_status();
        let mut events = runtime.subscribe();
        let mut entry = sample_entry("catalog");
        entry.listen_port = 0;

        runtime
            .configure_for_next_start(entry.clone())
            .await
            .expect("configure entry");
        entries_rx.changed().await.expect("entries revision");
        status_rx.changed().await.expect("primary status revision");
        let entries = entries_rx.borrow_and_update().clone();
        let primary = status_rx.borrow_and_update().clone();
        assert_eq!(primary.entries_revision, entries.revision);
        assert_eq!(entries.entries.len(), 1);
        assert_eq!(entries.entries[0].name, entry.name);
        assert!(matches!(
            events.try_recv(),
            Ok(ProxyEvent::EntryUpdated { .. })
        ));

        let entries_before = runtime.entries_snapshot();
        let status_before = runtime.status();
        runtime
            .configure_for_next_start(entry)
            .await
            .expect("equal configure is accepted");
        assert!(Arc::ptr_eq(&entries_before, &runtime.entries_snapshot()));
        assert!(Arc::ptr_eq(&status_before, &runtime.status()));
        assert!(entries_rx.has_changed().is_ok_and(|changed| !changed));
        assert!(status_rx.has_changed().is_ok_and(|changed| !changed));
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn transient_scope_replaces_completely_without_persisting_and_operator_wins() {
        let dir = test_dir();
        let core = Arc::new(open_test_core(&dir).unwrap());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut derived = sample_entry("shared");
        derived.listen_port = 0;
        let mut stale = sample_entry("stale");
        stale.listen_port = 0;

        runtime
            .replace_scoped_entries(
                ProxyEntryScope::Runtime,
                vec![derived.clone(), stale.clone()],
            )
            .await
            .unwrap();
        assert!(config::load_entries(&dir.join("config.toml"))
            .unwrap()
            .is_empty());
        assert_eq!(core.entries().await.len(), 2);

        let mut operator = derived.clone();
        operator.backend = "http://127.0.0.1:9091".into();
        runtime.upsert(operator.clone()).await.unwrap();
        runtime
            .replace_scoped_entries(ProxyEntryScope::Runtime, vec![derived])
            .await
            .unwrap();

        let effective = core.entries().await;
        assert_eq!(effective, [operator.clone()]);
        assert_eq!(
            config::load_entries(&dir.join("config.toml")).unwrap(),
            [operator.clone()]
        );
        let restarted = open_test_core(&dir).unwrap();
        assert_eq!(restarted.entries().await, [operator]);
        runtime.stop_all().await.expect("stop Proxy listeners");
    }

    #[tokio::test]
    async fn operator_noop_preserves_noncolliding_runtime_desire_and_listener() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut derived = sample_entry("runtime-only");
        derived.listen_port = 0;
        let mut operator = sample_entry("operator-only");
        operator.listen_port = 0;

        runtime
            .replace_scoped_entries(ProxyEntryScope::Runtime, vec![derived.clone()])
            .await
            .unwrap();
        runtime.upsert(operator.clone()).await.unwrap();
        runtime
            .upsert(operator.clone())
            .await
            .expect("equal operator desire is a no-op");

        assert_eq!(core.entries().await, [operator, derived]);
        assert!(runtime
            .status()
            .proxies
            .iter()
            .any(|proxy| proxy.name == "runtime-only"));
        runtime.stop_all().await.expect("stop Proxy listeners");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn last_requester_drop_after_durable_commit_still_converges_status_and_event() {
        let dir = test_dir();
        let core = Arc::new(open_test_core(&dir).unwrap());
        let runtime = ProxyRuntime::new(Arc::clone(&core));
        let mut status = runtime.watch_status();
        let mut events = runtime.subscribe();
        let mut entry = sample_entry("cancelled-requester");
        entry.listen_port = 0;
        core.pause_next_commit_after_durable();

        let request = {
            let runtime = runtime.clone();
            let entry = entry.clone();
            tokio::spawn(async move { runtime.upsert(entry).await })
        };
        while !core.is_commit_paused() {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            config::load_entries(&dir.join("config.toml")).unwrap(),
            [entry.clone()]
        );

        request.abort();
        let _ = request.await;
        drop(runtime);
        core.release_commit();

        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if status
                    .borrow_and_update()
                    .proxies
                    .iter()
                    .any(|proxy| proxy.name == entry.name)
                {
                    break;
                }
                status
                    .changed()
                    .await
                    .expect("owned command keeps status live");
            }
        })
        .await;
        assert!(
            observed.is_ok(),
            "owned command must publish after requester drop"
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), events.recv())
                .await
                .unwrap()
                .unwrap(),
            ProxyEvent::EntryUpdated { entry: updated } if updated == entry
        ));
        assert_eq!(core.entries().await, [entry]);
    }

    #[tokio::test]
    async fn terminal_shutdown_reaps_lifecycle_and_rejects_restart() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(core);
        let mut entry = sample_entry("terminal");
        entry.listen_port = free_tcp_port();
        runtime.upsert(entry.clone()).await.expect("arm listener");
        wait_for_proxy_state(&runtime, &entry.name, "running").await;

        runtime.shutdown().await.expect("terminal Proxy shutdown");
        assert_eq!(runtime.status().proxies[0].state, "stopped");
        let lifecycle = runtime.inner.lifecycle.lock().await;
        assert!(lifecycle.active.is_empty());
        assert!(lifecycle.retiring.is_empty());
        assert!(lifecycle.draining.is_empty());
        drop(lifecycle);
        assert!(matches!(
            runtime.start_all().await,
            Err(ProxyError::ShutDown)
        ));
    }

    #[tokio::test]
    async fn panicked_terminal_worker_settles_all_shutdown_waiters() {
        let runtime = ProxyRuntime::new(Arc::new(test_core()));
        runtime.panic_next_shutdown();

        let first = tokio::time::timeout(Duration::from_secs(2), runtime.shutdown())
            .await
            .expect("first shutdown waiter settles after worker panic")
            .expect_err("terminal worker loss must be explicit");
        assert!(matches!(
            &first,
            ProxyError::Worker(error) if error.contains("injected Proxy shutdown panic")
        ));
        assert!(runtime
            .commands
            .shutdown_failure
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_deref()
            .is_some_and(|error| error.contains("injected Proxy shutdown panic")));
        let repeated = tokio::time::timeout(Duration::from_secs(2), runtime.shutdown())
            .await
            .expect("later shutdown waiter observes terminal settlement")
            .expect_err("terminal failure remains visible to later observers");
        assert_eq!(repeated.to_string(), first.to_string());
    }

    #[tokio::test]
    async fn stop_all_acknowledges_execution_noop_and_closed_admission_truthfully() {
        let runtime = ProxyRuntime::new(Arc::new(test_core()));
        assert!(!runtime
            .stop_all()
            .await
            .expect("an admitted already-stopped command is a real no-op"));

        let mut entry = sample_entry("stop-ack");
        entry.listen_port = 0;
        runtime.upsert(entry).await.expect("arm listener");
        assert!(runtime
            .stop_all()
            .await
            .expect("listener retirement is acknowledged"));
        assert!(!runtime
            .stop_all()
            .await
            .expect("repeated stop observes the accepted no-op"));

        runtime.shutdown().await.expect("terminal shutdown");
        assert!(matches!(
            runtime.stop_all().await,
            Err(ProxyError::ShutDown)
        ));
    }

    #[tokio::test]
    async fn stop_all_reports_lost_worker_acknowledgement() {
        let runtime = ProxyRuntime::new(Arc::new(test_core()));
        runtime.panic_next_stop_all();

        let error = runtime
            .stop_all()
            .await
            .expect_err("worker loss cannot be reported as a no-op");
        assert!(matches!(
            error,
            ProxyError::Worker(detail) if detail.contains("before acknowledgement")
        ));
        assert!(!runtime
            .stop_all()
            .await
            .expect("runtime remains usable after the failed command worker"));
    }

    #[tokio::test]
    async fn dropping_last_runtime_owner_aborts_listener_and_releases_port() {
        let core = Arc::new(test_core());
        let runtime = ProxyRuntime::new(core);
        let mut entry = sample_entry("drop-owner");
        entry.listen_port = free_tcp_port();
        runtime.upsert(entry.clone()).await.expect("arm listener");
        wait_for_proxy_state(&runtime, &entry.name, "running").await;

        let port = entry.listen_port;
        drop(runtime);
        tokio::time::timeout(Duration::from_secs(2), async move {
            loop {
                if let Ok(listener) = std::net::TcpListener::bind(("0.0.0.0", port)) {
                    drop(listener);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Drop releases listener port");
    }

    #[test]
    fn runtime_status_wire_round_trips() {
        let status = ProxyRuntimeStatus {
            revision: 3,
            entries_revision: 0,
            proxies: vec![ProxyStatus {
                name: "api".into(),
                listen_port: 9443,
                backend: "http://127.0.0.1:8080".into(),
                allow_remote: false,
                cert_source: "self-signed".into(),
                cert_revision: 2,
                state: "running".into(),
                error: None,
            }],
        };
        let encoded = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<ProxyRuntimeStatus>(&encoded).unwrap(),
            status
        );
    }
}
