//! Daemon core composition — the single place that constructs every domain core, wires the
//! cross-domain integration bridges between them, spawns the domain background tasks
//! (orchestrator + certmesh role loops), and tears it all down in order.
//!
//! Before P07 this graph was hand-written twice — in the binary's `daemon_mode` and again
//! in the Windows service's `run_service` — and the two had already drifted into a verified
//! `koi install` defect. [`crate::cores::build_cores`] is now the one copy both call, so the daemon they
//! construct is identical by construction.
//!
//! The enrollment-approval pump is intentionally *not* spawned here: its decider differs by
//! host (the foreground daemon prompts on stdin; consoleless hosts deny). The caller spawns
//! it via [`crate::certmesh::spawn_enrollment_approval`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use futures_util::FutureExt;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_common::integration::{
    AliasFeedback, CertmeshSnapshot, DnsProbe, MdnsSnapshot, ProxySnapshot, TlsIdentitySource,
};

const BUILD_ROLLBACK_TIMEOUT: Duration = Duration::from_secs(20);

/// Immutable persistence layout derived by an application composition root.
///
/// Domain cores receive the final paths they own; they never discover process-global
/// storage or reproduce Koi's filesystem layout themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistencePaths {
    data_dir: PathBuf,
    dns_state: PathBuf,
    health_state: PathBuf,
    health_log: PathBuf,
    proxy_config: PathBuf,
    proxy_certificates: PathBuf,
}

impl PersistencePaths {
    pub fn from_data_dir(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let state_dir = data_dir.join("state");
        Self {
            dns_state: state_dir.join("dns.json"),
            health_state: state_dir.join("health.json"),
            health_log: data_dir.join("logs/health.log"),
            proxy_config: data_dir.join("config.toml"),
            proxy_certificates: data_dir.join("proxy-certs"),
            data_dir,
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn dns_state(&self) -> &Path {
        &self.dns_state
    }

    pub fn health_state(&self) -> &Path {
        &self.health_state
    }

    pub fn health_log(&self) -> &Path {
        &self.health_log
    }

    pub fn proxy_config(&self) -> &Path {
        &self.proxy_config
    }

    pub fn proxy_certificates(&self) -> &Path {
        &self.proxy_certificates
    }
}

/// Instance-scoped owner of the one terminal composition shutdown transaction.
///
/// The actual teardown task is retained here rather than in the caller's await
/// future. Dropping or cancelling a waiter therefore cannot detach background
/// work or skip domain release; a later waiter observes the same transaction.
#[derive(Default)]
struct CompositionLifecycle {
    state: StdMutex<CompositionShutdownState>,
    completed: Notify,
}

#[derive(Default)]
struct CompositionShutdownState {
    started: bool,
    complete: bool,
    running: Vec<JoinHandle<()>>,
    retired: Vec<JoinHandle<()>>,
    task: Option<JoinHandle<()>>,
}

impl CompositionLifecycle {
    /// Admit steady-state work under composition ownership. Admission and the
    /// terminal transition share one synchronous gate, so a task can never race
    /// into the graph after shutdown has taken ownership.
    fn own_task(&self, task: JoinHandle<()>) {
        self.own_tasks(std::iter::once(task));
    }

    fn own_tasks(&self, tasks: impl IntoIterator<Item = JoinHandle<()>>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for task in tasks {
            if state.started {
                task.abort();
                state.retired.push(task);
            } else {
                state.running.push(task);
            }
        }
    }

    fn start(
        self: &Arc<Self>,
        cancel: CancellationToken,
        releases: ReleaseTargets,
        timeout: Duration,
        drain: Duration,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.started {
            return;
        }
        state.started = true;
        let tasks = std::mem::take(&mut state.running);

        // The admitted terminal transaction temporarily retains its owner. This
        // is the sole intentional lifecycle cycle, and completion breaks it by
        // removing the stored JoinHandle before releasing this Arc.
        let lifecycle = Arc::clone(self);
        let background = AbortOnDropTasks(tasks);
        let transaction = async move {
            let result = std::panic::AssertUnwindSafe(shutdown_transaction(
                cancel, background, releases, timeout, drain,
            ))
            .catch_unwind()
            .await;
            if result.is_err() {
                tracing::error!("Composition shutdown transaction panicked");
            }
            let mut state = lifecycle
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.complete = true;
            // Drop the handle to this now-terminal task and break the temporary
            // owner → handle → task → owner cycle before the task returns.
            state.task.take();
            drop(state);
            lifecycle.completed.notify_waiters();
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // A build future can be dropped while its executor is itself being
            // torn down. No async transaction can make progress in that case:
            // dropping this unspawned future synchronously aborts every task
            // through AbortOnDropTasks and invokes each domain's Drop fallback.
            // Most importantly, Drop never panics and retains no owner cycle.
            tracing::error!(
                "No Tokio runtime available for composition cleanup; applying synchronous fail-close fallback"
            );
            drop(transaction);
            state.complete = true;
            self.completed.notify_waiters();
            return;
        };
        let task = runtime.spawn(transaction);
        state.task = Some(task);
    }

    async fn wait(&self) {
        loop {
            let completed = self.completed.notified();
            let retired = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if state.complete {
                    Some(std::mem::take(&mut state.retired))
                } else {
                    None
                }
            };
            if let Some(retired) = retired {
                for task in retired {
                    let _ = task.await;
                }
                return;
            }
            completed.await;
        }
    }

    #[cfg(test)]
    fn is_complete(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .complete
    }

    #[cfg(test)]
    fn owned_task_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .running
            .len()
    }
}

impl Drop for CompositionLifecycle {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(task) = state.task.as_mut() {
            task.abort();
        }
        for task in &state.running {
            task.abort();
        }
        for task in &state.retired {
            task.abort();
        }
    }
}

/// Synchronous fail-closed ownership around a set of Tokio tasks.
struct AbortOnDropTasks(Vec<JoinHandle<()>>);

impl AbortOnDropTasks {
    fn take(&mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.0)
    }
}

/// Domain owners retained by the terminal composition transaction until every
/// release fence has completed. A deadline may diagnose slow release, but can
/// never turn an admitted terminal transition into detached work.
struct ReleaseTargets {
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    mdns_bridge: Option<Arc<crate::bridges::MdnsBridge>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
    runtime: Option<Arc<koi_runtime::RuntimeCore>>,
    trust: Option<Arc<koi_trust::TrustCore>>,
}

impl From<&Cores> for ReleaseTargets {
    fn from(cores: &Cores) -> Self {
        Self {
            mdns: cores.mdns.clone(),
            mdns_bridge: cores.mdns_snapshot.clone(),
            dns: cores.dns.clone(),
            health: cores.health.clone(),
            proxy: cores.proxy.clone(),
            udp: cores.udp.clone(),
            runtime: cores.runtime.clone(),
            trust: cores.trust.clone(),
        }
    }
}

impl Drop for AbortOnDropTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Owns every resource admitted during composition until the graph is committed.
///
/// `build_cores` is async and may fail or be cancelled after an earlier domain
/// has bound native resources. This guard gives construction transaction
/// semantics: explicit errors use the acknowledged async rollback, while Drop
/// synchronously admits a self-retained rollback for a cancelled build future.
struct CoreBuildGuard {
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    mdns_bridge: Option<Arc<crate::bridges::MdnsBridge>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
    runtime: Option<Arc<koi_runtime::RuntimeCore>>,
    trust: Option<Arc<koi_trust::TrustCore>>,
    armed: bool,
}

impl CoreBuildGuard {
    fn new(parent: &CancellationToken) -> Self {
        Self {
            cancel: parent.child_token(),
            tasks: Vec::new(),
            mdns: None,
            mdns_bridge: None,
            dns: None,
            health: None,
            proxy: None,
            udp: None,
            runtime: None,
            trust: None,
            armed: true,
        }
    }

    async fn rollback(&mut self) {
        self.cancel.cancel();
        let deadline = tokio::time::Instant::now() + BUILD_ROLLBACK_TIMEOUT;
        reap_owned_tasks(
            std::mem::take(&mut self.tasks),
            deadline,
            "startup rollback",
        )
        .await;

        release_domain_targets(
            ReleaseTargets {
                mdns: self.mdns.clone(),
                mdns_bridge: self.mdns_bridge.clone(),
                dns: self.dns.clone(),
                health: self.health.clone(),
                proxy: self.proxy.clone(),
                udp: self.udp.clone(),
                runtime: self.runtime.clone(),
                trust: self.trust.clone(),
            },
            deadline,
            "startup domain rollback",
        )
        .await;
        self.armed = false;
    }

    fn commit_into(&mut self, lifecycle: &CompositionLifecycle) {
        lifecycle.own_tasks(self.tasks.drain(..));
        self.armed = false;
    }
}

impl Drop for CoreBuildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.cancel.cancel();

        // Dropping a cancelled build future is itself a terminal admission
        // edge. Transfer every partially-built task and domain owner into the
        // same self-retained transaction used by a live graph; aborting bare
        // handles here would otherwise detach their destructors from any owner.
        let lifecycle = Arc::new(CompositionLifecycle::default());
        lifecycle.own_tasks(self.tasks.drain(..));
        lifecycle.start(
            self.cancel.clone(),
            ReleaseTargets {
                mdns: self.mdns.take(),
                mdns_bridge: self.mdns_bridge.take(),
                dns: self.dns.take(),
                health: self.health.take(),
                proxy: self.proxy.take(),
                udp: self.udp.take(),
                runtime: self.runtime.take(),
                trust: self.trust.take(),
            },
            Duration::ZERO,
            Duration::ZERO,
        );
    }
}

/// The set of domain cores a daemon runs. Each is present only if its capability is enabled
/// (via the `no_*` flags in [`CoreSpec`]).
#[derive(Clone, Default)]
pub struct Cores {
    pub mdns: Option<Arc<koi_mdns::MdnsCore>>,
    pub certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    pub trust: Option<Arc<koi_trust::TrustCore>>,
    pub dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub health: Option<Arc<koi_health::HealthRuntime>>,
    pub proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    pub udp: Option<Arc<koi_udp::UdpRuntime>>,
    pub runtime: Option<Arc<koi_runtime::RuntimeCore>>,
    /// The one composition-owned product status boundary. Presentations read
    /// this feed; they do not query and reassemble individual domains.
    pub system_status: Arc<crate::status::KoiStatusRuntime>,
    /// The shared mDNS cached-records snapshot bridge consumed by explicitly wired
    /// cross-domain integrations such as DNS and Health. Presentation adapters read
    /// the same domain projection through `system_status`. `None` when mDNS is disabled.
    pub mdns_snapshot: Option<Arc<crate::bridges::MdnsBridge>>,
}

impl Cores {
    /// Publish a composition-owned capability fact into the aggregate.
    pub fn publish_composition_status(&self, report: crate::status::CapabilityReport) {
        assert!(
            matches!(report.status.name.as_str(), "ipc" | "pond"),
            "domain-owned capability status must arrive through its domain feed"
        );
        self.system_status.publish_composition_status(self, report);
    }

    /// Project Pond's exact typed serving-component status into the aggregate.
    pub fn publish_pond_status(&self, status: Arc<koi_common::pond::PondStatus>) {
        self.system_status.publish_pond_status(self, status);
    }
}

/// A live composed graph paired with its non-cloneable task/lifecycle owner.
///
/// Background tasks may capture cloneable [`Cores`] views, but can never capture
/// this owner. That one-way relationship rules out owner → task → owner cycles
/// while keeping ordinary domain access ergonomic through [`std::ops::Deref`].
pub struct RunningCores {
    // Drop the task owner first so every captured inert Cores view is aborted
    // before this root graph releases its own domain references.
    lifecycle: Arc<CompositionLifecycle>,
    cores: Cores,
}

impl RunningCores {
    fn new(cores: Cores) -> Self {
        Self {
            lifecycle: Arc::new(CompositionLifecycle::default()),
            cores,
        }
    }

    pub fn cores(&self) -> &Cores {
        &self.cores
    }

    /// Transfer a background task into the one terminal lifecycle owner.
    ///
    /// The task may capture an inert [`Cores`] clone, but must never capture
    /// this `RunningCores` owner. Keeping ownership one-way prevents lifecycle
    /// cycles while ensuring an unwind cannot detach steady-state work.
    pub fn own_task(&self, task: JoinHandle<()>) {
        self.lifecycle.own_task(task);
    }

    /// Transfer a set of already-spawned background tasks into the lifecycle
    /// owner at one synchronous boundary.
    pub fn own_tasks(&self, tasks: impl IntoIterator<Item = JoinHandle<()>>) {
        self.lifecycle.own_tasks(tasks);
    }

    #[cfg(test)]
    pub(crate) fn owned_task_count(&self) -> usize {
        self.lifecycle.owned_task_count()
    }
}

impl std::ops::Deref for RunningCores {
    type Target = Cores;

    fn deref(&self) -> &Self::Target {
        &self.cores
    }
}

impl Default for RunningCores {
    fn default() -> Self {
        Self::new(Cores::default())
    }
}

/// Error from [`crate::cores::build_cores`] when `fail_fast` is set (koi-embedded's library contract).
/// With `fail_fast = false` (the daemon/service default) `build_cores` never returns this —
/// a capability that fails to initialize is logged and dropped and the daemon keeps running.
#[derive(Debug, thiserror::Error)]
pub enum BuildCoresError {
    #[error("core composition was cancelled")]
    Cancelled,
    #[error("mDNS core init failed: {0}")]
    Mdns(#[from] koi_mdns::MdnsError),
    #[error("DNS init/start failed: {0}")]
    Dns(#[from] koi_dns::DnsError),
    #[error("proxy init/start failed: {0}")]
    Proxy(#[from] koi_proxy::ProxyError),
    #[error("health init/start failed: {0}")]
    Health(#[from] koi_health::HealthError),
    #[error("certmesh initialization failed: {0}")]
    CertmeshInit(String),
    #[error("Trust core init failed: {0}")]
    Trust(#[from] koi_trust::TrustError),
    #[error("runtime init/start failed: {0}")]
    Runtime(#[from] koi_runtime::RuntimeError),
}

/// Capability flags + inputs needed to build the cores. A daemon-`Config` subset, kept here
/// (rather than depending on the binary's `Config`) so koi-compose stays standalone.
///
/// The daemon and the Windows service fill it via [`CoreSpec::daemon_defaults`]; `koi-embedded`
/// sets its pinned data root and auto-start/background-loop opt-ins directly.
/// Every field has a daemon default so the two boot paths build the identical graph.
pub struct CoreSpec {
    pub no_mdns: bool,
    pub no_certmesh: bool,
    pub no_dns: bool,
    pub no_health: bool,
    pub no_proxy: bool,
    pub no_udp: bool,
    pub no_runtime: bool,
    /// Shared Koi data root injected into domains that persist state. `None` asks this
    /// composition root to resolve the platform default; the daemon supplies a concrete root.
    pub data_dir: Option<std::path::PathBuf>,
    /// DNS configuration (the caller's resolved `DnsConfig`).
    pub dns_config: koi_dns::DnsConfig,
    /// Runtime backend selector string ("auto", "docker", "podman", …).
    pub runtime: String,
    /// Daemon HTTP port (the local management/API port the daemon binds).
    pub http_port: u16,
    /// Start the DNS server after constructing its core. The daemon always does; embedded
    /// gates it on `dns_auto_start`.
    pub dns_auto_start: bool,
    /// This daemon's Docker-watch scope (ADR-035): only containers labeled
    /// `koi.scope = <scope>` are derived. `None` is the base scope — it derives
    /// unlabeled containers only. Lets a standing daemon and a run-scoped daemon
    /// share one Docker socket without racing for derived surfaces.
    pub runtime_scope: Option<String>,
    /// Start health checks after constructing the core (daemon: always; embedded: opt-in).
    pub health_auto_start: bool,
    /// Start the proxy listeners after constructing the core (daemon: always; embedded: opt-in).
    pub proxy_auto_start: bool,
    /// Spawn the runtime orchestrator when the runtime adapter is present (daemon: always;
    /// embedded: opt-in via the `orchestrator` builder flag).
    pub spawn_orchestrator: bool,
    /// Spawn the certmesh role-driven background loop when certmesh is present (daemon:
    /// always; embedded: on by default via the `certmesh_managed` builder flag, ADR-023).
    /// The loop is a no-op until the node is a member, so self-management is intrinsic to
    /// membership; a self-driving embedded consumer opts out with `certmesh_managed(false)`.
    pub spawn_certmesh_loops: bool,
    /// Fail-fast contract: when `true` (koi-embedded, a library), the first core that fails to
    /// initialize or auto-start aborts `build_cores` with [`BuildCoresError`]. When `false`
    /// (the daemon/service), failures are logged and that capability is dropped so the daemon
    /// keeps serving its remaining capabilities.
    pub fail_fast: bool,
}

impl CoreSpec {
    /// The daemon/Windows-service defaults for the embedded-fork fields: platform-default
    /// persisted state, always start DNS/health/proxy, always spawn the orchestrator and the
    /// Certmesh loops. Spread it into a struct literal so the daemon only names the
    /// capability flags + resolved inputs and cannot accidentally diverge from the service.
    ///
    /// ```ignore
    /// CoreSpec { no_mdns, /* … */, data_dir: Some(dir), dns_config, runtime, http_port,
    ///            ..CoreSpec::daemon_defaults() }
    /// ```
    pub fn daemon_defaults() -> Self {
        Self {
            no_mdns: false,
            no_certmesh: false,
            no_dns: false,
            no_health: false,
            no_proxy: false,
            no_udp: false,
            no_runtime: false,
            data_dir: None,
            dns_config: koi_dns::DnsConfig::default(),
            runtime: "auto".to_string(),
            http_port: 0,
            runtime_scope: None,
            dns_auto_start: true,
            health_auto_start: true,
            proxy_auto_start: true,
            spawn_orchestrator: true,
            spawn_certmesh_loops: true,
            fail_fast: false,
        }
    }
}

/// Initialize the certmesh core, auto-unlocking from the vault when a key is present.
///
/// Always returns a core (so HTTP routes mount even before `koi certmesh create`):
/// - CA not initialized → an uninitialized core (routes reachable for `/create`);
/// - CA initialized + a vault auto-unlock key present → booted **already unlocked**,
///   collapsing the old "create locked → read key → unlock" three-step;
/// - CA initialized + no key (or decryption fails) → a locked core.
///
/// This is the converged single definition shared by the daemon, the Windows service, and
/// koi-embedded (the daemon path thereby gains the vault auto-unlock embedded already had).
pub fn init_certmesh_core(
    data_dir: &Path,
    dns_zone: &str,
    local_hostname: &str,
) -> Result<Arc<koi_certmesh::CertmeshCore>, koi_certmesh::CertmeshError> {
    let paths = koi_certmesh::CertmeshPaths::with_data_dir(data_dir.to_path_buf());
    koi_certmesh::CertmeshCore::load_with_paths(paths, dns_zone, local_hostname).map(Arc::new)
}

/// Initialize Certmesh without blocking the caller's async executor.
///
/// Certmesh retains ownership of repository recovery, platform credential
/// inspection, and any legacy migration. Its joinable bootstrap job completes
/// those effects even if the startup requester is cancelled.
pub async fn init_certmesh_core_async(
    data_dir: &Path,
    dns_zone: &str,
    local_hostname: &str,
) -> Result<Arc<koi_certmesh::CertmeshCore>, koi_certmesh::CertmeshError> {
    let paths = koi_certmesh::CertmeshPaths::with_data_dir(data_dir.to_path_buf());
    koi_certmesh::CertmeshCore::load_with_paths_async(paths, dns_zone, local_hostname)
        .await
        .map(Arc::new)
}

/// Build all domain cores + cross-domain bridges, then spawn the caller-invariant domain
/// background tasks: the runtime orchestrator (when runtime is enabled) and the certmesh
/// role loops (when certmesh is enabled). Returns the assembled graph paired
/// with its non-cloneable [`RunningCores`] lifecycle owner.
///
/// The bridges are wired in dependency order: DNS consumes the mDNS/certmesh/alias bridges;
/// health consumes the mDNS/DNS/certmesh/proxy bridges. Disabled capabilities pass `None`.
pub async fn build_cores(
    spec: &CoreSpec,
    host: &crate::host::HostIdentity,
    cancel: &CancellationToken,
) -> Result<RunningCores, BuildCoresError> {
    let mut startup = CoreBuildGuard::new(cancel);
    macro_rules! fail_build {
        ($error:expr) => {{
            let error: BuildCoresError = $error;
            startup.rollback().await;
            return Err(error);
        }};
    }
    macro_rules! abort_if_cancelled {
        () => {
            if startup.cancel.is_cancelled() {
                fail_build!(BuildCoresError::Cancelled);
            }
        };
    }

    abort_if_cancelled!();

    // Resolve ambient/default policy exactly once. Every persisted domain receives either
    // this explicit root or a final path derived from this immutable layout value.
    let persistence = PersistencePaths::from_data_dir(
        koi_common::paths::koi_data_dir_with_override(spec.data_dir.as_deref()),
    );

    let mut initial_statuses = Vec::new();
    // ── mDNS ──
    let mdns_core = if !spec.no_mdns {
        let result = crate::mdns::build_core(startup.cancel.clone()).await;
        abort_if_cancelled!();
        match result {
            Ok(core) => {
                let core = Arc::new(core);
                startup.mdns = Some(Arc::clone(&core));
                Some(core)
            }
            Err(e) => {
                if spec.fail_fast {
                    fail_build!(e.into());
                }
                tracing::error!(error = %e, "Failed to initialize mDNS core");
                initial_statuses.push(crate::status::CapabilityReport::unavailable(
                    "mdns",
                    e.to_string(),
                ));
                None
            }
        }
    } else {
        tracing::info!("mDNS capability: disabled");
        initial_statuses.push(crate::status::CapabilityReport::disabled(
            "mdns",
            "--no-mdns",
        ));
        None
    };

    // ── Certmesh ──
    // Certmesh owns its complete blocking bootstrap transaction. It does not
    // return until recovery, vault auto-unlock, and its initial status seed have
    // completed, so cancelling this composition future cannot detach the work.
    let certmesh_core = if !spec.no_certmesh {
        let result = init_certmesh_core_async(
            persistence.data_dir(),
            &spec.dns_config.zone,
            host.hostname(),
        )
        .await;
        abort_if_cancelled!();
        match result {
            Ok(core) => Some(core),
            Err(e) => {
                if spec.fail_fast {
                    fail_build!(BuildCoresError::CertmeshInit(e.to_string()));
                }
                tracing::error!(error = %e, "certmesh initialization failed");
                initial_statuses.push(crate::status::CapabilityReport::unavailable(
                    "certmesh",
                    e.to_string(),
                ));
                None
            }
        }
    } else {
        tracing::info!("Certmesh capability: disabled");
        initial_statuses.push(crate::status::CapabilityReport::disabled(
            "certmesh",
            "--no-certmesh",
        ));
        None
    };

    // ── Integration bridges ──
    // These wrap domain cores and implement cross-domain traits from koi_common::integration.
    let mdns_bridge = if let Some(ref core) = mdns_core {
        let bridge = crate::bridges::MdnsBridge::spawn(core.clone()).await;
        abort_if_cancelled!();
        startup.mdns_bridge = Some(Arc::clone(&bridge));
        Some(bridge)
    } else {
        None
    };
    let mdns_snapshot: Option<Arc<dyn MdnsSnapshot>> = mdns_bridge
        .as_ref()
        .map(|bridge| Arc::clone(bridge) as Arc<dyn MdnsSnapshot>);

    let certmesh_bridge: Option<Arc<dyn CertmeshSnapshot>> = certmesh_core
        .as_ref()
        .map(|core| crate::bridges::CertmeshBridge::new(core.clone()) as Arc<dyn CertmeshSnapshot>);

    let tls_identity: Option<Arc<dyn TlsIdentitySource>> = certmesh_core.as_ref().map(|core| {
        crate::bridges::CertmeshTlsIdentityBridge::new(core.clone()) as Arc<dyn TlsIdentitySource>
    });

    let alias_feedback: Option<Arc<dyn AliasFeedback>> = certmesh_core.as_ref().map(|core| {
        crate::bridges::AliasFeedbackBridge::new(core.clone()) as Arc<dyn AliasFeedback>
    });

    // ── DNS (consumes mdns + certmesh + alias bridges) ──
    let dns_runtime = if !spec.no_dns {
        let core = koi_dns::DnsCore::open(
            persistence.dns_state().to_path_buf(),
            spec.dns_config.clone(),
            mdns_snapshot.clone(),
            certmesh_bridge.clone(),
            alias_feedback,
        )
        .await;
        abort_if_cancelled!();
        match core {
            Ok(core) => {
                let runtime = Arc::new(koi_dns::DnsRuntime::new(core));
                startup.dns = Some(Arc::clone(&runtime));
                if spec.dns_auto_start {
                    let result = runtime.start().await;
                    abort_if_cancelled!();
                    if let Err(e) = result {
                        if spec.fail_fast {
                            fail_build!(e.into());
                        }
                        tracing::error!(error = %e, "Failed to start DNS server");
                    } else {
                        let status = runtime.status();
                        match status.state {
                            koi_dns::DnsRuntimeState::Running => tracing::info!(
                                endpoints = ?status.endpoints,
                                reason = ?status.reason,
                                "DNS listener reconciled"
                            ),
                            koi_dns::DnsRuntimeState::Waiting => tracing::info!(
                                reason = ?status.reason,
                                "DNS listener waiting; retry remains armed"
                            ),
                            _ => {}
                        }
                    }
                }
                Some(runtime)
            }
            Err(e) => {
                if spec.fail_fast {
                    fail_build!(e.into());
                }
                tracing::error!(error = %e, "Failed to initialize DNS core");
                initial_statuses.push(crate::status::CapabilityReport::unavailable(
                    "dns",
                    e.to_string(),
                ));
                None
            }
        }
    } else {
        tracing::info!("DNS capability: disabled");
        initial_statuses.push(crate::status::CapabilityReport::disabled("dns", "--no-dns"));
        None
    };

    // ── Proxy ──
    let proxy_runtime = if !spec.no_proxy {
        let core = koi_proxy::ProxyCore::open(
            persistence.proxy_config().to_path_buf(),
            persistence.proxy_certificates().to_path_buf(),
        );
        match core {
            Ok(core) => {
                let runtime = Arc::new(koi_proxy::ProxyRuntime::with_tls_identity(
                    Arc::new(core),
                    tls_identity.clone(),
                ));
                startup.proxy = Some(Arc::clone(&runtime));
                if spec.proxy_auto_start {
                    let result = runtime.start_all().await;
                    abort_if_cancelled!();
                    if let Err(e) = result {
                        if spec.fail_fast {
                            fail_build!(e.into());
                        }
                        tracing::error!(error = %e, "Failed to start proxy listeners");
                    }
                }
                Some(runtime)
            }
            Err(e) => {
                if spec.fail_fast {
                    fail_build!(e.into());
                }
                tracing::error!(error = %e, "Failed to initialize proxy core");
                initial_statuses.push(crate::status::CapabilityReport::unavailable(
                    "proxy",
                    e.to_string(),
                ));
                None
            }
        }
    } else {
        tracing::info!("Proxy capability: disabled");
        initial_statuses.push(crate::status::CapabilityReport::disabled(
            "proxy",
            "--no-proxy",
        ));
        None
    };

    let dns_bridge: Option<Arc<dyn DnsProbe>> = dns_runtime
        .as_ref()
        .map(|rt| crate::bridges::DnsBridge::new(rt.clone()) as Arc<dyn DnsProbe>);

    let proxy_bridge: Option<Arc<dyn ProxySnapshot>> = proxy_runtime.as_ref().map(|runtime| {
        crate::bridges::ProxyBridge::new(Arc::clone(runtime)) as Arc<dyn ProxySnapshot>
    });

    // ── Health (consumes mdns + dns + certmesh + proxy bridges) ──
    let health_runtime = if !spec.no_health {
        let result = koi_health::HealthCore::open(
            koi_health::HealthPaths::new(
                persistence.health_state().to_path_buf(),
                persistence.health_log().to_path_buf(),
            ),
            mdns_snapshot.clone(),
            dns_bridge,
            certmesh_bridge,
            proxy_bridge,
        )
        .await;
        abort_if_cancelled!();
        match result {
            Ok(core) => {
                let runtime = Arc::new(koi_health::HealthRuntime::new(Arc::new(core)));
                startup.health = Some(Arc::clone(&runtime));
                if spec.health_auto_start {
                    let result = runtime.start().await;
                    abort_if_cancelled!();
                    if let Err(e) = result {
                        if spec.fail_fast {
                            fail_build!(e.into());
                        }
                        tracing::error!(error = %e, "Failed to start health checks");
                    }
                }
                Some(runtime)
            }
            Err(error) => {
                if spec.fail_fast {
                    fail_build!(error.into());
                }
                tracing::error!(%error, "Failed to initialize health core");
                initial_statuses.push(crate::status::CapabilityReport::unavailable(
                    "health",
                    error.to_string(),
                ));
                // A corrupt or unreadable state file is not an empty health
                // model. Leave the domain absent and make the failure visible.
                None
            }
        }
    } else {
        tracing::info!("Health capability: disabled");
        initial_statuses.push(crate::status::CapabilityReport::disabled(
            "health",
            "--no-health",
        ));
        None
    };

    // ── UDP ──
    let udp_runtime = if !spec.no_udp {
        let runtime = Arc::new(koi_udp::UdpRuntime::new(startup.cancel.clone()));
        startup.udp = Some(Arc::clone(&runtime));
        Some(runtime)
    } else {
        tracing::info!("UDP capability: disabled");
        initial_statuses.push(crate::status::CapabilityReport::disabled("udp", "--no-udp"));
        None
    };

    // ── Runtime adapter ──
    let runtime_core = if !spec.no_runtime {
        // No silent fallback: an unrecognized backend selector disables the
        // runtime adapter rather than quietly running Auto. The CLI rejects bad
        // values at parse time; this guards the service/env path.
        match koi_runtime::RuntimeBackendKind::from_str_loose(&spec.runtime) {
            Some(backend_kind) => {
                let rt_config = koi_runtime::RuntimeConfig {
                    backend_kind,
                    socket_path: None,
                };
                let core = Arc::new(koi_runtime::RuntimeCore::new(rt_config));
                startup.runtime = Some(Arc::clone(&core));
                let result = core.start_watching(startup.cancel.clone()).await;
                abort_if_cancelled!();
                match result {
                    Ok(()) => Some(core),
                    Err(e) => {
                        if spec.fail_fast {
                            fail_build!(e.into());
                        }
                        tracing::warn!(error = %e, "Runtime adapter unavailable, continuing without it");
                        initial_statuses.push(crate::status::CapabilityReport::unavailable(
                            "runtime",
                            e.to_string(),
                        ));
                        None
                    }
                }
            }
            None => {
                let error = koi_runtime::RuntimeError::BackendUnavailable(format!(
                    "unknown backend '{}'; accepted values: {}",
                    spec.runtime,
                    koi_runtime::RuntimeBackendKind::ACCEPTED.join(", ")
                ));
                if spec.fail_fast {
                    fail_build!(error.into());
                }
                tracing::error!(
                    value = %spec.runtime,
                    accepted = ?koi_runtime::RuntimeBackendKind::ACCEPTED,
                    "Unknown runtime backend; disabling runtime adapter"
                );
                initial_statuses.push(crate::status::CapabilityReport::unavailable(
                    "runtime",
                    format!("unknown backend '{}'", spec.runtime),
                ));
                None
            }
        }
    } else {
        tracing::info!("Runtime capability: disabled");
        initial_statuses.push(crate::status::CapabilityReport::disabled(
            "runtime",
            "--no-runtime",
        ));
        None
    };

    // ── OS trust store ──
    // Trust is an always-present bounded context: even with Certmesh disabled,
    // it owns and truthfully reports any Koi-managed roots left on this host.
    let trust_result = koi_trust::TrustCore::open(persistence.data_dir().to_path_buf()).await;
    abort_if_cancelled!();
    let trust_core = match trust_result {
        Ok(core) => {
            let core = Arc::new(core);
            startup.trust = Some(Arc::clone(&core));
            // Trust construction is observation-only so status/list consumers
            // cannot accidentally replay platform effects. Composition is the
            // long-lived application owner and explicitly owns startup recovery.
            if core.status().pending.is_some() {
                let result = core.reconcile().await;
                abort_if_cancelled!();
                if let Err(error) = result {
                    // Reconciliation already published the pending transition
                    // and error through TrustStatus. Keep that truthful domain
                    // available so every host can expose and retry it. A denied
                    // platform effect is not a construction failure, including
                    // for an embedded fail-fast host.
                    tracing::warn!(%error, "pending OS trust-store transition remains armed");
                }
            }
            Some(core)
        }
        Err(error) => {
            if spec.fail_fast {
                fail_build!(error.into());
            }
            tracing::error!(%error, "Trust domain initialization failed");
            initial_statuses.push(crate::status::CapabilityReport::unavailable(
                "trust",
                error.to_string(),
            ));
            None
        }
    };

    // ── Runtime orchestrator ──
    // Translates container lifecycle events into mDNS/DNS/health/proxy operations. The
    // daemon always spawns it; embedded opts in (a leaf host wants only the event stream).
    if spec.spawn_orchestrator {
        if let Some(ref rt) = runtime_core {
            startup.tasks.push(crate::orchestrator::spawn_orchestrator(
                rt,
                crate::orchestrator::OrchestrationTargets {
                    mdns: mdns_core.clone(),
                    dns: dns_runtime.clone(),
                    health: health_runtime.clone(),
                    proxy: proxy_runtime.clone(),
                },
                spec.runtime_scope.clone(),
                startup.cancel.clone(),
            ));
        }
    }

    if let Some(trust) = &trust_core {
        crate::trust::start_bridge(
            certmesh_core.clone(),
            Arc::clone(trust),
            startup.cancel.clone(),
            &mut startup.tasks,
        )
        .await;
        abort_if_cancelled!();
    }

    let system_status = Arc::new(crate::status::KoiStatusRuntime::default());
    system_status.install_initial_statuses(initial_statuses);
    let cores = Cores {
        mdns: mdns_core,
        certmesh: certmesh_core,
        trust: trust_core,
        dns: dns_runtime,
        health: health_runtime,
        proxy: proxy_runtime,
        udp: udp_runtime,
        runtime: runtime_core,
        system_status,
        mdns_snapshot: mdns_bridge,
    };
    crate::status::spawn_status_observer(cores.clone(), startup.cancel.clone(), &mut startup.tasks);

    // ── Certmesh background loops ──
    // Deadline observation always runs so status cannot go stale. Embedded may
    // opt out of automatic trust-bundle pull/renewal while driving those commands
    // itself. The approval pump remains caller-owned because its decider differs.
    if let Some(ref certmesh) = cores.certmesh {
        crate::certmesh::spawn_certmesh_background_tasks(
            certmesh,
            &startup.cancel,
            &mut startup.tasks,
            spec.spawn_certmesh_loops,
        );
    }

    let running = RunningCores::new(cores);
    startup.commit_into(&running.lifecycle);
    tracing::debug!("Domain cores built");
    Ok(running)
}

struct ReleaseTasks {
    tasks: Vec<Arc<DomainReleaseCompletion>>,
}

impl ReleaseTasks {
    fn push<F>(&mut self, release: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.tasks.push(DomainReleaseCompletion::start(release));
    }
}

/// One self-owned domain release fence.
///
/// The release itself, not the coordinator waiting for it, owns the temporary
/// task cycle. An unexpected panic in the transaction supervisor therefore
/// cannot detach an already-started domain fence. The release also contains its
/// own panic and always breaks the cycle so future waiters cannot be stranded.
#[derive(Default)]
struct DomainReleaseCompletion {
    state: StdMutex<DomainReleaseCompletionState>,
    completed: Notify,
}

#[derive(Default)]
struct DomainReleaseCompletionState {
    complete: bool,
    task: Option<JoinHandle<()>>,
}

impl DomainReleaseCompletion {
    fn start<F>(release: F) -> Arc<Self>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let completion = Arc::new(Self::default());
        let retained = Arc::clone(&completion);
        let mut state = completion
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.task = Some(tokio::spawn(async move {
            if std::panic::AssertUnwindSafe(release)
                .catch_unwind()
                .await
                .is_err()
            {
                tracing::error!("Domain release fence panicked");
            }
            let mut state = retained
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.complete = true;
            state.task.take();
            drop(state);
            retained.completed.notify_waiters();
        }));
        drop(state);
        completion
    }

    async fn wait(&self) {
        loop {
            let completed = self.completed.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .complete
            {
                return;
            }
            completed.await;
        }
    }
}

fn spawn_release_tasks(targets: ReleaseTargets) -> ReleaseTasks {
    let mut releases = ReleaseTasks { tasks: Vec::new() };
    // Reverse dependency order. Every independent fence is spawned before any
    // one of them is awaited by the transaction below.
    if let Some(runtime) = targets.runtime {
        releases.push(async move {
            if let Err(error) = runtime.shutdown().await {
                tracing::warn!(%error, "Error during Runtime shutdown");
            }
        });
    }
    if let Some(udp) = targets.udp {
        releases.push(async move {
            udp.shutdown().await;
        });
    }
    if let Some(health) = targets.health {
        releases.push(async move { health.shutdown().await });
    }
    if let Some(proxy) = targets.proxy {
        releases.push(async move {
            if let Err(error) = proxy.shutdown().await {
                tracing::warn!(%error, "Error during Proxy shutdown");
            }
        });
    }
    if let Some(dns) = targets.dns {
        releases.push(async move { dns.shutdown().await });
    }
    if let Some(bridge) = targets.mdns_bridge {
        releases.push(async move { bridge.shutdown().await });
    }
    if let Some(core) = targets.mdns {
        releases.push(async move {
            if let Err(error) = core.shutdown().await {
                tracing::warn!(%error, "Error during mDNS shutdown");
            }
        });
    }
    if let Some(trust) = targets.trust {
        releases.push(async move {
            if let Err(error) = trust.shutdown().await {
                tracing::warn!(%error, "Error during Trust shutdown");
            }
        });
    }
    releases
}

/// Self-owned release transaction shared by startup rollback and ordinary
/// teardown. Once started, caller cancellation can discard only its waiter:
/// the supervisor retains every domain future through its real completion.
#[derive(Default)]
struct DomainReleaseTransaction {
    state: StdMutex<DomainReleaseState>,
    completed: Notify,
}

#[derive(Default)]
struct DomainReleaseState {
    complete: bool,
    task: Option<JoinHandle<()>>,
}

impl DomainReleaseTransaction {
    fn start(
        targets: ReleaseTargets,
        deadline: tokio::time::Instant,
        phase: &'static str,
    ) -> Arc<Self> {
        let transaction = Arc::new(Self::default());
        let retained = Arc::clone(&transaction);
        let task = tokio::spawn(async move {
            let supervisor = std::panic::AssertUnwindSafe(async move {
                let release_tasks = spawn_release_tasks(targets).tasks;
                let releases = async move {
                    for task in release_tasks {
                        task.wait().await;
                    }
                };
                tokio::pin!(releases);
                if tokio::time::timeout_at(deadline, &mut releases)
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        phase,
                        "Domain release exceeded its deadline; retaining fences through completion"
                    );
                    releases.await;
                }
            })
            .catch_unwind()
            .await;
            if supervisor.is_err() {
                tracing::error!(phase, "Domain release transaction supervisor panicked");
            }

            let mut state = retained
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.complete = true;
            state.task.take();
            drop(state);
            retained.completed.notify_waiters();
        });
        transaction
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .task = Some(task);
        transaction
    }

    async fn wait(&self) {
        loop {
            let completed = self.completed.notified();
            if self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .complete
            {
                return;
            }
            completed.await;
        }
    }
}

/// Ordered teardown: cancel → drain in-flight → join tasks → terminal domain
/// release. Steady tasks share `timeout` and are abort-reaped at the deadline;
/// domain release fences are all retained through actual completion, with the
/// deadline used only for a slow-release diagnostic. The self-announce and trust-plane supervisors own
/// their mDNS records and withdraw them during the task-join phase, so no
/// announcement id is threaded through this boundary.
pub fn ordered_shutdown<'a>(
    cancel: &'a CancellationToken,
    cores: &'a RunningCores,
    timeout: Duration,
    drain: Duration,
) -> impl std::future::Future<Output = ()> + 'a {
    // Begin ownership transfer synchronously, before a caller has an awaitable
    // future it could drop. The returned future is only a waiter.
    cancel.cancel();
    let lifecycle = Arc::clone(&cores.lifecycle);
    lifecycle.start(
        cancel.clone(),
        ReleaseTargets::from(cores.cores()),
        timeout,
        drain,
    );
    async move { lifecycle.wait().await }
}

async fn shutdown_transaction(
    cancel: CancellationToken,
    mut background: AbortOnDropTasks,
    releases: ReleaseTargets,
    timeout: Duration,
    drain: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    cancel.cancel();

    if tokio::time::timeout_at(deadline, tokio::time::sleep(drain))
        .await
        .is_err()
    {
        tracing::warn!(?timeout, "Shutdown drain exhausted the deadline");
    }

    reap_owned_tasks(background.take(), deadline, "background").await;

    release_domain_targets(releases, deadline, "domain release").await;
}

/// Start every independent domain release at one causal boundary and retain
/// each fence through actual completion. The deadline is diagnostic only here:
/// aborting a release future could strand a lifecycle mutex, status publisher,
/// socket, or admitted platform effect behind a false "stopped" result.
async fn release_domain_targets(
    releases: ReleaseTargets,
    deadline: tokio::time::Instant,
    phase: &'static str,
) {
    let transaction = DomainReleaseTransaction::start(releases, deadline, phase);
    transaction.wait().await;
}

/// Await owned tasks until `deadline`, then abort and reap every straggler.
///
/// `timeout(join_all(handles))` is subtly wrong here: dropping that timeout
/// drops the `JoinHandle`s and detaches their tasks. Borrowing each handle into
/// `timeout_at` keeps ownership available for the mandatory abort+await path.
async fn reap_owned_tasks(
    tasks: Vec<JoinHandle<()>>,
    deadline: tokio::time::Instant,
    phase: &'static str,
) {
    let mut tasks = AbortOnDropTasks(tasks);
    let mut timed_out = false;
    for task in &mut tasks.0 {
        if !timed_out {
            match tokio::time::timeout_at(deadline, &mut *task).await {
                Ok(result) => {
                    if let Err(error) = result {
                        tracing::debug!(%error, phase, "Owned shutdown task did not exit cleanly");
                    }
                    continue;
                }
                Err(_) => {
                    timed_out = true;
                    tracing::warn!(
                        phase,
                        "Shutdown phase exceeded its deadline; aborting stragglers"
                    );
                }
            }
        }

        task.abort();
        let _ = (&mut *task).await;
    }
    tasks.0.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_certmesh::{CertmeshCore, CertmeshPaths};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropFlag(Arc<AtomicBool>);

    fn test_host() -> crate::host::HostIdentity {
        crate::host::HostIdentity::from_hostname("compose-test-host").unwrap()
    }

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn free_dns_port() -> u16 {
        for _ in 0..32 {
            let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("bind candidate TCP port");
            let port = tcp.local_addr().expect("candidate address").port();
            if let Ok(udp) = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)) {
                drop(udp);
                drop(tcp);
                return port;
            }
        }
        panic!("could not reserve a DNS test port");
    }

    #[test]
    fn persistence_layout_is_derived_once_from_the_composed_root() {
        let root = PathBuf::from("/composed/koi-root");
        let paths = PersistencePaths::from_data_dir(root.clone());

        assert_eq!(paths.data_dir(), root);
        assert_eq!(paths.dns_state(), root.join("state/dns.json"));
        assert_eq!(paths.health_state(), root.join("state/health.json"));
        assert_eq!(paths.health_log(), root.join("logs/health.log"));
        assert_eq!(paths.proxy_config(), root.join("config.toml"));
        assert_eq!(paths.proxy_certificates(), root.join("proxy-certs"));
    }

    #[tokio::test]
    async fn explicit_data_roots_isolate_every_composed_domain_repository() {
        let base = koi_common::test::ensure_data_dir("koi-compose-persistence-tests").join(
            format!("isolated-roots-{}", koi_common::id::generate_short_id()),
        );
        let first_root = base.join("first");
        let second_root = base.join("second");

        async fn build_at(root: PathBuf, cancel: &CancellationToken) -> RunningCores {
            let mut spec = CoreSpec::daemon_defaults();
            spec.no_mdns = true;
            spec.no_certmesh = true;
            spec.no_udp = true;
            spec.no_runtime = true;
            spec.data_dir = Some(root);
            spec.dns_auto_start = false;
            spec.health_auto_start = false;
            spec.proxy_auto_start = false;
            spec.spawn_orchestrator = false;
            spec.spawn_certmesh_loops = false;
            spec.fail_fast = true;
            let host = test_host();
            build_cores(&spec, &host, cancel)
                .await
                .expect("compose cores")
        }

        let first_cancel = CancellationToken::new();
        let first = build_at(first_root.clone(), &first_cancel).await;
        first
            .dns
            .as_ref()
            .expect("DNS domain")
            .add_entry(koi_dns::DnsEntry {
                name: "first.internal.".to_string(),
                ip: "10.0.0.1".to_string(),
                ttl: None,
            })
            .expect("persist DNS entry");
        first
            .health
            .as_ref()
            .expect("Health domain")
            .add_check(koi_health::HealthCheck {
                name: "first".to_string(),
                kind: koi_health::ServiceCheckKind::Tcp,
                target: "127.0.0.1:1".to_string(),
                interval_secs: 30,
                timeout_secs: 1,
            })
            .await
            .expect("persist Health check");
        first
            .proxy
            .as_ref()
            .expect("Proxy domain")
            .configure_for_next_start(koi_proxy::ProxyEntry {
                name: "first".to_string(),
                listen_port: free_dns_port(),
                backend: "http://127.0.0.1:1".to_string(),
                allow_remote: false,
            })
            .await
            .expect("persist Proxy entry");

        let first_paths = PersistencePaths::from_data_dir(first_root.clone());
        assert!(first_paths.dns_state().is_file());
        assert!(first_paths.health_state().is_file());
        assert!(first_paths.proxy_config().is_file());

        let second_cancel = CancellationToken::new();
        let second = build_at(second_root.clone(), &second_cancel).await;
        assert!(second
            .dns
            .as_ref()
            .expect("DNS domain")
            .list_names()
            .is_empty());
        assert!(second
            .health
            .as_ref()
            .expect("Health domain")
            .list_checks()
            .await
            .is_empty());
        assert!(second
            .proxy
            .as_ref()
            .expect("Proxy domain")
            .entries()
            .await
            .is_empty());

        let second_paths = PersistencePaths::from_data_dir(second_root);
        assert!(!second_paths.dns_state().exists());
        assert!(!second_paths.health_state().exists());
        assert!(!second_paths.proxy_config().exists());

        ordered_shutdown(
            &first_cancel,
            &first,
            Duration::from_secs(5),
            Duration::ZERO,
        )
        .await;
        ordered_shutdown(
            &second_cancel,
            &second,
            Duration::from_secs(5),
            Duration::ZERO,
        )
        .await;
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn cleanup_admission_without_a_runtime_uses_the_synchronous_fallback() {
        let lifecycle = Arc::new(CompositionLifecycle::default());
        lifecycle.start(
            CancellationToken::new(),
            ReleaseTargets {
                mdns: None,
                mdns_bridge: None,
                dns: None,
                health: None,
                proxy: None,
                udp: None,
                runtime: None,
                trust: None,
            },
            Duration::ZERO,
            Duration::ZERO,
        );

        assert!(lifecycle.is_complete());
        assert_eq!(Arc::strong_count(&lifecycle), 1);
    }

    #[tokio::test]
    async fn fail_fast_build_rolls_back_already_bound_domains_and_tasks() {
        let base = koi_common::test::ensure_data_dir("koi-compose-cores-tests")
            .join(format!("rollback-{}", koi_common::id::generate_short_id()));
        let port = free_dns_port();
        let mut spec = CoreSpec::daemon_defaults();
        spec.no_mdns = true;
        spec.no_certmesh = true;
        spec.no_health = true;
        spec.no_proxy = true;
        spec.no_udp = true;
        spec.data_dir = Some(base.clone());
        spec.dns_config = koi_dns::DnsConfig {
            bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            ..Default::default()
        };
        spec.runtime = "definitely-not-a-runtime".to_string();
        spec.fail_fast = true;

        let cancel = CancellationToken::new();
        let host = test_host();
        let result = build_cores(&spec, &host, &cancel).await;
        assert!(matches!(result, Err(BuildCoresError::Runtime(_))));

        // DNS was already acknowledged Running before the late Runtime error.
        // The rollback fence must have reaped it and released both transports.
        let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .expect("rollback released DNS TCP socket");
        let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .expect("rollback released DNS UDP socket");
        drop((tcp, udp));
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn cancelled_build_never_publishes_a_partial_graph() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let spec = CoreSpec {
            no_mdns: true,
            no_certmesh: true,
            no_dns: true,
            no_health: true,
            no_proxy: true,
            no_udp: true,
            no_runtime: true,
            fail_fast: true,
            ..CoreSpec::daemon_defaults()
        };

        assert!(matches!(
            build_cores(&spec, &test_host(), &cancel).await,
            Err(BuildCoresError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn abandoning_a_partial_build_fail_closes_tasks_and_native_owners() {
        let base = koi_common::test::ensure_data_dir("koi-compose-cores-tests").join(format!(
            "abandoned-build-{}",
            koi_common::id::generate_short_id()
        ));
        let port = free_dns_port();
        let dns = Arc::new(koi_dns::DnsRuntime::new(
            koi_dns::DnsCore::open(
                base.join("dns.json"),
                koi_dns::DnsConfig {
                    bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    port,
                    ..Default::default()
                },
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        dns.start().await.expect("DNS start");

        let parent = CancellationToken::new();
        let mut startup = CoreBuildGuard::new(&parent);
        let startup_cancel = startup.cancel.clone();
        startup.dns = Some(Arc::clone(&dns));
        let weak_dns = Arc::downgrade(&dns);
        startup.tasks.push(tokio::spawn({
            let dns = Arc::clone(&dns);
            async move {
                let _owned_until_cancelled = dns;
                std::future::pending::<()>().await;
            }
        }));
        drop(dns);

        // This is exactly what dropping `build_cores` at any await does: the
        // guard's synchronous Drop closes cancellation and aborts every owned
        // publisher before releasing the partial graph.
        drop(startup);
        assert!(startup_cancel.is_cancelled());
        tokio::time::timeout(Duration::from_secs(3), async {
            while weak_dns.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abandoned partial graph was released");

        let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .expect("abandoned build released DNS TCP socket");
        let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .expect("abandoned build released DNS UDP socket");
        drop((tcp, udp));
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn dropping_an_unpolled_shutdown_waiter_cannot_detach_owned_tasks() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        let cores = RunningCores::default();
        cores.own_task(task);
        let cancel = CancellationToken::new();

        let waiter = ordered_shutdown(&cancel, &cores, Duration::from_secs(1), Duration::ZERO);
        drop(waiter);

        tokio::time::timeout(Duration::from_secs(2), cores.lifecycle.wait())
            .await
            .expect("retained shutdown transaction");
        assert!(cancel.is_cancelled());
        assert!(dropped.load(Ordering::SeqCst));
        assert!(cores.lifecycle.is_complete());
    }

    #[tokio::test]
    async fn panicking_domain_release_breaks_its_temporary_owner_cycle() {
        let completion = DomainReleaseCompletion::start(async {
            panic!("injected domain release panic");
        });
        let weak = Arc::downgrade(&completion);

        tokio::time::timeout(Duration::from_secs(1), completion.wait())
            .await
            .expect("panic-contained release completion");
        assert!(
            completion
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .task
                .is_none(),
            "release completion retained its own finished task"
        );
        drop(completion);
        assert!(
            weak.upgrade().is_none(),
            "release completion retained an Arc cycle after panic"
        );
    }

    #[tokio::test]
    async fn dropping_the_running_owner_aborts_a_bound_task_that_captures_inert_cores() {
        let running = RunningCores::default();
        let inert_cores = running.cores().clone();
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("presentation listener");
        let address = listener.local_addr().expect("presentation address");
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        running.own_task(tokio::spawn(async move {
            let _guard = guard;
            let _keep_graph_alive = inert_cores;
            let _listener = listener;
            std::future::pending::<()>().await;
        }));

        drop(running);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lifecycle drop aborted the graph-owned task");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(listener) = std::net::TcpListener::bind(address) {
                    drop(listener);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lifecycle drop released the task-owned presentation socket");
    }

    #[tokio::test]
    async fn aborting_self_announce_releases_dns_and_mdns_session_resources() {
        let base = koi_common::test::ensure_data_dir("koi-compose-cores-tests").join(format!(
            "announce-abort-{}",
            koi_common::id::generate_short_id()
        ));
        let provider_cancel = CancellationToken::new();
        let mdns = Arc::new(
            koi_mdns::MdnsCore::with_cancel(provider_cancel.clone())
                .await
                .expect("mDNS core"),
        );
        let dns = Arc::new(koi_dns::DnsRuntime::new(
            koi_dns::DnsCore::open(
                base.join("dns.json"),
                koi_dns::DnsConfig::default(),
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        let running = RunningCores::new(Cores {
            mdns: Some(Arc::clone(&mdns)),
            dns: Some(Arc::clone(&dns)),
            ..Cores::default()
        });
        let announce_cancel = CancellationToken::new();
        crate::self_announce::spawn(
            &running,
            crate::self_announce::SelfAnnounceConfig {
                host: crate::host::HostIdentity::from_hostname("test-host").unwrap(),
                http_port: 43210,
                dashboard_enabled: false,
                announce_http: false,
                announce_mcp: true,
                dns_zone: "internal".to_string(),
            },
            announce_cancel,
        );
        let txt_name = "_mcp.test-host.internal";
        tokio::time::timeout(Duration::from_secs(5), async {
            while dns.get_txt(txt_name).is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("self-announce published the TXT lease");

        drop(running);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !dns.get_txt(txt_name).is_empty() || !mdns.admin_registrations().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("task abort dropped both process-derived owners");

        dns.shutdown().await;
        provider_cancel.cancel();
        mdns.shutdown().await.expect("mDNS shutdown");
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn cancelling_a_waiter_during_drain_does_not_cancel_the_transaction() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        let background = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        let cores = RunningCores::default();
        cores.own_task(background);
        let cancel = CancellationToken::new();
        {
            let waiter = ordered_shutdown(
                &cancel,
                &cores,
                Duration::from_secs(2),
                Duration::from_millis(50),
            );
            tokio::pin!(waiter);
            tokio::select! {
                _ = &mut waiter => panic!("shutdown unexpectedly completed before drain cancellation"),
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }

        tokio::time::timeout(Duration::from_secs(2), cores.lifecycle.wait())
            .await
            .expect("transaction survived waiter cancellation");
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn admitted_shutdown_self_owns_through_release_after_waiter_and_owner_drop() {
        let base = koi_common::test::ensure_data_dir("koi-compose-cores-tests").join(format!(
            "shutdown-release-{}",
            koi_common::id::generate_short_id()
        ));
        let port = free_dns_port();
        let dns = Arc::new(koi_dns::DnsRuntime::new(
            koi_dns::DnsCore::open(
                base.join("dns.json"),
                koi_dns::DnsConfig {
                    bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    port,
                    ..Default::default()
                },
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        dns.start().await.expect("DNS start");
        let cores = RunningCores::new(Cores {
            dns: Some(Arc::clone(&dns)),
            ..Cores::default()
        });
        let cancel = CancellationToken::new();

        let waiter = ordered_shutdown(
            &cancel,
            &cores,
            Duration::from_secs(2),
            Duration::from_millis(25),
        );
        drop(waiter);
        drop(cores);
        tokio::time::timeout(Duration::from_secs(3), async {
            while dns.status().running {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("domain release transaction");

        assert!(
            !dns.status().running,
            "retained runtime is terminally stopped"
        );
        let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .expect("shutdown released DNS TCP socket");
        let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .expect("shutdown released DNS UDP socket");
        drop((tcp, udp));
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn expired_deadline_retains_each_domain_release_to_completion() {
        let base = koi_common::test::ensure_data_dir("koi-compose-cores-tests").join(format!(
            "shutdown-admission-{}",
            koi_common::id::generate_short_id()
        ));
        let port = free_dns_port();
        let dns = Arc::new(koi_dns::DnsRuntime::new(
            koi_dns::DnsCore::open(
                base.join("dns.json"),
                koi_dns::DnsConfig {
                    bind_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    port,
                    ..Default::default()
                },
                None,
                None,
                None,
            )
            .await
            .expect("DNS core"),
        ));
        dns.start().await.expect("DNS start");
        let cores = RunningCores::new(Cores {
            dns: Some(Arc::clone(&dns)),
            ..Cores::default()
        });
        let cancel = CancellationToken::new();

        ordered_shutdown(&cancel, &cores, Duration::ZERO, Duration::ZERO).await;

        assert!(
            dns.start().await.is_err(),
            "DNS terminal admission was fenced"
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port));
                let udp = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port));
                if let (Ok(tcp), Ok(udp)) = (tcp, udp) {
                    drop((tcp, udp));
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminally admitted DNS release dropped both sockets");
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn ordered_shutdown_crosses_the_non_cancellable_trust_terminal_fence() {
        let base = koi_common::test::ensure_data_dir("koi-compose-cores-tests").join(format!(
            "trust-release-{}",
            koi_common::id::generate_short_id()
        ));
        let (trust, _store) = koi_trust::TrustCore::open_memory(base.clone())
            .await
            .expect("test Trust core");
        let trust = Arc::new(trust);
        let cores = RunningCores::new(Cores {
            trust: Some(Arc::clone(&trust)),
            ..Cores::default()
        });
        let cancel = CancellationToken::new();

        let waiter = ordered_shutdown(&cancel, &cores, Duration::ZERO, Duration::ZERO);
        drop(waiter);
        tokio::time::timeout(Duration::from_secs(2), cores.lifecycle.wait())
            .await
            .expect("Trust hard fence completed");

        assert!(matches!(
            trust.reconcile().await,
            Err(koi_trust::TrustError::ShutDown)
        ));
        let _ = std::fs::remove_dir_all(base);
    }

    /// Regression guard for ADR-017 F11: the **real boot path** (`init_certmesh_core`,
    /// not the unused `try_auto_unlock`) must refuse to auto-unlock when the machine
    /// fingerprint changed since CA creation (a VM clone / disk restore). The fix
    /// that wires `machine_binding_ok` into this path is exactly what an earlier
    /// implementation missed — this test ensures it can't silently un-wire again.
    #[tokio::test]
    async fn init_certmesh_core_refuses_auto_unlock_on_machine_change() {
        let base = koi_common::test::ensure_data_dir("koi-compose-cores-tests").join("f11-boot");
        let _ = std::fs::remove_dir_all(&base);
        let paths = CertmeshPaths::with_data_dir(base.clone());

        // Create a CA with auto-unlock — records the vault key + machine.bind.
        let core = CertmeshCore::uninitialized_with_paths(paths.clone())
            .with_local_hostname("compose-test-host")
            .expect("configure host identity");
        core.create(koi_certmesh::protocol::CreateCaRequest {
            passphrase: "f11-boot-pass".into(),
            entropy_hex: "11".repeat(32),
            operator: None,
            enrollment_open: true,
            requires_approval: false,
            auto_unlock: true,
            totp_secret_hex: None,
        })
        .await
        .expect("CA create");

        // Same host (machine.bind matches) → the boot path auto-unlocks.
        let booted = init_certmesh_core(&base, "internal", "compose-test-host").expect("core");
        assert!(
            !booted.status().authority.as_ref().unwrap().locked,
            "matching machine binding should auto-unlock at boot"
        );

        // Simulate a clone/restore: overwrite the recorded fingerprint. The boot
        // path must now refuse auto-unlock and come up LOCKED.
        std::fs::write(paths.machine_bind_path(), b"not-this-host-fingerprint").unwrap();
        let booted_after =
            init_certmesh_core(&base, "internal", "compose-test-host").expect("core");
        assert!(
            booted_after.status().authority.as_ref().unwrap().locked,
            "a changed machine fingerprint must refuse auto-unlock at boot (F11)"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
