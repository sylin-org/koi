//! Operator-armed, read-only LAN presentation adapter (ADR-042).
//!
//! Pond is not another daemon or a second domain model. It is one desired-state
//! listener inside the serving monolith. The full operator API stays on its configured
//! bind; this adapter mounts only the assets and read models the browser UI consumes.

use std::future::IntoFuture as _;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use axum::extract::{Extension, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, oneshot, watch, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use utoipa::OpenApi;

use koi_common::persist::AtomicCommit;
use koi_common::status::StatusFeed;
use koi_dashboard::browser::BrowserState;

pub use koi_common::pond::{
    PondFirewallState, PondFirewallStatus, PondState, PondStatus, PondUiStatus,
};

/// The standard Pond listener follows the daemon's standard three-port run.
pub const DEFAULT_POND_PORT: u16 = 5644;

const RETRY_INTERVAL: Duration = Duration::from_secs(2);
const OBSERVE_INTERVAL: Duration = Duration::from_secs(5);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
// Longer than the adapter-owned firewall deadline: normal shutdown must join a probe rather
// than abort its Tokio waiter while the process-owning blocking task is still reaping.
const RECONCILER_STOP_TIMEOUT: Duration = Duration::from_secs(6);
const FIREWALL_ASSESS_TIMEOUT: Duration = Duration::from_secs(5);
const POND_HTML_CSP: &str = koi_ui::DOCUMENT_CSP;

/// Derive the fourth port in a Koi install's contiguous port run.
pub fn port_for_http(http_port: u16) -> Option<u16> {
    http_port.checked_add(3)
}

#[derive(Clone)]
pub struct PondConfig {
    pub port: u16,
    pub intent_path: PathBuf,
    pub started_at: Instant,
    pub browser: Option<BrowserState>,
    pub system_status: Arc<koi_compose::status::KoiStatusRuntime>,
    pub parent_cancel: CancellationToken,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PondIntent {
    desired: bool,
}

struct RunHandle {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Drop for RunHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

#[derive(Default)]
struct PondLifecycle {
    generation: u64,
    run: Option<RunHandle>,
    shutdown: bool,
}

/// Best-effort semantic facts from the Pond serving component.
///
/// Consumers recover current truth from [`PondRuntime::status`] after lag; these events are
/// deliberately about meaningful transitions rather than a replayable state model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PondEvent {
    DesiredStateChanged {
        generation: u64,
        desired: bool,
    },
    LifecycleChanged {
        generation: u64,
        previous: PondState,
        current: PondState,
        running: bool,
        reason: Option<String>,
    },
}

struct PondDomainInner {
    config: PondConfig,
    status: StatusFeed<PondStatus>,
    event_tx: broadcast::Sender<PondEvent>,
    /// Serializes status and semantic-event publication across lifecycle transitions.
    transition: StdMutex<()>,
    reconcile_now: Notify,
    #[cfg(test)]
    force_intent_uncertain: std::sync::atomic::AtomicBool,
}

/// Domain state and public read model shared with a listener generation.
///
/// This deliberately excludes lifecycle ownership. A reconciler may keep the domain alive
/// while it drains, but can never retain the facade that owns its own `JoinHandle`.
#[derive(Clone)]
struct PondDomain {
    inner: Arc<PondDomainInner>,
}

struct PondRuntimeInner {
    domain: PondDomain,
    lifecycle: Mutex<PondLifecycle>,
}

impl Drop for PondRuntimeInner {
    fn drop(&mut self) {
        let lifecycle = self.lifecycle.get_mut();
        lifecycle.shutdown = true;
        self.domain.publish_terminal_admission();
        if let Some(run) = lifecycle.run.as_mut() {
            // `RunHandle::drop` repeats this fence. Doing it before the owner's fields are
            // destroyed makes the terminal ownership rule explicit and closes the listener as
            // soon as the final facade disappears.
            run.cancel.cancel();
            run.task.abort();
        }
    }
}

/// One in-process desired-state controller for the read-only listener.
#[derive(Clone)]
pub struct PondRuntime {
    inner: Arc<PondRuntimeInner>,
}

/// Failure to admit or durably commit an operator lifecycle command.
///
/// Terminal admission is distinct from persistence failure: once the daemon
/// owns Pond shutdown, a restartable command must not rewrite next-boot desire
/// that this runtime can no longer reconcile.
#[derive(Debug, thiserror::Error)]
pub enum PondCommandError {
    #[error("Pond is shutting down")]
    ShuttingDown,
    #[error("Pond lifecycle intent is visible, but crash durability could not be confirmed: {0}")]
    DurabilityUncertain(#[source] std::io::Error),
    #[error(transparent)]
    Persist(#[from] std::io::Error),
}

impl PondRuntime {
    /// Construct Pond from its durable desired state.
    ///
    /// An unreadable or malformed intent is not equivalent to a disabled component: fail
    /// construction so composition can surface the initialization error truthfully.
    pub fn new(config: PondConfig) -> Result<Self, std::io::Error> {
        let intent = koi_common::persist::read_json_if_exists::<PondIntent>(&config.intent_path)
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("{}: {error}", config.intent_path.display()),
                )
            })?
            .unwrap_or_default();
        let mut initial = if intent.desired {
            PondStatus::awaiting_reconciliation(config.port)
        } else {
            PondStatus::disabled(config.port)
        };
        initial.ui = shared_ui_status();
        let domain = PondDomain {
            inner: Arc::new(PondDomainInner {
                config,
                status: StatusFeed::new(initial),
                event_tx: koi_common::events::event_channel().0,
                transition: StdMutex::new(()),
                reconcile_now: Notify::new(),
                #[cfg(test)]
                force_intent_uncertain: std::sync::atomic::AtomicBool::new(false),
            }),
        };
        Ok(Self {
            inner: Arc::new(PondRuntimeInner {
                domain,
                lifecycle: Mutex::new(PondLifecycle::default()),
            }),
        })
    }

    /// Return the current immutable status in constant time.
    pub fn status(&self) -> Arc<PondStatus> {
        self.inner.domain.inner.status.current()
    }

    /// Subscribe to the current snapshot and future coalesced status changes.
    pub fn watch_status(&self) -> watch::Receiver<Arc<PondStatus>> {
        self.inner.domain.inner.status.subscribe()
    }

    /// Subscribe to best-effort semantic lifecycle events.
    pub fn subscribe(&self) -> broadcast::Receiver<PondEvent> {
        self.inner.domain.inner.event_tx.subscribe()
    }

    fn ui_status(&self) -> PondUiStatus {
        shared_ui_status()
    }

    /// Reconcile the desire already loaded by construction, then own daemon shutdown.
    pub async fn supervise(&self) {
        if !self.inner.domain.inner.config.parent_cancel.is_cancelled() {
            let mut lifecycle = self.inner.lifecycle.lock().await;
            if self.status().desired {
                self.arm_locked(&mut lifecycle).await;
            }
        }

        self.inner
            .domain
            .inner
            .config
            .parent_cancel
            .cancelled()
            .await;
        self.shutdown().await;
    }

    /// Replace visible desire and settle the first real bind/assessment attempt.
    /// A post-replacement durability failure is returned after status/events
    /// accept the visible fact.
    pub async fn enable(&self) -> Result<PondStatus, PondCommandError> {
        let mut lifecycle = self.inner.lifecycle.lock().await;
        self.close_cancelled_admission(&mut lifecycle);
        if lifecycle.shutdown {
            return Err(PondCommandError::ShuttingDown);
        }
        let durability = self.persist_intent(true)?;

        self.arm_locked(&mut lifecycle).await;
        let status = self.status().as_ref().clone();
        match durability {
            AtomicCommit::Durable => Ok(status),
            AtomicCommit::DurabilityUncertain(error) => {
                Err(PondCommandError::DurabilityUncertain(error))
            }
        }
    }

    /// Replace the stop intent before tearing down the socket. A post-replacement
    /// durability failure is returned after status/events accept the visible fact.
    pub async fn disable(&self) -> Result<PondStatus, PondCommandError> {
        let mut lifecycle = self.inner.lifecycle.lock().await;
        self.close_cancelled_admission(&mut lifecycle);
        if lifecycle.shutdown {
            return Err(PondCommandError::ShuttingDown);
        }
        let durability = self.persist_intent(false)?;
        self.stop_locked(&mut lifecycle, false, false, RECONCILER_STOP_TIMEOUT)
            .await;
        let status = self.status().as_ref().clone();
        match durability {
            AtomicCommit::Durable => Ok(status),
            AtomicCommit::DurabilityUncertain(error) => {
                Err(PondCommandError::DurabilityUncertain(error))
            }
        }
    }

    fn persist_intent(&self, desired: bool) -> Result<AtomicCommit, std::io::Error> {
        let outcome = koi_common::persist::write_json_pretty_commit(
            &self.inner.domain.inner.config.intent_path,
            &PondIntent { desired },
        )?;
        #[cfg(test)]
        let outcome = if self
            .inner
            .domain
            .inner
            .force_intent_uncertain
            .swap(false, std::sync::atomic::Ordering::AcqRel)
            && matches!(&outcome, AtomicCommit::Durable)
        {
            AtomicCommit::DurabilityUncertain(std::io::Error::other(
                "injected Pond intent durability uncertainty",
            ))
        } else {
            outcome
        };
        Ok(outcome)
    }

    #[cfg(test)]
    fn make_next_intent_durability_uncertain(&self) {
        self.inner
            .domain
            .inner
            .force_intent_uncertain
            .store(true, std::sync::atomic::Ordering::Release);
    }

    async fn arm_locked(&self, lifecycle: &mut PondLifecycle) {
        if lifecycle
            .run
            .as_ref()
            .is_some_and(|handle| !handle.task.is_finished())
        {
            self.inner.domain.inner.reconcile_now.notify_one();
            return;
        }
        if let Some(finished) = lifecycle.run.as_mut() {
            // Keep ownership in the lifecycle slot while awaiting. If this command future is
            // cancelled, a later command can still reap the exact same task.
            let _ = (&mut finished.task).await;
            lifecycle.run = None;
        }

        let generation = advance_generation(lifecycle);
        self.publish_status(
            generation,
            PondStatus {
                revision: 0,
                generation,
                accepting_commands: true,
                desired: true,
                running: false,
                state: PondState::Reconciling,
                port: self.inner.domain.inner.config.port,
                urls: Vec::new(),
                url: None,
                firewall: unknown_firewall(),
                ui: self.ui_status(),
                reason: None,
            },
        );

        let cancel = CancellationToken::new();
        let (initial_tx, initial_rx) = oneshot::channel();
        let task = self.spawn_reconcile(generation, cancel.clone(), initial_tx);
        lifecycle.run = Some(RunHandle { cancel, task });

        let _ = tokio::time::timeout(SETTLE_TIMEOUT, initial_rx).await;
    }

    fn spawn_reconcile(
        &self,
        generation: u64,
        cancel: CancellationToken,
        initial: oneshot::Sender<()>,
    ) -> JoinHandle<()> {
        let domain = self.inner.domain.clone();
        tokio::spawn(async move {
            // Keep the reconciler in this task rather than spawning a detached child. Aborting
            // the RunHandle must drop the listener and every in-flight observation future.
            domain.reconcile(generation, cancel.clone(), initial).await;
            if cancel.is_cancelled() {
                return;
            }
            domain.publish_status(
                generation,
                PondStatus {
                    revision: 0,
                    generation,
                    accepting_commands: true,
                    desired: true,
                    running: false,
                    state: PondState::Error,
                    port: domain.inner.config.port,
                    urls: Vec::new(),
                    url: None,
                    firewall: unknown_firewall(),
                    ui: domain.ui_status(),
                    reason: Some("Pond listener reconciler ended unexpectedly".to_string()),
                },
            );
        })
    }

    async fn shutdown(&self) {
        self.shutdown_with_timeout(RECONCILER_STOP_TIMEOUT).await;
    }

    async fn shutdown_with_timeout(&self, stop_timeout: Duration) {
        let mut lifecycle = self.inner.lifecycle.lock().await;
        if lifecycle.shutdown && lifecycle.run.is_none() {
            return;
        }
        lifecycle.shutdown = true;
        self.inner.domain.publish_terminal_admission();
        let desired = self.status().desired;
        self.stop_locked(&mut lifecycle, desired, true, stop_timeout)
            .await;
    }

    async fn stop_locked(
        &self,
        lifecycle: &mut PondLifecycle,
        desired: bool,
        daemon_shutdown: bool,
        stop_timeout: Duration,
    ) {
        let current = self.status();
        let final_state = if desired {
            PondState::Waiting
        } else {
            PondState::Disabled
        };
        if lifecycle.run.is_none()
            && current.desired == desired
            && !current.running
            && current.state == final_state
            && (!daemon_shutdown
                || !desired
                || current.reason.as_deref() == Some("listener stopped with daemon"))
        {
            return;
        }

        let generation = advance_generation(lifecycle);
        if lifecycle.run.is_some() || current.running {
            // Advance the publication-owned generation before awaiting teardown. The old
            // observer may still complete an in-flight firewall probe, but it can no longer
            // overwrite the durable desire or emit a superseded transition. Deriving the
            // fence under the publication gate also preserves the newest accepted observation.
            self.publish_stop_fence(generation, desired, daemon_shutdown);
        }
        if let Some(handle) = lifecycle.run.as_mut() {
            handle.cancel.cancel();
            if tokio::time::timeout(stop_timeout, &mut handle.task)
                .await
                .is_err()
            {
                tracing::warn!(
                    timeout_ms = stop_timeout.as_millis(),
                    "Pond reconciler did not stop after cancellation; aborting it"
                );
                handle.task.abort();
                let _ = (&mut handle.task).await;
            }
            // This assignment happens only after the owned task was joined. Cancellation at
            // either await above leaves the handle in place for a later bounded retry.
            lifecycle.run = None;
        }

        let mut final_status = if desired {
            PondStatus::awaiting_reconciliation(self.inner.domain.inner.config.port)
        } else {
            PondStatus::disabled(self.inner.domain.inner.config.port)
        };
        final_status.generation = generation;
        final_status.ui = self.ui_status();
        if daemon_shutdown && desired {
            final_status.reason = Some("listener stopped with daemon".to_string());
        }
        self.publish_status(generation, final_status);
    }

    fn publish_status(&self, generation: u64, status: PondStatus) -> Arc<PondStatus> {
        self.inner.domain.publish_status(generation, status)
    }

    fn close_cancelled_admission(&self, lifecycle: &mut PondLifecycle) {
        if self.inner.domain.inner.config.parent_cancel.is_cancelled() && !lifecycle.shutdown {
            lifecycle.shutdown = true;
            self.inner.domain.publish_terminal_admission();
        }
    }

    fn publish_stop_fence(
        &self,
        generation: u64,
        desired: bool,
        daemon_shutdown: bool,
    ) -> Arc<PondStatus> {
        self.inner
            .domain
            .publish_stop_fence(generation, desired, daemon_shutdown)
    }

    #[cfg(test)]
    fn set_reconciling(&self, generation: u64) {
        self.inner.domain.set_reconciling(generation);
    }
}

impl PondDomain {
    fn ui_status(&self) -> PondUiStatus {
        shared_ui_status()
    }

    async fn reconcile(
        &self,
        generation: u64,
        cancel: CancellationToken,
        initial: oneshot::Sender<()>,
    ) {
        let mut initial = Some(initial);
        loop {
            if cancel.is_cancelled() {
                return;
            }
            self.set_reconciling(generation);

            let listener = match tokio::net::TcpListener::bind((
                Ipv4Addr::UNSPECIFIED,
                self.inner.config.port,
            ))
            .await
            {
                Ok(listener) => listener,
                Err(error) => {
                    self.set_waiting(
                        generation,
                        self.inner.config.port,
                        format!("Pond listener bind failed: {error}"),
                        unknown_firewall(),
                    );
                    signal_initial(&mut initial);
                    if self.wait_retry(&cancel).await {
                        return;
                    }
                    continue;
                }
            };

            let bound_port = match listener.local_addr() {
                Ok(address) => address.port(),
                Err(error) => {
                    self.set_waiting(
                        generation,
                        self.inner.config.port,
                        format!("could not inspect Pond listener: {error}"),
                        unknown_firewall(),
                    );
                    signal_initial(&mut initial);
                    if self.wait_retry(&cancel).await {
                        return;
                    }
                    continue;
                }
            };
            self.set_bound_reconciling(generation, bound_port);
            self.refresh_observation(generation, bound_port).await;
            signal_initial(&mut initial);

            let server_cancel = CancellationToken::new();
            let router = public_routes_for_domain(self.clone());
            let graceful = server_cancel.clone();
            let server = axum::serve(listener, router)
                .with_graceful_shutdown(async move { graceful.cancelled().await })
                .into_future();
            tokio::pin!(server);
            let mut observe = tokio::time::interval(OBSERVE_INTERVAL);
            observe.tick().await;

            let ended_reason = loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        server_cancel.cancel();
                        if tokio::time::timeout(SERVER_DRAIN_TIMEOUT, &mut server)
                            .await
                            .is_err()
                        {
                            tracing::warn!(
                                timeout_ms = SERVER_DRAIN_TIMEOUT.as_millis(),
                                "Pond HTTP connections exceeded the graceful drain deadline"
                            );
                        }
                        // Returning drops the pinned server future, closing the listener and
                        // every connection even when graceful drain timed out.
                        return;
                    }
                    result = &mut server => {
                        break match result {
                            Ok(()) => "Pond listener ended unexpectedly".to_string(),
                            Err(error) => format!("Pond listener failed: {error}"),
                        };
                    }
                    _ = observe.tick() => self.refresh_observation(generation, bound_port).await,
                    _ = self.inner.reconcile_now.notified() => {
                        self.refresh_observation(generation, bound_port).await;
                    }
                }
            };
            self.set_waiting(generation, bound_port, ended_reason, unknown_firewall());
            if self.wait_retry(&cancel).await {
                return;
            }
        }
    }

    fn set_reconciling(&self, generation: u64) {
        self.publish_status(
            generation,
            PondStatus {
                revision: 0,
                generation,
                accepting_commands: true,
                desired: true,
                running: false,
                state: PondState::Reconciling,
                port: self.inner.config.port,
                urls: Vec::new(),
                url: None,
                firewall: unknown_firewall(),
                ui: self.ui_status(),
                reason: None,
            },
        );
    }

    fn set_waiting(
        &self,
        generation: u64,
        port: u16,
        reason: String,
        firewall: PondFirewallStatus,
    ) {
        self.publish_status(
            generation,
            PondStatus {
                revision: 0,
                generation,
                accepting_commands: true,
                desired: true,
                running: false,
                state: PondState::Waiting,
                port,
                urls: Vec::new(),
                url: None,
                firewall,
                ui: self.ui_status(),
                reason: Some(reason),
            },
        );
    }

    fn set_bound_reconciling(&self, generation: u64, port: u16) {
        self.publish_status(
            generation,
            PondStatus {
                revision: 0,
                generation,
                accepting_commands: true,
                desired: true,
                running: true,
                state: PondState::Reconciling,
                port,
                urls: Vec::new(),
                url: None,
                firewall: PondFirewallStatus {
                    state: PondFirewallState::Unknown,
                    detail: "listener bound; assessing LAN reachability".to_string(),
                },
                ui: self.ui_status(),
                reason: Some("assessing LAN interfaces and firewall policy".to_string()),
            },
        );
    }

    fn set_bound_waiting(
        &self,
        generation: u64,
        port: u16,
        reason: String,
        firewall: PondFirewallStatus,
        urls: Vec<String>,
    ) {
        self.publish_status(
            generation,
            PondStatus {
                revision: 0,
                generation,
                accepting_commands: true,
                desired: true,
                running: true,
                state: PondState::Waiting,
                port,
                url: urls.first().cloned(),
                urls,
                firewall,
                ui: self.ui_status(),
                reason: Some(reason),
            },
        );
    }

    async fn refresh_observation(&self, generation: u64, port: u16) {
        let interfaces = match crate::network::lan_ipv4_interfaces() {
            Ok(interfaces) => interfaces,
            Err(error) => {
                self.set_bound_waiting(
                    generation,
                    port,
                    format!("could not observe LAN interfaces: {error}"),
                    PondFirewallStatus {
                        state: PondFirewallState::Unknown,
                        detail: "LAN interface observation failed".to_string(),
                    },
                    Vec::new(),
                );
                return;
            }
        };
        if interfaces.is_empty() {
            self.set_bound_waiting(
                generation,
                port,
                "no LAN-routable IPv4 interface is available".to_string(),
                PondFirewallStatus {
                    state: PondFirewallState::Unknown,
                    detail: "waiting for a LAN interface".to_string(),
                },
                Vec::new(),
            );
            return;
        }
        let urls = interfaces
            .iter()
            .map(|interface| format!("http://{}:{port}/", interface.address))
            .collect::<Vec<_>>();
        let firewall = assess_firewall(port, &interfaces[0].name).await;
        if !firewall_admits_lan_reachability(firewall.state) {
            self.set_bound_waiting(generation, port, firewall.detail.clone(), firewall, urls);
            return;
        }

        self.publish_status(
            generation,
            PondStatus {
                revision: 0,
                generation,
                accepting_commands: true,
                desired: true,
                running: true,
                state: PondState::Running,
                port,
                url: urls.first().cloned(),
                urls,
                firewall,
                ui: self.ui_status(),
                reason: None,
            },
        );
    }

    async fn wait_retry(&self, cancel: &CancellationToken) -> bool {
        tokio::select! {
            _ = cancel.cancelled() => true,
            _ = tokio::time::sleep(RETRY_INTERVAL) => false,
            _ = self.inner.reconcile_now.notified() => false,
        }
    }

    fn publish_status(&self, generation: u64, mut status: PondStatus) -> Arc<PondStatus> {
        self.transition_status(move |current| {
            if generation < current.generation {
                return None;
            }
            status.generation = generation;
            // Terminal command admission is facade-owned and monotonic. A
            // draining listener generation may not reopen it.
            status.accepting_commands = current.accepting_commands;
            // Lifecycle observations never own the UI projection. Preserving it here makes
            // same-generation publication compositional instead of last-writer-wins.
            status.ui = current.ui.clone();
            Some(status)
        })
    }

    fn publish_terminal_admission(&self) -> Arc<PondStatus> {
        self.transition_status(|current| {
            if !current.accepting_commands {
                return None;
            }
            let mut next = current.clone();
            next.accepting_commands = false;
            Some(next)
        })
    }

    /// Advance the lifecycle epoch from the exact status held by the publication gate.
    fn publish_stop_fence(
        &self,
        generation: u64,
        desired: bool,
        daemon_shutdown: bool,
    ) -> Arc<PondStatus> {
        self.transition_status(move |current| {
            let mut fenced = current.clone();
            fenced.generation = generation;
            fenced.desired = desired;
            fenced.reason = Some(if daemon_shutdown {
                "daemon is stopping the Pond listener".to_string()
            } else {
                "operator requested Pond shutdown".to_string()
            });
            Some(fenced)
        })
    }

    /// The only status/event publication path for this Pond instance.
    fn transition_status(
        &self,
        transition: impl FnOnce(&PondStatus) -> Option<PondStatus>,
    ) -> Arc<PondStatus> {
        let _transition = self
            .inner
            .transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut accepted = None;
        let published = self.inner.status.update(|current| {
            let mut next = transition(current)?;
            next.revision = current.revision;
            if current == &next {
                return None;
            }
            next.revision = current.revision.saturating_add(1);
            accepted = Some((current.clone(), next.clone()));
            Some(next)
        });

        if let Some((previous, current)) = accepted {
            // The status feed has already accepted `current`; every event observer can
            // therefore reread this state or something newer. The transition mutex remains
            // held until all events for this revision have been emitted.
            if previous.desired != current.desired {
                let _ = self.inner.event_tx.send(PondEvent::DesiredStateChanged {
                    generation: current.generation,
                    desired: current.desired,
                });
            }
            if previous.generation != current.generation
                || previous.state != current.state
                || previous.running != current.running
            {
                let _ = self.inner.event_tx.send(PondEvent::LifecycleChanged {
                    generation: current.generation,
                    previous: previous.state,
                    current: current.state,
                    running: current.running,
                    reason: current.reason.clone(),
                });
            }
        }
        published
    }
}

fn advance_generation(lifecycle: &mut PondLifecycle) -> u64 {
    lifecycle.generation = lifecycle.generation.saturating_add(1);
    lifecycle.generation
}

fn signal_initial(sender: &mut Option<oneshot::Sender<()>>) {
    if let Some(sender) = sender.take() {
        let _ = sender.send(());
    }
}

fn unknown_firewall() -> PondFirewallStatus {
    PondFirewallStatus {
        state: PondFirewallState::Unknown,
        detail: "firewall not assessed before a listener bind".to_string(),
    }
}

fn firewall_admits_lan_reachability(state: PondFirewallState) -> bool {
    matches!(state, PondFirewallState::Open | PondFirewallState::Inactive)
}

async fn assess_firewall(port: u16, interface: &str) -> PondFirewallStatus {
    let interface = interface.to_string();
    // Start the budget before entering Tokio's blocking queue. A saturated pool must consume
    // the deadline rather than postponing it and outliving reconciler shutdown.
    let deadline = std::time::Instant::now() + FIREWALL_ASSESS_TIMEOUT;
    match tokio::task::spawn_blocking(move || assess_firewall_blocking(port, &interface, deadline))
        .await
    {
        Ok(status) => status,
        Err(error) => PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("firewall assessment task failed: {error}"),
        },
    }
}

#[cfg(target_os = "linux")]
fn assess_firewall_blocking(
    port: u16,
    interface: &str,
    deadline: std::time::Instant,
) -> PondFirewallStatus {
    assess_firewalld(port, interface, deadline)
        .or_else(|| assess_ufw(port, deadline))
        .unwrap_or_else(|| PondFirewallStatus {
            state: PondFirewallState::Inactive,
            detail:
                "neither firewalld nor UFW is active; other host firewall policy was not assessed"
                    .to_string(),
        })
}

#[cfg(target_os = "linux")]
fn assess_firewalld(
    port: u16,
    interface: &str,
    deadline: std::time::Instant,
) -> Option<PondFirewallStatus> {
    let state = match run_firewall_command("firewall-cmd", &["--state"], deadline) {
        Ok(state) => state,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            return Some(PondFirewallStatus {
                state: PondFirewallState::Unknown,
                detail: format!("could not query firewalld state: {error}"),
            });
        }
    };
    if !state.status.success() {
        return None;
    }

    let interface_arg = format!("--get-zone-of-interface={interface}");
    let zone = run_firewall_command("firewall-cmd", &[&interface_arg], deadline)
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|zone| zone.trim().to_string())
        .filter(|zone| !zone.is_empty())
        .or_else(|| {
            run_firewall_command("firewall-cmd", &["--get-default-zone"], deadline)
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|zone| zone.trim().to_string())
                .filter(|zone| !zone.is_empty())
        });
    let Some(zone) = zone else {
        return Some(PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("firewalld is active but the zone for {interface} is unknown"),
        });
    };
    let zone_arg = format!("--zone={zone}");
    let port_arg = format!("--query-port={port}/tcp");
    let query = run_firewall_command("firewall-cmd", &[&zone_arg, &port_arg], deadline);
    match query {
        Ok(output) if output.status.success() => Some(PondFirewallStatus {
            state: PondFirewallState::Open,
            detail: format!("firewalld zone {zone} admits TCP {port}"),
        }),
        Ok(output) if output.status.code() == Some(1) => Some(PondFirewallStatus {
            state: PondFirewallState::Blocked,
            detail: format!("firewalld zone {zone} does not admit TCP {port}"),
        }),
        Ok(output) => Some(PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!(
                "firewalld could not assess TCP {port} in zone {zone} (exit {:?})",
                output.status.code()
            ),
        }),
        Err(error) => Some(PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("could not query firewalld: {error}"),
        }),
    }
}

#[cfg(target_os = "linux")]
fn assess_ufw(port: u16, deadline: std::time::Instant) -> Option<PondFirewallStatus> {
    let output = match run_firewall_command("ufw", &["status", "verbose"], deadline) {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            return Some(PondFirewallStatus {
                state: PondFirewallState::Unknown,
                detail: format!("could not query UFW: {error}"),
            });
        }
    };
    if !output.status.success() {
        return Some(PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!(
                "UFW is present but could not be assessed non-interactively (exit {:?})",
                output.status.code()
            ),
        });
    }
    let body = String::from_utf8_lossy(&output.stdout);
    if body.lines().any(|line| line.trim() == "Status: inactive") {
        return None;
    }
    Some(assess_ufw_status(port, &body))
}

#[cfg(target_os = "linux")]
fn run_firewall_command(
    program: &str,
    args: &[&str],
    deadline: std::time::Instant,
) -> std::io::Result<std::process::Output> {
    use std::io::Read as _;
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    if std::time::Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("firewall assessment deadline elapsed before {program}"),
        ));
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn()?;

    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            if let Some(mut pipe) = child.stdout.take() {
                pipe.read_to_end(&mut stdout)?;
            }
            return Ok(std::process::Output {
                status,
                stdout,
                stderr: Vec::new(),
            });
        }

        let now = std::time::Instant::now();
        if now >= deadline {
            // The command owns a fresh process group. Kill the whole group so a helper cannot
            // strand descendants, then always wait for the direct child to avoid a zombie.
            let process_group = -(child.id() as i32);
            // SAFETY: `process_group` names the fresh group assigned above; SIGKILL requires no
            // borrowed memory and failure is handled by the direct-child fallback.
            let _ = unsafe { libc::kill(process_group, libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "{program} exceeded the {} ms firewall assessment deadline",
                    FIREWALL_ASSESS_TIMEOUT.as_millis()
                ),
            ));
        }
        std::thread::sleep(
            deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(20)),
        );
    }
}

#[cfg(target_os = "linux")]
fn assess_ufw_status(port: u16, status: &str) -> PondFirewallStatus {
    for line in status.lines().map(str::trim) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(action_index) = fields
            .iter()
            .position(|field| matches!(*field, "ALLOW" | "LIMIT" | "DENY" | "REJECT"))
        else {
            continue;
        };
        // A bare UFW rule starts with `5644/tcp`. A safely scoped rule renders
        // its destination first, for example
        // `192.168.1.109 5644/tcp on enp0s31f6 ALLOW IN ...`. Only scan the
        // `To` columns before the action so source-side text cannot be mistaken
        // for the admitted destination port.
        let Some(target) = fields[..action_index]
            .iter()
            .copied()
            .find(|target| ufw_target_admits_tcp(target, port))
        else {
            continue;
        };
        let action = fields[action_index];
        match action {
            "ALLOW" | "LIMIT" => {
                return PondFirewallStatus {
                    state: PondFirewallState::Open,
                    detail: format!("UFW rule {target} admits TCP {port}"),
                };
            }
            "DENY" | "REJECT" => {
                return PondFirewallStatus {
                    state: PondFirewallState::Blocked,
                    detail: format!("UFW rule {target} rejects TCP {port}"),
                };
            }
            _ => {}
        }
    }

    if status.contains("Default: allow (incoming)") {
        PondFirewallStatus {
            state: PondFirewallState::Open,
            detail: format!("UFW's default incoming policy admits TCP {port}"),
        }
    } else if status.contains("Default: deny (incoming)")
        || status.contains("Default: reject (incoming)")
    {
        PondFirewallStatus {
            state: PondFirewallState::Blocked,
            detail: format!("UFW's default incoming policy does not admit TCP {port}"),
        }
    } else {
        PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("UFW is active but its policy for TCP {port} is unclear"),
        }
    }
}

#[cfg(target_os = "linux")]
fn ufw_target_admits_tcp(target: &str, port: u16) -> bool {
    let (ports, protocol) = target.split_once('/').unwrap_or((target, "tcp"));
    if !protocol.eq_ignore_ascii_case("tcp") {
        return false;
    }
    let (start, end) = ports
        .split_once(':')
        .map_or((ports, ports), |(start, end)| (start, end));
    let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) else {
        return false;
    };
    (start..=end).contains(&port)
}

#[cfg(windows)]
fn assess_firewall_blocking(
    port: u16,
    _interface: &str,
    deadline: std::time::Instant,
) -> PondFirewallStatus {
    let rule = format!("Koi Pond (TCP {port})");
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            return PondFirewallStatus {
                state: PondFirewallState::Unknown,
                detail: format!("could not resolve the running executable: {error}"),
            };
        }
    };
    match crate::windows_firewall::assess_managed_until(&rule, "TCP", port, &exe, deadline) {
        Ok(crate::windows_firewall::Assessment::Open) => PondFirewallStatus {
            state: PondFirewallState::Open,
            detail: format!("Windows Firewall managed rule admits TCP {port}"),
        },
        Ok(crate::windows_firewall::Assessment::Inactive) => PondFirewallStatus {
            state: PondFirewallState::Inactive,
            detail: "Windows Firewall is not enabled for an active network profile".to_string(),
        },
        Ok(crate::windows_firewall::Assessment::Blocked(
            crate::windows_firewall::BlockReason::MissingOrMismatchedRule,
        )) => PondFirewallStatus {
            state: PondFirewallState::Blocked,
            detail: format!(
                "Windows Firewall managed rule for TCP {port} is absent, disabled, or not scoped to the running executable"
            ),
        },
        Ok(crate::windows_firewall::Assessment::Blocked(
            crate::windows_firewall::BlockReason::ActiveProfileNotCovered,
        )) => PondFirewallStatus {
            state: PondFirewallState::Blocked,
            detail: format!(
                "Windows Firewall managed rule for TCP {port} does not cover the active network profile"
            ),
        },
        Err(error) => PondFirewallStatus {
            state: PondFirewallState::Unknown,
            detail: format!("could not query Windows Firewall: {error}"),
        },
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn assess_firewall_blocking(
    port: u16,
    _interface: &str,
    _deadline: std::time::Instant,
) -> PondFirewallStatus {
    PondFirewallStatus {
        state: PondFirewallState::Unknown,
        detail: format!(
            "host firewall admission for TCP {port} is provisioned by the platform installer"
        ),
    }
}

fn shared_ui_status() -> PondUiStatus {
    PondUiStatus {
        available: true,
        revision: Some("shared-renderer".to_string()),
    }
}

/// Project only mDNS-discovered services into Pond's unauthenticated document.
/// Operator preferences, local candidates, health checks, operations and identity posture
/// stay behind the authenticated adapter.
fn public_catalog(
    snapshot: &koi_common::service::CatalogSnapshot,
) -> koi_common::service::CatalogSnapshot {
    use koi_common::service::{AvailableAction, KoiPresence, MeshIdentityState, ObservationKind};

    let mut services = snapshot
        .services
        .iter()
        .filter(|service| {
            service
                .observations
                .iter()
                .any(|observation| observation.kind == ObservationKind::Mdns)
        })
        .cloned()
        .collect::<Vec<_>>();
    for service in &mut services {
        service.alias = None;
        service.favorite = false;
        service.checks.clear();
        service.active_operations.clear();
        service.ambiguity = None;
        service.observations.clear();
        service
            .available_actions
            .retain(|action| *action == AvailableAction::Open);
        for endpoint in &mut service.endpoints {
            endpoint.reachability.clear();
            endpoint.client_tls.clear();
            endpoint.authority_needs.clear();
            if let Some(scope) = &mut endpoint.network_scope {
                scope.interface = None;
                scope.local_address = None;
                scope.route_source.clear();
                scope.provider_scope = None;
            }
        }
    }

    let device_ids = services
        .iter()
        .map(|service| service.device_id.clone())
        .collect::<std::collections::HashSet<_>>();
    let mut devices = snapshot
        .devices
        .iter()
        .filter(|device| device_ids.contains(&device.id))
        .cloned()
        .collect::<Vec<_>>();
    for device in &mut devices {
        device.koi_presence = KoiPresence::Observed;
        device.mesh_identity.state = MeshIdentityState::Unknown;
        device.mesh_identity.observation_ids.clear();
        for name in &mut device.names {
            name.observation_ids.clear();
        }
        for address in &mut device.addresses {
            address.observation_ids.clear();
        }
    }

    koi_common::service::CatalogSnapshot {
        schema: snapshot.schema,
        epoch: "pond-public".to_string(),
        revision: snapshot.revision,
        generated_at: snapshot.generated_at,
        devices,
        services,
        local_candidates: Vec::new(),
    }
}

#[cfg(test)]
mod browser_projection_tests {
    #[test]
    fn public_snapshot_excludes_authenticated_discovery_provenance() {
        let snapshot = koi_common::mdns_browser::BrowserSnapshot {
            browse_active: true,
            instances: vec![koi_common::mdns_browser::ServiceInstance {
                name: "private-unresolved-instance".into(),
                service_type: "_private._tcp".into(),
                ..Default::default()
            }],
            service_types: vec![koi_common::mdns_browser::TypeSummary {
                service_type: "_private._tcp".into(),
                count: 1,
                ..Default::default()
            }],
            total_instances: 1,
            total_types: 1,
            discovery: koi_common::integration::MdnsDiscoverySnapshot {
                revision: 91,
                sources: vec![koi_common::integration::MdnsDiscoverySource {
                    query: "private-query".into(),
                    provider: Some("private-provider".into()),
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        let value = super::public_browser_snapshot(snapshot);
        assert!(value.get("discovery").is_none());
        assert!(value.get("browse_active").is_none());
        let encoded = value.to_string();
        assert!(!encoded.contains("private-provider"));
        assert!(!encoded.contains("private-query"));
        assert!(!encoded.contains("private-unresolved-instance"));
        assert_eq!(value["total_instances"], 0);
        assert_eq!(value["total_types"], 0);
    }
}

#[cfg(test)]
fn public_routes(runtime: PondRuntime) -> Router {
    public_routes_for_domain(runtime.inner.domain.clone())
}

fn public_routes_for_domain(domain: PondDomain) -> Router {
    Router::new()
        .route("/", get(ui_selector_handler))
        .route("/healthz", get(pond_health_handler))
        .route("/v1/status", get(pond_status_projection_handler))
        .route(
            "/v1/mdns/browser/snapshot",
            get(pond_browser_snapshot_handler),
        )
        .route("/v1/dns/entries", get(pond_dns_entries_handler))
        .layer(Extension(domain))
}

/// Routes mounted only on the full operator adapter. DAT middleware remains outside.
pub fn operator_routes(runtime: PondRuntime) -> Router {
    Router::new()
        .route(
            "/v1/pond",
            get(pond_operator_status_handler)
                .put(pond_enable_handler)
                .delete(pond_disable_handler),
        )
        .layer(Extension(runtime))
}

async fn ui_selector_handler(
    Extension(domain): Extension<PondDomain>,
    request: Request,
) -> Response {
    let state = match koi_ui::UiState::parse_query(request.uri().query().unwrap_or_default()) {
        Ok(state) => state,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    let status = domain.inner.config.system_status.status();
    let public_status = crate::pond_public_status::project(
        status.as_ref(),
        domain.inner.config.started_at.elapsed().as_secs(),
    );
    let operator = koi_ui::OperatorSnapshot {
        revision: public_status.revision,
        capabilities: public_status
            .capabilities
            .into_iter()
            .map(|capability| koi_common::capability::CapabilityStatus {
                name: capability.name,
                summary: if !capability.enabled {
                    "Not enabled".to_string()
                } else if capability.healthy {
                    "Available".to_string()
                } else {
                    "Needs attention".to_string()
                },
                healthy: capability.healthy,
            })
            .collect(),
        ..Default::default()
    };
    let catalog = public_catalog(&status.catalog);
    let document = koi_ui::render_with_operator_state(
        koi_ui::View::Snapshot(&catalog),
        Some(&operator),
        koi_ui::Links {
            refresh: Some("./"),
            endpoint_actions: koi_ui::EndpointActions::OpenOnly,
            preference_actions: false,
            operator_actions: koi_ui::OperatorActions::None,
        },
        &state,
    );
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, POND_HTML_CSP),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        document,
    )
        .into_response()
}

async fn pond_health_handler() -> &'static str {
    "OK"
}

async fn pond_status_projection_handler(
    Extension(domain): Extension<PondDomain>,
) -> Json<crate::pond_public_status::PondPublicStatus> {
    let status = domain.inner.config.system_status.status();
    Json(crate::pond_public_status::project(
        &status,
        domain.inner.config.started_at.elapsed().as_secs(),
    ))
}

async fn pond_browser_snapshot_handler(Extension(domain): Extension<PondDomain>) -> Response {
    let Some(browser) = &domain.inner.config.browser else {
        return disabled_response("mdns-browser");
    };
    browser.meta.touch();
    Json(public_browser_snapshot(browser.cache.snapshot().await)).into_response()
}

// Explicit public wire allowlist: adding authenticated inspection evidence to the
// common snapshot must never expand Pond's public projection.
fn public_browser_snapshot(
    mut snapshot: koi_common::mdns_browser::BrowserSnapshot,
) -> serde_json::Value {
    // Found-only evidence is operator inspection data. Conservatively retain
    // only resolved rows (including their existing removal tombstones).
    snapshot.instances.retain(|instance| instance.resolved);
    let reported_types = snapshot
        .discovery
        .service_types
        .iter()
        .map(|value| value.trim_end_matches('.').trim_end_matches(".local"))
        .collect::<std::collections::HashSet<_>>();
    snapshot.service_types.retain_mut(|service_type| {
        service_type.count = snapshot
            .instances
            .iter()
            .filter(|instance| {
                instance.service_type == service_type.service_type && instance.removed_at.is_none()
            })
            .count();
        reported_types.contains(service_type.service_type.as_str())
            || snapshot
                .instances
                .iter()
                .any(|instance| instance.service_type == service_type.service_type)
    });
    snapshot.total_types = snapshot.service_types.len();
    snapshot.total_instances = snapshot
        .instances
        .iter()
        .filter(|instance| instance.removed_at.is_none())
        .count();
    serde_json::json!({
        "revision": snapshot.revision,
        "total_types": snapshot.total_types,
        "total_instances": snapshot.total_instances,
        "service_types": snapshot.service_types,
        "instances": snapshot.instances,
        "cache_age_secs": snapshot.cache_age_secs,
        "burst": snapshot.burst,
    })
}

async fn pond_dns_entries_handler(Extension(domain): Extension<PondDomain>) -> Response {
    let status = domain.inner.config.system_status.status();
    let Some(catalog) = &status.domains.dns_catalog else {
        return disabled_response("dns");
    };
    Json(serde_json::json!({ "entries": &catalog.entries })).into_response()
}

fn disabled_response(capability: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "capability_disabled",
            "message": format!("The '{capability}' capability is disabled on this daemon.")
        })),
    )
        .into_response()
}

#[utoipa::path(get, path = "/v1/pond", tag = "pond",
    summary = "Read Pond desired and observed state",
    responses((status = 200, body = PondStatus),
              (status = 401, description = "Daemon access token required")))]
async fn pond_operator_status_handler(
    Extension(runtime): Extension<PondRuntime>,
) -> Json<PondStatus> {
    Json(runtime.status().as_ref().clone())
}

#[utoipa::path(put, path = "/v1/pond", tag = "pond",
    summary = "Desire and reconcile the read-only LAN listener",
    responses((status = 200, body = PondStatus),
              (status = 503, body = PondStatus, description = "Desired but not reachable yet"),
              (status = 500, description = "Intent persistence failed or durability is uncertain"),
              (status = 401, description = "Daemon access token required")))]
async fn pond_enable_handler(Extension(runtime): Extension<PondRuntime>) -> Response {
    match runtime.enable().await {
        Ok(status) if status.state == PondState::Running => Json(status).into_response(),
        Ok(status) => (StatusCode::SERVICE_UNAVAILABLE, Json(status)).into_response(),
        Err(PondCommandError::ShuttingDown) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(runtime.status().as_ref().clone()),
        )
            .into_response(),
        Err(PondCommandError::Persist(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "pond_intent_not_persisted",
                "message": error.to_string()
            })),
        )
            .into_response(),
        Err(PondCommandError::DurabilityUncertain(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "pond_intent_durability_uncertain",
                "message": error.to_string()
            })),
        )
            .into_response(),
    }
}

#[utoipa::path(delete, path = "/v1/pond", tag = "pond",
    summary = "Persistently stop the read-only LAN listener",
    responses((status = 200, body = PondStatus),
              (status = 503, body = PondStatus, description = "Daemon is shutting down"),
              (status = 500, description = "Intent persistence failed or durability is uncertain"),
              (status = 401, description = "Daemon access token required")))]
async fn pond_disable_handler(Extension(runtime): Extension<PondRuntime>) -> Response {
    match runtime.disable().await {
        Ok(status) => Json(status).into_response(),
        Err(PondCommandError::ShuttingDown) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(runtime.status().as_ref().clone()),
        )
            .into_response(),
        Err(PondCommandError::Persist(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "pond_intent_not_persisted",
                "message": error.to_string()
            })),
        )
            .into_response(),
        Err(PondCommandError::DurabilityUncertain(error)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "pond_intent_durability_uncertain",
                "message": error.to_string()
            })),
        )
            .into_response(),
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        pond_operator_status_handler,
        pond_enable_handler,
        pond_disable_handler
    ),
    components(schemas(
        PondStatus,
        PondState,
        PondFirewallStatus,
        PondFirewallState,
        PondUiStatus
    ))
)]
pub struct PondApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn unique_root(name: &str) -> PathBuf {
        koi_common::test::ensure_data_dir("pond-runtime-tests")
            .join(format!("{name}-{}", koi_common::id::generate_short_id()))
    }

    fn test_config(root: &std::path::Path, parent_cancel: CancellationToken) -> PondConfig {
        PondConfig {
            port: DEFAULT_POND_PORT,
            intent_path: root.join("pond.json"),
            started_at: Instant::now(),
            browser: None,
            system_status: Arc::new(koi_compose::status::KoiStatusRuntime::default()),
            parent_cancel,
        }
    }

    fn test_runtime() -> PondRuntime {
        let root = unique_root("runtime");
        PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap()
    }

    fn drain_desired_events(events: &mut broadcast::Receiver<PondEvent>) -> Vec<bool> {
        let mut desired = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let PondEvent::DesiredStateChanged { desired: value, .. } = event {
                desired.push(value);
            }
        }
        desired
    }

    #[test]
    fn status_wire_round_trips() {
        let status = PondStatus {
            revision: 7,
            generation: 3,
            accepting_commands: true,
            desired: true,
            running: true,
            state: PondState::Running,
            port: DEFAULT_POND_PORT,
            urls: vec!["http://192.168.1.2:5644/".to_string()],
            url: Some("http://192.168.1.2:5644/".to_string()),
            firewall: PondFirewallStatus {
                state: PondFirewallState::Open,
                detail: "open".to_string(),
            },
            ui: PondUiStatus {
                available: true,
                revision: Some("sha256:test".to_string()),
            },
            reason: None,
        };
        let encoded = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<PondStatus>(&encoded).unwrap(),
            status
        );
    }

    #[tokio::test]
    async fn status_feed_is_immediate_revisioned_and_suppresses_noops() {
        let runtime = test_runtime();
        let mut rx = runtime.watch_status();
        let initial = runtime.status();
        assert_eq!(initial.revision, 0);
        assert!(Arc::ptr_eq(&initial, &rx.borrow()));

        runtime.publish_status(0, PondStatus::disabled(DEFAULT_POND_PORT));
        assert!(rx.has_changed().is_ok_and(|changed| !changed));

        runtime.set_reconciling(0);
        rx.changed().await.unwrap();
        let reconciling = rx.borrow_and_update().clone();
        assert_eq!(reconciling.revision, 1);
        assert_eq!(reconciling.state, PondState::Reconciling);

        runtime.set_reconciling(0);
        assert!(rx.has_changed().is_ok_and(|changed| !changed));
    }

    #[test]
    fn constructor_loads_desire_before_exposing_status() {
        let root = unique_root("initial-desire");
        koi_common::persist::write_json_pretty(
            &root.join("pond.json"),
            &PondIntent { desired: true },
        )
        .unwrap();

        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();
        let status = runtime.status();
        assert!(status.desired);
        assert!(!status.running);
        assert_eq!(status.state, PondState::Waiting);
        assert_eq!(status.revision, 0);
        assert_eq!(status.generation, 0);
    }

    #[test]
    fn constructor_rejects_corrupt_intent_instead_of_claiming_disabled() {
        let root = unique_root("corrupt-intent");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("pond.json"), "{broken").unwrap();

        let error = PondRuntime::new(test_config(&root, CancellationToken::new()))
            .err()
            .expect("corrupt intent must fail construction");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn constructor_rejects_missing_or_unknown_intent_fields() {
        for (name, json) in [
            ("missing-desired", "{}"),
            ("misspelled-desired", r#"{"desire":true}"#),
            (
                "unknown-field",
                r#"{"desired":true,"surprise":"ignored would be unsafe"}"#,
            ),
        ] {
            let root = unique_root(name);
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("pond.json"), json).unwrap();

            let error = PondRuntime::new(test_config(&root, CancellationToken::new()))
                .err()
                .expect("ambiguous intent must fail construction");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{name}");
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn failed_intent_commit_publishes_neither_status_nor_event() {
        let root = unique_root("failed-intent-commit");
        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();
        let before = runtime.status();
        let statuses = runtime.watch_status();
        let mut events = runtime.subscribe();
        std::fs::create_dir_all(root.join("pond.json")).unwrap();

        assert!(runtime.enable().await.is_err());
        assert!(Arc::ptr_eq(&before, &runtime.status()));
        assert!(statuses.has_changed().is_ok_and(|changed| !changed));
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn visible_intent_uncertainty_is_typed_and_retryable_for_both_values() {
        let root = unique_root("uncertain-intent");
        let mut config = test_config(&root, CancellationToken::new());
        config.port = 0;
        let runtime = PondRuntime::new(config).unwrap();
        let mut events = runtime.subscribe();

        runtime.make_next_intent_durability_uncertain();
        assert!(matches!(
            runtime.enable().await,
            Err(PondCommandError::DurabilityUncertain(_))
        ));
        assert!(runtime.status().desired);
        assert!(runtime.status().accepting_commands);
        assert_eq!(drain_desired_events(&mut events), [true]);
        let persisted: PondIntent =
            koi_common::persist::read_json(&root.join("pond.json")).unwrap();
        assert!(persisted.desired);

        runtime
            .enable()
            .await
            .expect("identical enable retry confirms durability");
        assert!(drain_desired_events(&mut events).is_empty());

        runtime.make_next_intent_durability_uncertain();
        assert!(matches!(
            runtime.disable().await,
            Err(PondCommandError::DurabilityUncertain(_))
        ));
        assert!(!runtime.status().desired);
        assert!(runtime.status().accepting_commands);
        assert_eq!(drain_desired_events(&mut events), [false]);
        let persisted: PondIntent =
            koi_common::persist::read_json(&root.join("pond.json")).unwrap();
        assert!(!persisted.desired);

        runtime
            .disable()
            .await
            .expect("identical disable retry confirms durability");
        assert!(drain_desired_events(&mut events).is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn intent_durability_uncertainty_is_explicit_on_the_http_boundary() {
        let lifecycle_root = unique_root("uncertain-intent-http");
        let mut config = test_config(&lifecycle_root, CancellationToken::new());
        config.port = 0;
        let lifecycle = PondRuntime::new(config).unwrap();
        lifecycle.make_next_intent_durability_uncertain();
        let response = pond_enable_handler(Extension(lifecycle.clone())).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "pond_intent_durability_uncertain");
        assert!(lifecycle.status().desired);

        lifecycle
            .shutdown_with_timeout(Duration::from_millis(10))
            .await;
        let _ = std::fs::remove_dir_all(lifecycle_root);
    }

    #[tokio::test]
    async fn events_are_emitted_only_after_their_status_is_current() {
        let runtime = test_runtime();
        let mut events = runtime.subscribe();

        let published = runtime.publish_status(
            1,
            PondStatus {
                revision: 0,
                generation: 1,
                accepting_commands: true,
                desired: true,
                running: false,
                state: PondState::Reconciling,
                port: DEFAULT_POND_PORT,
                urls: Vec::new(),
                url: None,
                firewall: unknown_firewall(),
                ui: runtime.ui_status(),
                reason: None,
            },
        );
        assert_eq!(runtime.status().as_ref(), published.as_ref());

        let desired = events.recv().await.unwrap();
        assert_eq!(
            desired,
            PondEvent::DesiredStateChanged {
                generation: 1,
                desired: true,
            }
        );
        assert!(runtime.status().desired, "status must precede its event");

        let lifecycle = events.recv().await.unwrap();
        assert!(matches!(
            lifecycle,
            PondEvent::LifecycleChanged {
                generation: 1,
                previous: PondState::Disabled,
                current: PondState::Reconciling,
                running: false,
                ..
            }
        ));

        runtime.set_reconciling(1);
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn disable_is_serialized_and_rejects_superseded_observations() {
        let root = unique_root("disable-order");
        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();

        let enabled = runtime.enable().await.unwrap();
        assert!(enabled.desired);
        assert_eq!(enabled.generation, 1);
        let stale_generation = enabled.generation;

        let returned = runtime.disable().await.unwrap();
        let current = runtime.status();
        assert_eq!(&returned, current.as_ref());
        assert!(!current.desired);
        assert!(!current.running);
        assert_eq!(current.state, PondState::Disabled);
        assert!(current.generation > stale_generation);
        let before_stale = Arc::clone(&current);

        let rejected = runtime.publish_status(
            stale_generation,
            PondStatus {
                revision: 0,
                generation: stale_generation,
                accepting_commands: true,
                desired: true,
                running: true,
                state: PondState::Running,
                port: DEFAULT_POND_PORT,
                urls: vec!["http://192.168.1.2:5644/".into()],
                url: Some("http://192.168.1.2:5644/".into()),
                firewall: PondFirewallStatus {
                    state: PondFirewallState::Open,
                    detail: "open".into(),
                },
                ui: runtime.ui_status(),
                reason: None,
            },
        );
        assert!(Arc::ptr_eq(&before_stale, &rejected));
        assert_eq!(runtime.status().state, PondState::Disabled);

        let persisted: PondIntent =
            koi_common::persist::read_json(&root.join("pond.json")).unwrap();
        assert!(!persisted.desired);
    }

    #[tokio::test]
    async fn disable_installs_its_generation_fence_before_awaiting_worker_exit() {
        let root = unique_root("disable-fence");
        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        {
            let mut lifecycle = runtime.inner.lifecycle.lock().await;
            lifecycle.generation = 1;
            lifecycle.run = Some(RunHandle {
                cancel: CancellationToken::new(),
                task: tokio::spawn(async move {
                    let _ = release_rx.await;
                }),
            });
        }
        runtime.publish_status(
            1,
            PondStatus {
                revision: 0,
                generation: 1,
                accepting_commands: true,
                desired: true,
                running: true,
                state: PondState::Running,
                port: DEFAULT_POND_PORT,
                urls: vec!["http://192.0.2.10:5644/".to_string()],
                url: Some("http://192.0.2.10:5644/".to_string()),
                firewall: PondFirewallStatus {
                    state: PondFirewallState::Open,
                    detail: "open".to_string(),
                },
                ui: PondUiStatus::default(),
                reason: None,
            },
        );

        let mut statuses = runtime.watch_status();
        let disabling = tokio::spawn({
            let runtime = runtime.clone();
            async move { runtime.disable().await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = statuses.borrow_and_update().clone();
                if status.generation == 2 && !status.desired && status.running {
                    break;
                }
                statuses.changed().await.unwrap();
            }
        })
        .await
        .expect("disable did not install its generation fence");

        let fenced = runtime.status();
        let rejected = runtime.publish_status(
            1,
            PondStatus {
                desired: true,
                reason: Some("superseded worker result".to_string()),
                ..fenced.as_ref().clone()
            },
        );
        assert!(Arc::ptr_eq(&fenced, &rejected));
        assert!(!runtime.status().desired);

        release_tx.send(()).unwrap();
        let final_status = disabling.await.unwrap().unwrap();
        assert_eq!(final_status.generation, 2);
        assert!(!final_status.desired);
        assert!(!final_status.running);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disable_aborts_a_cancellation_insensitive_reconciler_by_deadline() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let root = unique_root("disable-hard-deadline");
        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = oneshot::channel();
        let task = {
            let dropped = Arc::clone(&dropped);
            tokio::spawn(async move {
                let _drop_flag = DropFlag(dropped);
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            })
        };
        started_rx.await.unwrap();
        {
            let mut lifecycle = runtime.inner.lifecycle.lock().await;
            lifecycle.generation = 1;
            lifecycle.run = Some(RunHandle {
                cancel: CancellationToken::new(),
                task,
            });
        }
        runtime.publish_status(
            1,
            PondStatus {
                revision: 0,
                generation: 1,
                accepting_commands: true,
                desired: true,
                running: true,
                state: PondState::Running,
                port: DEFAULT_POND_PORT,
                urls: vec!["http://192.0.2.10:5644/".to_string()],
                url: Some("http://192.0.2.10:5644/".to_string()),
                firewall: PondFirewallStatus {
                    state: PondFirewallState::Open,
                    detail: "open".to_string(),
                },
                ui: PondUiStatus::default(),
                reason: None,
            },
        );

        let stopped = tokio::time::timeout(
            RECONCILER_STOP_TIMEOUT + Duration::from_secs(1),
            runtime.disable(),
        )
        .await
        .expect("disable exceeded its hard reconciler deadline")
        .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        assert!(!stopped.running);
        assert_eq!(stopped.state, PondState::Disabled);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn final_runtime_drop_breaks_the_reconciler_cycle_and_closes_its_listener() {
        let root = unique_root("drop-owner");
        let mut config = test_config(&root, CancellationToken::new());
        config.port = 0;
        let runtime = PondRuntime::new(config).unwrap();
        let enabled = runtime.enable().await.unwrap();
        assert!(
            enabled.running,
            "the real listener must be bound before drop"
        );
        let port = enabled.port;
        let owner = Arc::downgrade(&runtime.inner);
        let domain = Arc::downgrade(&runtime.inner.domain.inner);

        drop(runtime);

        assert!(
            owner.upgrade().is_none(),
            "the reconciler retained its owner"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while domain.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the aborted reconciler retained Pond domain state");
        assert!(
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .is_err(),
            "the Pond listener survived its final runtime owner"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_shutdown_retains_the_join_handle_for_a_bounded_retry() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let root = unique_root("cancelled-shutdown");
        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let worker_cancel = CancellationToken::new();
        let worker_cancel_probe = worker_cancel.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let task = tokio::spawn({
            let dropped = Arc::clone(&dropped);
            async move {
                let _drop = DropFlag(dropped);
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            }
        });
        started_rx.await.unwrap();
        {
            let mut lifecycle = runtime.inner.lifecycle.lock().await;
            lifecycle.generation = 1;
            lifecycle.run = Some(RunHandle {
                cancel: worker_cancel,
                task,
            });
        }
        runtime.publish_status(
            1,
            PondStatus {
                desired: true,
                running: true,
                state: PondState::Running,
                generation: 1,
                ..PondStatus::awaiting_reconciliation(DEFAULT_POND_PORT)
            },
        );

        let shutting_runtime = runtime.clone();
        let shutting = tokio::spawn(async move {
            shutting_runtime
                .shutdown_with_timeout(Duration::from_secs(60))
                .await;
        });
        worker_cancel_probe.cancelled().await;
        shutting.abort();
        let _ = shutting.await;

        assert!(runtime.inner.lifecycle.lock().await.run.is_some());
        assert!(
            !dropped.load(Ordering::SeqCst),
            "cancelling shutdown detached or destroyed its owned task"
        );

        runtime
            .shutdown_with_timeout(Duration::from_millis(10))
            .await;
        assert!(runtime.inner.lifecycle.lock().await.run.is_none());
        assert!(dropped.load(Ordering::SeqCst));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn normal_shutdown_joins_the_owned_reconciler_and_is_idempotent() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let root = unique_root("normal-shutdown");
        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn({
            let dropped = Arc::clone(&dropped);
            async move {
                let _drop = DropFlag(dropped);
                task_cancel.cancelled().await;
            }
        });
        {
            let mut lifecycle = runtime.inner.lifecycle.lock().await;
            lifecycle.generation = 1;
            lifecycle.run = Some(RunHandle { cancel, task });
        }

        runtime.shutdown_with_timeout(Duration::from_secs(1)).await;
        let revision = runtime.status().revision;
        {
            let lifecycle = runtime.inner.lifecycle.lock().await;
            assert!(lifecycle.shutdown);
            assert!(lifecycle.run.is_none());
        }
        assert!(dropped.load(Ordering::SeqCst));

        runtime.shutdown_with_timeout(Duration::from_secs(1)).await;
        assert_eq!(runtime.status().revision, revision);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn terminal_shutdown_rejects_restartable_commands_before_persistence() {
        let disabled_root = unique_root("shutdown-rejects-enable");
        let disabled =
            PondRuntime::new(test_config(&disabled_root, CancellationToken::new())).unwrap();
        let mut disabled_status = disabled.watch_status();
        disabled
            .shutdown_with_timeout(Duration::from_millis(10))
            .await;
        disabled_status.changed().await.unwrap();
        assert!(!disabled_status.borrow_and_update().accepting_commands);
        let before = disabled.status();
        assert!(!before.accepting_commands);
        assert!(matches!(
            disabled.enable().await,
            Err(PondCommandError::ShuttingDown)
        ));
        assert!(Arc::ptr_eq(&before, &disabled.status()));
        assert!(
            !disabled_root.join("pond.json").exists(),
            "rejected enable must not create durable desire"
        );

        let desired_root = unique_root("shutdown-rejects-disable");
        koi_common::persist::write_json_pretty(
            &desired_root.join("pond.json"),
            &PondIntent { desired: true },
        )
        .unwrap();
        let desired =
            PondRuntime::new(test_config(&desired_root, CancellationToken::new())).unwrap();
        desired
            .shutdown_with_timeout(Duration::from_millis(10))
            .await;
        let before = desired.status();
        assert!(!before.accepting_commands);
        assert!(matches!(
            desired.disable().await,
            Err(PondCommandError::ShuttingDown)
        ));
        assert!(Arc::ptr_eq(&before, &desired.status()));
        let persisted: PondIntent =
            koi_common::persist::read_json(&desired_root.join("pond.json")).unwrap();
        assert!(
            persisted.desired,
            "rejected disable must preserve next-boot desire"
        );

        let response = pond_enable_handler(Extension(disabled.clone())).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: PondStatus = serde_json::from_slice(&body).unwrap();
        assert!(!status.accepting_commands);
        assert_eq!(status, *disabled.status());

        let response = pond_disable_handler(Extension(desired.clone())).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: PondStatus = serde_json::from_slice(&body).unwrap();
        assert!(!status.accepting_commands);
        assert_eq!(status, *desired.status());

        let _ = std::fs::remove_dir_all(disabled_root);
        let _ = std::fs::remove_dir_all(desired_root);
    }

    #[tokio::test]
    async fn parent_shutdown_rejection_first_closes_the_status_boundary() {
        let root = unique_root("parent-shutdown-admission");
        let parent_cancel = CancellationToken::new();
        let runtime = PondRuntime::new(test_config(&root, parent_cancel.clone())).unwrap();
        let mut status = runtime.watch_status();
        parent_cancel.cancel();

        assert!(matches!(
            runtime.enable().await,
            Err(PondCommandError::ShuttingDown)
        ));
        status.changed().await.unwrap();
        assert!(!status.borrow_and_update().accepting_commands);
        assert!(!runtime.status().accepting_commands);
        assert!(!root.join("pond.json").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn concurrent_commands_leave_durable_intent_and_status_coherent() {
        let root = unique_root("concurrent-commands");
        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();
        let mut commands = Vec::new();
        for index in 0..12 {
            let runtime = runtime.clone();
            commands.push(tokio::spawn(async move {
                if index % 2 == 0 {
                    runtime.enable().await.map(|status| status.desired)
                } else {
                    runtime.disable().await.map(|status| status.desired)
                }
            }));
        }
        for command in commands {
            command.await.unwrap().unwrap();
        }

        let persisted: PondIntent =
            koi_common::persist::read_json(&root.join("pond.json")).unwrap();
        let status = runtime.status();
        assert_eq!(persisted.desired, status.desired);
        assert!(!status.running);
        if persisted.desired {
            assert!(matches!(
                status.state,
                PondState::Reconciling | PondState::Waiting
            ));
        } else {
            assert_eq!(status.state, PondState::Disabled);
        }

        runtime.disable().await.unwrap();
    }

    #[tokio::test]
    async fn supervision_reconciles_loaded_desire_and_preserves_it_on_shutdown() {
        let root = unique_root("supervise-cancel");
        koi_common::persist::write_json_pretty(
            &root.join("pond.json"),
            &PondIntent { desired: true },
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let runtime = PondRuntime::new(test_config(&root, cancel.clone())).unwrap();
        let mut status = runtime.watch_status();

        let supervisor = tokio::spawn({
            let runtime = runtime.clone();
            async move { runtime.supervise().await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if status.borrow().generation == 1 && status.borrow().state == PondState::Waiting {
                    break;
                }
                status.changed().await.unwrap();
            }
        })
        .await
        .expect("initial supervision did not settle");
        cancel.cancel();
        supervisor.await.unwrap();

        let stopped = runtime.status();
        assert!(!stopped.running);
        assert!(stopped.desired);
        assert_eq!(stopped.state, PondState::Waiting);
        assert_eq!(stopped.generation, 2);
        assert_eq!(
            stopped.reason.as_deref(),
            Some("listener stopped with daemon")
        );
    }

    #[test]
    fn pond_port_is_the_fourth_port_and_refuses_overflow() {
        assert_eq!(port_for_http(5641), Some(DEFAULT_POND_PORT));
        assert_eq!(port_for_http(u16::MAX), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ufw_assessment_honors_tcp_rules_ranges_and_default_policy() {
        let open = assess_ufw_status(
            DEFAULT_POND_PORT,
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n\
             5600:5700/tcp ALLOW IN 192.168.1.0/24\n",
        );
        assert_eq!(open.state, PondFirewallState::Open);

        let scoped = assess_ufw_status(
            DEFAULT_POND_PORT,
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n\
             192.168.1.109 5644/tcp on enp0s31f6 ALLOW IN 192.168.1.95 # koi-pond-gate\n",
        );
        assert_eq!(scoped.state, PondFirewallState::Open);

        let udp_only = assess_ufw_status(
            DEFAULT_POND_PORT,
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n\
             5644/udp ALLOW IN Anywhere\n",
        );
        assert_eq!(udp_only.state, PondFirewallState::Blocked);

        let default_open = assess_ufw_status(
            DEFAULT_POND_PORT,
            "Status: active\nDefault: allow (incoming), allow (outgoing)\n",
        );
        assert_eq!(default_open.state, PondFirewallState::Open);
    }

    #[test]
    fn unknown_firewall_never_claims_lan_reachability() {
        assert!(firewall_admits_lan_reachability(PondFirewallState::Open));
        assert!(firewall_admits_lan_reachability(
            PondFirewallState::Inactive
        ));
        assert!(!firewall_admits_lan_reachability(
            PondFirewallState::Blocked
        ));
        assert!(!firewall_admits_lan_reachability(
            PondFirewallState::Unknown
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn firewall_probe_kills_and_reaps_a_child_at_its_deadline() {
        let started = std::time::Instant::now();
        let error = run_firewall_command(
            "sleep",
            &["30"],
            std::time::Instant::now() + Duration::from_millis(100),
        )
        .expect_err("hung firewall helper must be terminated");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "killed child was not reaped promptly"
        );
    }

    #[test]
    fn pond_openapi_excludes_retired_bundle_publication() {
        let spec = PondApiDoc::openapi();
        assert!(!spec.paths.paths.contains_key("/v1/ui"));
    }

    #[tokio::test]
    async fn public_root_uses_shared_renderer_and_has_no_bundle_assets() {
        let root = unique_root("pond-shared-renderer");
        let runtime = PondRuntime::new(test_config(&root, CancellationToken::new())).unwrap();
        let app = public_routes(runtime);
        let response = app
            .clone()
            .oneshot(Request::get("/?tab=about").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            koi_ui::DOCUMENT_CSP
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("id=\"about\""));
        assert!(html.contains(">Certmesh<"));
        assert!(!html.contains("app.js"));
        assert!(!html.contains("Legacy"));

        for retired in ["/app.js", "/styles.css", "/_koi/ui/old/app.js"] {
            let response = app
                .clone()
                .oneshot(Request::get(retired).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{retired}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn stop_bounds_graceful_drain_when_a_client_never_finishes_its_request() {
        use tokio::io::AsyncWriteExt as _;

        let root = unique_root("pond-bounded-drain");
        let mut config = test_config(&root, CancellationToken::new());
        config.port = 0;
        let runtime = PondRuntime::new(config).unwrap();
        let port = runtime.enable().await.unwrap().port;

        let mut client = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
                    Ok(client) => break client,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("Pond listener was not accepting connections");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
            .await
            .unwrap();

        let disabled = tokio::time::timeout(Duration::from_secs(8), runtime.disable())
            .await
            .expect("a stalled client kept Pond shutdown alive")
            .unwrap();
        assert!(!disabled.running);
        assert_eq!(disabled.state, PondState::Disabled);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn public_router_has_only_allowlisted_reads() {
        let runtime = test_runtime();
        let app = public_routes(runtime);

        let mutation = app
            .clone()
            .oneshot(Request::post("/v1/dns/add").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(mutation.status(), StatusCode::NOT_FOUND);

        let excluded = app
            .clone()
            .oneshot(
                Request::get("/v1/certmesh/log")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(excluded.status(), StatusCode::NOT_FOUND);

        let dns = app
            .oneshot(Request::get("/v1/dns/entries").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(dns.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn pond_dns_entries_come_from_the_product_aggregate() {
        let root = unique_root("dns-catalog");
        let dns_core = koi_dns::DnsCore::open(
            root.join("dns.json"),
            koi_dns::DnsConfig::default(),
            None,
            None,
            None,
        )
        .await
        .expect("DNS core");
        dns_core
            .add_entry(koi_dns::DnsEntry {
                name: "pond.internal.".to_string(),
                ip: "10.0.0.24".to_string(),
                ttl: Some(60),
            })
            .expect("add DNS entry");
        let cores = koi_compose::cores::Cores {
            dns: Some(Arc::new(koi_dns::DnsRuntime::new(dns_core))),
            ..Default::default()
        };
        cores.system_status.reconcile(&cores);

        let mut config = test_config(&root, CancellationToken::new());
        config.system_status = Arc::clone(&cores.system_status);
        let runtime = PondRuntime::new(config).expect("Pond runtime");
        let response = public_routes(runtime)
            .oneshot(Request::get("/v1/dns/entries").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["entries"][0]["name"], "pond.internal.");
        assert_eq!(value["entries"][0]["ip"], "10.0.0.24");

        let _ = std::fs::remove_dir_all(root);
    }
}
