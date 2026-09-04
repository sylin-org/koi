//! Koi mDNS — a provider-agnostic DNS-SD bounded context.
//!
//! [`MdnsCore`] is the application boundary. Registration intent belongs to
//! the registry, browse demand belongs to the discovery hub, provider routing
//! belongs to the control plane, and native resources belong to provider
//! sessions. Public mutation methods are asynchronous because success means a
//! real provider operation has completed.

pub mod adapter;
#[cfg(target_os = "linux")]
pub mod avahi;
mod control_plane;
mod discovery;
pub mod error;
pub mod events;
pub mod http;
pub mod native;
pub mod protocol;
pub mod provider;
mod registry;
#[cfg(target_os = "linux")]
pub mod systemd_resolved;
#[cfg(target_os = "windows")]
pub mod windows_bonjour;
#[cfg(target_os = "windows")]
pub mod windows_dnsapi;

pub use self::discovery::{BrowseRecvError, BrowseSubscription};
pub use self::error::{MdnsError, Result};
pub use self::events::MdnsEvent;
pub use self::registry::LeasePolicy;

use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use koi_common::firewall::{FirewallPort, FirewallProtocol};
use koi_common::id::generate_short_id;
use koi_common::integration::MdnsDiscoverySnapshot;
use koi_common::mdns_protocol::MdnsControlPlaneStatus;
use koi_common::status::StatusFeed;
use koi_common::types::{ServiceRecord, ServiceType, SessionId};
use tokio::sync::{broadcast, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use self::adapter::MdnsAdapter;
use self::control_plane::MdnsControlPlane;
use self::discovery::{canonical_key, DiscoveryHub};
use self::registry::{
    heartbeat_policy, RegistrationAttempt, RegistrationRegistry, WithdrawalAttempt,
};
use crate::protocol::{
    AdminRegistration, DaemonStatus, LeaseMode, RegisterPayload, RegistrationCounts,
    RegistrationResult,
};

const REAPER_INTERVAL: Duration = Duration::from_secs(5);
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// mDNS UDP port.
pub const MDNS_PORT: u16 = 5353;

/// Whether a UDP port is exclusively free. This is a lab diagnostic, not
/// provider-selection evidence; adapters probe cooperative mDNS semantics.
pub fn udp_port_exclusively_free(port: u16) -> bool {
    std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

pub fn firewall_ports() -> Vec<FirewallPort> {
    vec![FirewallPort::new("mDNS", FirewallProtocol::Udp, MDNS_PORT)]
}

/// Application façade for registration, discovery, lifecycle, and status.
pub struct MdnsCore {
    discovery: Arc<DiscoveryHub>,
    control_plane: Arc<MdnsControlPlane>,
    registry: Arc<RegistrationRegistry>,
    operation_lock: Arc<Mutex<()>>,
    status: StatusFeed<MdnsStatus>,
    started_at: Instant,
    cancel: CancellationToken,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    lifecycle: Arc<MdnsLifecycle>,
    shutdown_task: StdMutex<Option<JoinHandle<()>>>,
}

struct MdnsLifecycleState {
    accepting: bool,
    in_flight: usize,
    shutdown_outcome: Option<std::result::Result<(), String>>,
}

/// Owns mDNS command admission and the one terminal completion result.
///
/// The retained task handle deliberately lives on [`MdnsCore`] instead of in
/// this `Arc`: the task may retain the state it must settle without creating an
/// `Arc -> JoinHandle -> Arc` cycle.
struct MdnsLifecycle {
    state: StdMutex<MdnsLifecycleState>,
    idle: tokio::sync::Notify,
    shutdown_changed: tokio::sync::Notify,
    #[cfg(test)]
    test: MdnsShutdownTestControl,
}

impl MdnsLifecycle {
    fn new() -> Self {
        Self {
            state: StdMutex::new(MdnsLifecycleState {
                accepting: true,
                in_flight: 0,
                shutdown_outcome: None,
            }),
            idle: tokio::sync::Notify::new(),
            shutdown_changed: tokio::sync::Notify::new(),
            #[cfg(test)]
            test: MdnsShutdownTestControl::new(),
        }
    }

    fn admit(self: &Arc<Self>) -> Result<MdnsOperationPermit> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.accepting {
            return Err(MdnsError::Daemon("mDNS core is shutting down".to_string()));
        }
        state.in_flight = state.in_flight.saturating_add(1);
        Ok(MdnsOperationPermit {
            lifecycle: Arc::clone(self),
        })
    }

    /// Close ordinary command admission and elect exactly one terminal owner.
    fn begin_shutdown(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.accepting {
            return false;
        }
        state.accepting = false;
        if state.in_flight == 0 {
            self.idle.notify_waiters();
        }
        true
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.accepting = false;
        if state.in_flight == 0 {
            self.idle.notify_waiters();
        }
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

    fn complete_shutdown(&self, outcome: std::result::Result<(), String>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.shutdown_outcome.is_none() {
            state.shutdown_outcome = Some(outcome);
            drop(state);
            self.shutdown_changed.notify_waiters();
        }
    }

    async fn wait_shutdown(&self) -> Result<()> {
        loop {
            let changed = self.shutdown_changed.notified();
            if let Some(outcome) = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .shutdown_outcome
                .clone()
            {
                return outcome.map_err(MdnsError::Daemon);
            }
            changed.await;
        }
    }
}

struct MdnsOperationPermit {
    lifecycle: Arc<MdnsLifecycle>,
}

impl Drop for MdnsOperationPermit {
    fn drop(&mut self) {
        let mut state = self
            .lifecycle
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        if !state.accepting && state.in_flight == 0 {
            self.lifecycle.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
struct MdnsShutdownTestControl {
    pause_next: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    released: std::sync::atomic::AtomicBool,
    release: tokio::sync::Notify,
    panic_next: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl MdnsShutdownTestControl {
    fn new() -> Self {
        Self {
            pause_next: std::sync::atomic::AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            released: std::sync::atomic::AtomicBool::new(false),
            release: tokio::sync::Notify::new(),
            panic_next: std::sync::atomic::AtomicBool::new(false),
        }
    }

    async fn pause_if_armed(&self) {
        use std::sync::atomic::Ordering;

        if !self.pause_next.swap(false, Ordering::AcqRel) {
            return;
        }
        self.entered.notify_waiters();
        loop {
            let released = self.release.notified();
            if self.released.load(Ordering::Acquire) {
                return;
            }
            released.await;
        }
    }
}

/// Bounded discovery facts carried by the primary mDNS domain status. The full
/// resolved record set remains available through [`MdnsCore::discovery_snapshot`].
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct MdnsDiscoverySummary {
    pub revision: u64,
    pub service_type_count: usize,
    pub record_count: usize,
    /// Demanded browse routes whose provider observation is currently
    /// unavailable. Their last accepted records remain visible as stale truth
    /// until an explicit removal or browse-generation retirement.
    #[serde(default)]
    pub unavailable_browse_count: usize,
}

/// One authoritative mDNS domain status, combining provider orchestration,
/// registration intent, and bounded discovery facts.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
pub struct MdnsStatus {
    /// Monotonic process-local revision for any semantic mDNS state change.
    #[serde(default)]
    pub revision: u64,
    pub control_plane: MdnsControlPlaneStatus,
    pub registrations: RegistrationCounts,
    pub discovery: MdnsDiscoverySummary,
}

/// A transport connection's registration lifetime.
///
/// The mDNS domain owns this guard so every transport gets identical fail-safe
/// cleanup. Dropping it after EOF, cancellation, a parse failure, or a write
/// failure moves all session-scoped registrations into their grace period.
pub struct RegistrationSession {
    registry: Arc<RegistrationRegistry>,
    control_plane: Arc<MdnsControlPlane>,
    status: StatusFeed<MdnsStatus>,
    id: SessionId,
}

impl RegistrationSession {
    pub fn id(&self) -> &SessionId {
        &self.id
    }
}

impl Drop for RegistrationSession {
    fn drop(&mut self) {
        for id in self.registry.drain_session(&self.id) {
            tracing::info!(id, session = %self.id.as_str(), "Registration draining");
        }
        refresh_mdns_operational_status(&self.status, &self.registry, &self.control_plane);
    }
}

impl MdnsCore {
    /// Start with platform-independent native Koi mDNS only.
    pub async fn new() -> Result<Self> {
        Self::with_cancel(CancellationToken::new()).await
    }

    /// Start with native Koi mDNS and a shared shutdown token.
    pub async fn with_cancel(cancel: CancellationToken) -> Result<Self> {
        Self::with_adapters(Vec::new(), cancel).await
    }

    /// Start with the platform adapter catalog. Native Koi is appended by the
    /// control plane as the reserved, always-available fallback.
    pub async fn with_adapters(
        adapters: Vec<Arc<dyn MdnsAdapter>>,
        cancel: CancellationToken,
    ) -> Result<Self> {
        let registry = Arc::new(RegistrationRegistry::new());
        let control_plane = MdnsControlPlane::start(adapters, Arc::clone(&registry)).await?;
        let (event_tx, _) = koi_common::events::event_channel();
        let operation_lock = Arc::new(Mutex::new(()));
        let lifecycle = Arc::new(MdnsLifecycle::new());
        let status = StatusFeed::new(MdnsStatus {
            revision: 0,
            control_plane: control_plane.status().as_ref().clone(),
            registrations: registry.counts(),
            discovery: MdnsDiscoverySummary::default(),
        });
        let discovery = Arc::new(DiscoveryHub::new(
            Arc::clone(&control_plane),
            event_tx,
            status.clone(),
        ));

        let lifecycle_cancel = cancel.child_token();
        let reaper = spawn_reaper(
            Arc::clone(&registry),
            Arc::clone(&control_plane),
            status.clone(),
            Arc::clone(&operation_lock),
            lifecycle_cancel.clone(),
        );
        let status_observer = spawn_status_observer(
            Arc::clone(&registry),
            Arc::clone(&control_plane),
            status.clone(),
            lifecycle_cancel.clone(),
        );

        Ok(Self {
            discovery,
            control_plane,
            registry,
            operation_lock,
            status,
            started_at: Instant::now(),
            cancel: lifecycle_cancel,
            workers: Arc::new(Mutex::new(vec![reaper, status_observer])),
            lifecycle,
            shutdown_task: StdMutex::new(None),
        })
    }

    pub async fn subscribe_type(&self, service_type: &str) -> Result<BrowseSubscription> {
        let (key, is_meta) = canonical_key(service_type)?;
        let _operation = self.operation_lock.lock().await;
        let _admission = self.lifecycle.admit()?;
        Ok(self.discovery.clone().subscribe_type(&key, is_meta))
    }

    pub async fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult> {
        self.register_with_policy(payload, LeasePolicy::Permanent, None)
            .await
    }

    /// Register presence whose caller proves liveness with [`Self::heartbeat`].
    ///
    /// The optional `lease_secs` belongs to this command: `None` selects the
    /// domain default, zero is invalid, and a positive value is the exact lease.
    /// HTTP and mode-transparent embedded facades both enter through this
    /// boundary so they cannot drift on registration lifetime.
    pub async fn register_heartbeat(&self, payload: RegisterPayload) -> Result<RegistrationResult> {
        let policy = heartbeat_policy(payload.lease_secs)?;
        self.register_with_policy(payload, policy, None).await
    }

    /// Transactional registration entry point used by every transport.
    pub async fn register_with_policy(
        &self,
        mut payload: RegisterPayload,
        policy: LeasePolicy,
        session_id: Option<SessionId>,
    ) -> Result<RegistrationResult> {
        let service_type = ServiceType::parse(&payload.service_type)?;
        payload.service_type = service_type.as_str().to_string();
        let _operation = self.operation_lock.lock().await;
        let _admission = self.lifecycle.admit()?;
        let mut transaction = RegistrationTransaction::new(
            Arc::clone(&self.registry),
            self.registry.begin_registration(
                generate_short_id(),
                payload.clone(),
                policy.clone(),
                session_id,
            ),
        );
        let id = transaction.id().to_string();
        let announcement = self.registry.desired_announcement(&id)?;

        if let Err(error) = self.control_plane.publish(announcement).await {
            drop(transaction);
            self.control_plane.reconcile_status().await;
            self.refresh_status();
            return Err(error);
        }
        if let Err(error) = self.registry.confirm_publication(&id) {
            let _ = self.control_plane.withdraw(&id).await;
            drop(transaction);
            self.control_plane.reconcile_status().await;
            self.refresh_status();
            return Err(error);
        }
        transaction.commit();
        self.control_plane.reconcile_status().await;
        self.refresh_status();

        let (mode, lease_secs) = lease_projection(&policy);
        let result = RegistrationResult {
            id,
            name: payload.name,
            service_type: service_type.short().to_string(),
            port: payload.port,
            mode,
            lease_secs,
        };
        tracing::info!(
            name = %result.name,
            service_type = %result.service_type,
            port = result.port,
            id = %result.id,
            "Service publication established"
        );
        Ok(result)
    }

    pub async fn heartbeat(&self, id: &str) -> Result<u64> {
        let _operation = self.operation_lock.lock().await;
        let _admission = self.lifecycle.admit()?;
        let lease_secs = self.registry.heartbeat(id)?;
        self.refresh_status();
        Ok(lease_secs)
    }

    /// Open a transport-owned registration session. Its `Drop` implementation
    /// is the authoritative disconnect signal for session leases.
    pub fn open_registration_session(&self) -> RegistrationSession {
        RegistrationSession {
            registry: Arc::clone(&self.registry),
            control_plane: Arc::clone(&self.control_plane),
            status: self.status.clone(),
            id: SessionId::new(generate_short_id()),
        }
    }

    /// Withdraw one registration, acknowledging native resource release before
    /// removing the aggregate from the registry.
    pub async fn unregister(&self, id: &str) -> Result<()> {
        let _operation = self.operation_lock.lock().await;
        let _admission = self.lifecycle.admit()?;
        self.withdraw_locked(id, "explicit").await
    }

    async fn withdraw_locked(&self, id: &str, reason: &'static str) -> Result<()> {
        let transaction = WithdrawalTransaction::new(
            Arc::clone(&self.registry),
            self.registry.begin_withdrawal(id)?,
        );
        let name = transaction.name().to_string();
        if let Err(error) = self.control_plane.withdraw(id).await {
            drop(transaction);
            self.control_plane.reconcile_status().await;
            self.refresh_status();
            return Err(error);
        }
        transaction.commit();
        self.control_plane.reconcile_status().await;
        self.refresh_status();
        tracing::info!(%name, id, reason, "Service publication withdrawn");
        Ok(())
    }

    pub async fn resolve(&self, instance: &str) -> Result<ServiceRecord> {
        let _operation = self.operation_lock.lock().await;
        let _admission = self.lifecycle.admit()?;
        self.discovery.clone().resolve(instance).await
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MdnsEvent> {
        self.discovery.subscribe_all()
    }

    /// Close browses, withdraw every publication, and release every provider
    /// session. A successful return proves the resources are gone.
    pub async fn shutdown(&self) -> Result<()> {
        if self.lifecycle.begin_shutdown() {
            // Election, task spawn, and retention contain no await. Once
            // admission closes, requester cancellation cannot strand the
            // domain between its terminal decision and a native-release owner.
            self.cancel.cancel();
            let lifecycle = Arc::clone(&self.lifecycle);
            let cancel = self.cancel.clone();
            let operation_lock = Arc::clone(&self.operation_lock);
            let discovery = Arc::clone(&self.discovery);
            let control_plane = Arc::clone(&self.control_plane);
            let registry = Arc::clone(&self.registry);
            let status = self.status.clone();
            let workers = Arc::clone(&self.workers);
            let task = tokio::spawn(async move {
                let completion = MdnsShutdownCompletion::new(
                    Arc::clone(&lifecycle),
                    cancel,
                    Arc::clone(&discovery),
                    Arc::clone(&control_plane),
                    Arc::clone(&registry),
                    status.clone(),
                    Arc::clone(&workers),
                );
                let result = shutdown_mdns_owned(
                    &lifecycle,
                    &operation_lock,
                    &discovery,
                    &control_plane,
                    &registry,
                    &status,
                    &workers,
                )
                .await;
                if result.is_ok() {
                    tracing::info!("mDNS core shut down");
                }
                completion.settle(result);
            });
            let mut retained = self
                .shutdown_task
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            debug_assert!(retained.is_none());
            *retained = Some(task);
        }
        self.lifecycle.wait_shutdown().await
    }

    pub fn admin_status(&self) -> DaemonStatus {
        let status = self.status();
        DaemonStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            platform: std::env::consts::OS.to_string(),
            registrations: status.registrations.clone(),
            control_plane: status.control_plane.clone(),
        }
    }

    /// Current immutable mDNS domain status. This is an `Arc` clone and does
    /// not inspect providers, acquire an async lock, or perform I/O.
    pub fn status(&self) -> Arc<MdnsStatus> {
        self.status.current()
    }

    /// Subscribe to the latest domain status. Updates are coalesced;
    /// domain events remain the history-bearing semantic stream.
    pub fn watch_status(&self) -> watch::Receiver<Arc<MdnsStatus>> {
        self.status.subscribe()
    }

    /// Full domain-owned network discovery snapshot for integrations that need
    /// records rather than the bounded counts in [`MdnsStatus`].
    pub fn discovery_snapshot(&self) -> Arc<MdnsDiscoverySnapshot> {
        self.discovery.snapshot()
    }

    /// Capture the primary status and full discovery projection from one completed
    /// domain generation.
    ///
    /// Discovery publishes first and records its revision in the enclosing status.
    /// Retrying the very small publication window here keeps composition ignorant of
    /// that invariant and prevents it from retaining a torn pair.
    pub fn status_with_discovery(&self) -> (Arc<MdnsStatus>, Arc<MdnsDiscoverySnapshot>) {
        loop {
            let before = self.status();
            let discovery = self.discovery_snapshot();
            let after = self.status();
            if Arc::ptr_eq(&before, &after) && after.discovery.revision == discovery.revision {
                return (after, discovery);
            }
            std::hint::spin_loop();
        }
    }

    /// Observe the full discovery projection without replaying lossy events.
    pub fn watch_discovery(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>> {
        self.discovery.watch_snapshot()
    }

    pub fn admin_registrations(&self) -> Vec<(String, AdminRegistration)> {
        self.registry.snapshot()
    }

    pub fn admin_inspect(&self, id_or_prefix: &str) -> Result<AdminRegistration> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        self.registry.snapshot_one(&full_id)
    }

    pub async fn admin_force_unregister(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        let _operation = self.operation_lock.lock().await;
        let _admission = self.lifecycle.admit()?;
        self.withdraw_locked(&full_id, "admin_force").await
    }

    pub fn admin_drain(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        let _admission = self.lifecycle.admit()?;
        self.registry.force_drain(&full_id)?;
        self.refresh_status();
        Ok(())
    }

    pub fn admin_revive(&self, id_or_prefix: &str) -> Result<()> {
        let full_id = self.registry.resolve_prefix(id_or_prefix)?;
        let _admission = self.lifecycle.admit()?;
        self.registry.force_revive(&full_id)?;
        self.refresh_status();
        Ok(())
    }

    fn refresh_status(&self) {
        refresh_mdns_operational_status(&self.status, &self.registry, &self.control_plane);
    }

    #[cfg(test)]
    fn pause_next_shutdown(&self) {
        use std::sync::atomic::Ordering;

        self.lifecycle.test.released.store(false, Ordering::Release);
        self.lifecycle
            .test
            .pause_next
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn release_shutdown(&self) {
        use std::sync::atomic::Ordering;

        self.lifecycle.test.released.store(true, Ordering::Release);
        self.lifecycle.test.release.notify_waiters();
    }

    #[cfg(test)]
    fn panic_next_shutdown(&self) {
        self.lifecycle
            .test
            .panic_next
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

struct MdnsShutdownCompletion {
    lifecycle: Arc<MdnsLifecycle>,
    cancel: CancellationToken,
    discovery: Arc<DiscoveryHub>,
    control_plane: Arc<MdnsControlPlane>,
    registry: Arc<RegistrationRegistry>,
    status: StatusFeed<MdnsStatus>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    settled: bool,
}

impl MdnsShutdownCompletion {
    fn new(
        lifecycle: Arc<MdnsLifecycle>,
        cancel: CancellationToken,
        discovery: Arc<DiscoveryHub>,
        control_plane: Arc<MdnsControlPlane>,
        registry: Arc<RegistrationRegistry>,
        status: StatusFeed<MdnsStatus>,
        workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    ) -> Self {
        Self {
            lifecycle,
            cancel,
            discovery,
            control_plane,
            registry,
            status,
            workers,
            settled: false,
        }
    }

    fn settle(mut self, result: Result<()>) {
        let outcome = result.map_err(|error| format!("mDNS shutdown failed: {error}"));
        if outcome.is_err() {
            self.fail_close();
        }
        self.lifecycle.complete_shutdown(outcome);
        self.settled = true;
    }

    fn fail_close(&self) {
        self.cancel.cancel();
        self.discovery.fail_close();
        self.control_plane.fail_close();
        for id in self.registry.all_ids() {
            if let Ok(attempt) = self.registry.begin_withdrawal(&id) {
                self.registry.commit_withdrawal(attempt);
            }
        }
        refresh_mdns_operational_status(&self.status, &self.registry, &self.control_plane);
        abort_workers(&self.workers);
    }
}

impl Drop for MdnsShutdownCompletion {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        self.fail_close();
        self.lifecycle.complete_shutdown(Err(
            "mDNS terminal worker stopped unexpectedly; native resources were fail-closed"
                .to_string(),
        ));
    }
}

async fn shutdown_mdns_owned(
    lifecycle: &MdnsLifecycle,
    operation_lock: &Mutex<()>,
    discovery: &DiscoveryHub,
    control_plane: &MdnsControlPlane,
    registry: &Arc<RegistrationRegistry>,
    status: &StatusFeed<MdnsStatus>,
    workers: &Mutex<Vec<JoinHandle<()>>>,
) -> Result<()> {
    // Every operation admitted before terminal election either finishes first
    // or is cancelled by its own caller before this release transaction starts.
    lifecycle.wait_idle().await;
    #[cfg(test)]
    lifecycle.test.pause_if_armed().await;

    let result = async {
        let _operation = operation_lock.lock().await;
        #[cfg(test)]
        if lifecycle
            .test
            .panic_next
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            panic!("injected mDNS terminal-shutdown panic");
        }

        discovery.shutdown_browses().await;
        for id in registry.all_ids() {
            if let Err(error) = withdraw_for_shutdown(
                registry,
                control_plane,
                status,
                &id,
            )
            .await
            {
                tracing::warn!(%id, %error, "Individual shutdown withdrawal deferred to provider-session shutdown");
            }
        }

        let result = control_plane.shutdown().await;
        if result.is_ok() {
            // Provider-session shutdown is authoritative release proof. Clear
            // any aggregate whose individual withdrawal failed before that
            // provider epoch closed.
            for id in registry.all_ids() {
                if let Ok(attempt) = registry.begin_withdrawal(&id) {
                    registry.commit_withdrawal(attempt);
                }
            }
        }
        refresh_mdns_operational_status(status, registry, control_plane);
        result
    }
    .await;

    // Worker ownership is part of the terminal transaction, not its caller's
    // acknowledgement future. This tail runs on both success and provider
    // failure; an unexpected panic is handled by `MdnsShutdownCompletion`.
    join_workers(workers).await;
    result
}

async fn withdraw_for_shutdown(
    registry: &Arc<RegistrationRegistry>,
    control_plane: &MdnsControlPlane,
    status: &StatusFeed<MdnsStatus>,
    id: &str,
) -> Result<()> {
    let transaction =
        WithdrawalTransaction::new(Arc::clone(registry), registry.begin_withdrawal(id)?);
    let name = transaction.name().to_string();
    if let Err(error) = control_plane.withdraw(id).await {
        drop(transaction);
        control_plane.reconcile_status().await;
        refresh_mdns_operational_status(status, registry, control_plane);
        return Err(error);
    }
    transaction.commit();
    control_plane.reconcile_status().await;
    refresh_mdns_operational_status(status, registry, control_plane);
    tracing::info!(%name, id, reason = "shutdown", "Service publication withdrawn");
    Ok(())
}

async fn join_workers(workers: &Mutex<Vec<JoinHandle<()>>>) {
    let deadline = tokio::time::Instant::now() + WORKER_SHUTDOWN_TIMEOUT;
    let mut workers = workers.lock().await;
    for worker in workers.iter_mut() {
        if tokio::time::timeout_at(deadline, &mut *worker)
            .await
            .is_err()
        {
            worker.abort();
            let _ = worker.await;
        }
    }
    workers.clear();
}

fn abort_workers(workers: &Mutex<Vec<JoinHandle<()>>>) {
    if let Ok(mut workers) = workers.try_lock() {
        for worker in workers.drain(..) {
            worker.abort();
        }
    }
}

fn refresh_mdns_operational_status(
    status: &StatusFeed<MdnsStatus>,
    registry: &RegistrationRegistry,
    control_plane: &MdnsControlPlane,
) {
    // Capture the operational facets before entering the primary status gate.
    // Discovery owns its facet and publishes it independently; rebuilding it
    // here would both overwrite a racing discovery generation and invert the
    // `types -> status` lock order used by the discovery transition.
    let registrations = registry.counts();
    let control_plane = control_plane.status().as_ref().clone();
    status.update(move |current| {
        if current.registrations == registrations && current.control_plane == control_plane {
            return None;
        }
        let mut next = current.clone();
        next.revision = current.revision.saturating_add(1);
        next.registrations = registrations;
        next.control_plane = control_plane;
        Some(next)
    });
}

fn spawn_status_observer(
    registry: Arc<RegistrationRegistry>,
    control_plane: Arc<MdnsControlPlane>,
    status: StatusFeed<MdnsStatus>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    // Subscribe before reconciling so a transition racing observer startup is
    // either captured by this read or remains pending on a receiver.
    let mut control_status = control_plane.watch_status();
    refresh_mdns_operational_status(&status, &registry, &control_plane);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = control_status.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
            refresh_mdns_operational_status(&status, &registry, &control_plane);
        }
    })
}

fn spawn_reaper(
    registry: Arc<RegistrationRegistry>,
    control_plane: Arc<MdnsControlPlane>,
    status: StatusFeed<MdnsStatus>,
    operation_lock: Arc<Mutex<()>>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REAPER_INTERVAL);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _operation = operation_lock.lock().await;
                    let attempts = match registry.begin_reap() {
                        Ok(attempts) => attempts,
                        Err(error) => {
                            tracing::warn!(%error, "Registration reaper could not build withdrawal intent");
                            continue;
                        }
                    };
                    // `begin_reap` can move a heartbeat lease from alive to
                    // draining before it becomes eligible for withdrawal. That
                    // accepted timer transition is domain truth in its own
                    // right, even when this pass has no provider work to do.
                    refresh_mdns_operational_status(&status, &registry, &control_plane);
                    for attempt in attempts {
                        reap_one(
                            &registry,
                            &control_plane,
                            &status,
                            attempt,
                        )
                        .await;
                    }
                }
                _ = cancel.cancelled() => break,
            }
        }
        tracing::debug!("mDNS registration reaper stopped");
    })
}

impl Drop for MdnsCore {
    fn drop(&mut self) {
        self.lifecycle.close();
        self.cancel.cancel();
        if let Some(task) = self
            .shutdown_task
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            task.abort();
        }
        self.discovery.fail_close();
        self.control_plane.fail_close();
        abort_workers(&self.workers);
    }
}

async fn reap_one(
    registry: &Arc<RegistrationRegistry>,
    control_plane: &MdnsControlPlane,
    status: &StatusFeed<MdnsStatus>,
    attempt: WithdrawalAttempt,
) {
    let transaction = WithdrawalTransaction::new(Arc::clone(registry), attempt);
    let id = transaction.id().to_string();
    let name = transaction.name().to_string();
    match control_plane.withdraw(&id).await {
        Ok(()) => {
            transaction.commit();
            control_plane.reconcile_status().await;
            refresh_mdns_operational_status(status, registry, control_plane);
            tracing::info!(%name, %id, reason = "expired", "Service publication withdrawn");
        }
        Err(error) => {
            drop(transaction);
            control_plane.reconcile_status().await;
            refresh_mdns_operational_status(status, registry, control_plane);
            tracing::warn!(%name, %id, %error, "Expired publication withdrawal will retry");
        }
    }
}

/// Cancellation-safe registry mutation. Until `commit`, dropping the future
/// restores the exact aggregate that preceded publication.
struct RegistrationTransaction {
    registry: Arc<RegistrationRegistry>,
    attempt: Option<RegistrationAttempt>,
    id: String,
}

impl RegistrationTransaction {
    fn new(registry: Arc<RegistrationRegistry>, attempt: RegistrationAttempt) -> Self {
        let id = attempt.outcome.id().to_string();
        Self {
            registry,
            attempt: Some(attempt),
            id,
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn commit(&mut self) {
        self.attempt.take();
    }
}

impl Drop for RegistrationTransaction {
    fn drop(&mut self) {
        if let Some(attempt) = self.attempt.take() {
            self.registry.rollback_registration(attempt);
        }
    }
}

/// Cancellation-safe withdrawal intent. A dropped operation becomes desired
/// again and control-plane reconciliation restores any already-released lease.
struct WithdrawalTransaction {
    registry: Arc<RegistrationRegistry>,
    attempt: Option<WithdrawalAttempt>,
    id: String,
    name: String,
}

impl WithdrawalTransaction {
    fn new(registry: Arc<RegistrationRegistry>, attempt: WithdrawalAttempt) -> Self {
        let id = attempt.id.clone();
        let name = attempt.announcement.name.clone();
        Self {
            registry,
            attempt: Some(attempt),
            id,
            name,
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn commit(mut self) {
        if let Some(attempt) = self.attempt.take() {
            self.registry.commit_withdrawal(attempt);
        }
    }
}

impl Drop for WithdrawalTransaction {
    fn drop(&mut self) {
        if let Some(attempt) = self.attempt.take() {
            self.registry.rollback_withdrawal(attempt);
        }
    }
}

fn lease_projection(policy: &LeasePolicy) -> (LeaseMode, Option<u64>) {
    match policy {
        LeasePolicy::Session { .. } => (LeaseMode::Session, None),
        LeasePolicy::Heartbeat { lease, .. } => (LeaseMode::Heartbeat, Some(lease.as_secs())),
        LeasePolicy::Permanent => (LeaseMode::Permanent, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::mdns_protocol::ControlPlaneState;
    use std::collections::HashMap;

    fn terminal_test_payload() -> RegisterPayload {
        RegisterPayload {
            name: "Terminal test".to_string(),
            service_type: "_koi-terminal._tcp.local.".to_string(),
            port: 4242,
            ip: None,
            lease_secs: None,
            txt: HashMap::new(),
        }
    }

    fn seed_terminal_registration(core: &MdnsCore, id: &str) {
        let attempt = core.registry.begin_registration(
            id.to_string(),
            terminal_test_payload(),
            LeasePolicy::Permanent,
            None,
        );
        core.registry
            .confirm_publication(attempt.outcome.id())
            .expect("confirm test registration");
        core.refresh_status();
    }

    #[test]
    fn mdns_status_wire_round_trips_and_ignores_additive_fields() {
        let expected = MdnsStatus {
            revision: 11,
            control_plane: MdnsControlPlaneStatus::default(),
            registrations: RegistrationCounts {
                alive: 2,
                draining: 1,
                permanent: 1,
                total: 3,
            },
            discovery: MdnsDiscoverySummary {
                revision: 7,
                service_type_count: 2,
                record_count: 4,
                unavailable_browse_count: 1,
            },
        };

        let encoded = serde_json::to_string(&expected).expect("serialize mDNS status");
        assert_eq!(
            serde_json::from_str::<MdnsStatus>(&encoded).expect("round-trip mDNS status"),
            expected
        );

        let mut additive = serde_json::to_value(&expected).expect("encode mDNS status value");
        additive
            .as_object_mut()
            .expect("mDNS status is an object")
            .insert(
                "future_domain_fact".to_string(),
                serde_json::json!({"available": true}),
            );
        assert_eq!(
            serde_json::from_value::<MdnsStatus>(additive)
                .expect("ignore an additive mDNS status field"),
            expected
        );
    }

    #[tokio::test]
    async fn enclosing_status_revisions_only_for_semantic_changes() {
        let core = MdnsCore::new().await.expect("start mDNS core");
        core.shutdown().await.expect("stop mDNS workers");
        let mut changes = core.watch_status();
        let initial = core.status();
        changes.borrow_and_update();

        core.refresh_status();
        assert!(
            Arc::ptr_eq(&initial, &core.status()),
            "a semantic no-op must retain the exact enclosing status snapshot"
        );
        assert!(
            !changes.has_changed().expect("status sender remains open"),
            "a semantic no-op must not wake enclosing-status consumers"
        );

        seed_terminal_registration(&core, "status-revision");
        changes
            .changed()
            .await
            .expect("the semantic status change is published");
        let revised = core.status();
        assert_eq!(revised.registrations.total, 1);
        assert!(revised.revision > initial.revision);
        changes.borrow_and_update();

        core.refresh_status();
        assert!(
            Arc::ptr_eq(&revised, &core.status()),
            "repeating the accepted projection must retain its Arc and revision"
        );
        assert!(
            !changes.has_changed().expect("status sender remains open"),
            "repeating the accepted projection must not emit another update"
        );
    }

    #[tokio::test]
    async fn operational_refresh_preserves_the_discovery_owned_facet() {
        let registry = RegistrationRegistry::new();
        let attempt = registry.begin_registration(
            "facet-local-refresh".to_string(),
            terminal_test_payload(),
            LeasePolicy::Permanent,
            None,
        );
        registry
            .confirm_publication(attempt.outcome.id())
            .expect("confirm test registration");
        let control_plane =
            MdnsControlPlane::start(Vec::new(), Arc::new(RegistrationRegistry::new()))
                .await
                .expect("native control plane");
        let discovery = MdnsDiscoverySummary {
            revision: 17,
            service_type_count: 3,
            record_count: 8,
            unavailable_browse_count: 2,
        };
        let status = StatusFeed::new(MdnsStatus {
            revision: 4,
            control_plane: MdnsControlPlaneStatus::default(),
            registrations: RegistrationCounts::default(),
            discovery: discovery.clone(),
        });

        refresh_mdns_operational_status(&status, &registry, &control_plane);

        let current = status.current();
        assert_eq!(current.revision, 5);
        assert_eq!(current.registrations.total, 1);
        assert_eq!(current.discovery, discovery);
        control_plane
            .shutdown()
            .await
            .expect("control-plane shutdown");
    }

    #[test]
    fn free_port_reports_free_and_held_port_reports_taken() {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).expect("bind");
        let port = socket.local_addr().expect("local address").port();
        assert!(!udp_port_exclusively_free(port));
        drop(socket);
        assert!(udp_port_exclusively_free(port));
    }

    #[test]
    fn draining_registration_session_moves_its_leases() {
        let registry = Arc::new(RegistrationRegistry::new());
        let session_id = SessionId::new("transport-session".to_string());
        let attempt = registry.begin_registration(
            "registration".to_string(),
            RegisterPayload {
                name: "Session service".to_string(),
                service_type: "_http._tcp".to_string(),
                port: 8080,
                ip: None,
                lease_secs: None,
                txt: HashMap::new(),
            },
            LeasePolicy::Session {
                grace: Duration::from_secs(30),
            },
            Some(session_id.clone()),
        );
        registry.confirm_publication(attempt.outcome.id()).unwrap();
        assert_eq!(registry.counts().alive, 1);

        assert_eq!(registry.drain_session(&session_id), vec!["registration"]);

        assert_eq!(registry.counts().alive, 0);
        assert_eq!(registry.counts().draining, 1);
    }

    #[tokio::test]
    async fn lifecycle_commands_fence_the_enclosing_domain_status() {
        let cancel = CancellationToken::new();
        let core = MdnsCore::with_cancel(cancel.clone())
            .await
            .expect("start mDNS core");

        // Construction returns only after the provider decision is reflected
        // in the primary domain status. Native can legitimately be degraded on
        // a constrained host, but an acknowledged initial probe is never the
        // placeholder Stopped/Reconciling state.
        let started = core.status();
        assert!(matches!(
            started.control_plane.state,
            ControlPlaneState::Ready | ControlPlaneState::Degraded
        ));
        assert_eq!(
            started.control_plane,
            core.control_plane.status().as_ref().clone()
        );

        core.shutdown().await.expect("shutdown mDNS core");

        // No polling: the public command fences both the provider-owned status
        // and MdnsCore's enclosing projection before it returns.
        let stopped = core.status();
        assert_eq!(stopped.control_plane.state, ControlPlaneState::Stopped);
        assert_eq!(stopped.registrations.total, 0);
        assert_eq!(
            stopped.control_plane,
            core.control_plane.status().as_ref().clone()
        );
        assert!(stopped.revision > started.revision);
        assert!(
            core.workers.lock().await.is_empty(),
            "successful shutdown must reap the observer and lease reaper"
        );

        cancel.cancel();
    }

    #[tokio::test]
    async fn cancelled_terminal_requesters_need_no_retry_to_converge() {
        let core = Arc::new(MdnsCore::new().await.expect("start mDNS core"));
        seed_terminal_registration(&core, "terminal-registration");
        let _browse = core
            .subscribe_type("_koi-terminal._tcp")
            .await
            .expect("start domain-owned browse");

        core.pause_next_shutdown();
        let entered = core.lifecycle.test.entered.notified();
        let first = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.shutdown().await })
        };
        tokio::time::timeout(Duration::from_secs(2), entered)
            .await
            .expect("terminal owner should reach the deterministic gate");

        // A concurrent caller attaches to the same completion. Removing every
        // requester proves that neither one owns the actual release tail.
        let second = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.shutdown().await })
        };
        tokio::task::yield_now().await;
        first.abort();
        second.abort();
        assert!(first
            .await
            .expect_err("first requester was cancelled")
            .is_cancelled());
        assert!(second
            .await
            .expect_err("second requester was cancelled")
            .is_cancelled());

        assert!(matches!(
            core.subscribe_type("_late._tcp").await,
            Err(MdnsError::Daemon(_))
        ));

        core.release_shutdown();
        tokio::time::timeout(Duration::from_secs(10), core.lifecycle.wait_shutdown())
            .await
            .expect("retained terminal owner should finish without a requester")
            .expect("terminal release should succeed");

        let stopped = core.status();
        assert_eq!(stopped.control_plane.state, ControlPlaneState::Stopped);
        assert_eq!(stopped.registrations.total, 0);
        assert!(core.discovery_snapshot().service_types.is_empty());
        assert!(core.discovery_snapshot().records.is_empty());
        assert!(
            core.workers.lock().await.is_empty(),
            "observer and lease-reaper handles must be reaped"
        );
    }

    #[tokio::test]
    async fn concurrent_shutdown_callers_share_one_terminal_result() {
        let core = Arc::new(MdnsCore::new().await.expect("start mDNS core"));
        core.pause_next_shutdown();
        let entered = core.lifecycle.test.entered.notified();
        let first = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.shutdown().await })
        };
        tokio::time::timeout(Duration::from_secs(2), entered)
            .await
            .expect("terminal owner should reach the deterministic gate");
        let second = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.shutdown().await })
        };

        core.release_shutdown();
        tokio::time::timeout(Duration::from_secs(10), first)
            .await
            .expect("first shared waiter should settle")
            .expect("first waiter task should not panic")
            .expect("first waiter should observe success");
        tokio::time::timeout(Duration::from_secs(10), second)
            .await
            .expect("second shared waiter should settle")
            .expect("second waiter task should not panic")
            .expect("second waiter should observe the same success");
    }

    #[tokio::test]
    async fn panicked_terminal_owner_settles_every_waiter_and_fail_closes() {
        let core = Arc::new(MdnsCore::new().await.expect("start mDNS core"));
        let _browse = core
            .subscribe_type("_koi-terminal._tcp")
            .await
            .expect("start domain-owned browse");
        core.panic_next_shutdown();

        let first = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.shutdown().await })
        };
        let second = {
            let core = Arc::clone(&core);
            tokio::spawn(async move { core.shutdown().await })
        };

        let first = tokio::time::timeout(Duration::from_secs(5), first)
            .await
            .expect("first waiter must not be stranded")
            .expect("the acknowledgement waiter itself should not panic")
            .expect_err("terminal panic must be observable");
        let second = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .expect("second waiter must not be stranded")
            .expect("the acknowledgement waiter itself should not panic")
            .expect_err("shared terminal panic must be observable");
        assert_eq!(first.to_string(), second.to_string());
        assert!(first.to_string().contains("stopped unexpectedly"));
        assert!(core.workers.lock().await.is_empty());
        assert!(core.discovery_snapshot().service_types.is_empty());
        assert!(core.discovery_snapshot().records.is_empty());
        let status = core.status();
        assert_eq!(status.control_plane.state, ControlPlaneState::Stopped);
        assert_eq!(status.registrations.total, 0);
        assert_eq!(status.discovery, MdnsDiscoverySummary::default());
    }
}
