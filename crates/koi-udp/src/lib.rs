//! UDP datagram bridging over HTTP/SSE.
//!
//! Containers cannot bind host UDP sockets directly. This crate exposes a
//! lease-based HTTP API that lets a containerised process:
//!
//! 1. **Bind** a host UDP port (creating a `UdpBinding`).
//! 2. **Receive** datagrams via an SSE stream (`GET /v1/udp/recv/{id}`).
//! 3. **Send** datagrams through the bound socket (`POST /v1/udp/send/{id}`).
//! 4. **Heartbeat** to extend the lease (`POST /v1/udp/heartbeat/{id}`).
//!
//! Bindings expire after `lease_secs` without a heartbeat, at which point the
//! reaper closes the socket. This prevents resource leaks if a container dies.
//!
//! Follows the same Core/Runtime pattern as `koi-health` and `koi-dns`.

mod binding;
pub mod http;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, oneshot, watch, Mutex, Notify, RwLock};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use koi_common::status::StatusFeed;

use binding::ActiveBinding;

// ── Public types ────────────────────────────────────────────────────

/// A datagram received on a bound socket, ready to be relayed over SSE.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct UdpDatagram {
    pub binding_id: String,
    pub src: String,
    /// Base64-encoded payload.
    pub payload: String,
    pub received_at: DateTime<Utc>,
}

/// Request to send a datagram through a bound socket.
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
pub struct UdpSendRequest {
    /// Destination address in `host:port` form.
    pub dest: String,
    /// Base64-encoded payload.
    pub payload: String,
}

/// Request body for creating a new binding.
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
pub struct UdpBindRequest {
    /// Port to bind on the host (0 = OS-assigned).
    #[serde(default)]
    pub port: u16,
    /// Bind address. Default `127.0.0.1` (loopback); a non-loopback bind requires
    /// `allow_remote = true`.
    #[serde(default = "default_bind_addr")]
    pub addr: String,
    /// Lease duration in seconds. Default 300.
    #[serde(default = "default_lease")]
    pub lease_secs: u64,
    /// Allow binding on / sending to non-loopback addresses. Default `false` keeps
    /// the binding loopback-only so a daemon-token holder cannot turn it into a
    /// LAN/internet egress relay (the host's source address would launder the
    /// traffic — SSRF) or expose an ingest socket to the whole LAN. Opt in only
    /// for genuine cross-host datagram bridging.
    #[serde(default)]
    pub allow_remote: bool,
}

fn default_bind_addr() -> String {
    "127.0.0.1".to_string()
}

/// Validate a datagram destination before egress. Always rejects the unspecified
/// address, multicast, and the IPv4 broadcast address; rejects any non-loopback
/// destination unless the binding opted into `allow_remote`. This stops a token
/// holder from using a binding as an SSRF/egress relay with the host's identity.
fn validate_dest(dest: SocketAddr, allow_remote: bool) -> Result<(), UdpError> {
    let ip = dest.ip();
    let disallowed = ip.is_unspecified()
        || ip.is_multicast()
        || matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast());
    if disallowed {
        return Err(UdpError::InvalidAddr(format!(
            "disallowed UDP destination {dest}"
        )));
    }
    if !allow_remote && !ip.is_loopback() {
        return Err(UdpError::InvalidAddr(format!(
            "non-loopback destination {dest} requires allow_remote=true on the binding"
        )));
    }
    Ok(())
}

fn default_lease() -> u64 {
    300
}

/// Maximum lease duration (24 hours) to prevent unbounded resource retention.
const MAX_LEASE_SECS: u64 = 86400;

/// Metadata for a live binding (returned by status endpoint).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct BindingInfo {
    pub id: String,
    pub local_addr: String,
    pub created_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
    pub lease_secs: u64,
    /// Whether this binding may send to / listen on non-loopback addresses.
    pub allow_remote: bool,
}

/// Authoritative latest-value snapshot for UDP binding ownership.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct UdpRuntimeStatus {
    /// Monotonic semantic status revision.
    #[serde(default)]
    pub revision: u64,
    /// Whether this runtime still accepts and owns live work.
    #[serde(default = "default_running")]
    pub running: bool,
    /// Active bindings, sorted by binding ID.
    pub bindings: Vec<BindingInfo>,
}

/// Why a live UDP binding left the authoritative runtime model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpUnbindReason {
    Requested,
    LeaseExpired,
    Shutdown,
}

/// Best-effort semantic UDP lifecycle facts. Current binding truth always
/// comes from [`UdpRuntime::status`]; lagged receivers reread that snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpEvent {
    Bound(BindingInfo),
    Renewed {
        id: String,
        last_heartbeat: DateTime<Utc>,
    },
    Unbound {
        id: String,
        reason: UdpUnbindReason,
    },
    Stopped,
}

fn default_running() -> bool {
    true
}

impl Default for UdpRuntimeStatus {
    fn default() -> Self {
        Self {
            revision: 0,
            running: true,
            bindings: Vec::new(),
        }
    }
}

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum UdpError {
    #[error("UDP runtime is shutting down")]
    ShuttingDown,
    #[error("UDP command worker stopped unexpectedly: {0}")]
    Worker(String),
    #[error("binding not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid address: {0}")]
    InvalidAddr(String),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

// ── UdpRuntime ──────────────────────────────────────────────────────

struct OperationState {
    accepting: bool,
    in_flight: usize,
}

/// Admission barrier for resource-owning commands. It uses only a short
/// synchronous critical section; command I/O never holds an async lock.
struct OperationGate {
    state: StdMutex<OperationState>,
    idle: Notify,
}

impl OperationGate {
    fn new(accepting: bool) -> Self {
        Self {
            state: StdMutex::new(OperationState {
                accepting,
                in_flight: 0,
            }),
            idle: Notify::new(),
        }
    }

    fn enter(self: &Arc<Self>) -> Result<OperationPermit, UdpError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.accepting {
            return Err(UdpError::ShuttingDown);
        }
        state.in_flight = state.in_flight.saturating_add(1);
        Ok(OperationPermit {
            gate: Arc::clone(self),
        })
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.accepting = false;
        if state.in_flight == 0 {
            self.idle.notify_one();
        }
    }

    async fn wait_idle(&self) {
        loop {
            // Register first so a final permit cannot notify between the check
            // and this task becoming a waiter.
            let notified = self.idle.notified();
            let idle = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .in_flight
                == 0;
            if idle {
                return;
            }
            notified.await;
        }
    }
}

struct OperationPermit {
    gate: Arc<OperationGate>,
}

impl Drop for OperationPermit {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        if !state.accepting && state.in_flight == 0 {
            self.gate.idle.notify_one();
        }
    }
}

const MAX_IN_FLIGHT_COMMANDS: usize = 32;

/// Retains admitted native-resource commands independently of their callers.
/// A requester cancellation can discard only its acknowledgement; once socket
/// retirement starts, the domain finishes release, status, and event publication.
struct UdpCommandTasks {
    tasks: StdMutex<Vec<tokio::task::JoinHandle<()>>>,
    permits: Arc<tokio::sync::Semaphore>,
    accepting: AtomicBool,
}

impl UdpCommandTasks {
    fn new() -> Self {
        Self {
            tasks: StdMutex::new(Vec::new()),
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT_COMMANDS)),
            accepting: AtomicBool::new(true),
        }
    }

    async fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, UdpError> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| UdpError::ShuttingDown)?;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(UdpError::ShuttingDown);
        }
        Ok(permit)
    }

    fn close(&self) {
        self.accepting.store(false, Ordering::Release);
        self.permits.close();
    }

    fn retain(&self, task: tokio::task::JoinHandle<()>) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
    }
}

impl Drop for UdpCommandTasks {
    fn drop(&mut self) {
        for task in self
            .tasks
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

/// Manages UDP socket bindings, datagram relay, and lease reaping.
pub struct UdpRuntime {
    bindings: Arc<RwLock<HashMap<String, ActiveBinding>>>,
    status: StatusFeed<UdpRuntimeStatus>,
    event_tx: broadcast::Sender<UdpEvent>,
    /// Serializes the tiny status-then-event publication boundary. Native socket
    /// work stays outside this gate.
    transition: Arc<StdMutex<()>>,
    cancel: CancellationToken,
    operations: Arc<OperationGate>,
    commands: Arc<UdpCommandTasks>,
    reaper_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    panic_next_unbind: Arc<AtomicBool>,
}

impl UdpRuntime {
    /// Create a new runtime. Spawns a lease reaper task.
    pub fn new(cancel: CancellationToken) -> Self {
        let bindings: Arc<RwLock<HashMap<String, ActiveBinding>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let reaper_bindings = bindings.clone();
        let status = StatusFeed::new(UdpRuntimeStatus {
            running: !cancel.is_cancelled(),
            ..UdpRuntimeStatus::default()
        });
        let reaper_status = status.clone();
        let event_tx = koi_common::events::event_channel().0;
        let reaper_events = event_tx.clone();
        let transition = Arc::new(StdMutex::new(()));
        let reaper_transition = Arc::clone(&transition);
        let reaper_cancel = cancel.clone();
        let operations = Arc::new(OperationGate::new(!cancel.is_cancelled()));
        let reaper_operations = Arc::clone(&operations);
        let commands = Arc::new(UdpCommandTasks::new());
        let reaper_commands = Arc::clone(&commands);
        let reaper_handle = tokio::spawn(async move {
            Self::reaper_loop(
                reaper_bindings,
                reaper_status,
                reaper_events,
                reaper_transition,
                reaper_cancel,
                reaper_operations,
                reaper_commands,
            )
            .await;
        });

        Self {
            bindings,
            status,
            event_tx,
            transition,
            cancel,
            operations,
            commands,
            reaper_handle: Mutex::new(Some(reaper_handle)),
            #[cfg(test)]
            panic_next_unbind: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a new UDP binding. Binds a socket and starts a relay task.
    pub async fn bind(&self, req: UdpBindRequest) -> Result<BindingInfo, UdpError> {
        let _operation = self.begin_operation()?;
        let bind_addr: SocketAddr = format!("{}:{}", req.addr, req.port)
            .parse()
            .map_err(|e| UdpError::InvalidAddr(format!("{}", e)))?;

        // Secure-by-default: a non-loopback bind exposes an ingest socket to the
        // whole LAN, so it requires an explicit allow_remote opt-in.
        if !req.allow_remote && !bind_addr.ip().is_loopback() {
            return Err(UdpError::InvalidAddr(format!(
                "non-loopback bind {bind_addr} requires allow_remote=true"
            )));
        }

        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let id = Uuid::now_v7().to_string();
        let now = Utc::now();

        let lease_secs = req.lease_secs.min(MAX_LEASE_SECS);

        let mut active = ActiveBinding::new(
            id.clone(),
            socket,
            now,
            lease_secs,
            req.allow_remote,
            self.cancel.clone(),
        );

        let info = BindingInfo {
            id: id.clone(),
            local_addr: local_addr.to_string(),
            created_at: now,
            last_heartbeat: now,
            lease_secs,
            allow_remote: req.allow_remote,
        };

        let mut bindings = self.bindings.write().await;
        if let Err(error) = self.ensure_running() {
            drop(bindings);
            active.close().await;
            return Err(error);
        }
        bindings.insert(id, active);
        drop(bindings);

        {
            let _transition = self
                .transition
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.accept_bound(info.clone());
            self.emit(UdpEvent::Bound(info.clone()));
        }

        tracing::info!(binding = %info.id, addr = %info.local_addr, "UDP binding created");
        Ok(info)
    }

    /// Remove a binding and close its socket.
    pub async fn unbind(&self, id: &str) -> Result<(), UdpError> {
        // Shutdown closes admission to wake queued requesters. Once both
        // permits are held, an owned task carries native close through the
        // status/event causal tail even if this requester disappears.
        let command_permit = self.commands.admit().await?;
        let operation = self.begin_operation()?;
        let removed_id = id.to_string();
        let bindings = Arc::clone(&self.bindings);
        let status = self.status.clone();
        let event_tx = self.event_tx.clone();
        let transition = Arc::clone(&self.transition);
        #[cfg(test)]
        let panic_next_unbind = Arc::clone(&self.panic_next_unbind);
        let (reply, response) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _command_permit = command_permit;
            let _operation = operation;
            #[cfg(test)]
            if panic_next_unbind.swap(false, Ordering::AcqRel) {
                panic!("injected UDP unbind panic");
            }
            let result =
                Self::unbind_owned(bindings, status, event_tx, transition, removed_id).await;
            let _ = reply.send(result);
        });
        self.commands.retain(task);
        response
            .await
            .map_err(|_| UdpError::Worker("unbind ended before acknowledgement".into()))?
    }

    #[cfg(test)]
    fn panic_next_unbind(&self) {
        self.panic_next_unbind.store(true, Ordering::Release);
    }

    async fn unbind_owned(
        bindings: Arc<RwLock<HashMap<String, ActiveBinding>>>,
        status: StatusFeed<UdpRuntimeStatus>,
        event_tx: broadcast::Sender<UdpEvent>,
        transition: Arc<StdMutex<()>>,
        id: String,
    ) -> Result<(), UdpError> {
        let mut bindings = bindings.write().await;
        let binding = bindings
            .get_mut(&id)
            .ok_or_else(|| UdpError::NotFound(id.clone()))?;

        // Native close is the irreversible admission point. The binding stays
        // in the authoritative owner map until its relay/socket has joined.
        binding.close().await;
        if bindings.remove(&id).is_none() {
            // The write guard spans close, so this is defensive corruption
            // handling rather than a reachable concurrent-removal path.
            return Err(UdpError::NotFound(id));
        }
        drop(bindings);

        {
            let _transition = transition
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Self::accept_unbound_to(&status, std::slice::from_ref(&id), true);
            let _ = event_tx.send(UdpEvent::Unbound {
                id: id.clone(),
                reason: UdpUnbindReason::Requested,
            });
        }
        tracing::info!(binding = %id, "UDP binding removed");
        Ok(())
    }

    /// Subscribe to incoming datagrams for a binding.
    pub async fn subscribe_datagrams(
        &self,
        id: &str,
    ) -> Result<broadcast::Receiver<UdpDatagram>, UdpError> {
        let _operation = self.begin_operation()?;
        let bindings = self.bindings.read().await;
        let binding = bindings
            .get(id)
            .ok_or_else(|| UdpError::NotFound(id.to_string()))?;
        Ok(binding.subscribe())
    }

    /// Send a datagram through a binding's socket.
    pub async fn send(&self, id: &str, req: UdpSendRequest) -> Result<usize, UdpError> {
        use base64::Engine;

        let _operation = self.begin_operation()?;
        let dest: SocketAddr = req
            .dest
            .parse()
            .map_err(|e| UdpError::InvalidAddr(format!("{}", e)))?;

        let payload = base64::engine::general_purpose::STANDARD.decode(&req.payload)?;

        let sender = {
            let bindings = self.bindings.read().await;
            let binding = bindings
                .get(id)
                .ok_or_else(|| UdpError::NotFound(id.to_string()))?;
            validate_dest(dest, binding.allow_remote())?;
            binding.sender()
        };

        let sent = sender.send_to(payload, dest).await?;
        Ok(sent)
    }

    /// Extend a binding's lease.
    pub async fn heartbeat(&self, id: &str) -> Result<(), UdpError> {
        let _operation = self.begin_operation()?;
        let bindings = self.bindings.read().await;
        let binding = bindings
            .get(id)
            .ok_or_else(|| UdpError::NotFound(id.to_string()))?;
        // Keep the lease mutation, status acceptance, and semantic event in one
        // causal section. This also orders a heartbeat that already borrowed the
        // binding ahead of a concurrent unbind waiting for the map's write lock.
        let _transition = self
            .transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last_heartbeat = binding.touch();
        drop(bindings);
        self.accept_renewed(id, last_heartbeat);
        self.emit(UdpEvent::Renewed {
            id: id.to_string(),
            last_heartbeat,
        });
        Ok(())
    }

    fn ensure_running(&self) -> Result<(), UdpError> {
        if self.cancel.is_cancelled() {
            Err(UdpError::ShuttingDown)
        } else {
            Ok(())
        }
    }

    fn begin_operation(&self) -> Result<OperationPermit, UdpError> {
        self.ensure_running()?;
        let permit = self.operations.enter()?;
        // Close the narrow race where parent cancellation lands between the
        // token check and admission. Once this second check passes, shutdown's
        // gate waits for the operation to release every resource it may own.
        self.ensure_running()?;
        Ok(permit)
    }

    /// Return the current immutable runtime snapshot in constant time.
    pub fn status(&self) -> Arc<UdpRuntimeStatus> {
        self.status.current()
    }

    /// Subscribe to the current snapshot and future coalesced status changes.
    pub fn watch_status(&self) -> watch::Receiver<Arc<UdpRuntimeStatus>> {
        self.status.subscribe()
    }

    /// Subscribe to semantic binding lifecycle facts.
    pub fn subscribe(&self) -> broadcast::Receiver<UdpEvent> {
        self.event_tx.subscribe()
    }

    fn emit(&self, event: UdpEvent) {
        let _ = self.event_tx.send(event);
    }

    fn accept_bound(&self, info: BindingInfo) {
        self.status.update(move |current| {
            let mut bindings = current.bindings.clone();
            if let Some(existing) = bindings.iter_mut().find(|binding| binding.id == info.id) {
                *existing = info;
            } else {
                bindings.push(info);
            }
            bindings.sort_by(|left, right| left.id.cmp(&right.id));
            (current.bindings != bindings || !current.running).then_some(UdpRuntimeStatus {
                revision: current.revision.saturating_add(1),
                running: true,
                bindings,
            })
        });
    }

    fn accept_renewed(&self, id: &str, last_heartbeat: DateTime<Utc>) {
        self.status.update(|current| {
            let mut bindings = current.bindings.clone();
            let binding = bindings.iter_mut().find(|binding| binding.id == id)?;
            if binding.last_heartbeat >= last_heartbeat {
                return None;
            }
            binding.last_heartbeat = last_heartbeat;
            Some(UdpRuntimeStatus {
                revision: current.revision.saturating_add(1),
                running: current.running,
                bindings,
            })
        });
    }

    fn accept_unbound_to(status: &StatusFeed<UdpRuntimeStatus>, ids: &[String], running: bool) {
        status.update(|current| {
            let mut bindings = current.bindings.clone();
            bindings.retain(|binding| !ids.contains(&binding.id));
            (current.running != running || current.bindings != bindings).then_some(
                UdpRuntimeStatus {
                    revision: current.revision.saturating_add(1),
                    running,
                    bindings,
                },
            )
        });
    }

    fn take_expired_at(
        bindings: &mut HashMap<String, ActiveBinding>,
        now: Instant,
    ) -> Vec<(String, ActiveBinding)> {
        let expired = bindings
            .iter()
            .filter(|(_, binding)| binding.is_expired_at(now))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();

        expired
            .into_iter()
            .filter_map(|id| bindings.remove(&id).map(|binding| (id, binding)))
            .collect()
    }

    async fn close_bindings(bindings: Vec<(String, ActiveBinding)>) -> Vec<String> {
        let mut ids = Vec::with_capacity(bindings.len());
        for (id, mut binding) in bindings {
            binding.close().await;
            ids.push(id);
        }
        ids
    }

    async fn finish_shutdown(
        bindings: &RwLock<HashMap<String, ActiveBinding>>,
        status: &StatusFeed<UdpRuntimeStatus>,
        event_tx: &broadcast::Sender<UdpEvent>,
        transition: &StdMutex<()>,
    ) {
        let retiring = {
            let mut map = bindings.write().await;
            map.drain().collect::<Vec<_>>()
        };
        let mut ids = Self::close_bindings(retiring).await;
        // A prior owner task may have failed after releasing a socket but before
        // publishing its removal. Terminal recovery is authoritative: include
        // every still-advertised ID so shutdown cannot preserve a phantom
        // binding merely because it is already absent from the native-owner map.
        ids.extend(
            status
                .current()
                .bindings
                .iter()
                .map(|binding| binding.id.clone()),
        );
        ids.sort();
        ids.dedup();
        let _transition = transition
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::accept_unbound_to(status, &ids, false);
        for id in ids {
            let _ = event_tx.send(UdpEvent::Unbound {
                id,
                reason: UdpUnbindReason::Shutdown,
            });
        }
        let _ = event_tx.send(UdpEvent::Stopped);
    }

    /// Background task that reaps expired leases every 30 seconds.
    async fn reaper_loop(
        bindings: Arc<RwLock<HashMap<String, ActiveBinding>>>,
        status: StatusFeed<UdpRuntimeStatus>,
        event_tx: broadcast::Sender<UdpEvent>,
        transition: Arc<StdMutex<()>>,
        cancel: CancellationToken,
        operations: Arc<OperationGate>,
        commands: Arc<UdpCommandTasks>,
    ) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    commands.close();
                    operations.close();
                    operations.wait_idle().await;
                    Self::finish_shutdown(&bindings, &status, &event_tx, &transition).await;
                    break;
                },
                _ = interval.tick() => {
                    let expired = {
                        let mut map = bindings.write().await;
                        Self::take_expired_at(&mut map, Instant::now())
                    };
                    let expired = Self::close_bindings(expired).await;
                    for id in &expired {
                        tracing::info!(binding = %id, "Reaped expired UDP binding");
                    }
                    if !expired.is_empty() {
                        let _transition = transition
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        Self::accept_unbound_to(&status, &expired, true);
                        for id in expired {
                            let _ = event_tx.send(UdpEvent::Unbound {
                                id,
                                reason: UdpUnbindReason::LeaseExpired,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Stop accepting work and await the reaper and every relay/socket owner.
    /// A returned call and the published `running = false` status are both
    /// native-resource release fences.
    pub async fn shutdown(&self) {
        self.commands.close();
        self.cancel.cancel();
        // Serialize shutdown callers and borrow the reaper handle in place. A
        // cancelled caller leaves it stored for the next call (or Drop) rather
        // than detaching the task that owns final socket release.
        let mut reaper = self.reaper_handle.lock().await;
        if let Some(handle) = reaper.as_mut() {
            if let Err(error) = (&mut *handle).await {
                tracing::error!(%error, "UDP reaper failed during shutdown");
                self.operations.close();
                self.operations.wait_idle().await;
                Self::finish_shutdown(
                    &self.bindings,
                    &self.status,
                    &self.event_tx,
                    &self.transition,
                )
                .await;
            }
            reaper.take();
        }
        tracing::debug!("UDP runtime shut down");
    }
}

impl Drop for UdpRuntime {
    fn drop(&mut self) {
        // Callers that need acknowledgement use `shutdown`; Drop still ensures
        // an abandoned runtime tells its owned reaper and relays to retire.
        self.operations.close();
        self.commands.close();
        self.cancel.cancel();
        if let Some(reaper) = self.reaper_handle.get_mut().as_ref() {
            reaper.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind(("127.0.0.1", 0))
            .expect("bind ephemeral UDP socket")
            .local_addr()
            .expect("ephemeral UDP address")
            .port()
    }

    #[test]
    fn validate_dest_allows_loopback_by_default() {
        assert!(validate_dest("127.0.0.1:9999".parse().unwrap(), false).is_ok());
        assert!(validate_dest("[::1]:9999".parse().unwrap(), false).is_ok());
    }

    #[test]
    fn validate_dest_rejects_non_loopback_unless_allow_remote() {
        assert!(validate_dest("10.0.0.5:9999".parse().unwrap(), false).is_err());
        assert!(validate_dest("8.8.8.8:53".parse().unwrap(), false).is_err());
        // ...but permitted once the binding opts in.
        assert!(validate_dest("10.0.0.5:9999".parse().unwrap(), true).is_ok());
    }

    #[test]
    fn validate_dest_always_rejects_unspecified_multicast_broadcast() {
        // Even with allow_remote, these are never valid unicast destinations.
        assert!(validate_dest("0.0.0.0:9999".parse().unwrap(), true).is_err());
        assert!(validate_dest("224.0.0.1:9999".parse().unwrap(), true).is_err());
        assert!(validate_dest("255.255.255.255:9999".parse().unwrap(), true).is_err());
    }

    #[tokio::test]
    async fn bind_rejects_non_loopback_without_allow_remote() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let err = rt
            .bind(UdpBindRequest {
                port: 0,
                addr: "0.0.0.0".to_string(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await;
        assert!(matches!(err, Err(UdpError::InvalidAddr(_))));
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn bind_loopback_is_the_safe_default() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let info = rt
            .bind(UdpBindRequest {
                port: 0,
                addr: "127.0.0.1".to_string(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .expect("loopback bind should succeed");
        assert!(!info.allow_remote);
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn failed_socket_bind_changes_neither_status_nor_event() {
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = occupied.local_addr().unwrap().port();
        let rt = UdpRuntime::new(CancellationToken::new());
        let before = rt.status();
        let status = rt.watch_status();
        let mut events = rt.subscribe();

        let result = rt
            .bind(UdpBindRequest {
                port,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await;

        assert!(matches!(result, Err(UdpError::Io(_))));
        assert!(Arc::ptr_eq(&before, &rt.status()));
        assert!(status.has_changed().is_ok_and(|changed| !changed));
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn status_feed_tracks_bind_heartbeat_unbind_and_shutdown() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let mut rx = rt.watch_status();
        let mut events = rt.subscribe();
        let initial = rt.status();
        assert_eq!(initial.revision, 0);
        assert!(initial.running);

        let info = rt
            .bind(UdpBindRequest {
                port: 0,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .unwrap();
        rx.changed().await.unwrap();
        let bound = rx.borrow_and_update().clone();
        assert_eq!(bound.revision, 1);
        assert_eq!(bound.bindings.len(), 1);
        assert!(matches!(events.recv().await.unwrap(), UdpEvent::Bound(_)));
        assert_eq!(rt.status().revision, bound.revision);

        rt.heartbeat(&info.id).await.unwrap();
        rx.changed().await.unwrap();
        let heartbeat = rx.borrow_and_update().clone();
        assert_eq!(heartbeat.revision, 2);
        assert!(heartbeat.bindings[0].last_heartbeat > bound.bindings[0].last_heartbeat);
        assert!(matches!(
            events.recv().await.unwrap(),
            UdpEvent::Renewed { ref id, .. } if id == &info.id
        ));
        assert_eq!(rt.status().revision, heartbeat.revision);

        rt.unbind(&info.id).await.unwrap();
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow_and_update().revision, 3);
        assert!(rx.borrow().bindings.is_empty());
        assert!(matches!(
            events.recv().await.unwrap(),
            UdpEvent::Unbound {
                ref id,
                reason: UdpUnbindReason::Requested,
            } if id == &info.id
        ));
        assert_eq!(rt.status().revision, 3);

        rt.shutdown().await;
        rx.changed().await.unwrap();
        let stopped = rx.borrow_and_update().clone();
        assert_eq!(stopped.revision, 4);
        assert!(!stopped.running);
        assert_eq!(events.recv().await.unwrap(), UdpEvent::Stopped);
        assert_eq!(rt.status().revision, stopped.revision);

        rt.shutdown().await;
        assert!(rx.has_changed().is_ok_and(|changed| !changed));

        let bind_after_shutdown = rt
            .bind(UdpBindRequest {
                port: 0,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await;
        assert!(matches!(bind_after_shutdown, Err(UdpError::ShuttingDown)));
        assert!(matches!(
            rt.unbind("missing-after-shutdown").await,
            Err(UdpError::ShuttingDown)
        ));
    }

    #[tokio::test]
    async fn renewed_status_rejects_a_stale_completion() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let info = rt
            .bind(UdpBindRequest {
                port: 0,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .expect("bind");
        let initial = rt.status().bindings[0].last_heartbeat;
        let newest = initial + chrono::TimeDelta::seconds(2);
        rt.accept_renewed(&info.id, newest);
        let accepted = rt.status();
        assert_eq!(accepted.bindings[0].last_heartbeat, newest);

        rt.accept_renewed(&info.id, initial + chrono::TimeDelta::milliseconds(1));
        let after_stale = rt.status();
        assert!(Arc::ptr_eq(&accepted, &after_stale));
        assert_eq!(after_stale.bindings[0].last_heartbeat, newest);
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn terminal_recovery_clears_a_binding_missing_from_the_native_owner_map() {
        let now = Utc::now();
        let status = StatusFeed::new(UdpRuntimeStatus {
            revision: 7,
            running: true,
            bindings: vec![BindingInfo {
                id: "released-before-publication".to_string(),
                local_addr: "127.0.0.1:41234".to_string(),
                created_at: now,
                last_heartbeat: now,
                lease_secs: 60,
                allow_remote: false,
            }],
        });
        let bindings = RwLock::new(HashMap::new());
        let (events, mut receiver) = koi_common::events::event_channel();
        let transition = StdMutex::new(());

        UdpRuntime::finish_shutdown(&bindings, &status, &events, &transition).await;

        let current = status.current();
        assert_eq!(current.revision, 8);
        assert!(!current.running);
        assert!(current.bindings.is_empty());
        assert_eq!(
            receiver.recv().await.unwrap(),
            UdpEvent::Unbound {
                id: "released-before-publication".to_string(),
                reason: UdpUnbindReason::Shutdown,
            }
        );
        assert_eq!(receiver.recv().await.unwrap(), UdpEvent::Stopped);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_heartbeats_publish_status_and_events_in_one_order() {
        const HEARTBEATS: usize = 32;

        let rt = Arc::new(UdpRuntime::new(CancellationToken::new()));
        let mut events = rt.subscribe();
        let info = rt
            .bind(UdpBindRequest {
                port: 0,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .expect("bind");
        assert!(matches!(events.recv().await.unwrap(), UdpEvent::Bound(_)));

        let barrier = Arc::new(tokio::sync::Barrier::new(HEARTBEATS + 1));
        let tasks = (0..HEARTBEATS)
            .map(|_| {
                let rt = Arc::clone(&rt);
                let barrier = Arc::clone(&barrier);
                let id = info.id.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    rt.heartbeat(&id).await.expect("heartbeat");
                })
            })
            .collect::<Vec<_>>();
        barrier.wait().await;
        for task in tasks {
            task.await.expect("heartbeat task");
        }

        let mut published = Vec::with_capacity(HEARTBEATS);
        for _ in 0..HEARTBEATS {
            let event = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
                .await
                .expect("renewed event timeout")
                .expect("renewed event");
            match event {
                UdpEvent::Renewed { id, last_heartbeat } => {
                    assert_eq!(id, info.id);
                    published.push(last_heartbeat);
                }
                other => panic!("expected renewed event, got {other:?}"),
            }
        }
        assert!(published.windows(2).all(|pair| pair[0] < pair[1]));
        let status = rt.status();
        assert_eq!(status.revision, 1 + HEARTBEATS as u64);
        assert_eq!(
            status.bindings[0].last_heartbeat,
            *published.last().expect("last heartbeat")
        );

        rt.shutdown().await;
    }

    #[tokio::test]
    async fn unbind_returns_only_after_same_port_can_be_rebound() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let port = free_udp_port();
        let first = rt
            .bind(UdpBindRequest {
                port,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .unwrap();

        rt.unbind(&first.id).await.unwrap();
        let second = rt
            .bind(UdpBindRequest {
                port,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .expect("unbind success acknowledges relay and socket release");
        assert_eq!(second.local_addr, format!("127.0.0.1:{port}"));
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn unbind_reports_lost_worker_acknowledgement() {
        let rt = UdpRuntime::new(CancellationToken::new());
        rt.panic_next_unbind();

        let error = rt
            .unbind("worker-loss")
            .await
            .expect_err("worker loss cannot masquerade as shutdown");
        assert!(matches!(
            error,
            UdpError::Worker(detail) if detail.contains("before acknowledgement")
        ));
        assert!(matches!(
            rt.unbind("worker-loss").await,
            Err(UdpError::NotFound(id)) if id == "worker-loss"
        ));
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_unbind_converges_without_a_retry() {
        let rt = Arc::new(UdpRuntime::new(CancellationToken::new()));
        let port = free_udp_port();
        let info = rt
            .bind(UdpBindRequest {
                port,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .expect("bind");
        let mut status = rt.watch_status();
        let mut events = rt.subscribe();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        rt.bindings
            .write()
            .await
            .get_mut(&info.id)
            .expect("owned binding")
            .gate_close(Arc::clone(&entered), Arc::clone(&release));

        let unbinding_runtime = Arc::clone(&rt);
        let unbinding_id = info.id.clone();
        let unbinding = tokio::spawn(async move { unbinding_runtime.unbind(&unbinding_id).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("unbind reached native-release boundary");
        unbinding.abort();
        let _ = unbinding.await;
        release.notify_one();

        tokio::time::timeout(std::time::Duration::from_secs(1), status.changed())
            .await
            .expect("owned unbind status timeout")
            .expect("owned unbind status feed");
        assert!(status.borrow_and_update().bindings.is_empty());
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
                .await
                .expect("owned unbind event timeout")
                .expect("owned unbind event"),
            UdpEvent::Unbound {
                ref id,
                reason: UdpUnbindReason::Requested,
            } if id == &info.id
        ));
        assert!(!rt.bindings.read().await.contains_key(&info.id));
        assert!(rt.status().bindings.is_empty());
        let rebound = std::net::UdpSocket::bind(("127.0.0.1", port))
            .expect("owned unbind completion releases the socket without a retry");
        drop(rebound);
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn last_facade_drop_breaks_an_admitted_unbind_owner_chain() {
        let rt = Arc::new(UdpRuntime::new(CancellationToken::new()));
        let weak = Arc::downgrade(&rt);
        let port = free_udp_port();
        let info = rt
            .bind(UdpBindRequest {
                port,
                addr: "127.0.0.1".into(),
                lease_secs: 60,
                allow_remote: false,
            })
            .await
            .expect("bind");
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        rt.bindings
            .write()
            .await
            .get_mut(&info.id)
            .expect("owned binding")
            .gate_close(Arc::clone(&entered), Arc::clone(&release));

        let requester = {
            let rt = Arc::clone(&rt);
            let id = info.id.clone();
            tokio::spawn(async move { rt.unbind(&id).await })
        };
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("unbind did not reach native release");
        drop(rt);
        requester.abort();
        let _ = requester.await;
        release.notify_waiters();

        tokio::time::timeout(Duration::from_secs(1), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retained UDP command kept its facade owner alive");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(socket) = std::net::UdpSocket::bind(("127.0.0.1", port)) {
                    drop(socket);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("last-owner fail-close did not release the UDP socket");
    }

    #[tokio::test]
    async fn stopped_status_implies_all_udp_sockets_are_released() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let port = free_udp_port();
        rt.bind(UdpBindRequest {
            port,
            addr: "127.0.0.1".into(),
            lease_secs: 60,
            allow_remote: false,
        })
        .await
        .unwrap();

        rt.shutdown().await;
        assert!(!rt.status().running);
        let rebound = std::net::UdpSocket::bind(("127.0.0.1", port))
            .expect("stopped status is a native-resource release fence");
        drop(rebound);
    }

    #[test]
    fn runtime_status_wire_round_trips() {
        let now = Utc::now();
        let status = UdpRuntimeStatus {
            revision: 9,
            running: true,
            bindings: vec![BindingInfo {
                id: "binding-1".into(),
                local_addr: "127.0.0.1:5353".into(),
                created_at: now,
                last_heartbeat: now,
                lease_secs: 300,
                allow_remote: false,
            }],
        };
        let encoded = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<UdpRuntimeStatus>(&encoded).unwrap(),
            status
        );
    }

    #[tokio::test]
    async fn reaper_removal_publishes_one_semantic_status_change() {
        let rt = UdpRuntime::new(CancellationToken::new());
        let mut rx = rt.watch_status();
        rt.bind(UdpBindRequest {
            port: 0,
            addr: "127.0.0.1".into(),
            lease_secs: 60,
            allow_remote: false,
        })
        .await
        .unwrap();
        rx.changed().await.unwrap();
        let bound_revision = rx.borrow_and_update().revision;

        let expired = {
            let mut bindings = rt.bindings.write().await;
            UdpRuntime::take_expired_at(
                &mut bindings,
                Instant::now() + std::time::Duration::from_secs(61),
            )
        };
        assert_eq!(expired.len(), 1);
        let closed = UdpRuntime::close_bindings(expired).await;
        assert_eq!(closed.len(), 1);
        UdpRuntime::accept_unbound_to(&rt.status, &closed, true);

        rx.changed().await.unwrap();
        let reaped = rx.borrow_and_update().clone();
        assert_eq!(reaped.revision, bound_revision.saturating_add(1));
        assert!(reaped.bindings.is_empty());
        rt.shutdown().await;
    }

    #[tokio::test]
    async fn parent_cancellation_drains_bindings_and_publishes_stopped() {
        let cancel = CancellationToken::new();
        let rt = UdpRuntime::new(cancel.clone());
        let mut rx = rt.watch_status();
        rt.bind(UdpBindRequest {
            port: 0,
            addr: "127.0.0.1".into(),
            lease_secs: 60,
            allow_remote: false,
        })
        .await
        .unwrap();
        rx.changed().await.unwrap();
        rx.borrow_and_update();

        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.changed())
            .await
            .expect("cancellation should publish status")
            .unwrap();
        let stopped = rx.borrow_and_update().clone();
        assert!(!stopped.running);
        assert!(stopped.bindings.is_empty());
        assert!(matches!(
            rt.heartbeat("missing").await,
            Err(UdpError::ShuttingDown)
        ));
    }
}
