use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent as MdnsServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};

use koi_common::types::{ServiceRecord, ServiceType, META_QUERY};

use crate::error::{MdnsError, Result};
use crate::events::MdnsEvent as KoiEvent;

/// How long to wait for a service to resolve before giving up.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Capacity of each per-type fan-out broadcast channel.
///
/// Sized larger than the core-wide subscriber channel because the *first*
/// subscriber of a type triggers mdns-sd's synchronous cache replay
/// (`query_cache_for_service`), which can emit many cached instances before any
/// receiver reads. The per-type records cache makes any overflow non-fatal.
const TYPE_BROADCAST_CAPACITY: usize = 512;

// ── Worker operations ─────────────────────────────────────────────

/// Operations dispatched to the dedicated mDNS worker thread.
///
/// All `ServiceDaemon` interactions are serialized through this queue
/// so that the bounded internal channel in mdns-sd never blocks a
/// tokio thread.
enum MdnsOp {
    Register(Box<ServiceInfo>),
    Unregister(String), // fullname
    Browse {
        service_type: String,
        reply: oneshot::Sender<std::result::Result<mdns_sd::Receiver<MdnsServiceEvent>, String>>,
    },
    StopBrowse(String),
    Shutdown {
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
}

// ── Browse hub ────────────────────────────────────────────────────

/// One real mdns-sd browse per service type, fanned out to N subscriptions.
///
/// The pump task owns the single mdns-sd receiver for `gen`, translates events
/// into Koi types, and broadcasts them to `tx` (and the core-wide channel). The
/// `records` cache lets `resolve()` answer from a warm browse without waiting
/// for a re-announcement. `refcount` tracks live subscriptions; the last drop
/// stops the real browse.
struct TypeBrowse {
    tx: broadcast::Sender<KoiEvent>,
    refcount: usize,
    pump: Option<tokio::task::JoinHandle<()>>,
    records: HashMap<String, ServiceRecord>, // instance name -> record
    gen: u64,
}

// ── MdnsDaemon ────────────────────────────────────────────────────

/// Wraps the mdns-sd `ServiceDaemon` behind a dedicated worker thread, and owns
/// the browse hub that multiplexes one real browse per type across many
/// subscribers.
///
/// This is the ONLY file that imports mdns_sd types. All interactions
/// with the daemon are serialized through an unbounded command queue,
/// ensuring the daemon's bounded internal channel never blocks callers
/// (especially tokio tasks).
///
/// Fire-and-forget operations (register, unregister, stop_browse)
/// enqueue and return immediately. Operations that need a result
/// (browse, shutdown) await a oneshot reply from the worker.
pub(crate) struct MdnsDaemon {
    op_tx: Mutex<std::sync::mpsc::SyncSender<MdnsOp>>,
    /// Browse hub: canonical service type -> shared browse.
    types: Mutex<HashMap<String, TypeBrowse>>,
    /// Core-wide event channel (every active pump feeds this).
    event_tx: broadcast::Sender<KoiEvent>,
    next_gen: AtomicU64,
    /// Test-only instrumentation: counts real mdns-sd browse starts and
    /// stop_browse calls so tests can assert the N-subscribers→1-browse collapse
    /// and stop-on-last-drop behaviorally at the boundary (not via the fan-out
    /// seam). Zero cost in non-test builds.
    #[cfg(test)]
    browse_starts: AtomicU64,
    #[cfg(test)]
    stop_browse_calls: AtomicU64,
}

impl MdnsDaemon {
    pub fn new(event_tx: broadcast::Sender<KoiEvent>) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;
        let (op_tx, op_rx) = std::sync::mpsc::sync_channel(256);

        std::thread::Builder::new()
            .name("koi-mdns-ops".into())
            .spawn(move || worker_loop(daemon, op_rx))
            .map_err(|e| MdnsError::Daemon(format!("Failed to spawn mDNS worker: {e}")))?;

        Ok(Self {
            op_tx: Mutex::new(op_tx),
            types: Mutex::new(HashMap::new()),
            event_tx,
            next_gen: AtomicU64::new(0),
            #[cfg(test)]
            browse_starts: AtomicU64::new(0),
            #[cfg(test)]
            stop_browse_calls: AtomicU64::new(0),
        })
    }

    /// Send an operation to the worker thread.
    fn send(&self, op: MdnsOp) -> Result<()> {
        self.op_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .try_send(op)
            .map_err(|e| match e {
                std::sync::mpsc::TrySendError::Full(_) => {
                    MdnsError::Daemon("mDNS worker queue full".into())
                }
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    MdnsError::Daemon("mDNS worker stopped".into())
                }
            })
    }

    /// Start a real mdns-sd browse for a service type. Internal: only the pump
    /// calls this. Returns a receiver for raw mdns-sd events.
    async fn browse_raw(&self, service_type: &str) -> Result<mdns_sd::Receiver<MdnsServiceEvent>> {
        #[cfg(test)]
        self.browse_starts.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.send(MdnsOp::Browse {
            service_type: service_type.to_string(),
            reply: tx,
        })?;
        rx.await
            .map_err(|_| MdnsError::Daemon("mDNS worker dropped reply".into()))?
            .map_err(MdnsError::Daemon)
    }

    /// Stop a real mdns-sd browse by service type (fire-and-forget). Internal:
    /// only the subscription guard calls this on last drop.
    fn stop_browse(&self, service_type: &str) -> Result<()> {
        #[cfg(test)]
        self.stop_browse_calls.fetch_add(1, Ordering::Relaxed);
        self.send(MdnsOp::StopBrowse(service_type.to_string()))
    }

    /// Register a service on the network (fire-and-forget).
    ///
    /// Validates inputs synchronously, then enqueues the registration
    /// for the worker thread. Returns immediately.
    pub fn register(
        &self,
        name: &str,
        service_type: &str,
        port: u16,
        ip: Option<&str>,
        txt: &HashMap<String, String>,
    ) -> Result<()> {
        let hostname = hostname::get()
            .unwrap_or_else(|_| "localhost".into())
            .to_string_lossy()
            .to_string();

        let host = format!("{hostname}.local.");

        let properties: Vec<(&str, &str)> =
            txt.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        let ip_str = ip.unwrap_or("");
        let service_info =
            ServiceInfo::new(service_type, name, &host, ip_str, port, &properties[..])
                .map_err(|e| MdnsError::Daemon(e.to_string()))?;

        // Only auto-detect addresses when no explicit IP was provided.
        let mut service_info = if ip.is_none() {
            service_info.enable_addr_auto()
        } else {
            service_info
        };

        // Skip mDNS probing — the hostname is ours, so we claim the name
        // directly. This prevents stale records from a previous process
        // (which didn't cleanly unregister) from triggering RFC 6762 conflict
        // resolution and renaming our service to "name (2)".
        service_info.set_requires_probe(false);

        let fullname = service_info.get_fullname().to_string();
        tracing::debug!(fullname, ?ip, "Queued mDNS register");

        self.send(MdnsOp::Register(Box::new(service_info)))
    }

    /// Unregister a service by name and type (fire-and-forget).
    pub fn unregister(&self, name: &str, service_type: &str) -> Result<()> {
        let fullname = format!("{name}.{service_type}");
        self.send(MdnsOp::Unregister(fullname))
    }

    /// Subscribe to the core-wide event stream (all active types).
    pub fn subscribe_all(&self) -> broadcast::Receiver<KoiEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to a **canonical** service type key. The first subscriber
    /// starts the single real browse; the last drop stops it. Concurrent
    /// subscriptions are independent — dropping one never disturbs the others.
    ///
    /// `key` must already be canonical (see [`canonical_key`]); `is_meta` is
    /// `true` only for the meta-query type.
    pub fn subscribe_type(self: &Arc<Self>, key: &str, is_meta: bool) -> BrowseSubscription {
        let (rx, gen) = {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            let entry = types.entry(key.to_string()).or_insert_with(|| {
                let (tx, _rx0) = broadcast::channel(TYPE_BROADCAST_CAPACITY);
                let gen = self.next_gen.fetch_add(1, Ordering::Relaxed);
                let pump = spawn_type_pump(self.clone(), key.to_string(), is_meta, gen);
                TypeBrowse {
                    tx,
                    refcount: 0,
                    pump: Some(pump),
                    records: HashMap::new(),
                    gen,
                }
            });
            entry.refcount += 1;
            (entry.tx.subscribe(), entry.gen)
        };

        BrowseSubscription {
            rx: tokio::sync::Mutex::new(rx),
            _guard: Arc::new(TypeGuard {
                daemon: self.clone(),
                key: key.to_string(),
                gen,
            }),
        }
    }

    /// Resolve a specific service instance by its full name.
    ///
    /// Implemented as a temporary subscription through the hub: it can no longer
    /// kill concurrent subscribers, and it answers immediately from the per-type
    /// records cache when a browse is already warm.
    pub async fn resolve(self: &Arc<Self>, instance: &str) -> Result<ServiceRecord> {
        let parts: Vec<&str> = instance.splitn(2, '.').collect();
        if parts.len() < 2 {
            return Err(MdnsError::ResolveTimeout(format!(
                "Invalid instance name: {instance}"
            )));
        }
        let target_name = parts[0];
        let (key, is_meta) = canonical_key(parts[1])?;

        // Hold a subscription for the duration so the browse stays warm and we
        // observe live events; it drops (refcount--) when this function returns.
        let sub = self.subscribe_type(&key, is_meta);

        // Immediate cache hit (the common daemon-mode path, where the type is
        // already being browsed and would otherwise never replay to us).
        if let Some(record) = self.cached_record(&key, target_name) {
            return Ok(record);
        }

        let deadline = tokio::time::Instant::now() + RESOLVE_TIMEOUT;
        loop {
            tokio::select! {
                event = sub.recv() => {
                    match event {
                        Some(KoiEvent::Resolved(record)) if record.name == target_name => {
                            return Ok(record);
                        }
                        Some(_) => continue,
                        None => break,
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(MdnsError::ResolveTimeout(format!(
                        "Could not resolve {instance} within {RESOLVE_TIMEOUT:?}"
                    )));
                }
            }
        }

        Err(MdnsError::ResolveTimeout(format!(
            "Could not resolve {instance}"
        )))
    }

    /// Look up a cached resolved record for a type by instance name.
    fn cached_record(&self, key: &str, target_name: &str) -> Option<ServiceRecord> {
        let types = self.types.lock().unwrap_or_else(|e| e.into_inner());
        types.get(key)?.records.get(target_name).cloned()
    }

    /// Pump output: update the records cache and fan out to the per-type channel
    /// and the core-wide channel exactly once each. Skips stale-generation pumps.
    fn pump_emit(&self, key: &str, gen: u64, event: KoiEvent) {
        {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            let Some(entry) = types.get_mut(key) else {
                return; // entry torn down; pump will exit shortly
            };
            if entry.gen != gen {
                return; // a newer browse owns this type now
            }
            match &event {
                KoiEvent::Resolved(record) => {
                    entry.records.insert(record.name.clone(), record.clone());
                }
                KoiEvent::Removed { name, .. } => {
                    entry.records.remove(name);
                }
                KoiEvent::Found(_) => {}
            }
            let _ = entry.tx.send(event.clone());
        }
        let _ = self.event_tx.send(event);
    }

    /// Remove a type entry iff it still belongs to `gen`. Called when a pump
    /// exits unexpectedly (browse failed to start, or an external SearchStopped)
    /// so subscribers see `Closed` and a later subscribe re-browses, instead of
    /// a zombie Live entry with a dead pump.
    fn teardown_if_gen(&self, key: &str, gen: u64) {
        let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = types.get(key) {
            if entry.gen == gen {
                types.remove(key);
            }
        }
    }

    /// Shut down gracefully: abort all pumps, then stop the mdns-sd daemon.
    pub async fn shutdown(&self) -> Result<()> {
        {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            for (_key, mut entry) in types.drain() {
                if let Some(pump) = entry.pump.take() {
                    pump.abort();
                }
            }
        }
        let (tx, rx) = oneshot::channel();
        self.send(MdnsOp::Shutdown { reply: tx })?;
        rx.await
            .map_err(|_| MdnsError::Daemon("mDNS worker dropped reply".into()))?
            .map_err(MdnsError::Daemon)
    }

    // ── Test seams ────────────────────────────────────────────────
    // Deterministic injection mimics the pump's output (records update + dual
    // fan-out) so the multiplexing/refcount logic — the actual fix — is tested
    // without depending on real multicast delivery.

    #[cfg(test)]
    pub(crate) fn inject(&self, key: &str, event: KoiEvent) {
        {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = types.get_mut(key) {
                match &event {
                    KoiEvent::Resolved(record) => {
                        entry.records.insert(record.name.clone(), record.clone());
                    }
                    KoiEvent::Removed { name, .. } => {
                        entry.records.remove(name);
                    }
                    KoiEvent::Found(_) => {}
                }
                let _ = entry.tx.send(event.clone());
            }
        }
        let _ = self.event_tx.send(event);
    }

    #[cfg(test)]
    pub(crate) fn type_refcount(&self, key: &str) -> Option<usize> {
        self.types
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .map(|entry| entry.refcount)
    }

    /// Number of real mdns-sd browses started (one per pump). Proves the
    /// N-subscribers→1-browse collapse at the boundary.
    #[cfg(test)]
    pub(crate) fn browse_starts(&self) -> u64 {
        self.browse_starts.load(Ordering::Relaxed)
    }

    /// Number of real mdns-sd stop_browse calls. Proves stop-on-last-drop.
    #[cfg(test)]
    pub(crate) fn stop_browse_calls(&self) -> u64 {
        self.stop_browse_calls.load(Ordering::Relaxed)
    }
}

// ── Browse subscription ───────────────────────────────────────────

/// A subscription to a shared per-type browse.
///
/// Replaces the old per-handle `BrowseHandle`: it carries a `broadcast` receiver
/// of Koi events (mdns-sd never escapes) plus a refcount guard that stops the
/// underlying browse only when the last subscription drops.
pub struct BrowseSubscription {
    rx: tokio::sync::Mutex<broadcast::Receiver<KoiEvent>>,
    _guard: Arc<TypeGuard>,
}

impl BrowseSubscription {
    /// Receive the next service event, or `None` when the browse has stopped.
    ///
    /// A lagging subscriber (slow SSE client) drops the oldest missed events and
    /// continues — it never stalls the shared pump or other subscribers.
    pub async fn recv(&self) -> Option<KoiEvent> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(dropped = n, "mDNS subscription lagged; events skipped");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// Refcount guard: the last drop stops the shared browse and removes the entry.
struct TypeGuard {
    daemon: Arc<MdnsDaemon>,
    key: String,
    gen: u64,
}

impl Drop for TypeGuard {
    fn drop(&mut self) {
        // Short, std-mutex-only critical section — no `.await`, no nested daemon
        // locks. Safe because `subscribe_type` never holds `types` across an await.
        let removed = {
            let mut types = self.daemon.types.lock().unwrap_or_else(|e| e.into_inner());
            match types.get_mut(&self.key) {
                Some(entry) if entry.gen == self.gen => {
                    entry.refcount = entry.refcount.saturating_sub(1);
                    if entry.refcount == 0 {
                        types.remove(&self.key)
                    } else {
                        None
                    }
                }
                // Entry gone or replaced by a newer generation: our refcount
                // belonged to a browse that was already torn down.
                _ => None,
            }
        };

        if let Some(mut entry) = removed {
            if let Some(pump) = entry.pump.take() {
                pump.abort();
            }
            if let Err(e) = self.daemon.stop_browse(&self.key) {
                tracing::debug!(error = %e, key = %self.key, "stop_browse on last drop failed");
            }
        }
    }
}

// ── Pump ──────────────────────────────────────────────────────────

/// What the pump should do with a translated mdns-sd event.
enum PumpAction {
    Emit(KoiEvent),
    Skip,
    Stop,
}

/// Spawn the per-type pump task: one real browse, translated and fanned out.
fn spawn_type_pump(
    daemon: Arc<MdnsDaemon>,
    key: String,
    is_meta: bool,
    gen: u64,
) -> tokio::task::JoinHandle<()> {
    // The pump emits via `daemon.pump_emit`, which fans out through the hub
    // entry's sender (and the core-wide channel) and updates the records cache.
    tokio::spawn(async move {
        let receiver = match daemon.browse_raw(&key).await {
            Ok(receiver) => receiver,
            Err(e) => {
                tracing::warn!(key = %key, error = %e, "Failed to start mDNS browse for type");
                daemon.teardown_if_gen(&key, gen);
                return;
            }
        };

        // Loop ends when the flume sender is dropped (daemon shutting down) or
        // the browse is stopped (SearchStopped → PumpAction::Stop).
        while let Ok(mdns_event) = receiver.recv_async().await {
            match translate(mdns_event, is_meta) {
                PumpAction::Emit(event) => daemon.pump_emit(&key, gen, event),
                PumpAction::Skip => continue,
                PumpAction::Stop => break,
            }
        }

        daemon.teardown_if_gen(&key, gen);
    })
}

/// Translate a raw mdns-sd event into a pump action. The boundary parse of
/// service records and removed-event names happens here, exactly once.
fn translate(event: MdnsServiceEvent, is_meta: bool) -> PumpAction {
    match event {
        MdnsServiceEvent::ServiceFound(_, fullname) => {
            if is_meta {
                // Meta-query: "found" instances are themselves service types.
                let type_name = fullname
                    .trim_end_matches('.')
                    .trim_end_matches(".local")
                    .to_string();
                PumpAction::Emit(KoiEvent::Found(ServiceRecord {
                    name: type_name,
                    service_type: String::new(),
                    host: None,
                    ip: None,
                    port: None,
                    txt: Default::default(),
                }))
            } else {
                // Non-meta: found-but-unresolved is not surfaced (resolution
                // follows). Preserving this keeps the SSE event stream shape.
                PumpAction::Skip
            }
        }
        MdnsServiceEvent::ServiceResolved(resolved) => {
            PumpAction::Emit(KoiEvent::Resolved(resolved_to_record(&resolved)))
        }
        MdnsServiceEvent::ServiceRemoved(ty_domain, fullname) => {
            let (name, service_type) = parse_removed(&ty_domain, &fullname);
            PumpAction::Emit(KoiEvent::Removed { name, service_type })
        }
        MdnsServiceEvent::SearchStarted(_) => PumpAction::Skip,
        MdnsServiceEvent::SearchStopped(_) => PumpAction::Stop,
        _ => PumpAction::Skip,
    }
}

// ── Worker thread ─────────────────────────────────────────────────

fn worker_loop(daemon: ServiceDaemon, rx: std::sync::mpsc::Receiver<MdnsOp>) {
    tracing::debug!("mDNS worker thread started");

    while let Ok(op) = rx.recv() {
        match op {
            MdnsOp::Register(info) => {
                let fullname = info.get_fullname().to_string();
                if let Err(e) = daemon.register(*info) {
                    tracing::warn!(fullname, error = %e, "mDNS register failed");
                }
            }
            MdnsOp::Unregister(fullname) => {
                if let Err(e) = daemon.unregister(&fullname) {
                    tracing::warn!(fullname, error = %e, "mDNS unregister failed");
                }
            }
            MdnsOp::Browse {
                service_type,
                reply,
            } => {
                let result = daemon.browse(&service_type).map_err(|e| e.to_string());
                let _ = reply.send(result);
            }
            MdnsOp::StopBrowse(service_type) => {
                if let Err(e) = daemon.stop_browse(&service_type) {
                    tracing::debug!(service_type, error = %e, "mDNS stop_browse failed");
                }
            }
            MdnsOp::Shutdown { reply } => {
                let result = daemon.shutdown().map(|_| ()).map_err(|e| e.to_string());
                let _ = reply.send(result);
                break;
            }
        }
    }

    tracing::debug!("mDNS worker thread stopped");
}

// ── Type key / boundary parsing ───────────────────────────────────

/// Canonicalize a service type into the hub key + whether it is the meta query.
///
/// Both `discover` and `resolve` must produce the *same* key for a type, or they
/// would open two queriers for "the same" type and re-trigger the single-querier
/// overwrite bug. `ServiceType::parse` yields the canonical `_name._proto.local.`.
pub(crate) fn canonical_key(service_type: &str) -> Result<(String, bool)> {
    if service_type == META_QUERY {
        Ok((META_QUERY.to_string(), true))
    } else {
        Ok((
            ServiceType::parse(service_type)?.as_str().to_string(),
            false,
        ))
    }
}

/// Parse a removed event's `(ty_domain, fullname)` into `(instance, service_type)`
/// once, at the boundary. Mirrors the normalization used by [`resolved_to_record`].
fn parse_removed(ty_domain: &str, fullname: &str) -> (String, String) {
    let service_type = ty_domain
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();
    let instance = fullname
        .find("._")
        .map(|i| &fullname[..i])
        .unwrap_or(fullname)
        .to_string();
    (instance, service_type)
}

// ── Service record conversion ─────────────────────────────────────

/// Convert mdns-sd ResolvedService into our ServiceRecord.
/// This is the ONE place this conversion happens.
pub(crate) fn resolved_to_record(resolved: &ResolvedService) -> ServiceRecord {
    let fullname = resolved.get_fullname();

    // Extract instance name: "My Server._http._tcp.local." -> "My Server"
    let name = fullname
        .find("._")
        .map(|i| &fullname[..i])
        .unwrap_or(fullname)
        .to_string();

    let service_type = resolved.ty_domain.clone();
    let service_type = service_type
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();

    let host = resolved.get_hostname().to_string();
    let host = if host.is_empty() { None } else { Some(host) };

    // Prefer first IPv4, fallback to first IPv6
    let addresses = resolved.get_addresses();
    let ip = addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addresses.iter().next())
        .map(|a| a.to_ip_addr());

    // If the resolved IP is loopback (127.0.0.1 / ::1), the service is local
    // and mdns-sd returned the loopback address. Replace with the machine's
    // actual LAN IP so consumers (e.g. containers) get a routable address.
    let ip = ip.map(|addr| {
        if addr.is_loopback() {
            lan_ip().unwrap_or(addr).to_string()
        } else {
            addr.to_string()
        }
    });

    if addresses.len() > 1 {
        tracing::trace!(
            name,
            count = addresses.len(),
            selected = ?ip,
            "Multiple IPs found, using first"
        );
    }

    let txt: HashMap<String, String> = resolved
        .get_properties()
        .iter()
        .map(|p| (p.key().to_string(), p.val_str().to_string()))
        .collect();

    ServiceRecord {
        name,
        service_type,
        host,
        ip,
        port: Some(resolved.get_port()),
        txt,
    }
}

/// Return the first non-loopback, non-link-local IPv4 address on this machine.
fn lan_ip() -> Option<std::net::IpAddr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .filter_map(|iface| match iface.addr.ip() {
            std::net::IpAddr::V4(v4) if !v4.is_link_local() => Some(std::net::IpAddr::V4(v4)),
            _ => None,
        })
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_daemon() -> Arc<MdnsDaemon> {
        let (event_tx, _) = broadcast::channel(256);
        Arc::new(MdnsDaemon::new(event_tx).expect("spawn mDNS daemon"))
    }

    fn resolved(name: &str) -> KoiEvent {
        KoiEvent::Resolved(ServiceRecord {
            name: name.to_string(),
            service_type: "_test._tcp".to_string(),
            host: Some("host.local".to_string()),
            ip: Some("10.0.0.1".to_string()),
            port: Some(9999),
            txt: Default::default(),
        })
    }

    /// Receive with a timeout so a missing event fails fast instead of hanging.
    async fn recv_timeout(sub: &BrowseSubscription) -> Option<KoiEvent> {
        tokio::time::timeout(Duration::from_secs(2), sub.recv())
            .await
            .ok()
            .flatten()
    }

    /// Poll `cond` until true or 2s elapse (the pump starts its real browse
    /// asynchronously, so counters settle shortly after `subscribe_type`).
    async fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    const TEST_KEY: &str = "_test._tcp.local.";

    // ── One real browse per type (the multiplexing claim, at the boundary) ──

    #[tokio::test]
    async fn n_subscribers_collapse_to_one_real_browse() {
        let daemon = test_daemon();
        let sub1 = daemon.subscribe_type(TEST_KEY, false);
        let sub2 = daemon.subscribe_type(TEST_KEY, false);
        let sub3 = daemon.subscribe_type(TEST_KEY, false);
        assert_eq!(daemon.type_refcount(TEST_KEY), Some(3));

        // The pump issues exactly ONE real mdns-sd browse for all three subs.
        assert!(wait_until(|| daemon.browse_starts() >= 1).await);
        assert_eq!(
            daemon.browse_starts(),
            1,
            "3 subscribers must share a single real browse, not start 3"
        );
        drop((sub1, sub2, sub3));
    }

    #[tokio::test]
    async fn last_drop_issues_exactly_one_stop_browse() {
        let daemon = test_daemon();
        let sub1 = daemon.subscribe_type(TEST_KEY, false);
        let sub2 = daemon.subscribe_type(TEST_KEY, false);
        assert!(wait_until(|| daemon.browse_starts() >= 1).await);

        drop(sub1);
        // Dropping a non-last subscriber must NOT stop the real browse.
        assert_eq!(daemon.type_refcount(TEST_KEY), Some(1));
        assert_eq!(
            daemon.stop_browse_calls(),
            0,
            "browse must stay alive while a subscriber remains"
        );

        drop(sub2);
        assert!(wait_until(|| daemon.type_refcount(TEST_KEY).is_none()).await);
        assert_eq!(
            daemon.stop_browse_calls(),
            1,
            "last drop stops the real browse exactly once"
        );
        assert_eq!(daemon.browse_starts(), 1, "no extra browse was started");
    }

    #[tokio::test]
    async fn distinct_types_start_distinct_browses() {
        let daemon = test_daemon();
        let _a = daemon.subscribe_type("_a._tcp.local.", false);
        let _b = daemon.subscribe_type("_b._tcp.local.", false);
        assert!(wait_until(|| daemon.browse_starts() >= 2).await);
        assert_eq!(daemon.browse_starts(), 2);
    }

    #[tokio::test]
    async fn resolve_reuses_live_browse_without_starting_another() {
        let daemon = test_daemon();
        let sub = daemon.subscribe_type(TEST_KEY, false);
        assert!(wait_until(|| daemon.browse_starts() >= 1).await);

        // Warm the cache, then resolve through the shared hub.
        daemon.inject(TEST_KEY, resolved("zeta"));
        let _ = recv_timeout(&sub).await;
        let record = daemon
            .resolve("zeta._test._tcp.local.")
            .await
            .expect("resolve hits cache");
        assert_eq!(record.name, "zeta");

        assert_eq!(
            daemon.browse_starts(),
            1,
            "resolve must reuse the live browse, not start a second querier"
        );
        assert_eq!(
            daemon.type_refcount(TEST_KEY),
            Some(1),
            "resolve's temporary subscription dropped; the original survives"
        );
    }

    // ── Fan-out + refcount (the fix) ──────────────────────────────

    #[tokio::test]
    async fn concurrent_subscriptions_both_receive() {
        let daemon = test_daemon();
        let sub1 = daemon.subscribe_type(TEST_KEY, false);
        let sub2 = daemon.subscribe_type(TEST_KEY, false);
        assert_eq!(daemon.type_refcount(TEST_KEY), Some(2));

        daemon.inject(TEST_KEY, resolved("alpha"));

        let e1 = recv_timeout(&sub1).await.expect("sub1 receives");
        let e2 = recv_timeout(&sub2).await.expect("sub2 receives");
        assert!(matches!(e1, KoiEvent::Resolved(r) if r.name == "alpha"));
        assert!(matches!(e2, KoiEvent::Resolved(r) if r.name == "alpha"));
    }

    #[tokio::test]
    async fn dropping_one_subscription_leaves_the_other_live() {
        let daemon = test_daemon();
        let sub1 = daemon.subscribe_type(TEST_KEY, false);
        let sub2 = daemon.subscribe_type(TEST_KEY, false);

        drop(sub1);
        assert_eq!(
            daemon.type_refcount(TEST_KEY),
            Some(1),
            "browse stays alive for the surviving subscriber"
        );

        daemon.inject(TEST_KEY, resolved("beta"));
        let e2 = recv_timeout(&sub2).await.expect("survivor still receives");
        assert!(matches!(e2, KoiEvent::Resolved(r) if r.name == "beta"));
    }

    #[tokio::test]
    async fn refcount_last_drop_stops_browse() {
        let daemon = test_daemon();
        let sub1 = daemon.subscribe_type(TEST_KEY, false);
        let sub2 = daemon.subscribe_type(TEST_KEY, false);
        assert_eq!(daemon.type_refcount(TEST_KEY), Some(2));

        drop(sub2);
        assert_eq!(daemon.type_refcount(TEST_KEY), Some(1));

        drop(sub1);
        assert_eq!(
            daemon.type_refcount(TEST_KEY),
            None,
            "last drop removes the type entry (stops the real browse)"
        );
    }

    #[tokio::test]
    async fn resolve_during_active_subscription_does_not_terminate_it() {
        let daemon = test_daemon();
        let sub = daemon.subscribe_type(TEST_KEY, false);
        assert_eq!(daemon.type_refcount(TEST_KEY), Some(1));

        // Warm the cache so resolve returns immediately (refcount 2 -> 1).
        daemon.inject(TEST_KEY, resolved("gamma"));
        let _ = recv_timeout(&sub).await; // drain the warming event

        let record = daemon
            .resolve("gamma._test._tcp.local.")
            .await
            .expect("resolve hits cache");
        assert_eq!(record.name, "gamma");
        assert_eq!(
            daemon.type_refcount(TEST_KEY),
            Some(1),
            "resolve's temporary subscription dropped, original survives"
        );

        // The original subscription is still live and receiving.
        daemon.inject(TEST_KEY, resolved("delta"));
        let next = recv_timeout(&sub).await.expect("subscription still live");
        assert!(matches!(next, KoiEvent::Resolved(r) if r.name == "delta"));
    }

    #[tokio::test]
    async fn resolve_returns_cached_record_without_waiting() {
        let daemon = test_daemon();
        let sub = daemon.subscribe_type(TEST_KEY, false);
        daemon.inject(TEST_KEY, resolved("epsilon"));
        let _ = recv_timeout(&sub).await;

        // Well under RESOLVE_TIMEOUT (5s) — a cache miss would wait the full window.
        let record = tokio::time::timeout(
            Duration::from_millis(500),
            daemon.resolve("epsilon._test._tcp.local."),
        )
        .await
        .expect("resolve returns promptly")
        .expect("resolve succeeds");
        assert_eq!(record.name, "epsilon");
    }

    // ── Boundary parsing ──────────────────────────────────────────

    #[test]
    fn removed_event_is_parsed_at_boundary() {
        let (name, service_type) = parse_removed("_http._tcp.local.", "My NAS._http._tcp.local.");
        assert_eq!(name, "My NAS");
        assert_eq!(service_type, "_http._tcp");
    }

    #[test]
    fn canonical_key_normalizes_equivalent_inputs() {
        let (a, _) = canonical_key("_http._tcp").unwrap();
        let (b, _) = canonical_key("_http._tcp.local.").unwrap();
        let (c, _) = canonical_key("http").unwrap();
        assert_eq!(a, "_http._tcp.local.");
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn canonical_key_detects_meta_query() {
        let (key, is_meta) = canonical_key(META_QUERY).unwrap();
        assert_eq!(key, META_QUERY);
        assert!(is_meta);

        let (_, normal) = canonical_key("_http._tcp").unwrap();
        assert!(!normal);
    }

    // ── Boundary rule enforcement ─────────────────────────────────

    #[test]
    fn no_mdns_sd_outside_daemon_rs() {
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&src_dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) == Some("daemon.rs") {
                continue; // the one allowed file
            }
            let contents = std::fs::read_to_string(&path).expect("read source file");
            if contents.contains("mdns_sd") {
                offenders.push(path.display().to_string());
            }
        }
        assert!(
            offenders.is_empty(),
            "mdns_sd must only be referenced in daemon.rs; offenders: {offenders:?}"
        );
    }

    // ── Real-network end-to-end (manual: `cargo test -- --ignored`) ──
    //
    // These exercise the full path against a live mdns-sd ServiceDaemon and
    // real multicast loopback. They are ignored by default because multicast is
    // not guaranteed in CI; the deterministic tests above are the CI guards.

    /// Drain a subscription until a Resolved record with `name` arrives, or fail.
    async fn await_resolved(sub: &BrowseSubscription, name: &str) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, sub.recv()).await {
                Ok(Some(KoiEvent::Resolved(r))) if r.name == name => return true,
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => return false,
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires real mDNS multicast; run with --ignored"]
    async fn real_two_subscribers_both_resolve_same_service() {
        let daemon = test_daemon();
        daemon
            .register(
                "koi-p05-both",
                "_test._tcp.local.",
                9999,
                None,
                &HashMap::new(),
            )
            .expect("register");

        let sub1 = daemon.subscribe_type(TEST_KEY, false);
        let sub2 = daemon.subscribe_type(TEST_KEY, false);

        // Both subscribers resolve the SAME named service over one shared browse.
        assert!(
            await_resolved(&sub1, "koi-p05-both").await,
            "sub1 resolves it"
        );
        assert!(
            await_resolved(&sub2, "koi-p05-both").await,
            "sub2 resolves it too"
        );
        assert_eq!(daemon.browse_starts(), 1, "one shared real browse");

        daemon.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    #[ignore = "requires real mDNS multicast; run with --ignored"]
    async fn real_dropping_one_subscriber_keeps_the_browse_alive() {
        // The exact regression: under the old code, dropping one subscriber's
        // handle called stop_browse and killed the type's only querier. Here the
        // survivor must keep resolving a service announced AFTER the drop.
        let daemon = test_daemon();
        let sub1 = daemon.subscribe_type(TEST_KEY, false);
        let sub2 = daemon.subscribe_type(TEST_KEY, false);

        daemon
            .register(
                "koi-p05-first",
                "_test._tcp.local.",
                9001,
                None,
                &HashMap::new(),
            )
            .expect("register first");
        assert!(
            await_resolved(&sub2, "koi-p05-first").await,
            "sub2 sees the first"
        );

        drop(sub1); // would have stopped the shared browse under the old design
        assert_eq!(
            daemon.stop_browse_calls(),
            0,
            "browse survives a non-last drop"
        );

        daemon
            .register(
                "koi-p05-second",
                "_test._tcp.local.",
                9002,
                None,
                &HashMap::new(),
            )
            .expect("register second");
        assert!(
            await_resolved(&sub2, "koi-p05-second").await,
            "survivor still resolves a service announced after the drop"
        );

        daemon.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    #[ignore = "requires real mDNS multicast; run with --ignored"]
    async fn real_resolve_does_not_terminate_concurrent_subscriber() {
        let daemon = test_daemon();
        let sub = daemon.subscribe_type(TEST_KEY, false);

        daemon
            .register(
                "koi-p05-res",
                "_test._tcp.local.",
                9003,
                None,
                &HashMap::new(),
            )
            .expect("register");
        assert!(
            await_resolved(&sub, "koi-p05-res").await,
            "subscriber resolves it"
        );

        // resolve() through the shared hub must not stop the subscriber's browse.
        let resolved = daemon.resolve("koi-p05-res._test._tcp.local.").await;
        assert!(resolved.is_ok(), "resolve succeeds via the shared browse");
        assert_eq!(
            daemon.stop_browse_calls(),
            0,
            "resolve never stops the browse"
        );

        daemon
            .register(
                "koi-p05-res2",
                "_test._tcp.local.",
                9004,
                None,
                &HashMap::new(),
            )
            .expect("register 2");
        assert!(
            await_resolved(&sub, "koi-p05-res2").await,
            "subscriber still live after a concurrent resolve"
        );

        daemon.shutdown().await.expect("shutdown");
    }
}
