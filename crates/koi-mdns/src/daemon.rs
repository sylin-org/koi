use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use koi_common::types::{ServiceRecord, ServiceType, META_QUERY};

use crate::error::{MdnsError, Result};
use crate::events::MdnsEvent as KoiEvent;
use crate::provider::{
    MdnsProvider, ProviderBrowse, ProviderEvent, ProviderService, ProviderStatus,
};

/// How long to wait for a service to resolve before giving up.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Capacity of each per-type fan-out broadcast channel.
///
/// Sized larger than the core-wide subscriber channel because the *first*
/// subscriber of a type triggers mdns-sd's synchronous cache replay
/// (`query_cache_for_service`), which can emit many cached instances before any
/// receiver reads. The per-type records cache makes any overflow non-fatal.
const TYPE_BROADCAST_CAPACITY: usize = 512;

/// Backoff for restarting a raw browse that the platform mDNS engine stops while
/// Koi still has subscribers. The shared pump is the single recovery point, so
/// HTTP/SSE and every other consumer observe the same resilient subscription.
const BROWSE_RETRY_INITIAL: Duration = Duration::from_millis(100);
const BROWSE_RETRY_MAX: Duration = Duration::from_secs(5);

// ── Browse hub ────────────────────────────────────────────────────

/// One real provider browse per service type, fanned out to N subscriptions.
///
/// The pump task owns the single provider receiver for `gen`, translates events
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

// ── Receive activity ──────────────────────────────────────────────

/// Provider-neutral receive telemetry for `MdnsCore::status`.
///
/// DNS-SD browse APIs emit changes, not keepalives. A quiet network can be
/// healthy for an unbounded time. These facts are operator evidence; adapter
/// inspection, not event age, owns the provider-health verdict.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReceiveActivity {
    /// Total inbound events translated.
    pub events_seen: u64,
    /// Age in seconds of the most recent inbound event (`None` = nothing ever received).
    pub last_event_age_secs: Option<u64>,
    /// How long a real browse has been active, in seconds (`None` = no active browse).
    pub browse_active_secs: Option<u64>,
}

// ── MdnsDaemon ────────────────────────────────────────────────────

/// Provider-neutral browse hub that multiplexes one real browse per type across
/// many subscribers. OS/library details remain behind [`MdnsProvider`].
pub(crate) struct MdnsDaemon {
    provider: Arc<dyn MdnsProvider>,
    /// Browse hub: canonical service type -> shared browse.
    types: Mutex<HashMap<String, TypeBrowse>>,
    /// Core-wide event channel (every active pump feeds this).
    event_tx: broadcast::Sender<KoiEvent>,
    next_gen: AtomicU64,
    /// Monotonic baseline for every receive-activity timestamp. A fixed `Instant`
    /// captured at construction: browse-active and last-event ages are computed as
    /// `elapsed()` deltas against it, so a wall-clock step can never corrupt an age
    /// All the `*_ms` atomics below are "millis since this baseline", with `0`
    /// meaning "never".
    baseline: Instant,
    /// Receive-activity signal: every translated inbound event bumps these so
    /// status can state what was observed without inventing a keepalive contract.
    events_seen: AtomicU64,
    /// Millis-since-`baseline` of the most recent inbound event (`0` = none yet).
    last_event_ms: AtomicU64,
    /// Millis-since-`baseline` when a real browse most recently became active. Set the
    /// first time `subscribe_type` starts a real browse, and REFRESHED on every
    /// empty→non-empty transition of the types map — so a browse that starts after a
    /// long idle (the lazy meta-browse, the first discover-after-idle) gets a fresh
    /// staleness window instead of inheriting a stale one. `0` = no browse active.
    first_browse_ms: AtomicU64,
    /// Test-only instrumentation: counts real provider browse starts and
    /// stop_browse calls so tests can assert the N-subscribers→1-browse collapse
    /// and stop-on-last-drop behaviorally at the boundary (not via the fan-out
    /// seam). Zero cost in non-test builds.
    #[cfg(test)]
    browse_starts: AtomicU64,
    #[cfg(test)]
    stop_browse_calls: AtomicU64,
}

impl MdnsDaemon {
    pub fn new(provider: Arc<dyn MdnsProvider>, event_tx: broadcast::Sender<KoiEvent>) -> Self {
        Self {
            provider,
            types: Mutex::new(HashMap::new()),
            event_tx,
            next_gen: AtomicU64::new(0),
            baseline: Instant::now(),
            events_seen: AtomicU64::new(0),
            last_event_ms: AtomicU64::new(0),
            first_browse_ms: AtomicU64::new(0),
            #[cfg(test)]
            browse_starts: AtomicU64::new(0),
            #[cfg(test)]
            stop_browse_calls: AtomicU64::new(0),
        }
    }

    /// Start a real provider browse for a service type. Internal: only the pump
    /// calls this. Returns normalized provider observations.
    async fn browse_raw(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        #[cfg(test)]
        self.browse_starts.fetch_add(1, Ordering::Relaxed);
        self.provider.browse(service_type, is_meta).await
    }

    /// Stop a real provider browse by service type. Internal:
    /// only the subscription guard calls this on last drop.
    fn stop_browse(&self, service_type: &str) -> Result<()> {
        #[cfg(test)]
        self.stop_browse_calls.fetch_add(1, Ordering::Relaxed);
        self.provider.stop_browse(service_type)
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
        self.provider.register(name, service_type, port, ip, txt)
    }

    /// Unregister a service by name and type (fire-and-forget).
    pub fn unregister(&self, name: &str, service_type: &str) -> Result<()> {
        self.provider.unregister(name, service_type)
    }

    /// Subscribe to the core-wide event stream (all active types).
    pub fn subscribe_all(&self) -> broadcast::Receiver<KoiEvent> {
        self.event_tx.subscribe()
    }

    pub fn provider_status(&self) -> ProviderStatus {
        self.provider.status()
    }

    /// Subscribe to a **canonical** service type key. The first subscriber
    /// starts the single real browse; the last drop stops it. Concurrent
    /// subscriptions are independent — dropping one never disturbs the others.
    ///
    /// `key` must already be canonical (see [`canonical_key`]); `is_meta` is
    /// `true` only for the meta-query type.
    pub fn subscribe_type(self: &Arc<Self>, key: &str, is_meta: bool) -> BrowseSubscription {
        let (rx, gen, replay) = {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            // Empty→non-empty transition = a real browse becoming active after none.
            // Refresh the staleness window so a browse starting after a long idle (the
            // lazy meta-browse, the first discover-after-idle) gets a fresh window
            // instead of inheriting an old `first_browse_ms`. This `store` subsumes the
            // first-ever start (which is itself an empty→non-empty transition from the
            // `0` sentinel), so activity always measures browse-active time,
            // never core uptime.
            let browse_becoming_active = types.is_empty();
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
            if browse_becoming_active {
                self.first_browse_ms
                    .store(self.elapsed_ms().max(1), Ordering::Relaxed);
            }
            // Replay the warm cache to THIS subscriber only. mdns-sd replays its cache
            // synchronously to the FIRST listener of a type; the hub then shares that one
            // browse across N subscribers via a future-only broadcast. So a discover that
            // joins a type already being browsed (the lazy LAN-wide meta-browse, or an
            // earlier discover) would get future events only and never surface services
            // mdns-sd already resolved — exactly why a long-lived daemon's browse found
            // nothing while a cold standalone resolved fine. Replaying `records` here
            // closes that gap deterministically, without re-broadcasting to peers.
            let replay = replay_events(is_meta, &entry.records);
            (entry.tx.subscribe(), entry.gen, replay)
        };

        BrowseSubscription {
            rx: tokio::sync::Mutex::new(rx),
            replay: std::sync::Mutex::new(replay),
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

        // Prefer an already-resolved hub fact, then use a provider's native
        // point-resolution surface when the active capability plan has one.
        // Partial system facilities such as resolve1 are therefore useful
        // without being asked to impersonate a continuous browser.
        if let Some(record) = self.cached_record(&key, target_name) {
            return Ok(record);
        }
        if self.provider.capabilities().direct_resolve {
            match self.provider.resolve(target_name, &key).await {
                Ok(service) => {
                    self.note_inbound();
                    return Ok(provider_service_to_record(service));
                }
                Err(error) => {
                    tracing::debug!(
                        provider = self.provider.name(),
                        %error,
                        "Direct service resolution failed; falling back to the shared browse"
                    );
                }
            }
        }

        // Hold a subscription for the duration so the browse stays warm and we
        // observe live events; it drops (refcount--) when this function returns.
        let sub = self.subscribe_type(&key, is_meta);

        // Recheck after subscribing: a concurrent pump may have resolved the
        // record while the direct lookup was in flight.
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

    /// Millis since the monotonic `baseline`. `1`-floored so a genuine event at the
    /// very first instant is never mistaken for the `0` = "never" sentinel.
    fn elapsed_ms(&self) -> u64 {
        (self.baseline.elapsed().as_millis() as u64).max(1)
    }

    /// Record that an inbound mDNS event arrived. Stamps the
    /// last-event time off the monotonic `baseline` so a wall-clock step can't corrupt
    /// the computed age.
    fn note_inbound(&self) {
        self.events_seen.fetch_add(1, Ordering::Relaxed);
        self.last_event_ms
            .store(self.elapsed_ms(), Ordering::Relaxed);
    }

    /// Receive-activity snapshot for `MdnsCore::status`.
    ///
    /// - `browse_active_secs` is `Some(d)` while a real browse is active, measuring how
    ///   long *the browse* (not the core) has been up — `None` when no browse is active.
    /// - `last_event_age_secs` is the age of the most recent inbound event, or `None`
    ///   when nothing has ever been received.
    /// - `events_seen` is a display counter.
    ///
    /// All ages are derived from the monotonic `baseline`, so a clock step can't
    /// corrupt them. Event age is telemetry only: adapters own liveness decisions.
    pub(crate) fn receive_activity(&self) -> ReceiveActivity {
        let now = self.elapsed_ms();
        let events_seen = self.events_seen.load(Ordering::Relaxed);
        let last = self.last_event_ms.load(Ordering::Relaxed);
        let last_event_age_secs = (last != 0).then(|| now.saturating_sub(last) / 1000);
        let active = !self
            .types
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty();
        let first_browse = self.first_browse_ms.load(Ordering::Relaxed);
        let browse_active_secs =
            (active && first_browse != 0).then(|| now.saturating_sub(first_browse) / 1000);
        ReceiveActivity {
            events_seen,
            last_event_age_secs,
            browse_active_secs,
        }
    }

    /// Pump output: update the records cache and fan out to the per-type channel
    /// and the core-wide channel exactly once each. Skips stale-generation pumps.
    fn pump_emit(&self, key: &str, gen: u64, event: KoiEvent) {
        self.note_inbound();
        {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            let Some(entry) = types.get_mut(key) else {
                return; // entry torn down; pump will exit shortly
            };
            if entry.gen != gen {
                return; // a newer browse owns this type now
            }
            cache_update(key, &mut entry.records, &event);
            let _ = entry.tx.send(event.clone());
        }
        let _ = self.event_tx.send(event);
    }

    /// Whether a pump generation still owns a live shared browse. The last
    /// subscriber removes the entry and aborts its pump, so recovery loops never
    /// outlive the demand that created them.
    fn browse_generation_is_live(&self, key: &str, gen: u64) -> bool {
        self.types
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .is_some_and(|entry| entry.gen == gen && entry.refcount > 0)
    }

    /// Shut down gracefully: abort all pumps, then stop the selected provider.
    pub async fn shutdown(&self) -> Result<()> {
        {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            for (_key, mut entry) in types.drain() {
                if let Some(pump) = entry.pump.take() {
                    pump.abort();
                }
            }
        }
        self.provider.shutdown().await
    }

    // ── Test seams ────────────────────────────────────────────────
    // Deterministic injection mimics the pump's output (records update + dual
    // fan-out) so the multiplexing/refcount logic — the actual fix — is tested
    // without depending on real multicast delivery.

    #[cfg(test)]
    pub(crate) fn inject(&self, key: &str, event: KoiEvent) {
        self.note_inbound();
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

    /// Number of real provider browses started (one per pump). Proves the
    /// N-subscribers→1-browse collapse at the boundary.
    #[cfg(test)]
    pub(crate) fn browse_starts(&self) -> u64 {
        self.browse_starts.load(Ordering::Relaxed)
    }

    /// Number of real provider stop_browse calls. Proves stop-on-last-drop.
    #[cfg(test)]
    pub(crate) fn stop_browse_calls(&self) -> u64 {
        self.stop_browse_calls.load(Ordering::Relaxed)
    }
}

// ── Browse subscription ───────────────────────────────────────────

/// A subscription to a shared per-type browse.
///
/// Replaces the old per-handle `BrowseHandle`: it carries a `broadcast` receiver
/// of Koi events (provider types never escape) plus a refcount guard that stops the
/// underlying browse only when the last subscription drops.
pub struct BrowseSubscription {
    rx: tokio::sync::Mutex<broadcast::Receiver<KoiEvent>>,
    /// Warm-cache records (as `Resolved` events) replayed to THIS subscriber before
    /// live events, so a browse that joins an already-cached type still surfaces the
    /// services mdns-sd resolved before we subscribed. Drained once, then empty.
    replay: std::sync::Mutex<VecDeque<KoiEvent>>,
    _guard: Arc<TypeGuard>,
}

impl BrowseSubscription {
    /// Receive the next service event, or `None` when the browse has stopped.
    ///
    /// A lagging subscriber (slow SSE client) drops the oldest missed events and
    /// continues — it never stalls the shared pump or other subscribers.
    pub async fn recv(&self) -> Option<KoiEvent> {
        // Warm-cache replay first (cached resolved services), then live events.
        if let Some(event) = self
            .replay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
        {
            return Some(event);
        }
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
        let mut retry_delay = BROWSE_RETRY_INITIAL;

        loop {
            let mut receiver = match daemon.browse_raw(&key, is_meta).await {
                Ok(receiver) => receiver,
                Err(e) => {
                    if !daemon.browse_generation_is_live(&key, gen) {
                        return;
                    }
                    tracing::debug!(
                        key = %key,
                        error = %e,
                        retry_ms = retry_delay.as_millis(),
                        "mDNS browse waiting for an available provider route"
                    );
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = next_browse_retry(retry_delay);
                    continue;
                }
            };

            // A platform backend may close its receiver or emit SearchStopped even
            // though Koi still has consumers (observed on constrained macOS hosts).
            // Keep the shared channel alive and re-establish the raw browse here;
            // the last subscriber still aborts this task and issues stop_browse.
            while let Some(provider_event) = receiver.recv().await {
                daemon.pump_emit(&key, gen, provider_event_to_koi(provider_event));
                retry_delay = BROWSE_RETRY_INITIAL;
            }

            if !daemon.browse_generation_is_live(&key, gen) {
                return;
            }

            tracing::debug!(
                key = %key,
                retry_ms = retry_delay.as_millis(),
                "mDNS browse route closed; restarting while subscribers remain"
            );
            tokio::time::sleep(retry_delay).await;
            retry_delay = next_browse_retry(retry_delay);
        }
    })
}

fn next_browse_retry(current: Duration) -> Duration {
    current.saturating_mul(2).min(BROWSE_RETRY_MAX)
}

/// Apply one pump event to the hub entry's replay cache. Resolved services are
/// cached for every type; meta-query Found events (which ARE the discovered
/// type names — there is no further resolution step) are cached only for the
/// meta entry, so a late subscriber still learns the LAN's service types.
/// Plain Found events on normal types stay uncached: they are unresolved
/// teasers whose Resolved follow-up is the durable fact.
fn cache_update(key: &str, records: &mut HashMap<String, ServiceRecord>, event: &KoiEvent) {
    match event {
        KoiEvent::Resolved(record) => {
            records.insert(record.name.clone(), record.clone());
        }
        KoiEvent::Removed { name, .. } => {
            records.remove(name);
        }
        KoiEvent::Found(record) => {
            if key == META_QUERY {
                records.insert(record.name.clone(), record.clone());
            }
        }
    }
}

/// Build the replay for a new subscriber of a type. Meta entries replay as
/// Found events (the browser worker treats them as discovered types); normal
/// entries replay as Resolved (the durable, resolved facts).
fn replay_events(is_meta: bool, records: &HashMap<String, ServiceRecord>) -> VecDeque<KoiEvent> {
    records
        .values()
        .cloned()
        .map(|record| {
            if is_meta {
                KoiEvent::Found(record)
            } else {
                KoiEvent::Resolved(record)
            }
        })
        .collect()
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

// ── Service record conversion ─────────────────────────────────────

fn provider_event_to_koi(event: ProviderEvent) -> KoiEvent {
    match event {
        ProviderEvent::Found(service) => KoiEvent::Found(provider_service_to_record(service)),
        ProviderEvent::Resolved(service) => KoiEvent::Resolved(provider_service_to_record(service)),
        ProviderEvent::Removed { name, service_type } => KoiEvent::Removed { name, service_type },
    }
}

/// Project a lossless provider observation onto the existing compatibility
/// record. The provider model retains every interface-scoped address; the
/// public record continues to prefer IPv4 and expose one address for now.
fn provider_service_to_record(service: ProviderService) -> ServiceRecord {
    let ip = service
        .addresses
        .iter()
        .find(|address| address.address.is_ipv4())
        .or_else(|| service.addresses.first())
        .map(|address| address.address);

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

    if service.addresses.len() > 1 {
        tracing::trace!(
            name = %service.name,
            count = service.addresses.len(),
            selected = ?ip,
            "Multiple IPs found, using first"
        );
    }

    ServiceRecord {
        name: service.name,
        service_type: service.service_type,
        host: service.host,
        ip,
        port: service.port,
        txt: service.txt,
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
    use crate::native::NativeMdnsProvider;

    #[derive(Default)]
    struct TestProvider {
        browses: Mutex<HashMap<String, tokio::sync::mpsc::Sender<ProviderEvent>>>,
    }

    #[async_trait::async_trait]
    impl MdnsProvider for TestProvider {
        fn name(&self) -> &'static str {
            "test"
        }

        fn capabilities(&self) -> crate::adapter::MdnsCapabilities {
            crate::adapter::MdnsCapabilities::FULL_PROVIDER
        }

        fn api(&self) -> crate::adapter::AdapterApi {
            crate::adapter::AdapterApi::Embedded
        }

        fn status(&self) -> ProviderStatus {
            ProviderStatus {
                name: self.name().to_string(),
                healthy: true,
                detail: "test provider".to_string(),
            }
        }

        fn register(
            &self,
            _name: &str,
            _service_type: &str,
            _port: u16,
            _ip: Option<&str>,
            _txt: &HashMap<String, String>,
        ) -> Result<()> {
            Ok(())
        }

        fn unregister(&self, _name: &str, _service_type: &str) -> Result<()> {
            Ok(())
        }

        async fn browse(&self, service_type: &str, _is_meta: bool) -> Result<ProviderBrowse> {
            let (tx, rx) = tokio::sync::mpsc::channel(TYPE_BROADCAST_CAPACITY);
            self.browses
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(service_type.to_string(), tx);
            Ok(rx)
        }

        fn stop_browse(&self, service_type: &str) -> Result<()> {
            self.browses
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(service_type);
            Ok(())
        }

        async fn shutdown(&self) -> Result<()> {
            self.browses
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            Ok(())
        }
    }

    fn test_daemon() -> Arc<MdnsDaemon> {
        let (event_tx, _) = broadcast::channel(256);
        Arc::new(MdnsDaemon::new(Arc::new(TestProvider::default()), event_tx))
    }

    fn native_daemon() -> Arc<MdnsDaemon> {
        let (event_tx, _) = broadcast::channel(256);
        let provider = Arc::new(NativeMdnsProvider::new().expect("spawn native mDNS provider"));
        Arc::new(MdnsDaemon::new(provider, event_tx))
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

        // The pump issues exactly one provider browse for all three subscribers.
        assert!(wait_until(|| daemon.browse_starts() >= 1).await);
        assert_eq!(
            daemon.browse_starts(),
            1,
            "3 subscribers must share a single real browse, not start 3"
        );
        drop((sub1, sub2, sub3));
    }

    #[tokio::test]
    async fn receive_activity_tracks_inbound_events() {
        let daemon = test_daemon();

        // Fresh daemon (no browse): nothing received, no active browse.
        let h0 = daemon.receive_activity();
        assert_eq!(h0.events_seen, 0);
        assert_eq!(h0.last_event_age_secs, None);
        assert_eq!(
            h0.browse_active_secs, None,
            "no subscribers → no active browse"
        );

        // An active subscription makes the browse active, with a browse-active duration
        // measured from when the browse started (NOT core uptime).
        let sub = daemon.subscribe_type(TEST_KEY, false);
        assert!(
            wait_until(|| daemon.receive_activity().browse_active_secs.is_some()).await,
            "browse should be active with a subscriber"
        );

        // A received (injected) event bumps the receive-activity signal — the counter
        // rises and the last-event age becomes set. (Uses `> before`/`is_some` so it
        // is robust to incidental real mDNS traffic on the test host.)
        let before = daemon.receive_activity().events_seen;
        daemon.inject(TEST_KEY, resolved("alpha"));
        let h = daemon.receive_activity();
        assert!(
            h.events_seen > before,
            "an inbound event must increment the counter"
        );
        assert!(
            h.last_event_age_secs.is_some(),
            "age is set once something is received"
        );
        assert!(h.browse_active_secs.is_some());
        drop(sub);
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

    #[tokio::test]
    async fn new_subscriber_replays_warm_cache() {
        let daemon = test_daemon();
        // First subscriber starts the browse; warm the cache with a resolved service.
        let sub1 = daemon.subscribe_type(TEST_KEY, false);
        daemon.inject(TEST_KEY, resolved("zeta"));
        let _ = recv_timeout(&sub1).await; // sub1 saw it live

        // A discover that JOINS the already-warm type (the real daemon case: the
        // LAN-wide meta-browse or an earlier discover already cached the service)
        // must still surface it — not just future events. This is the regression
        // guard for "long-lived daemon browse finds nothing, cold standalone resolves".
        let sub2 = daemon.subscribe_type(TEST_KEY, false);
        let replayed = recv_timeout(&sub2)
            .await
            .expect("a new subscriber replays the warm cache");
        assert!(
            matches!(replayed, KoiEvent::Resolved(r) if r.name == "zeta"),
            "joining a warm browse replays the cached resolved service"
        );
    }

    // ── meta replay regression (Windows quiet-LAN browser defect) ────────

    fn type_record(name: &str) -> ServiceRecord {
        ServiceRecord {
            name: name.to_owned(),
            service_type: String::new(),
            host: None,
            ip: None,
            port: None,
            txt: Default::default(),
        }
    }

    #[test]
    fn meta_found_events_are_cached_for_replay() {
        let mut records = HashMap::new();
        cache_update(
            META_QUERY,
            &mut records,
            &KoiEvent::Found(type_record("_http._tcp")),
        );
        cache_update(
            META_QUERY,
            &mut records,
            &KoiEvent::Found(type_record("_ipp._tcp")),
        );
        assert_eq!(records.len(), 2, "meta Found events must be cached");

        let replay = replay_events(true, &records);
        assert_eq!(replay.len(), 2);
        assert!(
            replay
                .iter()
                .all(|event| matches!(event, KoiEvent::Found(_))),
            "meta replay must be Found events (the browser worker matches Found)"
        );
    }

    #[test]
    fn normal_type_found_events_stay_uncached() {
        let mut records = HashMap::new();
        cache_update(
            "_http._tcp.local.",
            &mut records,
            &KoiEvent::Found(type_record("My NAS")),
        );
        assert!(
            records.is_empty(),
            "unresolved Found teasers must not displace the durable Resolved facts"
        );
    }

    #[test]
    fn normal_type_replay_is_resolved() {
        let mut records = HashMap::new();
        let resolved = ServiceRecord {
            name: "My NAS".to_owned(),
            service_type: "_http._tcp".to_owned(),
            host: Some("nas.local.".to_owned()),
            ip: Some("192.168.1.10".to_owned()),
            port: Some(5000),
            txt: Default::default(),
        };
        cache_update(
            "_http._tcp.local.",
            &mut records,
            &KoiEvent::Resolved(resolved.clone()),
        );
        let replay = replay_events(false, &records);
        assert_eq!(replay.len(), 1);
        assert!(
            matches!(&replay[0], KoiEvent::Resolved(r) if r.name == "My NAS"),
            "normal replay stays Resolved"
        );
    }

    #[test]
    fn removed_event_still_evicts_from_meta_cache() {
        let mut records = HashMap::new();
        cache_update(
            META_QUERY,
            &mut records,
            &KoiEvent::Found(type_record("_http._tcp")),
        );
        cache_update(
            META_QUERY,
            &mut records,
            &KoiEvent::Removed {
                name: "_http._tcp".to_owned(),
                service_type: String::new(),
            },
        );
        assert!(records.is_empty(), "removals evict meta cache entries");
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

    #[test]
    fn browse_retry_backoff_is_bounded() {
        let mut delay = BROWSE_RETRY_INITIAL;
        for _ in 0..16 {
            delay = next_browse_retry(delay);
        }
        assert_eq!(delay, BROWSE_RETRY_MAX);
        assert_eq!(next_browse_retry(delay), BROWSE_RETRY_MAX);
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
        let daemon = native_daemon();
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
        let daemon = native_daemon();
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
        let daemon = native_daemon();
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
