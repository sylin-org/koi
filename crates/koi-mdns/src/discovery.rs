use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use koi_common::integration::MdnsDiscoverySnapshot;
use koi_common::status::StatusFeed;
use koi_common::types::{ServiceRecord, ServiceType, META_QUERY};

use crate::control_plane::MdnsControlPlane;
use crate::error::{MdnsError, Result};
use crate::events::MdnsEvent as KoiEvent;
use crate::provider::{ProviderBrowse, ProviderEvent, ProviderService};
use crate::{MdnsDiscoverySummary, MdnsStatus};

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
const BROWSE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(8);

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
    cancel: CancellationToken,
    records: HashMap<String, ServiceRecord>, // instance name -> record
    gen: u64,
    /// Whether this generation currently owns a live provider observation
    /// route. Accepted records survive a route loss; this bit tells the cheap
    /// primary status that those facts are temporarily stale while the pump
    /// reconnects.
    observing: bool,
}

// ── DiscoveryHub ────────────────────────────────────────────────────

/// Provider-neutral browse hub that multiplexes one real browse per type across
/// many subscribers. Provider policy remains in [`MdnsControlPlane`].
pub(crate) struct DiscoveryHub {
    control_plane: Arc<MdnsControlPlane>,
    /// Browse hub: canonical service type -> shared browse.
    types: Mutex<HashMap<String, TypeBrowse>>,
    /// Pumps whose last subscriber has gone away. Their cancellation is
    /// synchronous, but the hub retains each handle until it can reap it; Drop
    /// never manufactures a detached waiter task.
    retired_pumps: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Core-wide event channel (every active pump feeds this).
    event_tx: broadcast::Sender<KoiEvent>,
    /// Domain-owned current discovery truth. Events are only notifications;
    /// lagging or late consumers recover from this immutable snapshot.
    status: StatusFeed<MdnsDiscoverySnapshot>,
    /// The enclosing domain projection. Discovery updates its own facet
    /// synchronously before semantic events leave the boundary.
    domain_status: StatusFeed<MdnsStatus>,
    next_gen: AtomicU64,
}

impl DiscoveryHub {
    pub fn new(
        control_plane: Arc<MdnsControlPlane>,
        event_tx: broadcast::Sender<KoiEvent>,
        domain_status: StatusFeed<MdnsStatus>,
    ) -> Self {
        Self {
            control_plane,
            types: Mutex::new(HashMap::new()),
            retired_pumps: Mutex::new(Vec::new()),
            event_tx,
            status: StatusFeed::default(),
            domain_status,
            next_gen: AtomicU64::new(0),
        }
    }

    /// Start a real provider browse for a service type. Internal: only the pump
    /// calls this. Returns normalized provider observations.
    async fn browse_raw(&self, service_type: &str, is_meta: bool) -> Result<ProviderBrowse> {
        self.control_plane.browse(service_type, is_meta).await
    }

    /// Subscribe to the core-wide event stream (all active types).
    pub fn subscribe_all(&self) -> broadcast::Receiver<KoiEvent> {
        self.event_tx.subscribe()
    }

    /// Current immutable discovery snapshot in constant time.
    pub fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot> {
        self.status.current()
    }

    /// Subscribe to coalesced discovery changes.
    pub fn watch_snapshot(&self) -> tokio::sync::watch::Receiver<Arc<MdnsDiscoverySnapshot>> {
        self.status.subscribe()
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
            let entry = types.entry(key.to_string()).or_insert_with(|| {
                let (tx, _rx0) = broadcast::channel(TYPE_BROADCAST_CAPACITY);
                let gen = self.next_gen.fetch_add(1, Ordering::Relaxed);
                let cancel = CancellationToken::new();
                let pump =
                    spawn_type_pump(self.clone(), key.to_string(), is_meta, gen, cancel.clone());
                TypeBrowse {
                    tx,
                    refcount: 0,
                    pump: Some(pump),
                    cancel,
                    records: HashMap::new(),
                    gen,
                    observing: false,
                }
            });
            entry.refcount += 1;
            // Replay the warm cache to THIS subscriber only. mdns-sd replays its cache
            // synchronously to the FIRST listener of a type; the hub then shares that one
            // browse across N subscribers via a future-only broadcast. So a discover that
            // joins a type already being browsed (the lazy LAN-wide meta-browse, or an
            // earlier discover) would get future events only and never surface services
            // mdns-sd already resolved — exactly why a long-lived daemon's browse found
            // nothing while a cold standalone resolved fine. Replaying `records` here
            // closes that gap deterministically, without re-broadcasting to peers.
            // Retained records belong to the authoritative stale snapshot while
            // the provider route is unavailable. A new subscriber must not
            // receive them as if they were observations from a live browser.
            let replay = if entry.observing {
                replay_events(is_meta, &entry.records)
            } else {
                VecDeque::new()
            };
            let subscription = (entry.tx.subscribe(), entry.gen, replay);
            self.publish_snapshot(&types);
            subscription
        };

        BrowseSubscription {
            rx: tokio::sync::Mutex::new(rx),
            replay: std::sync::Mutex::new(replay),
            _guard: Arc::new(TypeGuard {
                hub: self.clone(),
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
        if let Some(record) = self.fresh_cached_record(&key, target_name) {
            return Ok(record);
        }
        if self.control_plane.status().routes.resolve.is_some() {
            match self.control_plane.resolve(target_name, &key).await {
                Ok(service) => {
                    return Ok(provider_service_to_record(service));
                }
                Err(error) => {
                    tracing::debug!(
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
        if let Some(record) = self.fresh_cached_record(&key, target_name) {
            return Ok(record);
        }

        let deadline = tokio::time::Instant::now() + RESOLVE_TIMEOUT;
        loop {
            tokio::select! {
                event = sub.recv() => {
                    match event {
                        Ok(KoiEvent::Resolved(record)) if record.name == target_name => {
                            return Ok(record);
                        }
                        Ok(_) => continue,
                        Err(BrowseRecvError::Lagged { dropped }) => {
                            tracing::debug!(dropped, %instance, "resolve subscriber lagged; rereading discovery state");
                            if let Some(record) = self.fresh_cached_record(&key, target_name) {
                                return Ok(record);
                            }
                        }
                        Err(BrowseRecvError::Closed) => break,
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    // A resolved event can be overwritten in the bounded stream
                    // while its current fact is already committed to the domain.
                    if let Some(record) = self.fresh_cached_record(&key, target_name) {
                        return Ok(record);
                    }
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

    /// Look up a record accepted by the current live provider observation.
    ///
    /// Records retained across route loss remain in [`Self::snapshot`] as stale
    /// facts, but cannot acknowledge a point resolution until a new raw browse
    /// observes them again.
    fn fresh_cached_record(&self, key: &str, target_name: &str) -> Option<ServiceRecord> {
        let types = self.types.lock().unwrap_or_else(|e| e.into_inner());
        let entry = types.get(key)?;
        if !entry.observing {
            return None;
        }
        entry.records.get(target_name).cloned()
    }

    /// Pump output: update the records cache and fan out to the per-type channel
    /// and the core-wide channel exactly once each. Skips stale-generation pumps.
    fn pump_emit(&self, key: &str, gen: u64, event: KoiEvent) {
        commit_pump_event(
            &self.types,
            &self.status,
            &self.domain_status,
            &self.event_tx,
            key,
            gen,
            event,
        );
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

    /// Shut down every demanded browse and await native browser release.
    pub async fn shutdown_browses(&self) {
        struct AbortOnDrop(Vec<tokio::task::JoinHandle<()>>);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                for pump in &self.0 {
                    pump.abort();
                }
            }
        }

        let mut pumps = {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            let active = types
                .drain()
                .filter_map(|(_key, mut entry)| {
                    entry.cancel.cancel();
                    entry.pump.take()
                })
                .collect::<Vec<_>>();
            let mut retired = self
                .retired_pumps
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            retired.extend(active);
            self.publish_snapshot(&types);
            AbortOnDrop(std::mem::take(&mut *retired))
        };
        let deadline = tokio::time::Instant::now() + BROWSE_SHUTDOWN_TIMEOUT;
        let mut timed_out = false;
        for pump in &mut pumps.0 {
            if !timed_out {
                match tokio::time::timeout_at(deadline, &mut *pump).await {
                    Ok(_) => continue,
                    Err(_) => timed_out = true,
                }
            }
            pump.abort();
            let _ = (&mut *pump).await;
        }
        pumps.0.clear();
    }

    /// Synchronous last-owner fence used when orderly terminal completion can
    /// no longer be awaited (facade drop or an unexpected terminal panic).
    pub(crate) fn fail_close(&self) {
        let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
        for (_, mut entry) in types.drain() {
            entry.cancel.cancel();
            if let Some(pump) = entry.pump.take() {
                pump.abort();
            }
        }
        for pump in self
            .retired_pumps
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
        {
            pump.abort();
        }
        self.publish_snapshot(&types);
    }

    fn publish_snapshot(&self, types: &HashMap<String, TypeBrowse>) {
        publish_snapshot_to(&self.status, &self.domain_status, types);
    }

    /// Publish whether one demanded browse generation currently has a provider
    /// observation route. Route loss is not service removal: accepted facts
    /// remain until an explicit provider removal or this browse's owner retires
    /// the complete generation.
    fn set_generation_observing(&self, key: &str, gen: u64, observing: bool) {
        let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
        if !set_observing_for_generation(&mut types, key, gen, observing) {
            return;
        }
        self.publish_snapshot(&types);
    }

    /// Admit a newly opened raw provider browse for one logical subscription.
    ///
    /// A false -> true transition may follow provider loss. Any records retained
    /// during that loss belong to the retired raw observation and cannot become
    /// current merely because a replacement receiver opened. Remove them while
    /// the route is still unavailable, publish both status projections, notify
    /// subscribers of those removals, and only then admit fresh observations.
    fn admit_observation_route(&self, key: &str, gen: u64) {
        let (type_tx, retired_records) = {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            let Some(entry) = types.get_mut(key) else {
                return;
            };
            if entry.gen != gen || entry.observing {
                return;
            }

            let type_tx = entry.tx.clone();
            let mut retired_records = entry
                .records
                .drain()
                .map(|(_, record)| record)
                .collect::<Vec<_>>();
            retired_records.sort_by(|left, right| {
                left.service_type
                    .cmp(&right.service_type)
                    .then_with(|| left.name.cmp(&right.name))
            });

            if !retired_records.is_empty() {
                self.publish_snapshot(&types);
            }
            (type_tx, retired_records)
        };

        // The authoritative full and bounded statuses already exclude every
        // retired record before either best-effort event stream is notified.
        for record in retired_records {
            let event = KoiEvent::Removed {
                name: record.name,
                service_type: record.service_type,
            };
            let _ = type_tx.send(event.clone());
            let _ = self.event_tx.send(event);
        }
        self.set_generation_observing(key, gen, true);
    }
}

/// Commit an observed fact to both authoritative latest-value projections before
/// releasing its best-effort notification. A consumer woken by either event
/// channel can therefore immediately reread coherent domain truth.
fn commit_pump_event(
    types: &Mutex<HashMap<String, TypeBrowse>>,
    discovery_status: &StatusFeed<MdnsDiscoverySnapshot>,
    domain_status: &StatusFeed<MdnsStatus>,
    event_tx: &broadcast::Sender<KoiEvent>,
    key: &str,
    generation: u64,
    event: KoiEvent,
) {
    {
        let mut types = types.lock().unwrap_or_else(|error| error.into_inner());
        let Some(entry) = types.get_mut(key) else {
            return;
        };
        if entry.gen != generation {
            return;
        }
        cache_update(key, &mut entry.records, &event);
        let type_tx = entry.tx.clone();
        publish_snapshot_to(discovery_status, domain_status, &types);
        let _ = type_tx.send(event.clone());
    }
    let _ = event_tx.send(event);
}

fn publish_snapshot_to(
    status: &StatusFeed<MdnsDiscoverySnapshot>,
    domain_status: &StatusFeed<MdnsStatus>,
    types: &HashMap<String, TypeBrowse>,
) {
    let (service_types, records) = snapshot_contents(types);
    let unavailable_browse_count = types
        .values()
        .filter(|entry| entry.refcount > 0 && !entry.observing)
        .count();
    let snapshot = status.update(move |current| {
        if current.service_types == service_types && current.records == records {
            return None;
        }
        Some(MdnsDiscoverySnapshot {
            revision: current.revision.saturating_add(1),
            service_types,
            records,
        })
    });
    publish_domain_discovery(domain_status, &snapshot, unavailable_browse_count);
}

fn set_observing_for_generation(
    types: &mut HashMap<String, TypeBrowse>,
    key: &str,
    generation: u64,
    observing: bool,
) -> bool {
    let Some(entry) = types.get_mut(key) else {
        return false;
    };
    if entry.gen != generation || entry.observing == observing {
        return false;
    }
    entry.observing = observing;
    true
}

fn publish_domain_discovery(
    status: &StatusFeed<MdnsStatus>,
    snapshot: &MdnsDiscoverySnapshot,
    unavailable_browse_count: usize,
) {
    let discovery = MdnsDiscoverySummary {
        revision: snapshot.revision,
        service_type_count: snapshot.service_types.len(),
        record_count: snapshot.records.len(),
        unavailable_browse_count,
    };
    status.update(move |current| {
        if current.discovery == discovery {
            return None;
        }
        let mut next = current.clone();
        next.revision = current.revision.saturating_add(1);
        next.discovery = discovery;
        Some(next)
    });
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

/// Delivery condition for one best-effort browse subscription.
///
/// `Lagged` is deliberately explicit: callers that maintain a projection must
/// reread [`crate::MdnsCore::discovery_snapshot`] rather than guessing what was
/// missed. `Closed` means the shared domain browse has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BrowseRecvError {
    #[error("browse subscription lagged by {dropped} events")]
    Lagged { dropped: u64 },
    #[error("browse subscription closed")]
    Closed,
}

impl BrowseSubscription {
    fn pop_fresh_replay(&self) -> Option<KoiEvent> {
        // Keep the route liveness check and replay removal in one critical
        // section. A route-loss update takes the same `types` lock, so a
        // retained observation can never be dequeued after that loss has been
        // admitted by the discovery boundary.
        let types = self
            ._guard
            .hub
            .types
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let observing = types
            .get(&self._guard.key)
            .is_some_and(|entry| entry.gen == self._guard.gen && entry.observing);
        let mut replay = self.replay.lock().unwrap_or_else(|e| e.into_inner());
        if !observing {
            replay.clear();
            return None;
        }
        replay.pop_front()
    }

    /// Receive the next best-effort service event.
    ///
    /// A lagging subscriber never stalls the shared pump. Lag is returned to
    /// the caller so a stateful consumer can converge from authoritative status.
    pub async fn recv(&self) -> std::result::Result<KoiEvent, BrowseRecvError> {
        // Warm-cache replay first (cached resolved services), then live events.
        if let Some(event) = self.pop_fresh_replay() {
            return Ok(event);
        }
        let mut rx = self.rx.lock().await;
        let result = map_browse_receive(rx.recv().await);
        if let Err(BrowseRecvError::Lagged { dropped }) = &result {
            tracing::warn!(dropped, "mDNS subscription lagged; status resync required");
        }
        result
    }
}

fn map_browse_receive(
    result: std::result::Result<KoiEvent, broadcast::error::RecvError>,
) -> std::result::Result<KoiEvent, BrowseRecvError> {
    result.map_err(|error| match error {
        broadcast::error::RecvError::Lagged(dropped) => BrowseRecvError::Lagged { dropped },
        broadcast::error::RecvError::Closed => BrowseRecvError::Closed,
    })
}

/// Refcount guard: the last drop stops the shared browse and removes the entry.
struct TypeGuard {
    hub: Arc<DiscoveryHub>,
    key: String,
    gen: u64,
}

impl Drop for TypeGuard {
    fn drop(&mut self) {
        // Short, std-mutex-only critical section — no `.await`, no nested daemon
        // locks. Safe because `subscribe_type` never holds `types` across an await.
        let mut types = self.hub.types.lock().unwrap_or_else(|e| e.into_inner());
        let removed = match types.get_mut(&self.key) {
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
        };

        if let Some(mut entry) = removed {
            entry.cancel.cancel();
            if let Some(pump) = entry.pump.take() {
                let mut retired = self
                    .hub
                    .retired_pumps
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                // Completed handles no longer own a task and can be dropped;
                // live handles remain owned until hub shutdown reaps them.
                retired.retain(|task| !task.is_finished());
                retired.push(pump);
            }
            self.hub.publish_snapshot(&types);
        }
    }
}

impl Drop for DiscoveryHub {
    fn drop(&mut self) {
        self.fail_close();
    }
}

fn snapshot_contents(types: &HashMap<String, TypeBrowse>) -> (Vec<String>, Vec<ServiceRecord>) {
    let mut service_types = types
        .get(META_QUERY)
        .into_iter()
        .flat_map(|browse| browse.records.values())
        .map(|record| record.name.clone())
        .collect::<Vec<_>>();
    service_types.sort();
    service_types.dedup();

    let mut records = types
        .iter()
        .filter(|(service_type, _)| service_type.as_str() != META_QUERY)
        .flat_map(|(_, browse)| browse.records.values().cloned())
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.service_type
            .cmp(&right.service_type)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.host.cmp(&right.host))
            .then_with(|| left.ip.cmp(&right.ip))
            .then_with(|| left.port.cmp(&right.port))
    });
    (service_types, records)
}

// ── Pump ──────────────────────────────────────────────────────────

/// Spawn the per-type pump task: one real browse, translated and fanned out.
fn spawn_type_pump(
    daemon: Arc<DiscoveryHub>,
    key: String,
    is_meta: bool,
    gen: u64,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    // The pump emits via `daemon.pump_emit`, which fans out through the hub
    // entry's sender (and the core-wide channel) and updates the records cache.
    tokio::spawn(async move {
        let mut retry_delay = BROWSE_RETRY_INITIAL;

        loop {
            let opened = tokio::select! {
                _ = cancel.cancelled() => return,
                result = daemon.browse_raw(&key, is_meta) => result,
            };
            let mut receiver = match opened {
                Ok(receiver) => {
                    daemon.admit_observation_route(&key, gen);
                    receiver
                }
                Err(e) => {
                    if !daemon.browse_generation_is_live(&key, gen) {
                        return;
                    }
                    daemon.set_generation_observing(&key, gen, false);
                    tracing::debug!(
                        key = %key,
                        error = %e,
                        retry_ms = retry_delay.as_millis(),
                        "mDNS browse waiting for an available provider route"
                    );
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = tokio::time::sleep(retry_delay) => {}
                    }
                    retry_delay = next_browse_retry(retry_delay);
                    continue;
                }
            };

            // A platform backend may close its receiver or emit SearchStopped even
            // though Koi still has consumers (observed on constrained macOS hosts).
            // Keep the shared channel alive and re-establish the raw browse here.
            // Cancellation closes and awaits the provider-owned browser lease.
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        if let Err(error) = receiver.close().await {
                            tracing::debug!(%error, key = %key, "mDNS browse close failed");
                        }
                        return;
                    }
                    event = receiver.recv() => {
                        let Some(provider_event) = event else { break; };
                        daemon.pump_emit(&key, gen, provider_event_to_koi(provider_event));
                        retry_delay = BROWSE_RETRY_INITIAL;
                    }
                }
            }

            // EOF reports only loss of the provider observation route. It is
            // not an authoritative removal of every service already observed
            // through that route, so retain the accepted cache while retrying.
            daemon.set_generation_observing(&key, gen, false);
            if let Err(error) = receiver.close().await {
                tracing::debug!(%error, key = %key, "closed mDNS browse cleanup failed");
            }

            if !daemon.browse_generation_is_live(&key, gen) {
                return;
            }

            tracing::debug!(
                key = %key,
                retry_ms = retry_delay.as_millis(),
                "mDNS browse route closed; restarting while subscribers remain"
            );
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(retry_delay) => {}
            }
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

/// Project a provider observation onto the existing compatibility record.
///
/// Selection is deterministic, but it never rewrites provider truth. In
/// particular, an observed loopback address belongs to the publishing host;
/// replacing it with one of this consumer's interface addresses would invent
/// reachability and could point at an entirely different service.
fn provider_service_to_record(service: ProviderService) -> ServiceRecord {
    let ip = service
        .addresses
        .iter()
        .find(|address| address.address.is_ipv4())
        .or_else(|| service.addresses.first())
        .map(|address| address.address);

    let ip = ip.map(|address| address.to_string());

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ProviderAddress, ProviderService};
    use crate::registry::RegistrationRegistry;

    fn cached_browse(records: impl IntoIterator<Item = ServiceRecord>) -> TypeBrowse {
        let (tx, _) = broadcast::channel(1);
        TypeBrowse {
            tx,
            refcount: 1,
            pump: None,
            cancel: CancellationToken::new(),
            records: records
                .into_iter()
                .map(|record| (record.name.clone(), record))
                .collect(),
            gen: 1,
            observing: true,
        }
    }

    fn record(name: &str, service_type: &str) -> ServiceRecord {
        ServiceRecord {
            name: name.to_string(),
            service_type: service_type.to_string(),
            host: Some(format!("{name}.local.")),
            ip: Some("192.0.2.10".to_string()),
            port: Some(80),
            txt: HashMap::new(),
        }
    }

    #[test]
    fn canonical_key_normalizes_equivalent_types() {
        assert_eq!(
            canonical_key("_http._tcp").unwrap(),
            canonical_key("_http._tcp.local.").unwrap()
        );
    }

    #[test]
    fn canonical_key_preserves_meta_query_identity() {
        assert_eq!(
            canonical_key(META_QUERY).unwrap(),
            (META_QUERY.to_string(), true)
        );
    }

    #[test]
    fn provider_projection_prefers_ipv4_but_keeps_record_data() {
        let record = provider_service_to_record(ProviderService {
            name: "printer".to_string(),
            service_type: "_ipp._tcp".to_string(),
            host: Some("printer.local.".to_string()),
            addresses: vec![
                ProviderAddress {
                    address: "fe80::1".parse().unwrap(),
                    interface_index: Some(2),
                    interface_name: Some("eth0".to_string()),
                },
                ProviderAddress {
                    address: "192.0.2.10".parse().unwrap(),
                    interface_index: Some(2),
                    interface_name: Some("eth0".to_string()),
                },
            ],
            port: Some(631),
            txt: HashMap::from([("note".to_string(), "office".to_string())]),
        });
        assert_eq!(record.ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(record.port, Some(631));
        assert_eq!(record.txt["note"], "office");
    }

    #[test]
    fn provider_projection_never_rewrites_a_peers_loopback_address() {
        let record = provider_service_to_record(ProviderService {
            name: "loopback-only".to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some("peer.local.".to_string()),
            addresses: vec![ProviderAddress {
                address: "127.0.0.1".parse().unwrap(),
                interface_index: Some(7),
                interface_name: Some("peer-loopback".to_string()),
            }],
            port: Some(8080),
            txt: HashMap::new(),
        });

        assert_eq!(record.ip.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(next_browse_retry(Duration::from_secs(4)), BROWSE_RETRY_MAX);
        assert_eq!(next_browse_retry(BROWSE_RETRY_MAX), BROWSE_RETRY_MAX);
    }

    #[test]
    fn authoritative_snapshot_is_sorted_and_removal_safe() {
        let http_type = record("_http._tcp.local.", META_QUERY);
        let ssh_type = record("_ssh._tcp.local.", META_QUERY);
        let mut types = HashMap::from([
            (META_QUERY.to_string(), cached_browse([http_type, ssh_type])),
            (
                "_http._tcp.local.".to_string(),
                cached_browse([
                    record("zeta", "_http._tcp.local."),
                    record("alpha", "_http._tcp.local."),
                ]),
            ),
        ]);

        let (service_types, records) = snapshot_contents(&types);
        assert_eq!(service_types, vec!["_http._tcp.local.", "_ssh._tcp.local."]);
        assert_eq!(
            records
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zeta"]
        );

        types
            .get_mut("_http._tcp.local.")
            .unwrap()
            .records
            .remove("alpha");
        let (_, records) = snapshot_contents(&types);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "zeta");
    }

    #[test]
    fn route_loss_marks_only_its_generation_unavailable_and_retains_records() {
        let mut types = HashMap::from([(
            "_http._tcp.local.".to_string(),
            TypeBrowse {
                gen: 9,
                ..cached_browse([record("old", "_http._tcp.local.")])
            },
        )]);

        assert!(!set_observing_for_generation(
            &mut types,
            "_http._tcp.local.",
            8,
            false,
        ));
        assert_eq!(types["_http._tcp.local."].records.len(), 1);
        assert!(set_observing_for_generation(
            &mut types,
            "_http._tcp.local.",
            9,
            false,
        ));
        assert_eq!(types["_http._tcp.local."].records.len(), 1);
        assert!(!types["_http._tcp.local."].observing);
    }

    #[tokio::test]
    async fn stale_records_remain_in_snapshot_but_cannot_resolve_or_replay() {
        let control = MdnsControlPlane::start(Vec::new(), Arc::new(RegistrationRegistry::new()))
            .await
            .expect("native control plane");
        let (events, _) = broadcast::channel(4);
        let domain = StatusFeed::default();
        let hub = Arc::new(DiscoveryHub::new(
            Arc::clone(&control),
            events,
            domain.clone(),
        ));
        let key = "_http._tcp.local.";
        let stale = record("old", key);
        hub.types
            .lock()
            .unwrap()
            .insert(key.to_string(), cached_browse([stale.clone()]));
        {
            let types = hub.types.lock().unwrap();
            hub.publish_snapshot(&types);
        }

        assert_eq!(hub.fresh_cached_record(key, "old"), Some(stale.clone()));
        let fresh_subscriber = hub.subscribe_type(key, false);
        assert_eq!(
            fresh_subscriber.pop_fresh_replay(),
            Some(KoiEvent::Resolved(stale.clone()))
        );
        drop(fresh_subscriber);
        let pending_replay = hub.subscribe_type(key, false);

        hub.set_generation_observing(key, 1, false);
        assert_eq!(hub.snapshot().records, vec![stale]);
        assert_eq!(domain.current().discovery.unavailable_browse_count, 1);
        assert!(hub.fresh_cached_record(key, "old").is_none());
        assert!(pending_replay.pop_fresh_replay().is_none());
        drop(pending_replay);

        let subscriber = hub.subscribe_type(key, false);
        assert!(subscriber.pop_fresh_replay().is_none());
        drop(subscriber);

        hub.shutdown_browses().await;
        control.shutdown().await.expect("control-plane shutdown");
    }

    #[tokio::test]
    async fn reopened_route_retires_absent_records_before_removal_notifications() {
        let control = MdnsControlPlane::start(Vec::new(), Arc::new(RegistrationRegistry::new()))
            .await
            .expect("native control plane");
        let (events, mut all_events) = broadcast::channel(4);
        let domain = StatusFeed::default();
        let hub = Arc::new(DiscoveryHub::new(
            Arc::clone(&control),
            events,
            domain.clone(),
        ));
        let key = "_http._tcp.local.";
        let stale = record("gone-while-unavailable", key);
        let mut browse = cached_browse([stale.clone()]);
        browse.gen = 9;
        browse.observing = false;
        let mut type_events = browse.tx.subscribe();
        hub.types.lock().unwrap().insert(key.to_string(), browse);
        {
            let types = hub.types.lock().unwrap();
            hub.publish_snapshot(&types);
        }
        let unavailable = domain.current();
        assert_eq!(unavailable.discovery.record_count, 1);
        assert_eq!(unavailable.discovery.unavailable_browse_count, 1);

        hub.admit_observation_route(key, 9);

        let snapshot = hub.snapshot();
        let current = domain.current();
        assert!(snapshot.records.is_empty());
        assert_eq!(current.discovery.revision, snapshot.revision);
        assert_eq!(current.discovery.record_count, 0);
        assert_eq!(current.discovery.unavailable_browse_count, 0);
        assert!(hub.types.lock().unwrap()[key].observing);
        assert!(hub.fresh_cached_record(key, &stale.name).is_none());
        let expected = KoiEvent::Removed {
            name: stale.name,
            service_type: stale.service_type,
        };
        assert_eq!(type_events.try_recv().unwrap(), expected);
        assert_eq!(all_events.try_recv().unwrap(), expected);

        hub.shutdown_browses().await;
        control.shutdown().await.expect("control-plane shutdown");
    }

    #[tokio::test]
    async fn bounded_browse_lag_is_explicit_for_authoritative_resync() {
        let (tx, mut rx) = broadcast::channel(1);
        tx.send(KoiEvent::Found(record("first", "_http._tcp.local.")))
            .unwrap();
        tx.send(KoiEvent::Found(record("second", "_http._tcp.local.")))
            .unwrap();

        assert!(matches!(
            map_browse_receive(rx.recv().await),
            Err(BrowseRecvError::Lagged { dropped: 1 })
        ));
        assert!(matches!(
            map_browse_receive(rx.recv().await),
            Ok(KoiEvent::Found(record)) if record.name == "second"
        ));
    }

    #[tokio::test]
    async fn last_subscriber_retires_pump_under_hub_ownership() {
        let control = MdnsControlPlane::start(Vec::new(), Arc::new(RegistrationRegistry::new()))
            .await
            .expect("native control plane");
        let (events, _) = broadcast::channel(4);
        let hub = Arc::new(DiscoveryHub::new(
            Arc::clone(&control),
            events,
            StatusFeed::default(),
        ));

        let subscription = hub.subscribe_type("_http._tcp.local.", false);
        drop(subscription);
        assert!(hub.types.lock().unwrap().is_empty());
        assert_eq!(hub.retired_pumps.lock().unwrap().len(), 1);

        hub.shutdown_browses().await;
        assert!(hub.retired_pumps.lock().unwrap().is_empty());
        control.shutdown().await.expect("control-plane shutdown");
    }

    #[test]
    fn discovery_facet_is_in_domain_status_before_event_fanout() {
        let status = StatusFeed::new(MdnsStatus::default());
        let snapshot = MdnsDiscoverySnapshot {
            revision: 4,
            service_types: vec!["_http._tcp.local.".to_string()],
            records: vec![record("api", "_http._tcp.local.")],
        };

        publish_domain_discovery(&status, &snapshot, 1);
        let current = status.current();
        assert_eq!(current.revision, 1);
        assert_eq!(current.discovery.revision, 4);
        assert_eq!(current.discovery.service_type_count, 1);
        assert_eq!(current.discovery.record_count, 1);
        assert_eq!(current.discovery.unavailable_browse_count, 1);

        let unchanged = status.current();
        publish_domain_discovery(&status, &snapshot, 1);
        assert!(Arc::ptr_eq(&unchanged, &status.current()));
    }

    #[test]
    fn pump_commits_full_and_bounded_status_before_both_event_fanouts() {
        let key = "_http._tcp.local.";
        let mut browse = cached_browse([]);
        browse.gen = 7;
        let mut type_events = browse.tx.subscribe();
        let types = Mutex::new(HashMap::from([(key.to_string(), browse)]));
        let discovery = StatusFeed::<MdnsDiscoverySnapshot>::default();
        let domain = StatusFeed::<MdnsStatus>::default();
        let (all_events, mut all_rx) = broadcast::channel(4);
        let observed = KoiEvent::Resolved(record("api", key));

        commit_pump_event(
            &types,
            &discovery,
            &domain,
            &all_events,
            key,
            7,
            observed.clone(),
        );

        let full = discovery.current();
        assert_eq!(full.revision, 1);
        assert_eq!(full.records, vec![record("api", key)]);
        let bounded = domain.current();
        assert_eq!(bounded.discovery.revision, full.revision);
        assert_eq!(bounded.discovery.record_count, 1);
        assert_eq!(type_events.try_recv().unwrap(), observed);
        assert_eq!(all_rx.try_recv().unwrap(), observed);
    }
}
