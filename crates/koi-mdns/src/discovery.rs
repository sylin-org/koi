use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use koi_common::types::{ServiceRecord, ServiceType, META_QUERY};

use crate::control_plane::MdnsControlPlane;
use crate::error::{MdnsError, Result};
use crate::events::MdnsEvent as KoiEvent;
use crate::provider::{ProviderBrowse, ProviderEvent, ProviderService};

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
    cancel: CancellationToken,
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

// ── DiscoveryHub ────────────────────────────────────────────────────

/// Provider-neutral browse hub that multiplexes one real browse per type across
/// many subscribers. Provider policy remains in [`MdnsControlPlane`].
pub(crate) struct DiscoveryHub {
    control_plane: Arc<MdnsControlPlane>,
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
}

impl DiscoveryHub {
    pub fn new(
        control_plane: Arc<MdnsControlPlane>,
        event_tx: broadcast::Sender<KoiEvent>,
    ) -> Self {
        Self {
            control_plane,
            types: Mutex::new(HashMap::new()),
            event_tx,
            next_gen: AtomicU64::new(0),
            baseline: Instant::now(),
            events_seen: AtomicU64::new(0),
            last_event_ms: AtomicU64::new(0),
            first_browse_ms: AtomicU64::new(0),
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
        if let Some(record) = self.cached_record(&key, target_name) {
            return Ok(record);
        }
        if self.control_plane.status().routes.resolve.is_some() {
            match self.control_plane.resolve(target_name, &key).await {
                Ok(service) => {
                    self.note_inbound();
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

    /// Shut down every demanded browse and await native browser release.
    pub async fn shutdown_browses(&self) {
        let pumps = {
            let mut types = self.types.lock().unwrap_or_else(|e| e.into_inner());
            types
                .drain()
                .filter_map(|(_key, mut entry)| {
                    entry.cancel.cancel();
                    entry.pump.take()
                })
                .collect::<Vec<_>>()
        };
        for pump in pumps {
            let _ = pump.await;
        }
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
    hub: Arc<DiscoveryHub>,
    key: String,
    gen: u64,
}

impl Drop for TypeGuard {
    fn drop(&mut self) {
        // Short, std-mutex-only critical section — no `.await`, no nested daemon
        // locks. Safe because `subscribe_type` never holds `types` across an await.
        let removed = {
            let mut types = self.hub.types.lock().unwrap_or_else(|e| e.into_inner());
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
            entry.cancel.cancel();
            if let Some(pump) = entry.pump.take() {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        let _ = pump.await;
                    });
                } else {
                    pump.abort();
                }
            }
        }
    }
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
    use crate::provider::{ProviderAddress, ProviderService};

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
    fn retry_backoff_is_bounded() {
        assert_eq!(next_browse_retry(Duration::from_secs(4)), BROWSE_RETRY_MAX);
        assert_eq!(next_browse_retry(BROWSE_RETRY_MAX), BROWSE_RETRY_MAX);
    }
}
