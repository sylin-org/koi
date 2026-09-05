//! mDNS browser surface — live network service-discovery explorer.
//!
//! Maintains an in-memory [`BrowserCache`] projected from the mDNS domain's authoritative
//! discovery snapshot. The [`worker`] owns only browse demand: it runs a meta-browse to
//! discover service types, then a per-type browse pump for each. The worker is driven lazily
//! by [`crate::meta_browse::LazyMetaBrowse`] — it starts on the first browser request and
//! idles out, so the daemon performs no LAN-wide browsing until a presentation surface asks.
//!
//! This is a **presentation read model** — the cache is an adapter-level concept, NOT a
//! domain concept.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::Extension;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use serde::Serialize;
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;

use crate::browse_source::{BrowseSource, BrowserEvent};
use crate::meta_browse::LazyMetaBrowse;
use koi_common::integration::MdnsDiscoverySnapshot;
use koi_common::types::ServiceRecord;
use koi_common::types::META_QUERY;

// ── HTML asset ──────────────────────────────────────────────────────

const BROWSER_HTML: &str = include_str!("../assets/mdns-browser.html");

// ── Cache model ─────────────────────────────────────────────────────

/// Seconds after removal before purging from cache.
const PURGE_AFTER_SECS: i64 = 120;

/// Top-level cache: types -> instances tree.
#[derive(Clone)]
pub struct BrowserCache {
    inner: Arc<RwLock<CacheInner>>,
    started_at: Instant,
}

struct CacheInner {
    /// Last accepted revision from the mDNS domain. `None` distinguishes an
    /// uninitialized projection from the domain's valid revision zero.
    source_revision: Option<u64>,
    /// Authoritative current membership. `types` may additionally retain removed
    /// instance tombstones briefly for the UI's fade-out presentation.
    active_types: HashSet<String>,
    types: HashMap<String, DiscoveredType>,
    // Deaf-detection counters (ADR-035 D6): bursts the meta-browse sent vs
    // answers heard. A recent burst with zero answers is the deaf verdict —
    // "announcing but hearing nothing" is a firewall, not a quiet network.
    total_bursts: u64,
    total_answers: u64,
    /// Answers heard since the most recent burst.
    current_burst_answers: u64,
    /// What the PREVIOUS burst heard (finalized when the next one starts).
    last_burst_answers: u64,
    last_burst_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl CacheInner {
    fn empty() -> Self {
        Self {
            source_revision: None,
            active_types: HashSet::new(),
            types: HashMap::new(),
            total_bursts: 0,
            total_answers: 0,
            current_burst_answers: 0,
            last_burst_answers: 0,
            last_burst_at: None,
        }
    }

    fn reconcile(&mut self, snapshot: &MdnsDiscoverySnapshot) -> bool {
        if self
            .source_revision
            .is_some_and(|revision| snapshot.revision <= revision)
        {
            return false;
        }

        let now = Utc::now().to_rfc3339();
        let mut active_types = snapshot
            .service_types
            .iter()
            .map(|service_type| normalize_type(service_type))
            .filter(|service_type| !service_type.is_empty())
            .collect::<HashSet<_>>();
        let mut records = HashMap::new();

        for record in &snapshot.records {
            let service_type = normalize_type(&record.service_type);
            if service_type.is_empty() || record.name.is_empty() {
                continue;
            }
            active_types.insert(service_type.clone());
            records.insert((service_type, record.name.clone()), record);
        }

        for service_type in &active_types {
            self.types
                .entry(service_type.clone())
                .or_insert_with(|| DiscoveredType {
                    service_type: service_type.clone(),
                    first_seen: now.clone(),
                    instances: HashMap::new(),
                });
        }

        for (service_type, dtype) in &mut self.types {
            for (name, instance) in &mut dtype.instances {
                let Some(record) = records.remove(&(service_type.clone(), name.clone())) else {
                    if instance.removed_at.is_none() {
                        instance.removed_at = Some(now.clone());
                    }
                    continue;
                };

                let resolved = has_usable_endpoint(record);
                let changed = instance.host != record.host
                    || instance.ip != record.ip
                    || instance.port != record.port
                    || instance.txt != record.txt
                    || instance.resolved != resolved
                    || instance.removed_at.is_some();
                instance.host.clone_from(&record.host);
                instance.ip.clone_from(&record.ip);
                instance.port = record.port;
                instance.txt.clone_from(&record.txt);
                instance.resolved = resolved;
                instance.removed_at = None;
                if changed {
                    instance.last_seen.clone_from(&now);
                }
            }
        }

        for ((service_type, name), record) in records {
            let dtype = self
                .types
                .entry(service_type.clone())
                .or_insert_with(|| DiscoveredType {
                    service_type: service_type.clone(),
                    first_seen: now.clone(),
                    instances: HashMap::new(),
                });
            dtype.instances.insert(
                name.clone(),
                service_instance(record, &service_type, name, &now),
            );
        }

        self.active_types = active_types;
        let active_types = self.active_types.clone();
        self.types.retain(|service_type, dtype| {
            active_types.contains(service_type) || !dtype.instances.is_empty()
        });
        self.source_revision = Some(snapshot.revision);
        true
    }
}

#[derive(Debug, Clone, Serialize)]
struct DiscoveredType {
    service_type: String,
    first_seen: String,
    instances: HashMap<String, ServiceInstance>,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceInstance {
    name: String,
    instance_name: String,
    service_type: String,
    host: Option<String>,
    ip: Option<String>,
    port: Option<u16>,
    txt: HashMap<String, String>,
    first_seen: String,
    last_seen: String,
    resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    removed_at: Option<String>,
}

impl BrowserCache {
    /// How many service types the cache currently knows (used by the
    /// meta-browse's requery burst report).
    pub async fn known_type_count(&self) -> usize {
        self.inner.read().await.active_types.len()
    }

    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheInner::empty())),
            started_at: Instant::now(),
        }
    }

    /// Construct an immediately truthful cache from the domain's current
    /// projection. Route state uses this instead of exposing an empty cache
    /// during the projector task's first scheduling window.
    pub fn from_snapshot(snapshot: &MdnsDiscoverySnapshot) -> Self {
        let mut inner = CacheInner::empty();
        inner.reconcile(snapshot);
        Self {
            inner: Arc::new(RwLock::new(inner)),
            started_at: Instant::now(),
        }
    }

    /// Reconcile presentation state from the mDNS domain's authoritative projection.
    ///
    /// Membership and service facts come only from this snapshot. Best-effort events
    /// never mutate them. Equal or older revisions are ignored; a removal is retained
    /// only as short-lived presentation metadata so the UI can animate it.
    pub async fn reconcile(&self, snapshot: &MdnsDiscoverySnapshot) -> bool {
        let mut inner = self.inner.write().await;
        inner.reconcile(snapshot)
    }

    /// A fresh query burst just went out (worker start or explicit requery).
    /// Heartbeat touches that find the worker already running are NOT bursts —
    /// otherwise "last burst" would always be moments ago and the deaf verdict
    /// would fire on every quiet LAN.
    pub async fn record_burst(&self) {
        let mut inner = self.inner.write().await;
        inner.total_bursts += 1;
        inner.last_burst_answers = inner.current_burst_answers;
        inner.current_burst_answers = 0;
        inner.last_burst_at = Some(Utc::now());
    }

    /// Record one answer as presentation activity. This intentionally does not
    /// change membership; the corresponding domain snapshot does that.
    async fn record_answer(&self, service: Option<&ServiceRecord>) {
        let mut inner = self.inner.write().await;
        inner.total_answers += 1;
        inner.current_burst_answers += 1;
        if let Some(service) = service {
            let service_type = normalize_type(&service.service_type);
            if inner.active_types.contains(&service_type) {
                let instance = inner
                    .types
                    .get_mut(&service_type)
                    .and_then(|dtype| dtype.instances.get_mut(&service.name));
                if let Some(instance) = instance.filter(|instance| instance.removed_at.is_none()) {
                    instance.last_seen = Utc::now().to_rfc3339();
                }
            }
        }
    }

    async fn purge_stale(&self) {
        let now = Utc::now();
        let mut inner = self.inner.write().await;
        for dtype in inner.types.values_mut() {
            dtype.instances.retain(|_, inst| {
                if let Some(ref removed) = inst.removed_at {
                    if let Ok(removed_time) = chrono::DateTime::parse_from_rfc3339(removed) {
                        let elapsed = now.signed_duration_since(removed_time);
                        return elapsed.num_seconds() < PURGE_AFTER_SECS;
                    }
                }
                true
            });
        }
        let active_types = inner.active_types.clone();
        inner.types.retain(|service_type, dtype| {
            active_types.contains(service_type) || !dtype.instances.is_empty()
        });
    }

    pub async fn snapshot(&self) -> BrowserSnapshot {
        let inner = self.inner.read().await;

        let mut all_instances = Vec::new();
        let mut type_summaries = Vec::new();

        for dtype in inner.types.values() {
            let live_count = dtype
                .instances
                .values()
                .filter(|i| i.removed_at.is_none())
                .count();
            if inner.active_types.contains(&dtype.service_type) {
                let (label, description) = match crate::well_known::annotate(&dtype.service_type) {
                    Some((l, d)) => (Some(l), Some(d)),
                    None => (None, None),
                };
                type_summaries.push(TypeSummary {
                    service_type: dtype.service_type.clone(),
                    count: live_count,
                    first_seen: dtype.first_seen.clone(),
                    label,
                    description,
                });
            }
            for inst in dtype.instances.values() {
                all_instances.push(inst.clone());
            }
        }

        type_summaries.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| left.service_type.cmp(&right.service_type))
        });
        all_instances.sort_by(|a, b| a.last_seen.cmp(&b.last_seen).reverse());

        let burst = BurstStats {
            bursts_sent: inner.total_bursts,
            answers_total: inner.total_answers,
            last_burst_at: inner.last_burst_at.map(|t| t.to_rfc3339()),
            last_burst_answers: inner.last_burst_answers,
            last_burst_age_secs: inner.last_burst_at.map(|t| (Utc::now() - t).num_seconds()),
        };

        BrowserSnapshot {
            revision: inner.source_revision,
            total_types: type_summaries.len(),
            total_instances: all_instances
                .iter()
                .filter(|i| i.removed_at.is_none())
                .count(),
            service_types: type_summaries,
            instances: all_instances,
            cache_age_secs: self.started_at.elapsed().as_secs(),
            burst,
        }
    }
}

impl Default for BrowserCache {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_type(t: &str) -> String {
    t.trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

fn short_name(full_name: &str, service_type: &str) -> String {
    let clean = full_name.trim_end_matches('.');
    for suffix in &[format!(".{service_type}.local"), format!(".{service_type}")] {
        if let Some(prefix) = clean.strip_suffix(suffix.as_str()) {
            let name = prefix.trim_end_matches('.');
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    clean.trim_end_matches(".local").to_string()
}

fn service_instance(
    record: &ServiceRecord,
    service_type: &str,
    instance_name: String,
    now: &str,
) -> ServiceInstance {
    ServiceInstance {
        name: short_name(&instance_name, service_type),
        instance_name,
        service_type: service_type.to_string(),
        host: record.host.clone(),
        ip: record.ip.clone(),
        port: record.port,
        txt: record.txt.clone(),
        first_seen: now.to_string(),
        last_seen: now.to_string(),
        resolved: has_usable_endpoint(record),
        removed_at: None,
    }
}

fn has_usable_endpoint(record: &ServiceRecord) -> bool {
    let has_host = record
        .host
        .as_deref()
        .is_some_and(|host| !host.trim().is_empty());
    let has_ip = record
        .ip
        .as_deref()
        .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok());
    record.port.is_some_and(|port| port != 0) && (has_host || has_ip)
}

// ── Snapshot types ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BrowserSnapshot {
    /// Revision of the authoritative mDNS discovery snapshot projected here.
    /// `None` means no domain snapshot has been accepted yet; revision zero is
    /// a distinct, valid domain fact.
    revision: Option<u64>,
    total_types: usize,
    total_instances: usize,
    service_types: Vec<TypeSummary>,
    instances: Vec<ServiceInstance>,
    cache_age_secs: u64,
    /// Burst vs answers counters — the raw material for the deaf-detection
    /// verdict ("announcing but hearing nothing — firewall, not network").
    burst: BurstStats,
}

/// Deaf-detection counters as data (the pane decides, the daemon measures).
#[derive(Debug, Clone, Serialize)]
pub struct BurstStats {
    pub bursts_sent: u64,
    pub answers_total: u64,
    /// RFC3339 timestamp of the most recent burst, absent before the first.
    pub last_burst_at: Option<String>,
    /// Answers the previous burst heard; zero with a fresh burst is the deaf
    /// verdict's trigger.
    pub last_burst_answers: u64,
    /// Seconds since that burst started, so the pane knows if it is fresh
    /// enough to judge answers against.
    pub last_burst_age_secs: Option<i64>,
}

#[derive(Debug, Serialize)]
struct TypeSummary {
    service_type: String,
    count: usize,
    first_seen: String,
    /// Friendly label for a well-known type (`_hap._tcp` → "HomeKit"), absent for
    /// unrecognized types so the UI falls back to the raw type.
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'static str>,
    /// One-line description of a well-known type, paired with `label`.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'static str>,
}

// ── Background worker ───────────────────────────────────────────────

/// Populate the [`BrowserCache`] by meta-browsing for types and per-type browsing for
/// instances. Runs until `cancel` fires (driven lazily by [`LazyMetaBrowse`]).
pub async fn worker(source: Arc<dyn BrowseSource>, cache: BrowserCache, cancel: CancellationToken) {
    tracing::info!("mDNS browser worker starting");
    // Starting this owned worker is the query-burst boundary. Keeping the
    // accounting in the worker avoids a second fire-and-forget task and makes
    // cancellation before the first browse truthful.
    cache.record_burst().await;

    // Subscribe before arming the meta browse so a synchronous cache replay cannot
    // race past the worker. The watch value is authoritative and already current.
    let mut snapshots = source.watch_snapshot();
    let mut meta_handle = match source.browse(META_QUERY).await {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to start meta-browse");
            None
        }
    };

    let initial = snapshots.borrow_and_update().clone();
    let mut pump_tasks = HashMap::new();
    sync_type_pumps(&source, initial.as_ref(), &mut pump_tasks, &cache, &cancel).await;

    let mut retry_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    retry_interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            event = async {
                match meta_handle.as_mut() {
                    Some(h) => h.recv().await,
                    None => std::future::pending::<Option<BrowserEvent>>().await,
                }
            } => {
                match event {
                    Some(BrowserEvent::Found(_) | BrowserEvent::Resolved(_)) => {
                        cache.record_answer(None).await;
                    }
                    Some(BrowserEvent::Resync) => {
                        cache.reconcile(source.snapshot().as_ref()).await;
                    }
                    Some(BrowserEvent::Removed { .. }) => {}
                    None => meta_handle = None,
                }
            }

            changed = snapshots.changed() => {
                if changed.is_err() {
                    tracing::warn!("mDNS discovery snapshot feed closed; stopping browser worker");
                    break;
                }
                let snapshot = snapshots.borrow_and_update().clone();
                sync_type_pumps(
                    &source,
                    snapshot.as_ref(),
                    &mut pump_tasks,
                    &cache,
                    &cancel,
                ).await;
            }

            _ = retry_interval.tick() => {
                if meta_handle.is_none() {
                    meta_handle = match source.browse(META_QUERY).await {
                        Ok(handle) => Some(handle),
                        Err(error) => {
                            tracing::debug!(%error, "Failed to restart meta-browse");
                            None
                        }
                    };
                }
                let snapshot = snapshots.borrow().clone();
                sync_type_pumps(
                    &source,
                    snapshot.as_ref(),
                    &mut pump_tasks,
                    &cache,
                    &cancel,
                ).await;
            }
        }
    }

    for (_, task) in pump_tasks.drain() {
        task.abort();
        let _ = task.await;
    }
    drop(meta_handle);

    tracing::info!("mDNS browser worker stopped");
}

async fn sync_type_pumps(
    source: &Arc<dyn BrowseSource>,
    snapshot: &MdnsDiscoverySnapshot,
    pumps: &mut HashMap<String, tokio::task::JoinHandle<()>>,
    cache: &BrowserCache,
    cancel: &CancellationToken,
) {
    let finished = pumps
        .iter()
        .filter_map(|(service_type, task)| task.is_finished().then_some(service_type.clone()))
        .collect::<Vec<_>>();
    for service_type in finished {
        if let Some(task) = pumps.remove(&service_type) {
            let _ = task.await;
        }
    }

    let desired = snapshot
        .service_types
        .iter()
        .filter_map(|service_type| {
            let normalized = normalize_type(service_type);
            (!normalized.is_empty()).then(|| (normalized, service_type.clone()))
        })
        .collect::<HashMap<_, _>>();

    let obsolete = pumps
        .keys()
        .filter(|service_type| !desired.contains_key(*service_type))
        .cloned()
        .collect::<Vec<_>>();
    for service_type in obsolete {
        if let Some(task) = pumps.remove(&service_type) {
            task.abort();
            let _ = task.await;
        }
    }

    let mut missing = desired
        .into_iter()
        .filter(|(service_type, _)| !pumps.contains_key(service_type))
        .collect::<Vec<_>>();
    missing.sort_by(|left, right| left.0.cmp(&right.0));

    for (service_type, browse_type) in missing {
        tracing::debug!(%service_type, "Discovered service type, starting per-type browse");
        match source.browse(&browse_type).await {
            Ok(mut handle) => {
                let source = source.clone();
                let cache = cache.clone();
                let cancel = cancel.clone();
                let task = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            event = handle.recv() => {
                                match event {
                                    Some(BrowserEvent::Resolved(record)) => {
                                        cache.record_answer(Some(&record)).await;
                                    }
                                    Some(BrowserEvent::Resync) => {
                                        cache.reconcile(source.snapshot().as_ref()).await;
                                    }
                                    Some(BrowserEvent::Found(_) | BrowserEvent::Removed { .. }) => {}
                                    None => break,
                                }
                            }
                        }
                    }
                });
                pumps.insert(service_type, task);
            }
            Err(error) => {
                tracing::debug!(%error, %browse_type, "Failed to browse type");
            }
        }
    }
}

/// Continuously project domain discovery truth into the presentation cache. Watching
/// the domain is cheap and does not arm multicast browsing; only `worker` owns query
/// demand. Keeping this projector alive also prevents idle-stop from leaving stale
/// membership visible through Pond or the snapshot endpoint.
async fn project_snapshots(
    source: Arc<dyn BrowseSource>,
    cache: BrowserCache,
    cancel: CancellationToken,
) {
    let mut snapshots = source.watch_snapshot();
    let initial = snapshots.borrow_and_update().clone();
    cache.reconcile(initial.as_ref()).await;
    let mut purge_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    purge_interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = purge_interval.tick() => cache.purge_stale().await,
            changed = snapshots.changed() => {
                if changed.is_err() {
                    break;
                }
                let snapshot = snapshots.borrow_and_update().clone();
                cache.reconcile(snapshot.as_ref()).await;
            }
        }
    }
}

// ── SSE stream ──────────────────────────────────────────────────────

pub(crate) fn browser_event_stream(
    source: Arc<dyn BrowseSource>,
    cache: BrowserCache,
    meta: Option<Arc<crate::meta_browse::LazyMetaBrowse>>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        let mut rx = source.subscribe();
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat.tick().await;

        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(BrowserEvent::Resync) => {
                            if let Some(event) = snapshot_resync_event(&source, &cache).await {
                                yield Ok(event);
                            }
                        }
                        Ok(event) => {
                            let sse = match &event {
                                BrowserEvent::Found(record) => {
                                    if record.service_type.is_empty() {
                                        Event::default()
                                            .event("type_found")
                                            .id(uuid::Uuid::now_v7().to_string())
                                            .json_data(serde_json::json!({
                                                "service_type": record.name,
                                            })).ok()
                                    } else {
                                        None
                                    }
                                }
                                BrowserEvent::Resolved(record) => {
                                    Event::default()
                                        .event("resolved")
                                        .id(uuid::Uuid::now_v7().to_string())
                                        .json_data(record).ok()
                                }
                                BrowserEvent::Removed { name, service_type } => {
                                    Event::default()
                                        .event("removed")
                                        .id(uuid::Uuid::now_v7().to_string())
                                        .json_data(serde_json::json!({
                                            "name": name,
                                            "service_type": service_type
                                        })).ok()
                                }
                                BrowserEvent::Resync => unreachable!("handled before event mapping"),
                            };
                            if let Some(ev) = sse {
                                yield Ok(ev);
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(dropped = n, "Browser SSE stream lagged; rereading snapshot");
                            if let Some(event) = snapshot_resync_event(&source, &cache).await {
                                yield Ok(event);
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                },
                _ = heartbeat.tick() => {
                    // An open subscription IS active use: every heartbeat re-touches
                    // the lazy meta-browse so the query worker never idles out under
                    // a connected client. Without this, browsing stops 5 minutes
                    // after subscribe and the pond silently drains.
                    if let Some(meta) = &meta {
                        meta.touch();
                    }
                    let snap = cache.snapshot().await;
                    if let Ok(ev) = Event::default()
                        .event("heartbeat")
                        .json_data(serde_json::json!({
                            "total_types": snap.total_types,
                            "total_instances": snap.total_instances
                        }))
                    {
                        yield Ok(ev);
                    }
                },
            }
        }
    }
}

async fn snapshot_resync_event(
    source: &Arc<dyn BrowseSource>,
    cache: &BrowserCache,
) -> Option<Event> {
    let authoritative = source.snapshot();
    cache.reconcile(authoritative.as_ref()).await;
    let snapshot = cache.snapshot().await;
    Event::default()
        .event("resync")
        .id(snapshot.revision?.to_string())
        .json_data(&snapshot)
        .ok()
}

// ── Shared state ────────────────────────────────────────────────────

/// Shared state for the browser routes.
#[derive(Clone)]
pub struct BrowserState {
    pub source: Arc<dyn BrowseSource>,
    pub cache: BrowserCache,
    pub meta: Arc<LazyMetaBrowse>,
    _lifecycle: Arc<BrowserLifecycle>,
}

struct BrowserLifecycle {
    cancel: CancellationToken,
    projector: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for BrowserLifecycle {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self
            .projector
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            task.abort();
        }
    }
}

impl BrowserState {
    /// Construct route state and own the permanent snapshot projector.
    ///
    /// The projector contains no domain truth; it keeps this presentation cache
    /// converged from the authoritative mDNS snapshot until either the parent
    /// scope or the final route-state clone is dropped.
    pub fn new(
        source: Arc<dyn BrowseSource>,
        cache: BrowserCache,
        meta: Arc<LazyMetaBrowse>,
        parent_cancel: CancellationToken,
    ) -> Self {
        let cancel = parent_cancel.child_token();
        let projector = tokio::spawn(project_snapshots(
            source.clone(),
            cache.clone(),
            cancel.clone(),
        ));
        Self {
            source,
            cache,
            meta,
            _lifecycle: Arc::new(BrowserLifecycle {
                cancel,
                projector: std::sync::Mutex::new(Some(projector)),
            }),
        }
    }
}

/// Build a [`BrowserState`] wrapping the given `MdnsCore` with a lazy meta-browse.
///
/// No LAN-wide browsing happens until the first browser request `touch()`es the
/// controller. `parent_cancel` ties the worker lifetime to daemon/embedded shutdown.
pub fn build_state(
    mdns_core: Arc<koi_mdns::MdnsCore>,
    parent_cancel: CancellationToken,
) -> BrowserState {
    let adapter = crate::browse_source::MdnsBrowseAdapter::new(mdns_core, parent_cancel.clone());
    let source = adapter as Arc<dyn BrowseSource>;
    let cache = BrowserCache::from_snapshot(source.snapshot().as_ref());
    let meta = LazyMetaBrowse::new(source.clone(), cache.clone(), parent_cancel.clone());
    BrowserState::new(source, cache, meta, parent_cancel)
}

// ── Routes ──────────────────────────────────────────────────────────

/// Build the browser sub-router mounted at `/v1/mdns/browser`.
pub fn routes(state: BrowserState) -> Router {
    Router::new()
        .route("/snapshot", get(get_snapshot))
        .route("/events", get(get_events))
        .route("/query", post(post_query))
        .layer(axum::Extension(state))
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /mdns-browser` — Serve the mDNS browser SPA with a Content-Security-Policy header.
pub async fn get_page() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_SECURITY_POLICY, crate::HTML_CSP)],
        Html(BROWSER_HTML),
    )
}

/// `GET /v1/mdns/browser/snapshot` — Full browser cache as JSON.
async fn get_snapshot(Extension(state): Extension<BrowserState>) -> Json<BrowserSnapshot> {
    state.meta.touch();
    Json(state.cache.snapshot().await)
}

/// `GET /v1/mdns/browser/events` — SSE stream of discovery events.
async fn get_events(
    Extension(state): Extension<BrowserState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    state.meta.touch();
    Sse::new(browser_event_stream(
        state.source.clone(),
        state.cache.clone(),
        Some(state.meta.clone()),
    ))
    .keep_alive(KeepAlive::default())
}

/// `POST /v1/mdns/browser/query` — force a fresh mDNS query burst ("ping the
/// pond"): restarts the meta-browse worker so `_services._dns-sd._udp` and
/// every known type are re-queried immediately. Idempotent. DAT-gated like
/// every other POST (a mutation of the browse session).
async fn post_query(Extension(state): Extension<BrowserState>) -> Json<serde_json::Value> {
    let types_known = state.meta.requery().await;
    Json(serde_json::json!({
        "restarted": true,
        "types_known": types_known,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browse_source::{BrowseError, BrowseHandle};
    use crate::meta_browse::{tests::StubSource, LazyMetaBrowse};
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::{broadcast, mpsc, oneshot, watch};
    use tokio_stream::StreamExt;

    fn record(name: &str) -> ServiceRecord {
        ServiceRecord {
            name: name.to_string(),
            service_type: "_ipp._tcp.local.".to_string(),
            host: Some("printer.local.".to_string()),
            ip: Some("192.168.1.42".to_string()),
            port: Some(631),
            txt: HashMap::new(),
        }
    }

    fn discovery(revision: u64, records: Vec<ServiceRecord>) -> MdnsDiscoverySnapshot {
        MdnsDiscoverySnapshot {
            revision,
            service_types: vec!["_ipp._tcp.local.".to_string()],
            records,
            sources: Vec::new(),
            observations: Vec::new(),
        }
    }

    #[tokio::test]
    async fn last_browser_owner_aborts_and_reaps_its_snapshot_projector() {
        struct DropProbe(Option<oneshot::Sender<()>>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                if let Some(done) = self.0.take() {
                    let _ = done.send(());
                }
            }
        }

        let cancel = CancellationToken::new();
        let observed_cancel = cancel.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let projector = tokio::spawn(async move {
            let _probe = DropProbe(Some(dropped_tx));
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.expect("projector started");

        drop(BrowserLifecycle {
            cancel,
            projector: std::sync::Mutex::new(Some(projector)),
        });

        assert!(observed_cancel.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("aborted projector is reaped by the runtime")
            .expect("projector drop probe remains connected");
    }

    #[tokio::test]
    async fn seeded_cache_is_truthful_before_any_projector_task_runs() {
        let cache = BrowserCache::from_snapshot(&discovery(7, vec![record("ready-now")]));
        let visible = cache.snapshot().await;

        assert_eq!(visible.revision, Some(7));
        assert_eq!(visible.total_types, 1);
        assert_eq!(visible.total_instances, 1);
        assert_eq!(visible.instances[0].name, "ready-now");
    }

    #[tokio::test]
    async fn uninitialized_cache_does_not_invent_revision_zero() {
        let visible = BrowserCache::new().snapshot().await;

        assert_eq!(visible.revision, None);
        let wire = serde_json::to_value(visible).expect("browser snapshot JSON");
        assert!(wire["revision"].is_null());
    }

    #[tokio::test]
    async fn partial_record_stays_partial_and_unresolved() {
        let mut partial = record("missing-port");
        partial.ip = None;
        partial.port = None;
        let cache = BrowserCache::from_snapshot(&discovery(1, vec![partial]));

        let visible = cache.snapshot().await;
        let instance = &visible.instances[0];
        assert_eq!(instance.host.as_deref(), Some("printer.local."));
        assert_eq!(instance.ip, None);
        assert_eq!(instance.port, None);
        assert!(!instance.resolved);
        let wire = serde_json::to_value(&visible).expect("browser snapshot JSON");
        assert!(wire["instances"][0]["ip"].is_null());
        assert!(wire["instances"][0]["port"].is_null());

        let mut unusable = record("no-locator");
        unusable.host = Some("  ".to_string());
        unusable.ip = Some("not-an-ip".to_string());
        let cache = BrowserCache::from_snapshot(&discovery(2, vec![unusable]));
        let visible = cache.snapshot().await;
        let instance = &visible.instances[0];
        assert_eq!(instance.host.as_deref(), Some("  "));
        assert_eq!(instance.ip.as_deref(), Some("not-an-ip"));
        assert_eq!(instance.port, Some(631));
        assert!(!instance.resolved);
    }

    #[tokio::test]
    async fn nonzero_port_and_either_concrete_locator_resolve() {
        let mut host_endpoint = record("host-endpoint");
        host_endpoint.ip = None;
        let mut ip_endpoint = record("ip-endpoint");
        ip_endpoint.host = None;
        let cache = BrowserCache::from_snapshot(&discovery(1, vec![host_endpoint, ip_endpoint]));

        let visible = cache.snapshot().await;
        assert_eq!(visible.instances.len(), 2);
        assert!(visible.instances.iter().all(|instance| instance.resolved));
    }

    #[tokio::test]
    async fn complete_record_resolves_without_rewriting_optional_fields() {
        let cache = BrowserCache::from_snapshot(&discovery(1, vec![record("complete")]));

        let visible = cache.snapshot().await;
        let instance = &visible.instances[0];
        assert_eq!(instance.host.as_deref(), Some("printer.local."));
        assert_eq!(instance.ip.as_deref(), Some("192.168.1.42"));
        assert_eq!(instance.port, Some(631));
        assert!(instance.resolved);
    }

    /// The contract the workbench (and any long-lived subscriber) depends on:
    /// a held-open events stream keeps the lazy meta-browse worker alive past
    /// the idle window, because every heartbeat re-touches the controller.
    /// Regression: the worker used to idle-stop 5 minutes after subscribe and
    /// the pond silently drained to a handful of entries.
    #[tokio::test]
    async fn burst_counters_judge_answers_per_burst() {
        // D6 (deaf-detection): bursts are counted, answers land on the burst
        // that heard them, and the snapshot exposes the previous burst's
        // answer count — the raw material for "announcing but hearing nothing".
        let cache = BrowserCache::new();
        let fresh = cache.snapshot().await;
        assert_eq!(fresh.burst.bursts_sent, 0);
        assert_eq!(fresh.burst.answers_total, 0);
        assert!(fresh.burst.last_burst_at.is_none());

        cache.record_burst().await;
        cache.record_answer(None).await;
        cache.record_answer(None).await;
        cache.record_answer(None).await;

        // A second burst finalizes the first one's answer count.
        cache.record_burst().await;
        let snap = cache.snapshot().await;
        assert_eq!(snap.burst.bursts_sent, 2);
        assert_eq!(
            snap.burst.answers_total, 3,
            "one meta answer + two resolutions"
        );
        assert_eq!(
            snap.burst.last_burst_answers, 3,
            "what the first burst heard"
        );
        assert_eq!(snap.burst.last_burst_age_secs, Some(0));
        assert!(snap.burst.last_burst_at.is_some());
    }

    #[tokio::test]
    async fn authoritative_snapshot_owns_membership_and_rejects_revision_rollback() {
        let cache = BrowserCache::new();
        assert!(
            cache
                .reconcile(&discovery(4, vec![record("Brother HL")]))
                .await
        );

        let visible = cache.snapshot().await;
        assert_eq!(visible.revision, Some(4));
        assert_eq!(visible.total_types, 1);
        assert_eq!(visible.total_instances, 1);

        let removed = MdnsDiscoverySnapshot {
            revision: 6,
            service_types: Vec::new(),
            records: Vec::new(),
            sources: Vec::new(),
            observations: Vec::new(),
        };
        assert!(cache.reconcile(&removed).await);
        assert!(!cache.reconcile(&discovery(5, vec![record("stale")])).await);
        let late_event = record("Brother HL");
        cache.record_answer(Some(&late_event)).await;

        let converged = cache.snapshot().await;
        assert_eq!(converged.revision, Some(6));
        assert_eq!(converged.total_types, 0);
        assert_eq!(converged.total_instances, 0);
        assert_eq!(
            converged.instances.len(),
            1,
            "removal tombstone is presentation-only"
        );
        assert!(converged.instances[0].removed_at.is_some());
    }

    #[tokio::test]
    async fn late_projection_subscriber_starts_from_current_snapshot() {
        let source = StubSource::new();
        source.publish_snapshot(discovery(9, vec![record("Office Printer")]));
        let source = source as Arc<dyn BrowseSource>;
        let cache = BrowserCache::new();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(project_snapshots(source, cache.clone(), cancel.clone()));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if cache.snapshot().await.revision == Some(9) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late subscriber reconciles immediately");

        let snapshot = cache.snapshot().await;
        assert_eq!(snapshot.total_instances, 1);
        cancel.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn worker_arms_types_from_current_snapshot_without_event_replay() {
        let source = StubSource::new();
        source.publish_snapshot(discovery(3, Vec::new()));
        let cache = BrowserCache::new();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(worker(
            source.clone() as Arc<dyn BrowseSource>,
            cache,
            cancel.clone(),
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            while source.browse_count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("current snapshot arms meta plus the discovered type browse");
        assert_eq!(source.browse_count(), 2);

        cancel.cancel();
        task.await.unwrap();
    }

    struct PreLaggedSource {
        snapshot: Arc<MdnsDiscoverySnapshot>,
        event_rx: Mutex<Option<broadcast::Receiver<BrowserEvent>>>,
        snapshot_tx: watch::Sender<Arc<MdnsDiscoverySnapshot>>,
    }

    impl PreLaggedSource {
        fn new(snapshot: MdnsDiscoverySnapshot) -> Arc<Self> {
            let (event_tx, event_rx) = broadcast::channel(1);
            event_tx
                .send(BrowserEvent::Removed {
                    name: "missed".to_string(),
                    service_type: "_ipp._tcp.local.".to_string(),
                })
                .unwrap();
            event_tx.send(BrowserEvent::Resync).unwrap();
            let snapshot = Arc::new(snapshot);
            let (snapshot_tx, _) = watch::channel(snapshot.clone());
            Arc::new(Self {
                snapshot,
                event_rx: Mutex::new(Some(event_rx)),
                snapshot_tx,
            })
        }
    }

    impl BrowseSource for PreLaggedSource {
        fn browse(
            &self,
            _service_type: &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<BrowseHandle, BrowseError>> + Send + '_>,
        > {
            let (_tx, rx) = mpsc::channel(1);
            Box::pin(async move { Ok(BrowseHandle::new(rx)) })
        }

        fn subscribe(&self) -> broadcast::Receiver<BrowserEvent> {
            self.event_rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .expect("test stream subscribes once")
        }

        fn snapshot(&self) -> Arc<MdnsDiscoverySnapshot> {
            self.snapshot.clone()
        }

        fn watch_snapshot(&self) -> watch::Receiver<Arc<MdnsDiscoverySnapshot>> {
            self.snapshot_tx.subscribe()
        }
    }

    #[tokio::test]
    async fn lagged_sse_consumer_rereads_authoritative_snapshot() {
        let source = PreLaggedSource::new(discovery(12, vec![record("Recovered Printer")]))
            as Arc<dyn BrowseSource>;
        let cache = BrowserCache::new();
        let stream = browser_event_stream(source, cache.clone(), None);
        tokio::pin!(stream);

        let event = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("lag produces a prompt resync event")
            .expect("stream remains open");
        assert!(event.is_ok());

        let snapshot = cache.snapshot().await;
        assert_eq!(snapshot.revision, Some(12));
        assert_eq!(snapshot.total_instances, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn held_open_event_stream_keeps_meta_browse_alive() {
        let idle = Duration::from_secs(300);
        let stub = StubSource::new();
        let dyn_source = stub.clone() as Arc<dyn BrowseSource>;
        let meta = LazyMetaBrowse::with_intervals(
            dyn_source.clone(),
            BrowserCache::new(),
            CancellationToken::new(),
            idle,
            Duration::from_secs(30),
        );
        meta.touch();

        let stream = browser_event_stream(dyn_source, BrowserCache::new(), Some(meta.clone()));
        tokio::pin!(stream);

        // Drive the stream past the idle window in heartbeat-sized steps.
        for _ in 0..24 {
            tokio::time::advance(Duration::from_secs(15)).await;
            tokio::task::yield_now().await;
            // Each poll consumes one heartbeat, which must re-touch the meta.
            let _ = stream.next().await;
        }

        assert!(
            meta.is_active(),
            "worker must still run after {}s: heartbeats keep the surface active",
            idle.as_secs()
        );
        assert!(stub.browse_count() >= 1, "the meta-browse was started");
        // The touch count is not directly exposed; browse_count staying >= 1
        // with is_active() true past the idle window IS the contract.
        let _ = stub.browses.load(Ordering::SeqCst);
    }
}
