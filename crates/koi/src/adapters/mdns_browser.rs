//! mDNS browser adapter — live network service discovery explorer.
//!
//! Maintains an in-memory `BrowserCache` populated by a background
//! worker. The worker runs a meta-browse to discover service types,
//! then spawns a per-type browse **pump** for each discovered type.
//! Each pump calls `BrowseHandle::recv()` which both feeds the
//! broadcast channel AND populates the cache with resolved instances.
//!
//! **App-state model:**
//!
//! ```text
//! BrowserCache
//!   └─ types: HashMap<String, DiscoveredType>
//!        └─ instances: HashMap<String, ServiceInstance>
//! ```
//!
//! This is a **presentation adapter** — the cache is an adapter-level
//! read model, NOT a domain concept. All data flows from `MdnsCore`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::Extension;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, Json};
use axum::routing::get;
use axum::Router;
use chrono::Utc;
use serde::Serialize;
use tokio::sync::RwLock;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;

use koi_common::types::META_QUERY;
use koi_mdns::MdnsEvent;

// ── HTML asset ──────────────────────────────────────────────────────

const BROWSER_HTML: &str = include_str!("../../assets/mdns-browser.html");

// ── Cache model ─────────────────────────────────────────────────────

/// Top-level cache: types → instances tree.
#[derive(Clone)]
pub(crate) struct BrowserCache {
    inner: Arc<RwLock<CacheInner>>,
    started_at: Instant,
}

struct CacheInner {
    /// Discovered service types, keyed by normalized type name (e.g. "_http._tcp").
    types: HashMap<String, DiscoveredType>,
}

/// A discovered mDNS service type with its resolved instances.
#[derive(Debug, Clone, Serialize)]
struct DiscoveredType {
    /// Normalized type name (e.g. "_http._tcp").
    service_type: String,
    /// When this type was first seen.
    first_seen: String,
    /// Resolved service instances keyed by full instance name.
    instances: HashMap<String, ServiceInstance>,
}

/// A resolved service instance.
#[derive(Debug, Clone, Serialize)]
struct ServiceInstance {
    /// Short display name (e.g. "My NAS").
    name: String,
    /// Full mDNS instance name (e.g. "My NAS._http._tcp.local.").
    instance_name: String,
    /// Parent type (e.g. "_http._tcp").
    service_type: String,
    /// Resolved hostname.
    host: String,
    /// Resolved IP address.
    ip: String,
    /// Resolved port.
    port: u16,
    /// TXT record key-value pairs.
    txt: HashMap<String, String>,
    /// ISO 8601 timestamp of first sighting.
    first_seen: String,
    /// ISO 8601 timestamp of latest update.
    last_seen: String,
    /// Whether this instance has been fully resolved.
    resolved: bool,
    /// If removed, the ISO 8601 timestamp when it was removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    removed_at: Option<String>,
}

/// Maximum total instances across all types.
const MAX_INSTANCES: usize = 2000;

/// Seconds after removal before purging from cache.
const PURGE_AFTER_SECS: i64 = 120;

impl BrowserCache {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheInner {
                types: HashMap::new(),
            })),
            started_at: Instant::now(),
        }
    }

    /// Record a discovered service type (from meta-browse).
    async fn record_type(&self, type_name: &str) {
        let now = Utc::now().to_rfc3339();
        let normalized = normalize_type(type_name);
        let mut inner = self.inner.write().await;
        inner
            .types
            .entry(normalized.clone())
            .or_insert_with(|| DiscoveredType {
                service_type: normalized,
                first_seen: now,
                instances: HashMap::new(),
            });
    }

    /// Record a resolved instance.
    async fn record_resolved(&self, record: &koi_common::types::ServiceRecord) {
        let now = Utc::now().to_rfc3339();
        let mut inner = self.inner.write().await;

        let svc_type = normalize_type(&record.service_type);

        // Ensure type entry exists
        let type_entry = inner
            .types
            .entry(svc_type.clone())
            .or_insert_with(|| DiscoveredType {
                service_type: svc_type.clone(),
                first_seen: now.clone(),
                instances: HashMap::new(),
            });

        // Upsert instance
        let full_name = record.name.clone();
        type_entry
            .instances
            .entry(full_name.clone())
            .and_modify(|inst| {
                inst.host = record.host.clone().unwrap_or_default();
                inst.ip = record.ip.clone().unwrap_or_default();
                inst.port = record.port.unwrap_or(inst.port);
                inst.txt = record.txt.clone();
                inst.resolved = true;
                inst.last_seen = now.clone();
                inst.removed_at = None;
            })
            .or_insert_with(|| ServiceInstance {
                name: short_name(&full_name, &svc_type),
                instance_name: full_name,
                service_type: svc_type,
                host: record.host.clone().unwrap_or_default(),
                ip: record.ip.clone().unwrap_or_default(),
                port: record.port.unwrap_or(0),
                txt: record.txt.clone(),
                first_seen: now.clone(),
                last_seen: now,
                resolved: true,
                removed_at: None,
            });

        // Enforce global instance cap
        let total: usize = inner.types.values().map(|t| t.instances.len()).sum();
        if total > MAX_INSTANCES {
            evict_oldest_instance(&mut inner.types);
        }
    }

    /// Mark an instance as removed, searching all types.
    async fn record_removed(&self, full_name: &str) {
        let now = Utc::now().to_rfc3339();
        let mut inner = self.inner.write().await;
        for dtype in inner.types.values_mut() {
            if let Some(inst) = dtype.instances.get_mut(full_name) {
                inst.removed_at = Some(now);
                return;
            }
        }
    }

    /// Purge instances removed longer than PURGE_AFTER_SECS ago.
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
        // Remove types whose instances are ALL gone (keep types with 0 live
        // instances only if they still have recently-removed entries).
        inner.types.retain(|_, dtype| !dtype.instances.is_empty());
    }

    /// Build a full snapshot for the API.
    async fn snapshot(&self) -> BrowserSnapshot {
        let inner = self.inner.read().await;

        let mut all_instances = Vec::new();
        let mut type_summaries = Vec::new();

        for dtype in inner.types.values() {
            let live_count = dtype
                .instances
                .values()
                .filter(|i| i.removed_at.is_none())
                .count();
            type_summaries.push(TypeSummary {
                service_type: dtype.service_type.clone(),
                count: live_count,
                first_seen: dtype.first_seen.clone(),
            });
            for inst in dtype.instances.values() {
                all_instances.push(inst.clone());
            }
        }

        type_summaries.sort_by(|a, b| b.count.cmp(&a.count));
        all_instances.sort_by(|a, b| a.last_seen.cmp(&b.last_seen).reverse());

        BrowserSnapshot {
            total_types: type_summaries.len(),
            total_instances: all_instances
                .iter()
                .filter(|i| i.removed_at.is_none())
                .count(),
            service_types: type_summaries,
            instances: all_instances,
            cache_age_secs: self.started_at.elapsed().as_secs(),
        }
    }
}

fn normalize_type(t: &str) -> String {
    t.trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

fn short_name(full_name: &str, service_type: &str) -> String {
    // Extract instance name from "My NAS._http._tcp.local."
    let clean = full_name.trim_end_matches('.');
    for suffix in &[
        format!(".{service_type}.local"),
        format!(".{service_type}"),
    ] {
        if let Some(prefix) = clean.strip_suffix(suffix.as_str()) {
            let name = prefix.trim_end_matches('.');
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    // Fallback: strip .local
    clean.trim_end_matches(".local").to_string()
}

fn evict_oldest_instance(types: &mut HashMap<String, DiscoveredType>) {
    let mut oldest_key = None;
    let mut oldest_type = None;
    let mut oldest_time = String::new();

    for (tname, dtype) in types.iter() {
        for (iname, inst) in &dtype.instances {
            if oldest_key.is_none() || inst.last_seen < oldest_time {
                oldest_time = inst.last_seen.clone();
                oldest_key = Some(iname.clone());
                oldest_type = Some(tname.clone());
            }
        }
    }

    if let (Some(tname), Some(iname)) = (oldest_type, oldest_key) {
        if let Some(dtype) = types.get_mut(&tname) {
            dtype.instances.remove(&iname);
        }
    }
}

// ── Snapshot types ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct BrowserSnapshot {
    total_types: usize,
    total_instances: usize,
    service_types: Vec<TypeSummary>,
    instances: Vec<ServiceInstance>,
    cache_age_secs: u64,
}

#[derive(Debug, Serialize)]
struct TypeSummary {
    service_type: String,
    count: usize,
    first_seen: String,
}

// ── Background worker ────────────────────────────────────────────────

/// Spawns the browser worker that populates the `BrowserCache`.
///
/// Architecture:
/// 1. Meta-browse discovers service types → `record_type()`
/// 2. For each discovered type, a per-type **pump task** is spawned
///    that calls `BrowseHandle::recv()` in a loop, which both feeds
///    the global broadcast channel AND gives us `Resolved` events
///    to write into the cache.
/// 3. Purge timer cleans stale entries every 30s.
pub(crate) async fn worker(
    mdns_core: Arc<koi_mdns::MdnsCore>,
    cache: BrowserCache,
    cancel: CancellationToken,
) {
    tracing::info!("mDNS browser worker starting");

    // Start the meta-browse to discover all service types
    let meta_handle = match mdns_core.browse(META_QUERY).await {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to start meta-browse");
            None
        }
    };

    let mut discovered_types = std::collections::HashSet::new();
    let mut pump_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // Purge timer
    let mut purge_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    purge_interval.tick().await; // skip immediate tick

    // Main loop: drive meta-browse, spawn per-type pumps, purge
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            // Drive the meta-browse handle to discover service types
            Some(event) = async {
                match meta_handle.as_ref() {
                    Some(h) => h.recv().await,
                    None => std::future::pending::<Option<MdnsEvent>>().await,
                }
            } => {
                if let MdnsEvent::Found(record) = event {
                    let type_name = record.name.clone();
                    if type_name.is_empty() {
                        continue;
                    }

                    cache.record_type(&type_name).await;

                    let normalized = normalize_type(&type_name);
                    if discovered_types.insert(normalized.clone()) {
                        tracing::debug!(service_type = %normalized, "Discovered service type, starting per-type browse");

                        // Start a per-type browse
                        let browse_type = format!("{normalized}.local.");
                        match mdns_core.browse(&browse_type).await {
                            Ok(handle) => {
                                // Spawn a pump task that drives recv() — this is
                                // critical: BrowseHandle::recv() is the pump that
                                // feeds events into the broadcast channel.
                                let cache_clone = cache.clone();
                                let cancel_clone = cancel.clone();

                                let task = tokio::spawn(async move {
                                    loop {
                                        tokio::select! {
                                            _ = cancel_clone.cancelled() => break,
                                            result = handle.recv() => {
                                                match result {
                                                    Some(MdnsEvent::Resolved(record)) => {
                                                        cache_clone.record_resolved(&record).await;
                                                    }
                                                    Some(MdnsEvent::Removed { name, .. }) => {
                                                        cache_clone.record_removed(&name).await;
                                                    }
                                                    Some(MdnsEvent::Found(_)) => {
                                                        // Per-type browses can emit Found
                                                        // but we already track types above.
                                                    }
                                                    None => break, // browse stopped
                                                }
                                            }
                                        }
                                    }
                                });
                                pump_tasks.push(task);
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, browse_type, "Failed to browse type");
                            }
                        }
                    }
                }
            }

            // Periodic purge
            _ = purge_interval.tick() => {
                cache.purge_stale().await;
            }
        }
    }

    // Shutdown: abort pump tasks
    for task in &pump_tasks {
        task.abort();
    }

    tracing::info!("mDNS browser worker stopped");
}

// ── SSE stream builder ───────────────────────────────────────────────

fn browser_event_stream(
    mdns_core: Arc<koi_mdns::MdnsCore>,
    cache: BrowserCache,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        let mut rx = mdns_core.subscribe();
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat.tick().await; // skip immediate tick

        loop {
            tokio::select! {
                Ok(event) = rx.recv() => {
                    let sse = match &event {
                        MdnsEvent::Found(record) => {
                            // Forward type discoveries (from meta-browse
                            // where service_type is empty)
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
                        MdnsEvent::Resolved(record) => {
                            Event::default()
                                .event("resolved")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(record).ok()
                        }
                        MdnsEvent::Removed { name, service_type } => {
                            Event::default()
                                .event("removed")
                                .id(uuid::Uuid::now_v7().to_string())
                                .json_data(serde_json::json!({
                                    "name": name,
                                    "service_type": service_type
                                })).ok()
                        }
                    };
                    if let Some(ev) = sse {
                        yield Ok(ev);
                    }
                },
                _ = heartbeat.tick() => {
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

// ── Shared state ─────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct BrowserState {
    pub(crate) mdns_core: Arc<koi_mdns::MdnsCore>,
    pub(crate) cache: BrowserCache,
}

// ── Routes ───────────────────────────────────────────────────────────

/// Build the browser sub-router mounted at `/v1/mdns/browser`.
pub(crate) fn routes(state: BrowserState) -> Router {
    Router::new()
        .route("/snapshot", get(get_snapshot))
        .route("/events", get(get_events))
        .layer(axum::Extension(state))
}

// ── Handlers ─────────────────────────────────────────────────────────

/// `GET /mdns-browser` — Serve the mDNS browser SPA.
pub(crate) async fn get_page() -> Html<&'static str> {
    Html(BROWSER_HTML)
}

/// `GET /v1/mdns/browser/snapshot` — Full browser cache as JSON.
async fn get_snapshot(
    Extension(state): Extension<BrowserState>,
) -> Json<BrowserSnapshot> {
    Json(state.cache.snapshot().await)
}

/// `GET /v1/mdns/browser/events` — SSE stream of discovery events.
async fn get_events(
    Extension(state): Extension<BrowserState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    Sse::new(browser_event_stream(state.mdns_core.clone(), state.cache.clone()))
        .keep_alive(KeepAlive::default())
}
