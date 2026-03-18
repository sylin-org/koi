//! mDNS browser adapter — live network service discovery explorer.
//!
//! Maintains an in-memory [`BrowserCache`] populated by a background
//! worker.  The worker runs a meta-browse to discover service types,
//! then spawns a per-type browse pump for each discovered type.
//!
//! Domain-specific mDNS operations are abstracted behind the
//! [`BrowseSource`] trait so that both the standalone daemon and
//! embedded mode can provide their own implementation.
//!
//! This is a **presentation adapter** — the cache is an adapter-level
//! read model, NOT a domain concept.

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
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;

use crate::types::META_QUERY;

// ── HTML asset ──────────────────────────────────────────────────────

const BROWSER_HTML: &str = include_str!("../assets/mdns-browser.html");

// ── Domain-agnostic types ───────────────────────────────────────────

/// A resolved service instance (domain-agnostic mirror of
/// `koi_common::types::ServiceRecord` with guaranteed non-optional
/// fields for the browser cache).
#[derive(Clone, Debug, Serialize)]
pub struct ResolvedService {
    pub name: String,
    pub service_type: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub txt: HashMap<String, String>,
}

/// Domain-agnostic browser event.
#[derive(Clone, Debug)]
pub enum BrowserEvent {
    Found { name: String, service_type: String },
    Resolved(ResolvedService),
    Removed { name: String, service_type: String },
}

impl From<&crate::types::ServiceRecord> for ResolvedService {
    fn from(record: &crate::types::ServiceRecord) -> Self {
        Self {
            name: record.name.clone(),
            service_type: record.service_type.clone(),
            host: record.host.clone().unwrap_or_default(),
            ip: record.ip.clone().unwrap_or_default(),
            port: record.port.unwrap_or(0),
            txt: record.txt.clone(),
        }
    }
}

/// Error returned by [`BrowseSource::browse`].
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BrowseError(pub String);

/// Handle for receiving events from a single browse operation.
pub struct BrowseHandle {
    rx: mpsc::Receiver<BrowserEvent>,
}

impl BrowseHandle {
    /// Create a new handle from an mpsc receiver.
    pub fn new(rx: mpsc::Receiver<BrowserEvent>) -> Self {
        Self { rx }
    }

    /// Receive the next event, or `None` if the browse stopped.
    pub async fn recv(&mut self) -> Option<BrowserEvent> {
        self.rx.recv().await
    }
}

/// Trait abstracting mDNS browse operations.
///
/// Implemented by the caller wrapping their concrete `MdnsCore`.
pub trait BrowseSource: Send + Sync {
    /// Start browsing for the given service type.
    ///
    /// Returns a handle that yields events for this browse.
    fn browse(
        &self,
        service_type: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BrowseHandle, BrowseError>> + Send + '_>,
    >;

    /// Subscribe to the global event broadcast channel.
    fn subscribe(&self) -> broadcast::Receiver<BrowserEvent>;
}

// ── Cache model ─────────────────────────────────────────────────────

/// Maximum total instances across all types.
const MAX_INSTANCES: usize = 2000;

/// Seconds after removal before purging from cache.
const PURGE_AFTER_SECS: i64 = 120;

/// Top-level cache: types -> instances tree.
#[derive(Clone)]
pub struct BrowserCache {
    inner: Arc<RwLock<CacheInner>>,
    started_at: Instant,
}

struct CacheInner {
    types: HashMap<String, DiscoveredType>,
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
    host: String,
    ip: String,
    port: u16,
    txt: HashMap<String, String>,
    first_seen: String,
    last_seen: String,
    resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    removed_at: Option<String>,
}

impl BrowserCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheInner {
                types: HashMap::new(),
            })),
            started_at: Instant::now(),
        }
    }

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

    async fn record_resolved(&self, record: &ResolvedService) {
        let now = Utc::now().to_rfc3339();
        let mut inner = self.inner.write().await;

        let svc_type = normalize_type(&record.service_type);

        let type_entry = inner
            .types
            .entry(svc_type.clone())
            .or_insert_with(|| DiscoveredType {
                service_type: svc_type.clone(),
                first_seen: now.clone(),
                instances: HashMap::new(),
            });

        let full_name = record.name.clone();
        type_entry
            .instances
            .entry(full_name.clone())
            .and_modify(|inst| {
                inst.host.clone_from(&record.host);
                inst.ip.clone_from(&record.ip);
                inst.port = record.port;
                inst.txt.clone_from(&record.txt);
                inst.resolved = true;
                inst.last_seen.clone_from(&now);
                inst.removed_at = None;
            })
            .or_insert_with(|| ServiceInstance {
                name: short_name(&full_name, &svc_type),
                instance_name: full_name,
                service_type: svc_type,
                host: record.host.clone(),
                ip: record.ip.clone(),
                port: record.port,
                txt: record.txt.clone(),
                first_seen: now.clone(),
                last_seen: now,
                resolved: true,
                removed_at: None,
            });

        let total: usize = inner.types.values().map(|t| t.instances.len()).sum();
        if total > MAX_INSTANCES {
            evict_oldest_instance(&mut inner.types);
        }
    }

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
        inner.types.retain(|_, dtype| !dtype.instances.is_empty());
    }

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

fn evict_oldest_instance(types: &mut HashMap<String, DiscoveredType>) {
    let mut oldest_key = None;
    let mut oldest_type = None;
    let mut oldest_time = String::new();

    for (tname, dtype) in types.iter() {
        for (iname, inst) in &dtype.instances {
            if oldest_key.is_none() || inst.last_seen < oldest_time {
                oldest_time.clone_from(&inst.last_seen);
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

// ── Snapshot types ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BrowserSnapshot {
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

// ── Background worker ───────────────────────────────────────────────

/// Spawns the browser worker that populates the [`BrowserCache`].
///
/// The caller is responsible for spawning this as a tokio task.
pub async fn worker(source: Arc<dyn BrowseSource>, cache: BrowserCache, cancel: CancellationToken) {
    tracing::info!("mDNS browser worker starting");

    let mut meta_handle = match source.browse(META_QUERY).await {
        Ok(handle) => Some(handle),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to start meta-browse");
            None
        }
    };

    let mut discovered_types = std::collections::HashSet::new();
    let mut pump_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    let mut purge_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    purge_interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            Some(event) = async {
                match meta_handle.as_mut() {
                    Some(h) => h.recv().await,
                    None => std::future::pending::<Option<BrowserEvent>>().await,
                }
            } => {
                if let BrowserEvent::Found { ref name, .. } = event {
                    let type_name = name.clone();
                    if type_name.is_empty() {
                        continue;
                    }

                    cache.record_type(&type_name).await;

                    let normalized = normalize_type(&type_name);
                    if discovered_types.insert(normalized.clone()) {
                        tracing::debug!(service_type = %normalized, "Discovered service type, starting per-type browse");

                        let browse_type = format!("{normalized}.local.");
                        match source.browse(&browse_type).await {
                            Ok(mut handle) => {
                                let cache_clone = cache.clone();
                                let cancel_clone = cancel.clone();

                                let task = tokio::spawn(async move {
                                    loop {
                                        tokio::select! {
                                            _ = cancel_clone.cancelled() => break,
                                            result = handle.recv() => {
                                                match result {
                                                    Some(BrowserEvent::Resolved(record)) => {
                                                        cache_clone.record_resolved(&record).await;
                                                    }
                                                    Some(BrowserEvent::Removed { name, .. }) => {
                                                        cache_clone.record_removed(&name).await;
                                                    }
                                                    Some(BrowserEvent::Found { .. }) => {}
                                                    None => break,
                                                }
                                            }
                                        }
                                    }
                                });
                                pump_tasks.push(task);
                                pump_tasks.retain(|h| !h.is_finished());
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, browse_type, "Failed to browse type");
                            }
                        }
                    }
                }
            }

            _ = purge_interval.tick() => {
                cache.purge_stale().await;
            }
        }
    }

    for task in &pump_tasks {
        task.abort();
    }

    tracing::info!("mDNS browser worker stopped");
}

// ── SSE stream ──────────────────────────────────────────────────────

fn browser_event_stream(
    source: Arc<dyn BrowseSource>,
    cache: BrowserCache,
) -> impl Stream<Item = Result<Event, Infallible>> {
    async_stream::stream! {
        let mut rx = source.subscribe();
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(15));
        heartbeat.tick().await;

        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(event) => {
                            let sse = match &event {
                                BrowserEvent::Found { name, service_type } => {
                                    if service_type.is_empty() {
                                        Event::default()
                                            .event("type_found")
                                            .id(uuid::Uuid::now_v7().to_string())
                                            .json_data(serde_json::json!({
                                                "service_type": name,
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
                            };
                            if let Some(ev) = sse {
                                yield Ok(ev);
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(dropped = n, "Browser SSE stream lagged");
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
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

// ── Shared state ────────────────────────────────────────────────────

/// Shared state for the browser routes.
#[derive(Clone)]
pub struct BrowserState {
    pub source: Arc<dyn BrowseSource>,
    pub cache: BrowserCache,
}

// ── Routes ──────────────────────────────────────────────────────────

/// Build the browser sub-router mounted at `/v1/mdns/browser`.
pub fn routes(state: BrowserState) -> Router {
    Router::new()
        .route("/snapshot", get(get_snapshot))
        .route("/events", get(get_events))
        .layer(axum::Extension(state))
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /mdns-browser` — Serve the mDNS browser SPA.
pub async fn get_page() -> Html<&'static str> {
    Html(BROWSER_HTML)
}

/// `GET /v1/mdns/browser/snapshot` — Full browser cache as JSON.
async fn get_snapshot(Extension(state): Extension<BrowserState>) -> Json<BrowserSnapshot> {
    Json(state.cache.snapshot().await)
}

/// `GET /v1/mdns/browser/events` — SSE stream of discovery events.
async fn get_events(
    Extension(state): Extension<BrowserState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    Sse::new(browser_event_stream(
        state.source.clone(),
        state.cache.clone(),
    ))
    .keep_alive(KeepAlive::default())
}
