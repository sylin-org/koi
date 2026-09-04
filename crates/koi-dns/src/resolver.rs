use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use hickory_proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::net::{DnsError as HickoryDnsError, NetError};
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, Server};
use hickory_server::zone_handler::MessageResponseBuilder;
use koi_common::integration::{
    AliasFeedback as AliasFeedbackTrait, CertmeshRosterSnapshot, CertmeshSnapshot,
    MdnsDiscoverySnapshot, MdnsSnapshot,
};
use koi_common::status::StatusFeed;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::aliases::AliasFeedback;
use crate::records::{build_snapshot, RecordsSnapshot};
use crate::runtime::{DnsRecordSummary, DnsRuntimeState, DnsRuntimeStatus};
use crate::safety::{is_local_client, RateLimiter};
use crate::state::{DnsEntry, DnsStateRepository};
use crate::zone::DnsZone;

pub use koi_common::api::DnsLookupResult;

/// Default TTL (seconds) for local zone answers.
const DEFAULT_LOCAL_TTL: u32 = 60;
/// Default max queries per second (global, best effort).
const DEFAULT_MAX_QPS: u32 = 200;
/// TCP timeout for DNS requests.
const TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Per-connection outgoing-response queue depth for DNS-over-TCP.
const TCP_RESPONSE_BUFFER: usize = 32;
/// Alias feedback flush interval.
const FEEDBACK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// Bounded ingress and retained retry budget for alias feedback.
const FEEDBACK_CAPACITY: usize = 128;

/// Events emitted by the DNS subsystem when managed records change.
#[derive(Debug, Clone)]
pub enum DnsEvent {
    /// A static DNS entry was added or updated.
    EntryUpdated { name: String, ip: String },
    /// A static DNS entry was removed.
    EntryRemoved { name: String },
    /// An ephemeral TXT value was published. The value is intentionally omitted
    /// because dashboard events are observational and may be unauthenticated.
    TxtUpdated { name: String },
    /// An ephemeral TXT value was removed.
    TxtRemoved { name: String },
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("invalid DNS zone: {0}")]
    InvalidZone(String),

    #[error("failed to bind DNS socket: {0}")]
    Bind(String),

    #[error("upstream resolver error: {0}")]
    Upstream(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid DNS entry: {0}")]
    InvalidEntry(String),

    #[error("invalid DNS name: {0}")]
    InvalidName(String),

    #[error("DNS lifecycle worker stopped unexpectedly: {0}")]
    Worker(String),

    #[error("DNS runtime has already shut down")]
    ShutDown,
}

/// Owner of a transient DNS desired-set projection.
///
/// Scoped entries are process-local observations, never operator configuration:
/// replacing a scope atomically replaces that producer's complete set and a
/// restart begins with every scope empty. Durable operator entries win a name
/// collision when DNS builds its effective answer set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DnsEntryScope {
    Runtime,
}

/// DNS configuration parameters.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub bind_addr: IpAddr,
    pub port: u16,
    pub zone: String,
    pub local_ttl: u32,
    pub allow_public_clients: bool,
    pub max_qps: u32,
    /// Serve `.local` zone from mDNS hostname cache.
    ///
    /// When enabled, queries for `<hostname>.local` are answered directly
    /// from the mDNS browse cache before falling through to upstream DNS.
    /// This provides platform-agnostic `.local` resolution for containers.
    pub local_zone: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind_addr: IpAddr::from([0, 0, 0, 0]),
            port: 53,
            zone: crate::DEFAULT_ZONE.to_string(),
            local_ttl: DEFAULT_LOCAL_TTL,
            allow_public_clients: false,
            max_qps: DEFAULT_MAX_QPS,
            local_zone: true,
        }
    }
}

/// DNS-owned, cheap presentation catalog.
///
/// Consumers can read effective names and operator-managed static entries
/// without reaching into the resolver's internal record model or repository.
/// Its revision advances only when either exposed collection changes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DnsCatalogSnapshot {
    /// Monotonic process-local semantic revision.
    #[serde(default)]
    pub revision: u64,
    /// Sorted, deduplicated effective names.
    pub names: Vec<String>,
    /// Operator-managed static entries in authoritative repository order.
    pub entries: Vec<DnsEntry>,
}

pub struct DnsCore {
    config: DnsConfig,
    zone: DnsZone,
    /// Optional `.local` zone — serves hostname→IP from mDNS cache.
    local_zone: Option<DnsZone>,
    state: DnsStateRepository,
    mdns: Option<Arc<dyn MdnsSnapshot>>,
    certmesh: Option<Arc<dyn CertmeshSnapshot>>,
    /// Accepted cross-domain inputs and the DNS-owned effective answer set.
    /// Writers cross `operation_lock`; readers clone one coherent projection.
    model: Arc<RwLock<DnsModel>>,
    alias_feedback: Option<Arc<dyn AliasFeedbackTrait>>,
    upstream: Option<TokioResolver>,
    alias_tx: Option<mpsc::Sender<AliasFeedback>>,
    rate_limiter: Arc<RateLimiter>,
    /// Serializes every accepted DNS command from preparation through status
    /// publication and event emission. The model/repository never observes
    /// detached concurrent read-modify-write transactions.
    operation_lock: Arc<std::sync::Mutex<()>>,
    event_tx: broadcast::Sender<DnsEvent>,
    catalog: StatusFeed<DnsCatalogSnapshot>,
    status: StatusFeed<DnsRuntimeStatus>,
    /// Ephemeral TXT records (ACME `dns-01` challenges). Keyed by normalized
    /// FQDN (lowercase, trailing dot). Deliberately in-memory only — challenge
    /// tokens are short-lived and must NOT be persisted.
    txt_records: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

struct DnsModel {
    mdns: Option<Arc<MdnsDiscoverySnapshot>>,
    certmesh: Option<Arc<CertmeshRosterSnapshot>>,
    scoped_entries: BTreeMap<DnsEntryScope, Vec<DnsEntry>>,
    records: RecordsSnapshot,
}

/// A DNS server whose UDP and TCP sockets are already bound.
///
/// Kept inside the DNS domain so [`crate::DnsRuntime`] can make binding part of the
/// synchronous start contract without leaking Hickory implementation details.
pub(crate) struct BoundDnsServer {
    server: Server<DnsHandler>,
    pub(crate) endpoints: Vec<SocketAddr>,
    pub(crate) observation: crate::listener::BindingObservation,
    pub(crate) reason: Option<String>,
}

/// Normalize a name for the ephemeral TXT store and for matching incoming TXT
/// queries: lowercase, trim whitespace, ensure exactly one trailing dot. This
/// mirrors how hickory presents query names (`Name::to_string()` is lowercase,
/// FQDN with a trailing dot) so an in-process `add_txt` and a real DNS TXT query
/// resolve to the same key.
fn normalize_txt_name(name: &str) -> String {
    let trimmed = name.trim().trim_end_matches('.').to_lowercase();
    format!("{trimmed}.")
}

impl DnsCore {
    /// Open the DNS domain against its explicitly composed durable state file.
    pub async fn open(
        state_path: PathBuf,
        config: DnsConfig,
        mdns: Option<Arc<dyn MdnsSnapshot>>,
        certmesh: Option<Arc<dyn CertmeshSnapshot>>,
        alias_feedback: Option<Arc<dyn AliasFeedbackTrait>>,
    ) -> Result<Self, DnsError> {
        let max_qps = config.max_qps;
        let zone = DnsZone::new(&config.zone)?;

        // Enable .local zone when configured and mDNS is available.
        let local_zone = if config.local_zone && mdns.is_some() {
            Some(DnsZone::new("local")?)
        } else {
            None
        };

        let state = DnsStateRepository::load(state_path)?;
        let upstream = Resolver::builder_tokio()
            .and_then(|builder| builder.build())
            .ok();

        let initial_mdns = mdns.as_ref().map(|source| source.snapshot());
        let initial_certmesh = certmesh.as_ref().map(|source| source.snapshot());
        let initial_state = state.snapshot();
        let initial_records = build_snapshot(
            &zone,
            &initial_state,
            initial_certmesh.as_deref(),
            initial_mdns.as_deref(),
        );
        let catalog = StatusFeed::new(DnsCatalogSnapshot {
            revision: 0,
            names: effective_names(&initial_records),
            entries: initial_state.entries,
        });
        let status = StatusFeed::new(DnsRuntimeStatus::stopped(
            &config,
            summarize_records(&initial_records, 0),
        ));
        let model = Arc::new(RwLock::new(DnsModel {
            mdns: initial_mdns,
            certmesh: initial_certmesh,
            scoped_entries: BTreeMap::new(),
            records: initial_records,
        }));

        Ok(Self {
            config,
            zone,
            local_zone,
            state,
            mdns,
            certmesh,
            model,
            alias_feedback,
            upstream,
            // The runtime arms the bounded feedback worker and owns its task.
            // A bare core remains a synchronous domain model with no detached
            // infrastructure of its own.
            alias_tx: None,
            rate_limiter: Arc::new(RateLimiter::new(max_qps)),
            operation_lock: Arc::new(std::sync::Mutex::new(())),
            event_tx: koi_common::events::event_channel().0,
            catalog,
            status,
            txt_records: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Normalize a candidate name against the domain-owned local zone.
    pub fn normalize_name(&self, name: &str) -> Option<String> {
        self.zone.normalize_name(name)
    }

    /// Current immutable DNS status. This is the domain's single cheap state
    /// boundary: record commands and listener lifecycle both publish here.
    pub fn status(&self) -> Arc<DnsRuntimeStatus> {
        self.status.current()
    }

    /// Subscribe to coalesced DNS status transitions.
    pub fn watch_status(&self) -> watch::Receiver<Arc<DnsRuntimeStatus>> {
        self.status.subscribe()
    }

    /// Current immutable presentation catalog.
    pub fn catalog_snapshot(&self) -> Arc<DnsCatalogSnapshot> {
        self.catalog.current()
    }

    /// Capture primary status and the presentation catalog from one causal
    /// publication. The catalog publishes first and its revision is recorded in
    /// primary status as the fence. Retrying that tiny publication window keeps
    /// this read independent of command and persistence locks.
    pub fn status_with_catalog(&self) -> (Arc<DnsRuntimeStatus>, Arc<DnsCatalogSnapshot>) {
        loop {
            let before = self.status();
            let catalog = self.catalog_snapshot();
            let after = self.status();
            if Arc::ptr_eq(&before, &after) && after.catalog_revision == catalog.revision {
                return (after, catalog);
            }
            std::hint::spin_loop();
        }
    }

    /// Subscribe to coalesced catalog changes.
    pub fn watch_catalog_snapshot(&self) -> watch::Receiver<Arc<DnsCatalogSnapshot>> {
        self.catalog.subscribe()
    }

    pub(crate) fn mdns_input(&self) -> Option<Arc<dyn MdnsSnapshot>> {
        self.mdns.clone()
    }

    pub(crate) fn certmesh_input(&self) -> Option<Arc<dyn CertmeshSnapshot>> {
        self.certmesh.clone()
    }

    /// Prepare the bounded alias-feedback worker for the runtime lifecycle.
    ///
    /// This mutates the not-yet-shared core exactly once. Spawning stays in
    /// [`crate::DnsRuntime`], which therefore owns the worker's cancellation
    /// token and join handle alongside every other DNS background task.
    pub(crate) fn prepare_alias_feedback(&mut self) -> Option<AliasFeedbackWorker> {
        let feedback = self.alias_feedback.clone()?;
        debug_assert!(self.alias_tx.is_none(), "alias feedback armed twice");
        let (tx, rx) = mpsc::channel(FEEDBACK_CAPACITY);
        self.alias_tx = Some(tx);
        Some(AliasFeedbackWorker {
            feedback,
            zone: self.zone.zone().to_string(),
            rx,
        })
    }

    pub(crate) fn set_runtime_status(
        &self,
        running: bool,
        desired: bool,
        state: DnsRuntimeState,
        endpoints: Vec<String>,
        reason: Option<String>,
    ) {
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.status.update(move |current| {
            let mut next = current.clone();
            next.running = running;
            next.desired = desired;
            next.state = state;
            next.endpoints = endpoints;
            next.reason = reason;
            publish_dns_status(current, next)
        });
    }

    fn publish_record_change(&self) {
        let records = self.rebuild_records();
        let txt_names = self
            .txt_records
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        let summary = summarize_records(&records, txt_names);
        let catalog = self.publish_catalog(&records);
        self.status.update(move |current| {
            let mut next = current.clone();
            next.records = summary;
            next.catalog_revision = catalog.revision;
            // Record content is intentionally available through specialized
            // queries rather than copied into every cheap status snapshot. Its
            // revision must still advance for same-count changes (IP/TTL edits,
            // or a second TXT value at one name) so observers know to reread.
            next.revision = current.revision.saturating_add(1);
            Some(next)
        });
    }

    /// Accept one mDNS projection and synchronously publish any changed DNS
    /// answer set. A newer source revision that has no DNS meaning remains a
    /// status no-op, but is retained for the next combined projection.
    pub(crate) fn accept_mdns_snapshot(&self, next: Arc<MdnsDiscoverySnapshot>) {
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut model = self
            .model
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if model
            .mdns
            .as_ref()
            .is_some_and(|current| current.revision >= next.revision)
        {
            return;
        }
        let previous_hosts = model.mdns.as_ref().map(|snapshot| snapshot.host_ips());
        model.mdns = Some(next);
        let next_records = self.build_records(&model);
        let local_answers_changed = self.local_zone.is_some()
            && previous_hosts != model.mdns.as_ref().map(|snapshot| snapshot.host_ips());
        let records_changed = model.records != next_records;
        model.records = next_records;
        let records = model.records.clone();
        drop(model);
        if records_changed || local_answers_changed {
            self.publish_effective_record_change(&records);
        }
    }

    /// Accept one Certmesh roster projection and publish when its DNS mapping
    /// changes, including replacements whose entry count stays constant.
    pub(crate) fn accept_certmesh_snapshot(&self, next: Arc<CertmeshRosterSnapshot>) {
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut model = self
            .model
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if model
            .certmesh
            .as_ref()
            .is_some_and(|current| current.revision >= next.revision)
        {
            return;
        }
        model.certmesh = Some(next);
        let next_records = self.build_records(&model);
        if model.records == next_records {
            return;
        }
        model.records = next_records;
        let records = model.records.clone();
        drop(model);
        self.publish_effective_record_change(&records);
    }

    /// Subscribe to DNS events.
    pub fn subscribe(&self) -> broadcast::Receiver<DnsEvent> {
        self.event_tx.subscribe()
    }

    /// Emit a DNS event.
    fn emit(&self, event: DnsEvent) {
        let _ = self.event_tx.send(event);
    }

    /// Add or update a static DNS entry. Persists to disk and emits an event.
    pub fn add_entry(&self, entry: DnsEntry) -> Result<Vec<DnsEntry>, DnsError> {
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut state = self.state.snapshot();
        if let Some(existing) = state.entries.iter_mut().find(|e| e.name == entry.name) {
            if existing == &entry {
                return Ok(state.entries);
            }
            *existing = entry.clone();
        } else {
            state.entries.push(entry.clone());
        }
        self.state.save(&state)?;
        self.publish_record_change();
        self.emit(DnsEvent::EntryUpdated {
            name: entry.name,
            ip: entry.ip,
        });
        Ok(state.entries)
    }

    /// Remove a static DNS entry by name. Persists to disk and emits an event.
    /// Returns `None` if the entry was not found.
    pub fn remove_entry(&self, name: &str) -> Result<Option<Vec<DnsEntry>>, DnsError> {
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut state = self.state.snapshot();
        let before = state.entries.len();
        state.entries.retain(|entry| entry.name != name);
        if state.entries.len() == before {
            return Ok(None);
        }
        self.state.save(&state)?;
        self.publish_record_change();
        self.emit(DnsEvent::EntryRemoved {
            name: name.to_string(),
        });
        Ok(Some(state.entries))
    }

    /// Replace one transient producer's complete DNS desired set.
    ///
    /// This is deliberately not persisted: runtime inventory is authoritative
    /// and is replayed from its latest status on every process start. Validation,
    /// model acceptance, status publication, and events form one synchronous
    /// command boundary after the operation gate has been acquired.
    pub fn replace_scoped_entries(
        &self,
        scope: DnsEntryScope,
        entries: Vec<DnsEntry>,
    ) -> Result<(), DnsError> {
        let entries = self.normalize_scoped_entries(entries)?;
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut model = self
            .model
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if model.scoped_entries.get(&scope) == Some(&entries) {
            return Ok(());
        }

        let previous = model.records.clone();
        if entries.is_empty() {
            model.scoped_entries.remove(&scope);
        } else {
            model.scoped_entries.insert(scope, entries);
        }
        let next = self.build_records(&model);
        model.records = next.clone();
        drop(model);

        if previous == next {
            return Ok(());
        }
        self.publish_effective_record_change(&next);
        self.emit_static_diff(&previous, &next);
        Ok(())
    }

    /// List static DNS entries from the persisted state.
    pub fn list_entries(&self) -> Vec<DnsEntry> {
        self.catalog_snapshot().entries.clone()
    }

    /// Publish an ephemeral TXT record value for `name` (ACME `dns-01`).
    ///
    /// The value is appended to any existing values for the name. TXT records
    /// are in-memory only and are never persisted.
    pub fn add_txt(&self, name: &str, value: &str) {
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let key = normalize_txt_name(name);
        let mut guard = self.txt_records.write().unwrap_or_else(|e| e.into_inner());
        let values = guard.entry(key.clone()).or_default();
        if !values.iter().any(|v| v == value) {
            values.push(value.to_string());
            drop(guard);
            self.publish_record_change();
            self.emit(DnsEvent::TxtUpdated { name: key });
        }
    }

    /// Remove all ephemeral TXT record values for `name`.
    pub fn remove_txt(&self, name: &str) {
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let key = normalize_txt_name(name);
        let mut guard = self.txt_records.write().unwrap_or_else(|e| e.into_inner());
        if guard.remove(&key).is_some() {
            drop(guard);
            self.publish_record_change();
            self.emit(DnsEvent::TxtRemoved { name: key });
        }
    }

    /// Remove one exact ephemeral TXT value without disturbing concurrent values
    /// at the same owner name. Returns whether the value was present.
    pub fn remove_txt_value(&self, name: &str, value: &str) -> bool {
        let _operation = self
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let key = normalize_txt_name(name);
        let mut guard = self.txt_records.write().unwrap_or_else(|e| e.into_inner());
        let Some(values) = guard.get_mut(&key) else {
            return false;
        };
        let before = values.len();
        values.retain(|candidate| candidate != value);
        let removed = values.len() != before;
        if values.is_empty() {
            guard.remove(&key);
        }
        if removed {
            drop(guard);
            self.publish_record_change();
            self.emit(DnsEvent::TxtRemoved { name: key });
        }
        removed
    }

    /// Return the currently published TXT values for `name` (empty if none).
    pub fn get_txt(&self, name: &str) -> Vec<String> {
        let key = normalize_txt_name(name);
        let guard = self.txt_records.read().unwrap_or_else(|e| e.into_inner());
        guard.get(&key).cloned().unwrap_or_default()
    }

    pub fn snapshot(&self) -> RecordsSnapshot {
        self.model
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .records
            .clone()
    }

    pub fn list_names(&self) -> Vec<String> {
        self.catalog_snapshot().names.clone()
    }

    pub fn resolve_local(&self, name: &str, record_type: RecordType) -> Option<DnsLookupResult> {
        let normalized = self.zone.normalize_name(name)?;
        let snapshot = self.snapshot();
        self.maybe_send_feedback(&snapshot.alias_feedback);

        let entries = snapshot
            .static_entries
            .get(&normalized)
            .map(|ips| (ips.clone(), "static"))
            .or_else(|| {
                snapshot
                    .certmesh_entries
                    .get(&normalized)
                    .map(|ips| (ips.clone(), "certmesh"))
            })
            .or_else(|| {
                snapshot
                    .mdns_entries
                    .get(&normalized)
                    .map(|ips| (ips.clone(), "mdns"))
            })?;

        let filtered = filter_ips(entries.0, record_type);
        if filtered.is_empty() {
            return None;
        }

        Some(DnsLookupResult {
            name: normalized,
            ips: filtered,
            source: entries.1.to_string(),
        })
    }

    /// Resolve a `.local` hostname directly from the mDNS cache.
    pub fn resolve_mdns_local(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Option<DnsLookupResult> {
        let local_zone = self.local_zone.as_ref()?;
        let normalized = local_zone.normalize_name(name)?;

        // Extract bare hostname: "node-azure-pool.local." → "node-azure-pool"
        let hostname = normalized.trim_end_matches('.').trim_end_matches(".local");
        if hostname.is_empty() {
            return None;
        }

        let model = self.model.read().unwrap_or_else(|error| error.into_inner());
        let host_ips = model.mdns.as_ref()?.host_ips();

        let ip = host_ips.get(hostname)?;
        let filtered = filter_ips(vec![*ip], record_type);
        if filtered.is_empty() {
            return None;
        }

        Some(DnsLookupResult {
            name: normalized,
            ips: filtered,
            source: "mdns-local".to_string(),
        })
    }

    pub async fn lookup(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<Option<DnsLookupResult>, DnsError> {
        if !matches!(
            record_type,
            RecordType::A | RecordType::AAAA | RecordType::ANY
        ) {
            return Err(DnsError::InvalidEntry(format!(
                "unsupported DNS address record type: {record_type}"
            )));
        }
        let query_name = Name::from_ascii(name)
            .map_err(|error| DnsError::InvalidName(format!("`{name}`: {error}")))?;
        let canonical_name = query_name.to_string();

        // Koi's configured zone is authoritative. A miss in its complete
        // effective model is verified absence and must not depend on an
        // unrelated upstream resolver's health.
        if self.zone.is_local_name(&canonical_name) {
            return Ok(self.resolve_local(&canonical_name, record_type));
        }

        // Check .local mDNS knowledge before the explicitly supported upstream
        // fallback. A cache miss is not enough to claim global absence.
        if let Some(result) = self.resolve_mdns_local(&canonical_name, record_type) {
            return Ok(Some(result));
        }

        let Some(records) = self
            .lookup_upstream_records(query_name.clone(), record_type)
            .await?
        else {
            return Ok(None);
        };
        let mut ips = Vec::new();
        for record in &records {
            if let Some(ip) = rdata_ip_addr(&record.data) {
                ips.push(ip);
            }
        }
        if ips.is_empty() {
            return Ok(None);
        }

        Ok(Some(DnsLookupResult {
            name: query_name.to_string(),
            ips,
            source: "upstream".to_string(),
        }))
    }

    /// Resolve once through the configured upstream and preserve the semantic
    /// difference between an authoritative negative answer and inability to
    /// observe one. DNS wire and facade lookup both use this classification.
    async fn lookup_upstream_records(
        &self,
        query_name: Name,
        record_type: RecordType,
    ) -> Result<Option<Vec<Record>>, DnsError> {
        let resolver = self.upstream.as_ref().ok_or_else(|| {
            DnsError::Upstream("system resolver configuration is unavailable".into())
        })?;
        match resolver.lookup(query_name, record_type).await {
            Ok(lookup) => {
                let records = lookup
                    .answers()
                    .iter()
                    .filter(|record| match record_type {
                        RecordType::ANY => {
                            matches!(record.record_type(), RecordType::A | RecordType::AAAA)
                        }
                        _ => record.record_type() == record_type,
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                Ok((!records.is_empty()).then_some(records))
            }
            Err(NetError::Dns(HickoryDnsError::NoRecordsFound(_))) => Ok(None),
            Err(error) => Err(DnsError::Upstream(error.to_string())),
        }
    }

    pub(crate) async fn bind_server(&self) -> Result<BoundDnsServer, DnsError> {
        let listeners = crate::listener::bind(self.config.bind_addr, self.config.port).await?;
        let handler = DnsHandler::new(self.clone());
        let mut server = Server::new(handler);
        for udp in listeners.udp {
            server.register_socket(udp);
        }
        for tcp in listeners.tcp {
            server.register_listener(tcp, TCP_TIMEOUT, TCP_RESPONSE_BUFFER);
        }

        Ok(BoundDnsServer {
            server,
            endpoints: listeners.endpoints,
            observation: listeners.observation,
            reason: listeners.reason,
        })
    }

    fn maybe_send_feedback(&self, feedback: &[AliasFeedback]) {
        let Some(tx) = &self.alias_tx else {
            return;
        };
        for item in feedback {
            let _ = tx.try_send(AliasFeedback {
                hostname: item.hostname.clone(),
                alias: item.alias.trim_end_matches('.').to_string(),
            });
        }
    }
}

impl BoundDnsServer {
    pub(crate) async fn serve(mut self, cancel: CancellationToken) -> Result<(), DnsError> {
        let server_token = self.server.shutdown_token().clone();
        let server_done = self.server.block_until_done();
        tokio::pin!(server_done);

        let result = tokio::select! {
            _ = cancel.cancelled() => {
                server_token.cancel();
                server_done.await
            }
            result = &mut server_done => result,
        };

        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(DnsError::Upstream(error.to_string())),
        }
    }
}

impl Clone for DnsCore {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            zone: self.zone.clone(),
            local_zone: self.local_zone.clone(),
            state: self.state.clone(),
            mdns: self.mdns.clone(),
            certmesh: self.certmesh.clone(),
            model: Arc::clone(&self.model),
            alias_feedback: self.alias_feedback.clone(),
            upstream: self.upstream.clone(),
            alias_tx: self.alias_tx.clone(),
            rate_limiter: Arc::clone(&self.rate_limiter),
            operation_lock: Arc::clone(&self.operation_lock),
            event_tx: self.event_tx.clone(),
            catalog: self.catalog.clone(),
            status: self.status.clone(),
            txt_records: Arc::clone(&self.txt_records),
        }
    }
}

impl DnsCore {
    fn build_records(&self, model: &DnsModel) -> RecordsSnapshot {
        let state = self.effective_static_state(model);
        build_snapshot(
            &self.zone,
            &state,
            model.certmesh.as_deref(),
            model.mdns.as_deref(),
        )
    }

    fn effective_static_state(&self, model: &DnsModel) -> crate::state::DnsState {
        let mut state = self.state.snapshot();
        let mut occupied = state
            .entries
            .iter()
            .filter_map(|entry| self.zone.normalize_name(&entry.name))
            .collect::<HashSet<_>>();
        for entries in model.scoped_entries.values() {
            for entry in entries {
                // Scoped entries are normalized on acceptance. Keep the check
                // defensive so malformed durable operator state cannot grant a
                // transient producer ownership of an unrelated name.
                let Some(name) = self.zone.normalize_name(&entry.name) else {
                    continue;
                };
                if occupied.insert(name) {
                    state.entries.push(entry.clone());
                }
            }
        }
        state
    }

    pub(crate) fn normalize_scoped_entries(
        &self,
        entries: Vec<DnsEntry>,
    ) -> Result<Vec<DnsEntry>, DnsError> {
        let mut normalized = Vec::with_capacity(entries.len());
        for mut entry in entries {
            entry.name = self.zone.normalize_name(&entry.name).ok_or_else(|| {
                DnsError::InvalidEntry(format!(
                    "name '{}' is outside {}",
                    entry.name,
                    self.zone.zone()
                ))
            })?;
            entry.ip.parse::<IpAddr>().map_err(|_| {
                DnsError::InvalidEntry(format!("'{}' is not an IP address", entry.ip))
            })?;
            normalized.push(entry);
        }
        normalized.sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(pair) = normalized
            .windows(2)
            .find(|pair| pair[0].name == pair[1].name)
        {
            return Err(DnsError::InvalidEntry(format!(
                "duplicate scoped name '{}'",
                pair[0].name
            )));
        }
        Ok(normalized)
    }

    fn emit_static_diff(&self, previous: &RecordsSnapshot, next: &RecordsSnapshot) {
        for name in previous.static_entries.keys() {
            if !next.static_entries.contains_key(name) {
                self.emit(DnsEvent::EntryRemoved { name: name.clone() });
            }
        }
        for (name, ips) in &next.static_entries {
            if previous.static_entries.get(name) == Some(ips) {
                continue;
            }
            if let Some(ip) = ips.first() {
                self.emit(DnsEvent::EntryUpdated {
                    name: name.clone(),
                    ip: ip.to_string(),
                });
            }
        }
    }

    fn rebuild_records(&self) -> RecordsSnapshot {
        let mut model = self
            .model
            .write()
            .unwrap_or_else(|error| error.into_inner());
        model.records = self.build_records(&model);
        model.records.clone()
    }

    fn publish_effective_record_change(&self, records: &RecordsSnapshot) {
        let txt_names = self
            .txt_records
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        let summary = summarize_records(records, txt_names);
        let catalog = self.publish_catalog(records);
        self.status.update(move |current| {
            let mut next = current.clone();
            next.records = summary;
            next.catalog_revision = catalog.revision;
            // Effective answers changed even when source counts did not. The
            // revision tells specialized-query consumers to reread.
            next.revision = current.revision.saturating_add(1);
            Some(next)
        });
    }

    fn publish_catalog(&self, records: &RecordsSnapshot) -> Arc<DnsCatalogSnapshot> {
        let names = effective_names(records);
        let entries = self.state.snapshot().entries;
        self.catalog.update(move |current| {
            if current.names == names && current.entries == entries {
                return None;
            }
            Some(DnsCatalogSnapshot {
                revision: current.revision.saturating_add(1),
                names,
                entries,
            })
        })
    }
}

fn effective_names(snapshot: &RecordsSnapshot) -> Vec<String> {
    let mut names = HashSet::new();
    names.extend(snapshot.static_entries.keys().cloned());
    names.extend(snapshot.certmesh_entries.keys().cloned());
    names.extend(snapshot.mdns_entries.keys().cloned());
    let mut names: Vec<_> = names.into_iter().collect();
    names.sort();
    names
}

fn summarize_records(snapshot: &RecordsSnapshot, txt_names: usize) -> DnsRecordSummary {
    DnsRecordSummary {
        static_entries: snapshot.static_entries.len(),
        certmesh_entries: snapshot.certmesh_entries.len(),
        mdns_entries: snapshot.mdns_entries.len(),
        txt_names,
    }
}

fn publish_dns_status(
    current: &DnsRuntimeStatus,
    mut next: DnsRuntimeStatus,
) -> Option<DnsRuntimeStatus> {
    next.revision = current.revision;
    if &next == current {
        return None;
    }
    next.revision = current.revision.saturating_add(1);
    Some(next)
}

fn filter_ips(mut ips: Vec<IpAddr>, record_type: RecordType) -> Vec<IpAddr> {
    match record_type {
        RecordType::A => {
            ips.retain(|ip| matches!(ip, IpAddr::V4(_)));
        }
        RecordType::AAAA => {
            ips.retain(|ip| matches!(ip, IpAddr::V6(_)));
        }
        RecordType::ANY => {}
        _ => ips.clear(),
    }
    ips
}

struct DnsHandler {
    core: DnsCore,
}

impl DnsHandler {
    fn new(core: DnsCore) -> Self {
        Self { core }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let info = match request.request_info() {
            Ok(info) => info,
            Err(_) => {
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.error_msg(&request.metadata, ResponseCode::FormErr);
                return response_handle
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| {
                        error_response_info(&request.metadata, ResponseCode::FormErr)
                    });
            }
        };

        if !self.core.config.allow_public_clients && !is_local_client(&request.src()) {
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(info.metadata, ResponseCode::Refused);
            return response_handle
                .send_response(response)
                .await
                .unwrap_or_else(|_| error_response_info(info.metadata, ResponseCode::Refused));
        }

        if !self.core.rate_limiter.allow(request.src().ip()) {
            // REFUSED (not SERVFAIL) when shedding load: SERVFAIL invites immediate
            // client retries, amplifying a flood; REFUSED signals "won't serve".
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(info.metadata, ResponseCode::Refused);
            return response_handle
                .send_response(response)
                .await
                .unwrap_or_else(|_| error_response_info(info.metadata, ResponseCode::Refused));
        }

        let query = info.query;
        let query_name = query.name();
        let query_type = query.query_type();
        let query_str = query_name.to_string();

        let mut answers: Vec<Record> = Vec::new();
        let mut response_code = ResponseCode::NoError;
        let mut authoritative = false;
        let mut query_upstream = false;

        // ── Ephemeral TXT (ACME dns-01) ──
        // TXT queries are served from the in-memory challenge store before any
        // A/AAAA zone logic. A/AAAA behavior below is unchanged.
        let txt_values = if query_type == RecordType::TXT {
            self.core.get_txt(&query_str)
        } else {
            Vec::new()
        };
        if query_type == RecordType::TXT && !txt_values.is_empty() {
            authoritative = true;
            let name = Name::from(query_name);
            let record = Record::from_rdata(
                name,
                self.core.config.local_ttl,
                RData::TXT(hickory_proto::rr::rdata::TXT::new(txt_values)),
            );
            answers.push(record);
        } else if self.core.zone.is_local_name(&query_str) {
            // Primary zone (.internal): static + certmesh + mDNS aliases
            authoritative = true;
            match self.core.resolve_local(&query_str, query_type) {
                Some(result) => {
                    let name = Name::from(query_name);
                    for ip in result.ips {
                        let record = Record::from_rdata(
                            name.clone(),
                            self.core.config.local_ttl,
                            RData::from(ip),
                        );
                        answers.push(record);
                    }
                }
                None => {
                    response_code = if matches!(
                        query_type,
                        RecordType::A | RecordType::AAAA | RecordType::ANY
                    ) {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::NotImp
                    };
                }
            }
        } else if self
            .core
            .local_zone
            .as_ref()
            .is_some_and(|z| z.is_local_name(&query_str))
        {
            // .local zone: direct hostname→IP from mDNS cache
            match self.core.resolve_mdns_local(&query_str, query_type) {
                Some(result) => {
                    authoritative = true;
                    let name = Name::from(query_name);
                    for ip in result.ips {
                        let record = Record::from_rdata(
                            name.clone(),
                            self.core.config.local_ttl,
                            RData::from(ip),
                        );
                        answers.push(record);
                    }
                }
                None => {
                    // A local cache miss is not global absence. Use the same
                    // upstream classifier as every other forwarded query.
                    query_upstream = true;
                }
            }
        } else {
            query_upstream = true;
        }

        if query_upstream {
            match self
                .core
                .lookup_upstream_records(Name::from(query_name), query_type)
                .await
            {
                Ok(Some(records)) => answers.extend(records),
                Ok(None) => response_code = ResponseCode::NXDomain,
                Err(error) => {
                    tracing::debug!(%error, "Upstream lookup failed");
                    response_code = ResponseCode::ServFail;
                }
            }
        }

        // hickory 0.26 split the old flat `Header` into `Metadata` (flags/codes)
        // plus `HeaderCounts`; the builder takes the owned `Metadata`.
        let mut metadata = Metadata::response_from_request(info.metadata);
        metadata.authoritative = authoritative;
        metadata.response_code = response_code;

        let builder = MessageResponseBuilder::from_message_request(request);
        let response = builder.build(
            metadata,
            answers.iter(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
        );

        response_handle
            .send_response(response)
            .await
            .unwrap_or_else(|_| {
                ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                })
            })
    }
}

/// Build a bare `ResponseInfo` for the rare case where sending the real response
/// fails — mirrors the response header the client would have received.
fn error_response_info(request_meta: &Metadata, code: ResponseCode) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(request_meta);
    metadata.response_code = code;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

fn rdata_ip_addr(data: &RData) -> Option<IpAddr> {
    match data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

pub(crate) struct AliasFeedbackWorker {
    feedback: Arc<dyn AliasFeedbackTrait>,
    zone: String,
    rx: mpsc::Receiver<AliasFeedback>,
}

impl AliasFeedbackWorker {
    pub(crate) async fn run(self, cancel: CancellationToken) {
        alias_feedback_loop(self.feedback, self.zone, self.rx, cancel).await;
    }
}

async fn alias_feedback_loop(
    feedback: Arc<dyn AliasFeedbackTrait>,
    zone: String,
    mut rx: mpsc::Receiver<AliasFeedback>,
    cancel: CancellationToken,
) {
    let mut pending: HashMap<String, HashSet<String>> = HashMap::new();
    let mut interval = tokio::time::interval(FEEDBACK_INTERVAL);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                if pending.is_empty() {
                    continue;
                }
                let mut drained = HashMap::new();
                std::mem::swap(&mut drained, &mut pending);
                for (hostname, aliases) in drained {
                    for alias in aliases {
                        if let Err(error) = feedback.record_alias(&hostname, &alias).await {
                            tracing::warn!(%hostname, %alias, %error, "alias feedback command failed; retaining it for retry");
                            pending.entry(hostname.clone()).or_default().insert(alias);
                        }
                    }
                }
            }
            msg = rx.recv() => {
                let Some(msg) = msg else { break; };
                let alias = msg.alias.trim_end_matches('.').to_string();
                if alias.ends_with(&format!(".{zone}")) {
                    let duplicate = pending
                        .get(&msg.hostname)
                        .is_some_and(|aliases| aliases.contains(&alias));
                    let pending_len = pending.values().map(HashSet::len).sum::<usize>();
                    if duplicate {
                        continue;
                    }
                    if pending_len >= FEEDBACK_CAPACITY {
                        tracing::warn!(
                            hostname = %msg.hostname,
                            %alias,
                            capacity = FEEDBACK_CAPACITY,
                            "alias feedback retry set is full; dropping newest hint"
                        );
                        continue;
                    }
                    pending.entry(msg.hostname).or_default().insert(alias);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, Query};
    use hickory_resolver::config::{
        ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts,
    };
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use koi_common::integration::AliasFeedbackError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    #[derive(Default)]
    struct FailOnceAliasFeedback {
        attempts: AtomicUsize,
        accepted: StdMutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl AliasFeedbackTrait for FailOnceAliasFeedback {
        async fn record_alias(
            &self,
            hostname: &str,
            alias: &str,
        ) -> Result<(), AliasFeedbackError> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(AliasFeedbackError("transient test failure".to_string()));
            }
            self.accepted
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push((hostname.to_string(), alias.to_string()));
            Ok(())
        }
    }

    /// Build a DnsCore backed by a throwaway state file so tests never touch
    /// real on-disk state.
    async fn test_core() -> DnsCore {
        let tmp = std::env::temp_dir().join(format!(
            "koi-dns-test-{}.json",
            koi_common::id::generate_short_id()
        ));
        DnsCore::open(tmp, DnsConfig::default(), None, None, None)
            .await
            .expect("core should build")
    }

    async fn controlled_upstream(
        response_code: ResponseCode,
    ) -> (
        TokioResolver,
        CancellationToken,
        tokio::task::JoinHandle<()>,
    ) {
        let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind controlled upstream");
        let address = socket.local_addr().expect("controlled upstream address");
        let cancel = CancellationToken::new();
        let server_cancel = cancel.clone();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            loop {
                let received = tokio::select! {
                    _ = server_cancel.cancelled() => break,
                    received = socket.recv_from(&mut buffer) => received,
                };
                let (length, peer) = received.expect("receive upstream query");
                let request = Message::from_vec(&buffer[..length]).expect("decode upstream query");
                let mut response = request.into_response();
                response.metadata.response_code = response_code;
                let response = response.to_vec().expect("encode upstream response");
                socket
                    .send_to(&response, peer)
                    .await
                    .expect("send upstream response");
            }
        });

        let mut connection = ConnectionConfig::udp();
        connection.port = address.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(address.ip(), true, vec![connection])],
        );
        let mut options = ResolverOpts::default();
        options.attempts = 1;
        options.timeout = Duration::from_millis(250);
        options.cache_size = 0;
        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(options)
            .build()
            .expect("build controlled resolver");
        (resolver, cancel, server)
    }

    async fn wire_response_code(
        address: SocketAddr,
        query: Option<(&str, RecordType)>,
    ) -> ResponseCode {
        let socket = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind DNS test client");
        let mut message = Message::query();
        if let Some((name, record_type)) = query {
            message.add_query(Query::query(
                Name::from_ascii(name).expect("valid test query"),
                record_type,
            ));
        }
        socket
            .send_to(&message.to_vec().expect("encode DNS query"), address)
            .await
            .expect("send DNS query");
        let mut response = [0_u8; 4096];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut response))
                .await
                .expect("DNS response timeout")
                .expect("receive DNS response");
        Message::from_vec(&response[..length])
            .expect("decode DNS response")
            .metadata
            .response_code
    }

    #[tokio::test]
    async fn lookup_and_local_wire_preserve_upstream_absence_and_failure() {
        for (upstream_code, expected_wire) in [
            (ResponseCode::NXDomain, ResponseCode::NXDomain),
            (ResponseCode::ServFail, ResponseCode::ServFail),
        ] {
            let (resolver, upstream_cancel, upstream) = controlled_upstream(upstream_code).await;
            let mut core = test_core().await;
            core.config.bind_addr = std::net::Ipv4Addr::LOCALHOST.into();
            core.config.port = 0;
            core.local_zone = Some(DnsZone::new("local").expect("test local zone"));
            core.upstream = Some(resolver);

            let direct = core.lookup("missing.example.", RecordType::A).await;
            match upstream_code {
                ResponseCode::NXDomain => assert!(direct.expect("verified absence").is_none()),
                ResponseCode::ServFail => assert!(matches!(direct, Err(DnsError::Upstream(_)))),
                _ => unreachable!("test controls response codes"),
            }

            let runtime = crate::DnsRuntime::new(core);
            assert!(runtime.start().await.expect("start DNS wire server"));
            let address = runtime.status().endpoints[0]
                .parse::<SocketAddr>()
                .expect("DNS wire address");
            assert_eq!(
                wire_response_code(address, Some(("missing.local.", RecordType::A))).await,
                expected_wire
            );
            runtime.shutdown().await;
            upstream_cancel.cancel();
            upstream.await.expect("controlled upstream joins");
        }
    }

    #[tokio::test]
    async fn malformed_wire_request_is_formerr_and_invalid_facade_name_is_typed() {
        let mut core = test_core().await;
        assert!(matches!(
            core.lookup("bad name", RecordType::A).await,
            Err(DnsError::InvalidName(_))
        ));
        core.config.bind_addr = std::net::Ipv4Addr::LOCALHOST.into();
        core.config.port = 0;
        let runtime = crate::DnsRuntime::new(core);
        assert!(runtime.start().await.expect("start DNS wire server"));
        let address = runtime.status().endpoints[0]
            .parse::<SocketAddr>()
            .expect("DNS wire address");
        assert_eq!(
            wire_response_code(address, None).await,
            ResponseCode::FormErr
        );
        runtime.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn failed_alias_feedback_is_retained_and_awaited_on_the_owned_worker() {
        let feedback = Arc::new(FailOnceAliasFeedback::default());
        let (tx, rx) = mpsc::channel(FEEDBACK_CAPACITY);
        tx.send(AliasFeedback {
            hostname: "node".to_string(),
            alias: "http.internal".to_string(),
        })
        .await
        .expect("queue feedback");
        let cancel = CancellationToken::new();
        let worker_feedback = feedback.clone() as Arc<dyn AliasFeedbackTrait>;
        let worker_cancel = cancel.clone();
        let worker = tokio::spawn(alias_feedback_loop(
            worker_feedback,
            "internal".to_string(),
            rx,
            worker_cancel,
        ));

        for _ in 0..3 {
            tokio::task::yield_now().await;
            if feedback.attempts.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::advance(FEEDBACK_INTERVAL).await;
        }
        assert_eq!(feedback.attempts.load(Ordering::SeqCst), 1);
        assert!(feedback
            .accepted
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty());

        tokio::time::advance(FEEDBACK_INTERVAL).await;
        tokio::task::yield_now().await;
        assert_eq!(feedback.attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            feedback
                .accepted
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_slice(),
            &[("node".to_string(), "http.internal".to_string())]
        );

        cancel.cancel();
        worker.await.expect("feedback worker");
    }

    /// Drives the real DnsCore command path: subscribe → add_entry → assert the
    /// EntryUpdated event is broadcast through the core's own channel. Fails if
    /// `add_entry` stops emitting (i.e. tests Koi wiring, not tokio).
    #[tokio::test]
    async fn add_entry_emits_entry_updated_through_core() {
        let core = test_core().await;
        let mut rx = core.subscribe();
        let mut status_rx = core.watch_status();
        let mut catalog_rx = core.watch_catalog_snapshot();
        let before = core.status();
        let catalog_before = core.catalog_snapshot();

        let entry = DnsEntry {
            name: "test.internal.".to_string(),
            ip: "10.0.0.1".to_string(),
            ttl: None,
        };
        core.add_entry(entry.clone())
            .expect("add_entry should succeed");

        match rx.try_recv().expect("should receive event") {
            DnsEvent::EntryUpdated { name, ip } => {
                assert_eq!(name, "test.internal.");
                assert_eq!(ip, "10.0.0.1");
            }
            other => panic!("expected EntryUpdated, got {other:?}"),
        }
        let committed = core.status();
        let committed_catalog = core.catalog_snapshot();
        assert!(committed.revision > before.revision);
        assert_eq!(committed.records.static_entries, 1);
        assert_eq!(committed_catalog.revision, catalog_before.revision + 1);
        assert_eq!(committed_catalog.names, ["test.internal."]);
        assert_eq!(
            committed_catalog.entries.as_slice(),
            std::slice::from_ref(&entry)
        );
        assert!(status_rx.has_changed().expect("status feed remains open"));
        assert!(catalog_rx.has_changed().expect("catalog feed remains open"));

        // Repeating an identical command is a semantic no-op: it neither bumps
        // the revision nor invents a second success event.
        status_rx.borrow_and_update();
        catalog_rx.borrow_and_update();
        core.add_entry(entry).expect("idempotent add");
        assert_eq!(core.status().revision, committed.revision);
        assert!(Arc::ptr_eq(&committed_catalog, &core.catalog_snapshot()));
        assert!(!status_rx.has_changed().expect("status feed remains open"));
        assert!(!catalog_rx.has_changed().expect("catalog feed remains open"));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn runtime_scope_is_complete_transient_and_operator_names_win() {
        let path = std::env::temp_dir().join(format!(
            "koi-dns-runtime-scope-{}.json",
            koi_common::id::generate_short_id()
        ));
        let config = DnsConfig::default();
        let core = DnsCore::open(path.clone(), config.clone(), None, None, None)
            .await
            .expect("DNS core");
        let runtime_entries = vec![
            DnsEntry {
                name: "zeta".to_string(),
                ip: "10.0.0.2".to_string(),
                ttl: None,
            },
            DnsEntry {
                name: "alpha.internal".to_string(),
                ip: "10.0.0.1".to_string(),
                ttl: Some(15),
            },
        ];
        core.replace_scoped_entries(DnsEntryScope::Runtime, runtime_entries.clone())
            .expect("accept runtime desired set");

        assert!(
            core.list_entries().is_empty(),
            "transient entries are not operator state"
        );
        assert_eq!(
            core.resolve_local("alpha.internal.", RecordType::A)
                .expect("runtime answer")
                .ips,
            ["10.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            core.catalog_snapshot().names,
            ["alpha.internal.", "zeta.internal."]
        );

        // Input order has no semantics and therefore publishes nothing.
        let accepted_status = core.status();
        let accepted_catalog = core.catalog_snapshot();
        let mut reordered = runtime_entries;
        reordered.reverse();
        core.replace_scoped_entries(DnsEntryScope::Runtime, reordered)
            .expect("idempotent reorder");
        assert!(Arc::ptr_eq(&accepted_status, &core.status()));
        assert!(Arc::ptr_eq(&accepted_catalog, &core.catalog_snapshot()));

        let operator = DnsEntry {
            name: "alpha.internal.".to_string(),
            // Koi deliberately excludes public/documentation ranges from its
            // local answer set. Use a private address so this assertion tests
            // ownership precedence rather than the resolver's safety filter.
            ip: "192.168.50.50".to_string(),
            ttl: None,
        };
        core.add_entry(operator).expect("operator entry");
        assert_eq!(
            core.resolve_local("alpha.internal.", RecordType::A)
                .expect("operator answer")
                .ips,
            ["192.168.50.50".parse::<IpAddr>().unwrap()]
        );
        core.remove_entry("alpha.internal.")
            .expect("remove operator")
            .expect("operator existed");
        assert_eq!(
            core.resolve_local("alpha.internal.", RecordType::A)
                .expect("runtime answer restored")
                .ips,
            ["10.0.0.1".parse::<IpAddr>().unwrap()]
        );

        core.replace_scoped_entries(DnsEntryScope::Runtime, Vec::new())
            .expect("clear complete runtime set");
        assert!(core
            .resolve_local("alpha.internal.", RecordType::A)
            .is_none());
        drop(core);

        let reopened = DnsCore::open(path.clone(), config, None, None, None)
            .await
            .expect("reopen DNS core");
        assert!(reopened
            .resolve_local("zeta.internal.", RecordType::A)
            .is_none());
        assert!(reopened.list_entries().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn invalid_runtime_replacement_preserves_the_last_accepted_set() {
        let core = test_core().await;
        core.replace_scoped_entries(
            DnsEntryScope::Runtime,
            vec![DnsEntry {
                name: "good".to_string(),
                ip: "10.0.0.8".to_string(),
                ttl: None,
            }],
        )
        .expect("initial desired set");
        let status = core.status();
        let catalog = core.catalog_snapshot();

        assert!(core
            .replace_scoped_entries(
                DnsEntryScope::Runtime,
                vec![DnsEntry {
                    name: "bad".to_string(),
                    ip: "not-an-address".to_string(),
                    ttl: None,
                }],
            )
            .is_err());
        assert!(Arc::ptr_eq(&status, &core.status()));
        assert!(Arc::ptr_eq(&catalog, &core.catalog_snapshot()));
        assert!(core
            .resolve_local("good.internal.", RecordType::A)
            .is_some());
    }

    #[tokio::test]
    async fn presentation_catalog_is_seeded_and_tracks_only_exposed_changes() {
        let path = std::env::temp_dir().join(format!(
            "koi-dns-seeded-names-{}.json",
            koi_common::id::generate_short_id()
        ));
        std::fs::write(
            &path,
            br#"{"entries":[{"name":"seed.internal.","ip":"10.0.0.7","ttl":null}]}"#,
        )
        .expect("write persisted DNS state");
        let core = DnsCore::open(path.clone(), DnsConfig::default(), None, None, None)
            .await
            .expect("core should load persisted state");
        let seeded = core.catalog_snapshot();
        assert_eq!(seeded.revision, 0);
        assert_eq!(seeded.names, ["seed.internal."]);
        assert_eq!(seeded.entries.len(), 1);

        let mut catalog = core.watch_catalog_snapshot();
        catalog.borrow_and_update();
        core.add_entry(DnsEntry {
            name: "seed.internal.".to_string(),
            ip: "10.0.0.8".to_string(),
            ttl: Some(30),
        })
        .expect("same-name record edit");
        let edited = core.catalog_snapshot();
        assert_eq!(edited.revision, seeded.revision + 1);
        assert_eq!(edited.names, seeded.names);
        assert_eq!(edited.entries[0].ip, "10.0.0.8");
        assert!(catalog.has_changed().expect("catalog feed remains open"));

        catalog.borrow_and_update();
        let status_after_record_edit = core.status();
        core.add_txt("_acme-challenge.seed.internal.", "token");
        assert!(core.status().revision > status_after_record_edit.revision);
        assert!(Arc::ptr_eq(&edited, &core.catalog_snapshot()));
        assert!(!catalog.has_changed().expect("catalog feed remains open"));

        core.add_entry(DnsEntry {
            name: "alpha.internal.".to_string(),
            ip: "10.0.0.9".to_string(),
            ttl: None,
        })
        .expect("new effective name");
        let expanded = core.catalog_snapshot();
        assert_eq!(expanded.revision, edited.revision + 1);
        assert_eq!(expanded.names, ["alpha.internal.", "seed.internal."]);
        assert_eq!(expanded.entries.len(), 2);
        assert!(catalog.has_changed().expect("catalog feed remains open"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn failed_entry_commit_publishes_neither_status_nor_event() {
        let base = std::env::temp_dir().join(format!(
            "koi-dns-unwritable-parent-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::write(&base, b"not a directory").expect("create path blocker");
        let core = DnsCore::open(
            base.join("dns.json"),
            DnsConfig::default(),
            None,
            None,
            None,
        )
        .await
        .expect("core should still initialize from empty state");
        let before = core.status();
        let catalog_before = core.catalog_snapshot();
        let mut events = core.subscribe();

        assert!(core
            .add_entry(DnsEntry {
                name: "never-committed.lan.".to_string(),
                ip: "10.0.0.8".to_string(),
                ttl: None,
            })
            .is_err());
        assert!(Arc::ptr_eq(&before, &core.status()));
        assert!(Arc::ptr_eq(&catalog_before, &core.catalog_snapshot()));
        assert!(events.try_recv().is_err());

        let _ = std::fs::remove_file(base);
    }

    #[tokio::test]
    async fn same_count_record_edits_still_advance_the_authoritative_revision() {
        let core = test_core().await;
        core.add_entry(DnsEntry {
            name: "mutable.internal.".to_string(),
            ip: "10.0.0.1".to_string(),
            ttl: Some(30),
        })
        .expect("initial add");
        let after_add = core.status();

        core.add_entry(DnsEntry {
            name: "mutable.internal.".to_string(),
            ip: "10.0.0.2".to_string(),
            ttl: Some(60),
        })
        .expect("same-count update");
        let after_edit = core.status();
        assert!(after_edit.revision > after_add.revision);
        assert_eq!(after_edit.records.static_entries, 1);

        core.add_txt("_acme-challenge.mutable.internal", "one");
        let after_first_txt = core.status();
        core.add_txt("_acme-challenge.mutable.internal", "two");
        let after_second_txt = core.status();
        assert!(after_second_txt.revision > after_first_txt.revision);
        assert_eq!(after_second_txt.records.txt_names, 1);

        assert!(core.remove_txt_value("_acme-challenge.mutable.internal", "one"));
        assert!(core.status().revision > after_second_txt.revision);
        assert_eq!(core.status().records.txt_names, 1);
    }

    #[test]
    fn concurrent_static_commands_cannot_erase_each_others_commits() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let core = Arc::new(runtime.block_on(test_core()));
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let threads = (0..8)
            .map(|index| {
                let core = Arc::clone(&core);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    core.add_entry(DnsEntry {
                        name: format!("node-{index}.internal."),
                        ip: format!("10.0.0.{}", index + 1),
                        ttl: None,
                    })
                    .expect("serialized add");
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for thread in threads {
            thread.join().expect("command thread");
        }

        assert_eq!(core.list_entries().len(), 8);
        assert_eq!(core.status().records.static_entries, 8);
    }

    #[test]
    fn coherent_status_capture_waits_out_a_split_publication() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let core = Arc::new(runtime.block_on(test_core()));
        let entry = DnsEntry {
            name: "coherent.internal.".to_string(),
            ip: "10.0.0.42".to_string(),
            ttl: None,
        };
        let catalog_before = core.catalog_snapshot();
        core.catalog.publish(DnsCatalogSnapshot {
            revision: catalog_before.revision.saturating_add(1),
            names: vec![entry.name.clone()],
            entries: vec![entry],
        });

        let worker = Arc::clone(&core);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx.send(worker.status_with_catalog()).unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("capture thread started");
        assert!(matches!(
            result_rx.recv_timeout(std::time::Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        let current = core.status();
        let mut next = current.as_ref().clone();
        next.revision = current.revision.saturating_add(1);
        next.catalog_revision = catalog_before.revision.saturating_add(1);
        next.records.static_entries = 1;
        core.status.publish(next);

        let (status, catalog) = result_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("coherent pair");
        thread.join().expect("capture thread");
        assert_eq!(status.records.static_entries, 1);
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.names, ["coherent.internal."]);
    }

    #[test]
    fn coherent_status_capture_never_waits_on_the_command_lock() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let core = Arc::new(runtime.block_on(test_core()));
        let operation = core
            .operation_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        let worker = Arc::clone(&core);
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            result_tx.send(worker.status_with_catalog()).unwrap();
        });

        let (status, catalog) = result_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("status boundary must remain cheap while a command is active");
        drop(operation);
        thread.join().expect("capture thread");
        assert_eq!(status.catalog_revision, catalog.revision);
    }

    #[tokio::test]
    async fn corrupt_persisted_state_fails_construction_instead_of_looking_empty() {
        let path = std::env::temp_dir().join(format!(
            "koi-dns-corrupt-{}.json",
            koi_common::id::generate_short_id()
        ));
        std::fs::write(&path, b"{ definitely not json").expect("write corrupt state");
        let result = DnsCore::open(path.clone(), DnsConfig::default(), None, None, None).await;
        assert!(
            matches!(result, Err(DnsError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidData)
        );
        let _ = std::fs::remove_file(path);
    }

    /// remove_entry on an existing entry emits EntryRemoved through the core.
    #[tokio::test]
    async fn remove_entry_emits_entry_removed_through_core() {
        let core = test_core().await;
        core.add_entry(DnsEntry {
            name: "gone.lan.".to_string(),
            ip: "10.0.0.9".to_string(),
            ttl: None,
        })
        .expect("add_entry should succeed");

        let mut rx = core.subscribe();
        let removed = core
            .remove_entry("gone.lan.")
            .expect("remove_entry should succeed");
        assert!(removed.is_some(), "entry should have been present");

        match rx.try_recv().expect("should receive event") {
            DnsEvent::EntryRemoved { name } => assert_eq!(name, "gone.lan."),
            other => panic!("expected EntryRemoved, got {other:?}"),
        }
    }

    /// add_txt → get_txt returns the published value.
    #[tokio::test]
    async fn add_txt_then_get_txt_returns_value() {
        let core = test_core().await;
        core.add_txt("_acme-challenge.host.lan", "token-abc");
        assert_eq!(
            core.get_txt("_acme-challenge.host.lan"),
            vec!["token-abc".to_string()]
        );
    }

    /// TXT name lookup is normalization-insensitive (case + trailing dot),
    /// matching how a real DNS query name is presented.
    #[tokio::test]
    async fn get_txt_is_normalization_insensitive() {
        let core = test_core().await;
        core.add_txt("_acme-challenge.Host.LAN", "token-xyz");
        // Trailing dot + different case must hit the same key.
        assert_eq!(
            core.get_txt("_acme-challenge.host.lan."),
            vec!["token-xyz".to_string()]
        );
    }

    /// remove_txt clears the published value.
    #[tokio::test]
    async fn remove_txt_clears_value() {
        let core = test_core().await;
        core.add_txt("_acme-challenge.gone.lan", "token-1");
        assert!(!core.get_txt("_acme-challenge.gone.lan").is_empty());
        core.remove_txt("_acme-challenge.gone.lan");
        assert!(core.get_txt("_acme-challenge.gone.lan").is_empty());
    }

    #[tokio::test]
    async fn remove_txt_value_preserves_concurrent_values_and_emits_names_only() {
        let core = test_core().await;
        let mut rx = core.subscribe();
        core.add_txt("_acme-challenge.shared.lan", "token-1");
        core.add_txt("_acme-challenge.shared.lan", "token-2");
        assert!(matches!(
            rx.try_recv().expect("first publish event"),
            DnsEvent::TxtUpdated { name } if name == "_acme-challenge.shared.lan."
        ));
        assert!(matches!(
            rx.try_recv().expect("second publish event"),
            DnsEvent::TxtUpdated { name } if name == "_acme-challenge.shared.lan."
        ));

        assert!(core.remove_txt_value("_acme-challenge.shared.lan", "token-1"));
        assert_eq!(
            core.get_txt("_acme-challenge.shared.lan"),
            vec!["token-2".to_string()]
        );
        assert!(matches!(
            rx.try_recv().expect("exact removal event"),
            DnsEvent::TxtRemoved { name } if name == "_acme-challenge.shared.lan."
        ));
        assert!(!core.remove_txt_value("_acme-challenge.shared.lan", "missing"));
    }

    /// get_txt on an unknown name returns empty.
    #[tokio::test]
    async fn get_txt_unknown_is_empty() {
        let core = test_core().await;
        assert!(core.get_txt("_acme-challenge.nobody.lan").is_empty());
    }

    /// Two subscribers to the same core each receive a core-emitted event.
    #[tokio::test]
    async fn multiple_subscribers_each_receive_core_event() {
        let core = test_core().await;
        let mut rx1 = core.subscribe();
        let mut rx2 = core.subscribe();

        core.add_entry(DnsEntry {
            name: "multi.lan.".to_string(),
            ip: "10.0.0.2".to_string(),
            ttl: None,
        })
        .expect("add_entry should succeed");

        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }
}
