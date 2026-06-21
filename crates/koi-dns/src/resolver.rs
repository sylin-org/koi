use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use hickory_proto::op::{Header, HeaderCounts, Metadata, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, Server};
use hickory_server::zone_handler::MessageResponseBuilder;
use koi_common::capability::{Capability, CapabilityStatus};
use koi_common::integration::{
    AliasFeedback as AliasFeedbackTrait, CertmeshSnapshot, MdnsSnapshot,
};
use koi_common::persist;
use koi_config::state::{DnsEntry, DnsState};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::aliases::AliasFeedback;
use crate::records::{build_snapshot, RecordsSnapshot};
use crate::safety::{is_local_client, RateLimiter};
use crate::zone::DnsZone;

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

/// Events emitted by the DNS subsystem when static entries change.
#[derive(Debug, Clone)]
pub enum DnsEvent {
    /// A static DNS entry was added or updated.
    EntryUpdated { name: String, ip: String },
    /// A static DNS entry was removed.
    EntryRemoved { name: String },
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
    /// Override the state file path (for testing / embedded use).
    /// When `None`, defaults to `koi_config::state::dns_state_path()`.
    pub state_path: Option<PathBuf>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind_addr: IpAddr::from([0, 0, 0, 0]),
            port: 53,
            zone: "lan".to_string(),
            local_ttl: DEFAULT_LOCAL_TTL,
            allow_public_clients: false,
            max_qps: DEFAULT_MAX_QPS,
            local_zone: true,
            state_path: None,
        }
    }
}

/// Result of resolving a name via the local resolver logic.
pub struct DnsLookupResult {
    pub name: String,
    pub ips: Vec<IpAddr>,
    pub source: String,
}

pub struct DnsCore {
    config: DnsConfig,
    zone: DnsZone,
    /// Optional `.local` zone — serves hostname→IP from mDNS cache.
    local_zone: Option<DnsZone>,
    state: StateCache,
    mdns: Option<Arc<dyn MdnsSnapshot>>,
    certmesh: Option<Arc<dyn CertmeshSnapshot>>,
    alias_feedback: Option<Arc<dyn AliasFeedbackTrait>>,
    upstream: Option<TokioResolver>,
    alias_tx: Option<mpsc::Sender<AliasFeedback>>,
    rate_limiter: Arc<RateLimiter>,
    event_tx: broadcast::Sender<DnsEvent>,
    /// Ephemeral TXT records (ACME `dns-01` challenges). Keyed by normalized
    /// FQDN (lowercase, trailing dot). Deliberately in-memory only — challenge
    /// tokens are short-lived and must NOT be persisted.
    txt_records: Arc<RwLock<HashMap<String, Vec<String>>>>,
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
    pub async fn new(
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

        let state = StateCache::new(config.state_path.clone());
        let upstream = Resolver::builder_tokio()
            .and_then(|builder| builder.build())
            .ok();

        let alias_tx = if let Some(af) = alias_feedback.clone() {
            let (tx, rx) = mpsc::channel(128);
            let zone_clone = zone.zone().to_string();
            tokio::spawn(async move {
                alias_feedback_loop(af, zone_clone, rx).await;
            });
            Some(tx)
        } else {
            None
        };

        Ok(Self {
            config,
            zone,
            local_zone,
            state,
            mdns,
            certmesh,
            alias_feedback,
            upstream,
            alias_tx,
            rate_limiter: Arc::new(RateLimiter::new(max_qps)),
            event_tx: koi_common::events::event_channel().0,
            txt_records: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn config(&self) -> &DnsConfig {
        &self.config
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
        let mut state = self.state.load();
        if let Some(existing) = state.entries.iter_mut().find(|e| e.name == entry.name) {
            *existing = entry.clone();
        } else {
            state.entries.push(entry.clone());
        }
        self.state.save(&state)?;
        self.emit(DnsEvent::EntryUpdated {
            name: entry.name,
            ip: entry.ip,
        });
        Ok(state.entries)
    }

    /// Remove a static DNS entry by name. Persists to disk and emits an event.
    /// Returns `None` if the entry was not found.
    pub fn remove_entry(&self, name: &str) -> Result<Option<Vec<DnsEntry>>, DnsError> {
        let mut state = self.state.load();
        let before = state.entries.len();
        state.entries.retain(|entry| entry.name != name);
        if state.entries.len() == before {
            return Ok(None);
        }
        self.state.save(&state)?;
        self.emit(DnsEvent::EntryRemoved {
            name: name.to_string(),
        });
        Ok(Some(state.entries))
    }

    /// List static DNS entries from the persisted state.
    pub fn list_entries(&self) -> Vec<DnsEntry> {
        self.state.load().entries
    }

    /// Publish an ephemeral TXT record value for `name` (ACME `dns-01`).
    ///
    /// The value is appended to any existing values for the name. TXT records
    /// are in-memory only and are never persisted.
    pub fn add_txt(&self, name: &str, value: &str) {
        let key = normalize_txt_name(name);
        let mut guard = self.txt_records.write().unwrap_or_else(|e| e.into_inner());
        let values = guard.entry(key).or_default();
        if !values.iter().any(|v| v == value) {
            values.push(value.to_string());
        }
    }

    /// Remove all ephemeral TXT record values for `name`.
    pub fn remove_txt(&self, name: &str) {
        let key = normalize_txt_name(name);
        let mut guard = self.txt_records.write().unwrap_or_else(|e| e.into_inner());
        guard.remove(&key);
    }

    /// Return the currently published TXT values for `name` (empty if none).
    pub fn get_txt(&self, name: &str) -> Vec<String> {
        let key = normalize_txt_name(name);
        let guard = self.txt_records.read().unwrap_or_else(|e| e.into_inner());
        guard.get(&key).cloned().unwrap_or_default()
    }

    pub fn snapshot(&self) -> RecordsSnapshot {
        let state = self.state.load();
        build_snapshot(
            &self.zone,
            &state,
            self.certmesh.as_deref(),
            self.mdns.as_deref(),
        )
    }

    pub fn list_names(&self) -> Vec<String> {
        let snapshot = self.snapshot();
        let mut names = HashSet::new();
        for name in snapshot.static_entries.keys() {
            names.insert(name.clone());
        }
        for name in snapshot.certmesh_entries.keys() {
            names.insert(name.clone());
        }
        for name in snapshot.mdns_entries.keys() {
            names.insert(name.clone());
        }
        let mut list: Vec<String> = names.into_iter().collect();
        list.sort();
        list
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

        let host_ips = self.mdns.as_ref()?.host_ips();

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

    pub async fn lookup(&self, name: &str, record_type: RecordType) -> Option<DnsLookupResult> {
        if let Some(result) = self.resolve_local(name, record_type) {
            return Some(result);
        }

        // Check .local zone (mDNS cache) before upstream
        if let Some(result) = self.resolve_mdns_local(name, record_type) {
            return Some(result);
        }

        let resolver = self.upstream.as_ref()?;
        let query_name = Name::from_ascii(name).ok()?;
        let lookup = resolver
            .lookup(query_name.clone(), record_type)
            .await
            .ok()?;
        let mut ips = Vec::new();
        for record in lookup.answers() {
            if let Some(ip) = rdata_ip_addr(&record.data) {
                ips.push(ip);
            }
        }
        if ips.is_empty() {
            return None;
        }

        Some(DnsLookupResult {
            name: query_name.to_string(),
            ips,
            source: "upstream".to_string(),
        })
    }

    pub async fn serve(&self, cancel: CancellationToken) -> Result<(), DnsError> {
        let addr = SocketAddr::new(self.config.bind_addr, self.config.port);
        let udp = UdpSocket::bind(addr)
            .await
            .map_err(|e| DnsError::Bind(e.to_string()))?;
        let tcp = TcpListener::bind(addr)
            .await
            .map_err(|e| DnsError::Bind(e.to_string()))?;

        let handler = DnsHandler::new(self.clone());
        let mut server = Server::new(handler);
        server.register_socket(udp);
        server.register_listener(tcp, TCP_TIMEOUT, TCP_RESPONSE_BUFFER);

        let server_token = server.shutdown_token().clone();
        let mut server_task = tokio::spawn(async move { server.block_until_done().await });

        tokio::select! {
            _ = cancel.cancelled() => {
                server_token.cancel();
            }
            _ = &mut server_task => {}
        }

        match server_task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(DnsError::Upstream(e.to_string())),
            Err(e) => Err(DnsError::Upstream(e.to_string())),
        }
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

#[async_trait::async_trait]
impl Capability for DnsCore {
    fn name(&self) -> &str {
        "dns"
    }

    async fn status(&self) -> CapabilityStatus {
        let snapshot = self.snapshot();
        let summary = format!(
            "{} static, {} certmesh, {} mdns",
            snapshot.static_entries.len(),
            snapshot.certmesh_entries.len(),
            snapshot.mdns_entries.len()
        );
        CapabilityStatus {
            name: "dns".to_string(),
            summary,
            healthy: true,
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
            alias_feedback: self.alias_feedback.clone(),
            upstream: self.upstream.clone(),
            alias_tx: self.alias_tx.clone(),
            rate_limiter: Arc::clone(&self.rate_limiter),
            event_tx: self.event_tx.clone(),
            txt_records: Arc::clone(&self.txt_records),
        }
    }
}

struct StateCache {
    path: PathBuf,
    state: Arc<RwLock<DnsState>>,
    mtime: Arc<RwLock<Option<SystemTime>>>,
}

impl StateCache {
    fn new(override_path: Option<PathBuf>) -> Self {
        Self {
            path: override_path.unwrap_or_else(koi_config::state::dns_state_path),
            state: Arc::new(RwLock::new(DnsState::default())),
            mtime: Arc::new(RwLock::new(None)),
        }
    }

    fn load(&self) -> DnsState {
        let new_mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let mut mtime_guard = self.mtime.write().unwrap_or_else(|e| e.into_inner());
        if *mtime_guard == new_mtime {
            return self.state.read().unwrap_or_else(|e| e.into_inner()).clone();
        }
        match persist::read_json_or_default::<DnsState>(&self.path) {
            Ok(state) => {
                *self.state.write().unwrap_or_else(|e| e.into_inner()) = state.clone();
                *mtime_guard = new_mtime;
                state
            }
            Err(_) => self.state.read().unwrap_or_else(|e| e.into_inner()).clone(),
        }
    }

    fn save(&self, state: &DnsState) -> Result<(), std::io::Error> {
        persist::write_json_pretty(&self.path, state)?;
        // Invalidate mtime cache so the next load() picks up the change.
        *self.mtime.write().unwrap_or_else(|e| e.into_inner()) = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        *self.state.write().unwrap_or_else(|e| e.into_inner()) = state.clone();
        Ok(())
    }
}

impl Clone for StateCache {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            state: Arc::clone(&self.state),
            mtime: Arc::clone(&self.mtime),
        }
    }
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

        if !self.core.rate_limiter.allow() {
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(info.metadata, ResponseCode::ServFail);
            return response_handle
                .send_response(response)
                .await
                .unwrap_or_else(|_| error_response_info(info.metadata, ResponseCode::ServFail));
        }

        let query = info.query;
        let query_name = query.name();
        let query_type = query.query_type();
        let query_str = query_name.to_string();

        let mut answers: Vec<Record> = Vec::new();
        let mut response_code = ResponseCode::NoError;
        let mut authoritative = false;

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
                    // Not in mDNS cache — fall through to upstream.
                }
            }
            // If answers is still empty after .local lookup, fall through
            // to upstream resolver below (no early return).
            if answers.is_empty() && response_code == ResponseCode::NoError {
                if let Some(resolver) = &self.core.upstream {
                    let lookup = resolver.lookup(Name::from(query_name), query_type).await;
                    match lookup {
                        Ok(result) => {
                            answers.extend(
                                result
                                    .answers()
                                    .iter()
                                    .filter(|r| match query_type {
                                        RecordType::ANY => {
                                            matches!(
                                                r.record_type(),
                                                RecordType::A | RecordType::AAAA
                                            )
                                        }
                                        _ => r.record_type() == query_type,
                                    })
                                    .cloned(),
                            );
                        }
                        Err(_) => {
                            // Upstream also failed — NXDOMAIN since we tried both
                            response_code = ResponseCode::NXDomain;
                        }
                    }
                }
            }
        } else if let Some(resolver) = &self.core.upstream {
            let lookup = resolver.lookup(Name::from(query_name), query_type).await;
            match lookup {
                Ok(result) => {
                    answers.extend(
                        result
                            .answers()
                            .iter()
                            .filter(|r| match query_type {
                                RecordType::ANY => {
                                    matches!(r.record_type(), RecordType::A | RecordType::AAAA)
                                }
                                _ => r.record_type() == query_type,
                            })
                            .cloned(),
                    );
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Upstream lookup failed");
                    response_code = ResponseCode::ServFail;
                }
            }
        } else {
            response_code = ResponseCode::Refused;
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

async fn alias_feedback_loop(
    feedback: Arc<dyn AliasFeedbackTrait>,
    zone: String,
    mut rx: mpsc::Receiver<AliasFeedback>,
) {
    let mut pending: HashMap<String, HashSet<String>> = HashMap::new();
    let mut interval = tokio::time::interval(FEEDBACK_INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if pending.is_empty() {
                    continue;
                }
                let mut drained = HashMap::new();
                std::mem::swap(&mut drained, &mut pending);
                for (hostname, aliases) in drained {
                    for alias in &aliases {
                        feedback.record_alias(&hostname, alias);
                    }
                }
            }
            msg = rx.recv() => {
                let Some(msg) = msg else { break; };
                let alias = msg.alias.trim_end_matches('.').to_string();
                if alias.ends_with(&format!(".{zone}")) {
                    pending.entry(msg.hostname).or_default().insert(alias);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DnsCore backed by a throwaway state file so tests never touch
    /// real on-disk state.
    async fn test_core() -> DnsCore {
        let tmp = std::env::temp_dir().join(format!(
            "koi-dns-test-{}.json",
            koi_common::id::generate_short_id()
        ));
        let config = DnsConfig {
            state_path: Some(tmp),
            ..DnsConfig::default()
        };
        DnsCore::new(config, None, None, None)
            .await
            .expect("core should build")
    }

    /// Drives the real DnsCore command path: subscribe → add_entry → assert the
    /// EntryUpdated event is broadcast through the core's own channel. Fails if
    /// `add_entry` stops emitting (i.e. tests Koi wiring, not tokio).
    #[tokio::test]
    async fn add_entry_emits_entry_updated_through_core() {
        let core = test_core().await;
        let mut rx = core.subscribe();

        core.add_entry(DnsEntry {
            name: "test.lan.".to_string(),
            ip: "10.0.0.1".to_string(),
            ttl: None,
        })
        .expect("add_entry should succeed");

        match rx.try_recv().expect("should receive event") {
            DnsEvent::EntryUpdated { name, ip } => {
                assert_eq!(name, "test.lan.");
                assert_eq!(ip, "10.0.0.1");
            }
            other => panic!("expected EntryUpdated, got {other:?}"),
        }
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
