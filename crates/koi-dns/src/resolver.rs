use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use hickory_proto::op::{Header, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{
    Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture,
};
use koi_certmesh::roster::Roster;
use koi_common::capability::{Capability, CapabilityStatus};
use koi_common::types::{ServiceRecord, META_QUERY};
use koi_config::state::{load_dns_state, DnsState};
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
/// Alias feedback flush interval.
const FEEDBACK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Capacity for the DNS event broadcast channel.
const BROADCAST_CHANNEL_CAPACITY: usize = 256;

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
    state: StateCache,
    mdns_cache: Option<MdnsCache>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    upstream: Option<TokioResolver>,
    alias_tx: Option<mpsc::Sender<AliasFeedback>>,
    started_at: std::time::Instant,
    rate_limiter: Arc<RateLimiter>,
    event_tx: broadcast::Sender<DnsEvent>,
}

impl DnsCore {
    pub async fn new(
        config: DnsConfig,
        mdns: Option<Arc<koi_mdns::MdnsCore>>,
        certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    ) -> Result<Self, DnsError> {
        let max_qps = config.max_qps;
        let zone = DnsZone::new(&config.zone)?;
        let state = StateCache::new();
        let mdns_cache = match mdns {
            Some(core) => Some(MdnsCache::spawn(core).await),
            None => None,
        };
        let upstream = Resolver::builder_tokio()
            .map(|builder| builder.build())
            .ok();

        let alias_tx = if certmesh.is_some() {
            let (tx, rx) = mpsc::channel(128);
            let cm = certmesh.clone().unwrap();
            let zone_clone = zone.zone().to_string();
            tokio::spawn(async move {
                alias_feedback_loop(cm, zone_clone, rx).await;
            });
            Some(tx)
        } else {
            None
        };

        Ok(Self {
            config,
            zone,
            state,
            mdns_cache,
            certmesh,
            upstream,
            alias_tx,
            started_at: std::time::Instant::now(),
            rate_limiter: Arc::new(RateLimiter::new(max_qps)),
            event_tx: broadcast::channel(BROADCAST_CHANNEL_CAPACITY).0,
        })
    }

    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Subscribe to DNS events.
    pub fn subscribe(&self) -> broadcast::Receiver<DnsEvent> {
        self.event_tx.subscribe()
    }

    /// Emit a DNS event (used by HTTP handlers after state changes).
    pub fn emit(&self, event: DnsEvent) {
        let _ = self.event_tx.send(event);
    }

    pub fn snapshot(&self) -> RecordsSnapshot {
        let state = self.state.load();
        let roster = load_roster();
        let mdns_records = self
            .mdns_cache
            .as_ref()
            .map(|c| c.snapshot())
            .unwrap_or_default();
        build_snapshot(&self.zone, &state, roster.as_ref(), &mdns_records)
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

    pub async fn lookup(&self, name: &str, record_type: RecordType) -> Option<DnsLookupResult> {
        if let Some(result) = self.resolve_local(name, record_type) {
            return Some(result);
        }

        let resolver = self.upstream.as_ref()?;
        let query_name = Name::from_ascii(name).ok()?;
        let lookup = resolver
            .lookup(query_name.clone(), record_type)
            .await
            .ok()?;
        let mut ips = Vec::new();
        for record in lookup.record_iter() {
            if let Some(ip) = rdata_ip_addr(record.data()) {
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
        let mut server = ServerFuture::new(handler);
        server.register_socket(udp);
        server.register_listener(tcp, TCP_TIMEOUT);

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

impl Capability for DnsCore {
    fn name(&self) -> &str {
        "dns"
    }

    fn status(&self) -> CapabilityStatus {
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
            zone: DnsZone::new(self.zone.zone()).unwrap(),
            state: self.state.clone(),
            mdns_cache: self.mdns_cache.clone(),
            certmesh: self.certmesh.clone(),
            upstream: self.upstream.clone(),
            alias_tx: self.alias_tx.clone(),
            started_at: self.started_at,
            rate_limiter: Arc::clone(&self.rate_limiter),
            event_tx: self.event_tx.clone(),
        }
    }
}

struct StateCache {
    path: PathBuf,
    state: Arc<RwLock<DnsState>>,
    mtime: Arc<RwLock<Option<SystemTime>>>,
}

impl StateCache {
    fn new() -> Self {
        Self {
            path: koi_config::state::dns_state_path(),
            state: Arc::new(RwLock::new(DnsState::default())),
            mtime: Arc::new(RwLock::new(None)),
        }
    }

    fn load(&self) -> DnsState {
        let new_mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let mut mtime_guard = self.mtime.write().unwrap();
        if *mtime_guard == new_mtime {
            return self.state.read().unwrap().clone();
        }
        match load_dns_state() {
            Ok(state) => {
                *self.state.write().unwrap() = state.clone();
                *mtime_guard = new_mtime;
                state
            }
            Err(_) => self.state.read().unwrap().clone(),
        }
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

#[derive(Clone)]
struct MdnsCache {
    records: Arc<RwLock<HashMap<String, HashMap<String, ServiceRecord>>>>,
    cancel: CancellationToken,
}

impl MdnsCache {
    async fn spawn(core: Arc<koi_mdns::MdnsCore>) -> Self {
        let records = Arc::new(RwLock::new(HashMap::new()));
        let cancel = CancellationToken::new();

        let meta_core = Arc::clone(&core);
        let meta_records = Arc::clone(&records);
        let meta_cancel = cancel.clone();
        tokio::spawn(async move {
            if let Ok(handle) = meta_core.browse(META_QUERY).await {
                run_meta_browse(meta_core, handle, meta_records, meta_cancel).await;
            }
        });

        Self { records, cancel }
    }

    fn snapshot(&self) -> Vec<ServiceRecord> {
        let guard = self.records.read().unwrap();
        guard
            .values()
            .flat_map(|map| map.values().cloned())
            .collect()
    }
}

impl Drop for MdnsCache {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn run_meta_browse(
    core: Arc<koi_mdns::MdnsCore>,
    handle: koi_mdns::BrowseHandle,
    records: Arc<RwLock<HashMap<String, HashMap<String, ServiceRecord>>>>,
    cancel: CancellationToken,
) {
    let active = Arc::new(tokio::sync::Mutex::new(HashSet::<String>::new()));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            event = handle.recv() => {
                let Some(event) = event else { break; };
                if let koi_mdns::events::MdnsEvent::Found(record) = event {
                    let service_type = record.name;
                    let mut guard = active.lock().await;
                    if guard.insert(service_type.clone()) {
                        let c = Arc::clone(&core);
                        let r = Arc::clone(&records);
                        let t = service_type.clone();
                        let cancel_child = cancel.clone();
                        tokio::spawn(async move {
                            if let Ok(handle) = c.browse(&t).await {
                                run_type_browse(handle, r, cancel_child).await;
                            }
                        });
                    }
                }
            }
        }
    }
}

async fn run_type_browse(
    handle: koi_mdns::BrowseHandle,
    records: Arc<RwLock<HashMap<String, HashMap<String, ServiceRecord>>>>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            event = handle.recv() => {
                let Some(event) = event else { break; };
                match event {
                    koi_mdns::events::MdnsEvent::Resolved(record) => {
                        let mut guard = records.write().unwrap();
                        let entry = guard.entry(record.service_type.clone()).or_default();
                        entry.insert(record.name.clone(), record);
                    }
                    koi_mdns::events::MdnsEvent::Removed { name, service_type } => {
                        let mut guard = records.write().unwrap();
                        let service_type = if service_type.is_empty() {
                            extract_service_type(&name)
                        } else {
                            Some(service_type)
                        };
                        if let Some(st) = service_type {
                            if let Some(map) = guard.get_mut(&st) {
                                let instance = extract_instance_name(&name);
                                if let Some(instance) = instance {
                                    map.remove(&instance);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn extract_service_type(fullname: &str) -> Option<String> {
    let idx = fullname.find("._")?;
    let rest = &fullname[idx + 1..];
    let trimmed = rest.trim_end_matches('.').trim_end_matches(".local");
    Some(trimmed.to_string())
}

fn extract_instance_name(fullname: &str) -> Option<String> {
    let idx = fullname.find("._")?;
    Some(fullname[..idx].to_string())
}

fn load_roster() -> Option<Roster> {
    let path = koi_certmesh::ca::roster_path();
    if !path.exists() {
        return None;
    }
    koi_certmesh::roster::load_roster(&path).ok()
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

impl RequestHandler for DnsHandler {
    fn handle_request<'life0, 'life1, 'async_trait, R>(
        &'life0 self,
        request: &'life1 Request,
        mut response_handle: R,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ResponseInfo> + Send + 'async_trait>>
    where
        R: 'async_trait + ResponseHandler,
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let info = match request.request_info() {
                Ok(info) => info,
                Err(_) => {
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response = builder.error_msg(request.header(), ResponseCode::FormErr);
                    return response_handle
                        .send_response(response)
                        .await
                        .unwrap_or_else(|_| {
                            ResponseInfo::from(header_from_request(
                                request.header(),
                                ResponseCode::FormErr,
                            ))
                        });
                }
            };

            if !self.core.config.allow_public_clients && !is_local_client(&request.src()) {
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.error_msg(info.header, ResponseCode::Refused);
                return response_handle
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| {
                        ResponseInfo::from(header_from_request(info.header, ResponseCode::Refused))
                    });
            }

            if !self.core.rate_limiter.allow() {
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.error_msg(info.header, ResponseCode::ServFail);
                return response_handle
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| {
                        ResponseInfo::from(header_from_request(info.header, ResponseCode::ServFail))
                    });
            }

            let query = info.query;
            let query_name = query.name();
            let query_type = query.query_type();
            let query_str = query_name.to_string();

            let mut answers: Vec<Record> = Vec::new();
            let mut response_code = ResponseCode::NoError;
            let mut authoritative = false;

            if self.core.zone.is_local_name(&query_str) {
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
            } else if let Some(resolver) = &self.core.upstream {
                let lookup = resolver.lookup(Name::from(query_name), query_type).await;
                match lookup {
                    Ok(result) => {
                        answers.extend(
                            result
                                .record_iter()
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

            let mut header = Header::response_from_request(info.header);
            header.set_authoritative(authoritative);
            header.set_response_code(response_code);

            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.build(
                header,
                answers.iter(),
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            );

            response_handle
                .send_response(response)
                .await
                .unwrap_or_else(|_| ResponseInfo::from(header))
        })
    }
}

fn header_from_request(header: &Header, code: ResponseCode) -> Header {
    let mut h = Header::response_from_request(header);
    h.set_response_code(code);
    h
}

fn rdata_ip_addr(data: &RData) -> Option<IpAddr> {
    match data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    }
}

async fn alias_feedback_loop(
    certmesh: Arc<koi_certmesh::CertmeshCore>,
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
                    let mut sans: Vec<String> = aliases.into_iter().collect();
                    sans.sort();
                    let _ = certmesh.add_alias_sans(&hostname, &sans).await;
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
