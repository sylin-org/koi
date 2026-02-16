use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;
use tokio_util::sync::CancellationToken;

use koi_client::KoiClient;
use koi_common::capability::Capability;
use koi_common::types::{EventKind, ServiceRecord};
use koi_config::state::{load_dns_state, save_dns_state, DnsEntry};
use koi_dns::{DnsLookupResult, DnsRuntime};
use koi_health::{HealthCheck, HealthRuntime};
use koi_mdns::protocol::{RegisterPayload, RegistrationResult};
use koi_mdns::{BrowseHandle as MdnsBrowseHandle, MdnsCore, MdnsEvent};
use koi_proxy::{ProxyEntry, ProxyRuntime};

use crate::{map_join_error, KoiError, KoiEvent};

enum HandleBackend {
    Embedded {
        mdns: Option<Arc<MdnsCore>>,
        dns: Option<Arc<DnsRuntime>>,
        health: Option<Arc<HealthRuntime>>,
        certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
        proxy: Option<Arc<ProxyRuntime>>,
        udp: Option<Arc<koi_udp::UdpRuntime>>,
    },
    Remote {
        client: Arc<KoiClient>,
    },
}

pub struct KoiHandle {
    backend: HandleBackend,
    events: broadcast::Sender<KoiEvent>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl KoiHandle {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_embedded(
        mdns: Option<Arc<MdnsCore>>,
        dns: Option<Arc<DnsRuntime>>,
        health: Option<Arc<HealthRuntime>>,
        certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
        proxy: Option<Arc<ProxyRuntime>>,
        udp: Option<Arc<koi_udp::UdpRuntime>>,
        events: broadcast::Sender<KoiEvent>,
        cancel: CancellationToken,
        tasks: Vec<JoinHandle<()>>,
    ) -> Self {
        Self {
            backend: HandleBackend::Embedded {
                mdns,
                dns,
                health,
                certmesh,
                proxy,
                udp,
            },
            events,
            cancel,
            tasks,
        }
    }

    pub(crate) fn new_remote(
        client: Arc<KoiClient>,
        events: broadcast::Sender<KoiEvent>,
        cancel: CancellationToken,
        tasks: Vec<JoinHandle<()>>,
    ) -> Self {
        Self {
            backend: HandleBackend::Remote { client },
            events,
            cancel,
            tasks,
        }
    }

    pub fn events(&self) -> BroadcastStream<KoiEvent> {
        BroadcastStream::new(self.events.subscribe())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<KoiEvent> {
        self.events.subscribe()
    }

    pub fn mdns(&self) -> Result<MdnsHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { mdns, .. } => {
                let core = mdns.as_ref().ok_or(KoiError::DisabledCapability("mdns"))?;
                Ok(MdnsHandle::new_embedded(
                    Arc::clone(core),
                    self.events.clone(),
                ))
            }
            HandleBackend::Remote { client } => Ok(MdnsHandle::new_remote(
                Arc::clone(client),
                self.events.clone(),
            )),
        }
    }

    pub fn dns(&self) -> Result<DnsHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { dns, .. } => {
                let runtime = dns.as_ref().ok_or(KoiError::DisabledCapability("dns"))?;
                Ok(DnsHandle::new_embedded(Arc::clone(runtime)))
            }
            HandleBackend::Remote { client } => Ok(DnsHandle::new_remote(Arc::clone(client))),
        }
    }

    pub fn health(&self) -> Result<HealthHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { health, .. } => {
                let runtime = health
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("health"))?;
                Ok(HealthHandle::new_embedded(Arc::clone(runtime)))
            }
            HandleBackend::Remote { client } => Ok(HealthHandle::new_remote(Arc::clone(client))),
        }
    }

    pub fn certmesh(&self) -> Result<CertmeshHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { certmesh, .. } => {
                let core = certmesh
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("certmesh"))?;
                Ok(CertmeshHandle::new_embedded(Arc::clone(core)))
            }
            HandleBackend::Remote { client } => Ok(CertmeshHandle::new_remote(Arc::clone(client))),
        }
    }

    pub fn proxy(&self) -> Result<ProxyHandle, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { proxy, .. } => {
                let runtime = proxy
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("proxy"))?;
                Ok(ProxyHandle::new_embedded(Arc::clone(runtime)))
            }
            HandleBackend::Remote { client } => Ok(ProxyHandle::new_remote(Arc::clone(client))),
        }
    }

    /// Get the UDP runtime handle.
    ///
    /// Only available in embedded mode — remote mode does not support UDP bridging
    /// (the remote daemon itself handles bindings).
    pub fn udp(&self) -> Result<Arc<koi_udp::UdpRuntime>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { udp, .. } => {
                let runtime = udp.as_ref().ok_or(KoiError::DisabledCapability("udp"))?;
                Ok(Arc::clone(runtime))
            }
            HandleBackend::Remote { .. } => Err(KoiError::DisabledCapability("udp (remote mode)")),
        }
    }

    pub async fn shutdown(mut self) -> Result<(), KoiError> {
        self.cancel.cancel();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }

        if let HandleBackend::Embedded {
            mdns,
            dns,
            health,
            proxy,
            ..
        } = &self.backend
        {
            if let Some(runtime) = proxy {
                runtime.stop_all().await;
            }
            if let Some(runtime) = health {
                let _ = runtime.stop().await;
            }
            if let Some(runtime) = dns {
                let _ = runtime.stop().await;
            }
            if let Some(core) = mdns {
                core.shutdown().await?;
            }
        }

        Ok(())
    }
}

pub struct KoiBrowseHandle {
    backend: BrowseBackend,
}

enum BrowseBackend {
    Embedded(MdnsBrowseHandle),
    Remote(Mutex<mpsc::Receiver<MdnsEvent>>),
}

impl KoiBrowseHandle {
    fn embedded(handle: MdnsBrowseHandle) -> Self {
        Self {
            backend: BrowseBackend::Embedded(handle),
        }
    }

    fn remote(rx: mpsc::Receiver<MdnsEvent>) -> Self {
        Self {
            backend: BrowseBackend::Remote(Mutex::new(rx)),
        }
    }

    pub async fn recv(&self) -> Option<MdnsEvent> {
        match &self.backend {
            BrowseBackend::Embedded(handle) => handle.recv().await,
            BrowseBackend::Remote(rx) => rx.lock().await.recv().await,
        }
    }
}

pub struct MdnsHandle {
    backend: MdnsBackend,
    events: broadcast::Sender<KoiEvent>,
}

enum MdnsBackend {
    Embedded { core: Arc<MdnsCore> },
    Remote { client: Arc<KoiClient> },
}

impl MdnsHandle {
    fn new_embedded(core: Arc<MdnsCore>, events: broadcast::Sender<KoiEvent>) -> Self {
        Self {
            backend: MdnsBackend::Embedded { core },
            events,
        }
    }

    fn new_remote(client: Arc<KoiClient>, events: broadcast::Sender<KoiEvent>) -> Self {
        Self {
            backend: MdnsBackend::Remote { client },
            events,
        }
    }

    pub fn core(&self) -> Result<Arc<MdnsCore>, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(Arc::clone(core)),
            MdnsBackend::Remote { .. } => Err(KoiError::DisabledCapability("mdns")),
        }
    }

    pub async fn browse(&self, service_type: &str) -> Result<KoiBrowseHandle, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => {
                let handle = core.browse(service_type).await?;
                Ok(KoiBrowseHandle::embedded(handle))
            }
            MdnsBackend::Remote { client } => {
                let (tx, rx) = mpsc::channel(64);
                let client = Arc::clone(client);
                let service_type = service_type.to_string();
                tokio::task::spawn_blocking(move || {
                    let stream = match client.browse_stream(&service_type) {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    for item in stream {
                        let Ok(json) = item else {
                            break;
                        };
                        if let Some(event) = mdns_event_from_pipeline(json) {
                            if tx.blocking_send(event).is_err() {
                                break;
                            }
                        }
                    }
                });
                Ok(KoiBrowseHandle::remote(rx))
            }
        }
    }

    pub async fn resolve(&self, name: &str) -> Result<ServiceRecord, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.resolve(name).await?),
            MdnsBackend::Remote { client } => {
                let name = name.to_string();
                let client = Arc::clone(client);
                let record = tokio::task::spawn_blocking(move || client.resolve(&name))
                    .await
                    .map_err(map_join_error)??;
                Ok(record)
            }
        }
    }

    pub fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.register(payload)?),
            MdnsBackend::Remote { client } => Ok(client.register(&payload)?),
        }
    }

    pub fn unregister(&self, id: &str) -> Result<(), KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.unregister(id)?),
            MdnsBackend::Remote { client } => Ok(client.unregister(id)?),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MdnsEvent> {
        match &self.backend {
            MdnsBackend::Embedded { core } => core.subscribe(),
            MdnsBackend::Remote { .. } => {
                let (_tx, rx) = broadcast::channel(1);
                rx
            }
        }
    }

    pub fn emit_event(&self, event: KoiEvent) {
        let _ = self.events.send(event);
    }
}

pub struct DnsHandle {
    backend: DnsBackend,
}

enum DnsBackend {
    Embedded { runtime: Arc<DnsRuntime> },
    Remote { client: Arc<KoiClient> },
}

impl DnsHandle {
    fn new_embedded(runtime: Arc<DnsRuntime>) -> Self {
        Self {
            backend: DnsBackend::Embedded { runtime },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: DnsBackend::Remote { client },
        }
    }

    pub fn runtime(&self) -> Result<Arc<DnsRuntime>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(Arc::clone(runtime)),
            DnsBackend::Remote { .. } => Err(KoiError::DisabledCapability("dns")),
        }
    }

    pub fn core(&self) -> Result<Arc<koi_dns::DnsCore>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(runtime.core()),
            DnsBackend::Remote { .. } => Err(KoiError::DisabledCapability("dns")),
        }
    }

    pub async fn lookup(
        &self,
        name: &str,
        record_type: hickory_proto::rr::RecordType,
    ) -> Option<DnsLookupResult> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => runtime.core().lookup(name, record_type).await,
            DnsBackend::Remote { client } => {
                let name = name.to_string();
                let client = Arc::clone(client);
                let result =
                    tokio::task::spawn_blocking(move || client.dns_lookup(&name, record_type))
                        .await
                        .ok()
                        .and_then(|res| res.ok());
                let json = match result {
                    Some(json) => json,
                    None => return None,
                };
                parse_dns_lookup(json)
            }
        }
    }

    pub fn list_names(&self) -> Vec<String> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => runtime.core().list_names(),
            DnsBackend::Remote { client } => {
                let result = client.dns_list();
                let Ok(json) = result else {
                    return Vec::new();
                };
                json.get("names")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|name| name.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default()
            }
        }
    }

    pub async fn start(&self) -> Result<bool, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => Ok(runtime.start().await?),
            DnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                let started = tokio::task::spawn_blocking(move || client.dns_start())
                    .await
                    .map_err(map_join_error)??
                    .get("started")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                Ok(started)
            }
        }
    }

    pub async fn stop(&self) -> bool {
        match &self.backend {
            DnsBackend::Embedded { runtime } => runtime.stop().await,
            DnsBackend::Remote { client } => {
                let client = Arc::clone(client);
                tokio::task::spawn_blocking(move || client.dns_stop())
                    .await
                    .ok()
                    .and_then(|res| res.ok())
                    .and_then(|json| json.get("stopped").and_then(|v| v.as_bool()))
                    .unwrap_or(false)
            }
        }
    }

    pub fn add_entry(&self, entry: DnsEntry) -> Result<Vec<DnsEntry>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => {
                let mut state = load_dns_state().unwrap_or_default();
                if let Some(existing) = state.entries.iter_mut().find(|e| e.name == entry.name) {
                    *existing = entry.clone();
                } else {
                    state.entries.push(entry.clone());
                }
                save_dns_state(&state)?;
                runtime.core().emit(koi_dns::DnsEvent::EntryUpdated {
                    name: entry.name,
                    ip: entry.ip,
                });
                Ok(state.entries)
            }
            DnsBackend::Remote { client } => {
                let json = client.dns_add(&entry.name, &entry.ip, entry.ttl)?;
                parse_dns_entries(json)
            }
        }
    }

    pub fn remove_entry(&self, name: &str) -> Result<Vec<DnsEntry>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => {
                let mut state = load_dns_state().unwrap_or_default();
                state.entries.retain(|entry| entry.name != name);
                save_dns_state(&state)?;
                runtime.core().emit(koi_dns::DnsEvent::EntryRemoved {
                    name: name.to_string(),
                });
                Ok(state.entries)
            }
            DnsBackend::Remote { client } => {
                let json = client.dns_remove(name)?;
                parse_dns_entries(json)
            }
        }
    }
}

pub struct HealthHandle {
    backend: HealthBackend,
}

enum HealthBackend {
    Embedded { runtime: Arc<HealthRuntime> },
    Remote { client: Arc<KoiClient> },
}

impl HealthHandle {
    fn new_embedded(runtime: Arc<HealthRuntime>) -> Self {
        Self {
            backend: HealthBackend::Embedded { runtime },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: HealthBackend::Remote { client },
        }
    }

    pub fn core(&self) -> Result<Arc<koi_health::HealthCore>, KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.core()),
            HealthBackend::Remote { .. } => Err(KoiError::DisabledCapability("health")),
        }
    }

    pub async fn status(&self) -> koi_health::HealthSnapshot {
        match &self.backend {
            HealthBackend::Embedded { runtime } => runtime.core().snapshot().await,
            HealthBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || client.health_status())
                    .await
                    .ok()
                    .and_then(|res| res.ok());
                json.and_then(|json| serde_json::from_value(json).ok())
                    .unwrap_or_else(|| koi_health::HealthSnapshot {
                        machines: Vec::new(),
                        services: Vec::new(),
                    })
            }
        }
    }

    pub async fn add_check(&self, check: HealthCheck) -> Result<(), KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.core().add_check(check).await?),
            HealthBackend::Remote { client } => {
                let client = Arc::clone(client);
                let check = check.clone();
                tokio::task::spawn_blocking(move || {
                    client.health_add_check(
                        &check.name,
                        check.kind,
                        &check.target,
                        check.interval_secs,
                        check.timeout_secs,
                    )
                })
                .await
                .map_err(map_join_error)??;
                Ok(())
            }
        }
    }

    pub async fn remove_check(&self, name: &str) -> Result<(), KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.core().remove_check(name).await?),
            HealthBackend::Remote { client } => {
                let client = Arc::clone(client);
                let name = name.to_string();
                tokio::task::spawn_blocking(move || client.health_remove_check(&name))
                    .await
                    .map_err(map_join_error)??;
                Ok(())
            }
        }
    }

    pub async fn start(&self) -> Result<bool, KoiError> {
        match &self.backend {
            HealthBackend::Embedded { runtime } => Ok(runtime.start().await?),
            HealthBackend::Remote { .. } => Ok(false),
        }
    }

    pub async fn stop(&self) -> bool {
        match &self.backend {
            HealthBackend::Embedded { runtime } => runtime.stop().await,
            HealthBackend::Remote { .. } => false,
        }
    }
}

pub struct CertmeshHandle {
    backend: CertmeshBackend,
}

enum CertmeshBackend {
    Embedded {
        core: Arc<koi_certmesh::CertmeshCore>,
    },
    Remote {
        client: Arc<KoiClient>,
    },
}

impl CertmeshHandle {
    fn new_embedded(core: Arc<koi_certmesh::CertmeshCore>) -> Self {
        Self {
            backend: CertmeshBackend::Embedded { core },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: CertmeshBackend::Remote { client },
        }
    }

    pub fn core(&self) -> Result<Arc<koi_certmesh::CertmeshCore>, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(Arc::clone(core)),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }

    pub async fn status(&self) -> koi_common::capability::CapabilityStatus {
        match &self.backend {
            CertmeshBackend::Embedded { core } => core.status(),
            CertmeshBackend::Remote { client } => {
                let client = Arc::clone(client);
                let json = tokio::task::spawn_blocking(move || client.unified_status())
                    .await
                    .ok()
                    .and_then(|res| res.ok());
                json.and_then(extract_capability_status)
                    .unwrap_or_else(default_capability_status)
            }
        }
    }
}

pub struct ProxyHandle {
    backend: ProxyBackend,
}

enum ProxyBackend {
    Embedded { runtime: Arc<ProxyRuntime> },
    Remote { client: Arc<KoiClient> },
}

impl ProxyHandle {
    fn new_embedded(runtime: Arc<ProxyRuntime>) -> Self {
        Self {
            backend: ProxyBackend::Embedded { runtime },
        }
    }

    fn new_remote(client: Arc<KoiClient>) -> Self {
        Self {
            backend: ProxyBackend::Remote { client },
        }
    }

    pub fn runtime(&self) -> Result<Arc<ProxyRuntime>, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(Arc::clone(runtime)),
            ProxyBackend::Remote { .. } => Err(KoiError::DisabledCapability("proxy")),
        }
    }

    pub fn core(&self) -> Result<Arc<koi_proxy::ProxyCore>, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.core()),
            ProxyBackend::Remote { .. } => Err(KoiError::DisabledCapability("proxy")),
        }
    }

    pub async fn entries(&self) -> Vec<ProxyEntry> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => runtime.core().entries().await,
            ProxyBackend::Remote { client } => {
                let client = Arc::clone(client);
                tokio::task::spawn_blocking(move || client.proxy_list())
                    .await
                    .ok()
                    .and_then(|res| res.ok())
                    .and_then(|json| parse_proxy_entries(json).ok())
                    .unwrap_or_default()
            }
        }
    }

    pub async fn upsert(&self, entry: ProxyEntry) -> Result<Vec<ProxyEntry>, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.core().upsert(entry).await?),
            ProxyBackend::Remote { client } => {
                let client = Arc::clone(client);
                let entry = entry.clone();
                let add_client = Arc::clone(&client);
                tokio::task::spawn_blocking(move || {
                    add_client.proxy_add(
                        &entry.name,
                        entry.listen_port,
                        &entry.backend,
                        entry.allow_remote,
                    )
                })
                .await
                .map_err(map_join_error)??;
                let list = tokio::task::spawn_blocking(move || client.proxy_list())
                    .await
                    .map_err(map_join_error)??;
                parse_proxy_entries(list)
            }
        }
    }

    pub async fn remove(&self, name: &str) -> Result<Vec<ProxyEntry>, KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.core().remove(name).await?),
            ProxyBackend::Remote { client } => {
                let client = Arc::clone(client);
                let name = name.to_string();
                let remove_client = Arc::clone(&client);
                tokio::task::spawn_blocking(move || remove_client.proxy_remove(&name))
                    .await
                    .map_err(map_join_error)??;
                let list = tokio::task::spawn_blocking(move || client.proxy_list())
                    .await
                    .map_err(map_join_error)??;
                parse_proxy_entries(list)
            }
        }
    }

    pub async fn start_all(&self) -> Result<(), KoiError> {
        match &self.backend {
            ProxyBackend::Embedded { runtime } => Ok(runtime.start_all().await?),
            ProxyBackend::Remote { .. } => Ok(()),
        }
    }

    pub async fn stop_all(&self) {
        if let ProxyBackend::Embedded { runtime } = &self.backend {
            runtime.stop_all().await;
        }
    }
}

fn parse_dns_lookup(json: serde_json::Value) -> Option<DnsLookupResult> {
    let name = json.get("name").and_then(|v| v.as_str())?.to_string();
    let source = json
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let ips = json.get("ips").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|ip| ip.as_str())
            .filter_map(|ip| ip.parse::<IpAddr>().ok())
            .collect::<Vec<_>>()
    })?;
    Some(DnsLookupResult { name, ips, source })
}

fn parse_dns_entries(json: serde_json::Value) -> Result<Vec<DnsEntry>, KoiError> {
    let entries = json.get("entries").ok_or_else(|| {
        KoiError::Dns(koi_dns::DnsError::Io(std::io::Error::other(
            "missing entries",
        )))
    })?;
    let entries = serde_json::from_value(entries.clone()).map_err(|e| {
        KoiError::Dns(koi_dns::DnsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        )))
    })?;
    Ok(entries)
}

fn parse_proxy_entries(json: serde_json::Value) -> Result<Vec<ProxyEntry>, KoiError> {
    let entries = json
        .get("entries")
        .ok_or_else(|| KoiError::Proxy(koi_proxy::ProxyError::Io("missing entries".to_string())))?
        .clone();
    serde_json::from_value(entries)
        .map_err(|e| KoiError::Proxy(koi_proxy::ProxyError::Io(e.to_string())))
}

fn extract_capability_status(
    json: serde_json::Value,
) -> Option<koi_common::capability::CapabilityStatus> {
    let caps = json.get("capabilities")?.as_array()?;
    for cap in caps {
        if cap.get("name")?.as_str()? == "certmesh" {
            let name = cap.get("name")?.as_str()?.to_string();
            let summary = cap
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let healthy = cap
                .get("healthy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            return Some(koi_common::capability::CapabilityStatus {
                name,
                summary,
                healthy,
            });
        }
    }
    None
}

fn default_capability_status() -> koi_common::capability::CapabilityStatus {
    koi_common::capability::CapabilityStatus {
        name: "certmesh".to_string(),
        summary: "unknown".to_string(),
        healthy: false,
    }
}

fn mdns_event_from_pipeline(json: serde_json::Value) -> Option<MdnsEvent> {
    if let Some(found) = json.get("found") {
        let record: ServiceRecord = serde_json::from_value(found.clone()).ok()?;
        return Some(MdnsEvent::Found(record));
    }
    if let Some(resolved) = json.get("resolved") {
        let record: ServiceRecord = serde_json::from_value(resolved.clone()).ok()?;
        return Some(MdnsEvent::Resolved(record));
    }
    if let Some(event) = json.get("event") {
        let kind: EventKind = serde_json::from_value(event.clone()).ok()?;
        let service = json
            .get("service")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let record: ServiceRecord = serde_json::from_value(service).ok()?;
        return match kind {
            EventKind::Found => Some(MdnsEvent::Found(record)),
            EventKind::Resolved => Some(MdnsEvent::Resolved(record)),
            EventKind::Removed => Some(MdnsEvent::Removed {
                name: record.name,
                service_type: record.service_type,
            }),
        };
    }
    None
}
