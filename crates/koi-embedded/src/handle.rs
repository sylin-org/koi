use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;
use tokio_util::sync::CancellationToken;

use koi_client::KoiClient;
use koi_common::capability::Capability;
use koi_common::peer::Peer;
use koi_common::types::{EventKind, ServiceRecord};
use koi_config::state::DnsEntry;
use koi_dns::{DnsLookupResult, DnsRuntime};
use koi_health::{HealthCheck, HealthRuntime};
use koi_mdns::protocol::{RegisterPayload, RegistrationResult};
use koi_mdns::{BrowseSubscription as MdnsBrowseHandle, MdnsCore, MdnsEvent};
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
        runtime: Option<Arc<koi_runtime::RuntimeCore>>,
    },
    Remote {
        client: Arc<KoiClient>,
    },
}

pub struct KoiHandle {
    backend: HandleBackend,
    data_dir: Option<std::path::PathBuf>,
    events: broadcast::Sender<KoiEvent>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    http_announce_id: Option<String>,
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
        runtime: Option<Arc<koi_runtime::RuntimeCore>>,
        data_dir: Option<std::path::PathBuf>,
        events: broadcast::Sender<KoiEvent>,
        cancel: CancellationToken,
        tasks: Vec<JoinHandle<()>>,
        http_announce_id: Option<String>,
    ) -> Self {
        Self {
            backend: HandleBackend::Embedded {
                mdns,
                dns,
                health,
                certmesh,
                proxy,
                udp,
                runtime,
            },
            data_dir,
            events,
            cancel,
            tasks,
            http_announce_id,
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
            data_dir: None,
            events,
            cancel,
            tasks,
            http_announce_id: None,
        }
    }

    pub fn events(&self) -> BroadcastStream<KoiEvent> {
        BroadcastStream::new(self.events.subscribe())
    }

    /// Serve `router` on `addr` with the same-port posture dial (ADR-020 §5):
    /// plain HTTP while this node is Open, mTLS once it is secure, flipping live
    /// with **no dropped connections** as the posture changes. The consumer writes
    /// one `serve` call and never branches on posture.
    ///
    /// Returns the supervisor's [`JoinHandle`]; the listener stops when this
    /// handle's `cancel` is triggered (e.g. on [`shutdown`](Self::shutdown)) or
    /// the passed `cancel` fires. Embedded only — a remote handle has no local
    /// identity to serve mTLS with.
    pub fn serve(
        &self,
        router: axum::Router,
        addr: std::net::SocketAddr,
        cancel: CancellationToken,
    ) -> Result<JoinHandle<()>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { certmesh, .. } => {
                let core = certmesh
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("certmesh"))?;
                let core = Arc::clone(core);
                Ok(tokio::spawn(async move {
                    if let Err(e) = crate::serve::serve_adaptive(core, router, addr, cancel).await {
                        tracing::error!(error = %e, "same-port serve failed to bind");
                    }
                }))
            }
            HandleBackend::Remote { .. } => {
                Err(KoiError::DisabledCapability("certmesh (remote mode)"))
            }
        }
    }

    /// Become a fully-participating trusted service in one call (ADR-020 §13 — the
    /// "3-line trusted service"):
    ///
    /// 1. acquire/maintain this node's identity (best-effort — an Open node with no
    ///    way to enroll simply stays plaintext),
    /// 2. announce `service_type` on the LAN at `addr`'s port with the node's
    ///    posture stamped into the TXT, **kept current across posture flips**, and
    /// 3. serve `router` on `addr` with the same-port dial ([`serve`](Self::serve)).
    ///
    /// The consumer never branches on posture and never wires identity, discovery,
    /// and serving separately. Returns the serve supervisor's [`JoinHandle`].
    /// Certificate *renewal* is handled by the certmesh background loops — enable
    /// them with `Builder::certmesh_background(true)` on a long-running host.
    /// Embedded only.
    pub async fn participate(
        &self,
        router: axum::Router,
        addr: std::net::SocketAddr,
        service_type: &str,
        cancel: CancellationToken,
    ) -> Result<JoinHandle<()>, KoiError> {
        let (certmesh, mdns) = match &self.backend {
            HandleBackend::Embedded { certmesh, mdns, .. } => (
                certmesh
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("certmesh"))?
                    .clone(),
                mdns.clone(),
            ),
            HandleBackend::Remote { .. } => {
                return Err(KoiError::DisabledCapability("certmesh (remote mode)"))
            }
        };

        // 1. Acquire/maintain identity. Open (no CA / not a member) stays plaintext.
        let _ = certmesh.ensure_identity().await;

        // 2. Announce with posture, refreshed on every flip so the LAN trust map
        //    never goes stale (ADR-020 §13 "maintained across flips").
        if let Some(mdns) = mdns {
            spawn_participate_announce(
                mdns,
                Arc::clone(&certmesh),
                service_type.to_string(),
                addr.port(),
                cancel.clone(),
            );
        } else {
            tracing::debug!("participate: mDNS disabled — serving without announcing");
        }

        // 3. Serve with the same-port posture dial.
        self.serve(router, addr, cancel)
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

    /// Open the encrypted key-value vault for general-purpose secret storage.
    ///
    /// The vault uses platform credential binding (keyring) when available,
    /// with a machine-bound fallback. Each call opens a fresh handle sharing
    /// the same on-disk state.
    pub fn vault(&self) -> Result<koi_crypto::vault::Vault, KoiError> {
        let dir = self
            .data_dir
            .as_ref()
            .ok_or(KoiError::DisabledCapability("vault (no data_dir)"))?;
        koi_crypto::vault::Vault::open(dir)
            .map_err(|e| KoiError::Io(std::io::Error::other(e.to_string())))
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

    /// Get the runtime adapter core.
    ///
    /// Only available in embedded mode when runtime is enabled.
    pub fn runtime(&self) -> Result<Arc<koi_runtime::RuntimeCore>, KoiError> {
        match &self.backend {
            HandleBackend::Embedded { runtime, .. } => {
                let core = runtime
                    .as_ref()
                    .ok_or(KoiError::DisabledCapability("runtime"))?;
                Ok(Arc::clone(core))
            }
            HandleBackend::Remote { .. } => {
                Err(KoiError::DisabledCapability("runtime (remote mode)"))
            }
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
            if let Some(id) = &self.http_announce_id {
                if let Some(core) = mdns {
                    if let Err(e) = core.unregister(id) {
                        tracing::warn!(error = %e, "Failed to withdraw HTTP mDNS announcement");
                    }
                }
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

/// Default discovery window (ADR-020 §8): long enough for mDNS resolution on a
/// quiet LAN, short enough to stay responsive — a sane default so the common
/// `discover(type)` call needs no tuning.
pub const DEFAULT_DISCOVER_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

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
                let handle = core.subscribe_type(service_type).await?;
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

    /// Discover peers of `service_type`, each enriched with its advertised trust
    /// posture, mesh anchor, and identity expiry (ADR-020 §8) — the fleet-wide
    /// trust-legibility primitive. A snapshot collected over
    /// [`DEFAULT_DISCOVER_WINDOW`]; for a custom window use
    /// [`discover_for`](Self::discover_for).
    ///
    /// The posture each peer carries is an **untrusted hint** (ADR-016 §2);
    /// `certmesh().verify(..)` / mTLS adjudicates actual trust. Works in both
    /// embedded and remote mode (it layers on [`browse`](Self::browse)).
    pub async fn discover(&self, service_type: &str) -> Result<Vec<Peer>, KoiError> {
        self.discover_for(service_type, DEFAULT_DISCOVER_WINDOW)
            .await
    }

    /// Like [`discover`](Self::discover) with an explicit collection `window`.
    pub async fn discover_for(
        &self,
        service_type: &str,
        window: std::time::Duration,
    ) -> Result<Vec<Peer>, KoiError> {
        let browse = self.browse(service_type).await?;
        let mut events = Vec::new();
        let deadline = tokio::time::sleep(window);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                ev = browse.recv() => match ev {
                    Some(e) => events.push(e),
                    None => break,
                },
            }
        }
        Ok(fold_peers(events))
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

    /// Subscribe to the live mDNS lifecycle-event stream (Found / Resolved / Removed).
    ///
    /// Available only in **embedded** mode, where there is a local `MdnsCore` to subscribe
    /// to. In **client (remote)** mode there is no all-types lifecycle stream to forward —
    /// the daemon's `/v1/mdns/subscribe` requires a service type — so this returns
    /// [`KoiError::RemoteUnsupported`]. For a remote event stream, use
    /// [`MdnsHandle::browse`] with a specific service type (it forwards the daemon's SSE).
    ///
    /// Previously this silently returned a dead receiver in remote mode (it yielded nothing,
    /// forever); the typed error makes the limitation visible instead of swallowing it.
    pub fn subscribe(&self) -> Result<broadcast::Receiver<MdnsEvent>, KoiError> {
        match &self.backend {
            MdnsBackend::Embedded { core } => Ok(core.subscribe()),
            MdnsBackend::Remote { .. } => Err(KoiError::RemoteUnsupported(
                "mdns subscribe — use mdns.browse(service_type) for a remote event stream",
            )),
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
            DnsBackend::Embedded { runtime } => Ok(runtime.core().add_entry(entry)?),
            DnsBackend::Remote { client } => {
                let json = client.dns_add(&entry.name, &entry.ip, entry.ttl)?;
                parse_dns_entries(json)
            }
        }
    }

    pub fn remove_entry(&self, name: &str) -> Result<Vec<DnsEntry>, KoiError> {
        match &self.backend {
            DnsBackend::Embedded { runtime } => {
                Ok(runtime.core().remove_entry(name)?.unwrap_or_default())
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
            CertmeshBackend::Embedded { core } => core.status().await,
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

    /// This node's current trust posture — the mode oracle (ADR-020 §0).
    ///
    /// Embedded only: a remote handle has no endpoint to query the daemon's
    /// posture yet (that arrives with the diagnose/status surface in a later
    /// ADR-020 phase), so it returns `DisabledCapability`.
    pub fn posture(&self) -> Result<koi_common::posture::Posture, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.posture()),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }

    /// This node's live identity, or `None` if it is Open (ADR-020 §7).
    /// Read-only; embedded only.
    pub async fn local_identity(&self) -> Result<Option<koi_certmesh::Identity>, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.local_identity().await),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }

    /// Ensure this node holds a current identity, then return it (ADR-020 §7).
    /// Idempotent and mode-transparent; embedded only.
    pub async fn ensure_identity(&self) -> Result<Option<koi_certmesh::Identity>, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.ensure_identity().await),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }

    /// Sign `bytes` into an `Envelope` (ADR-020 §3). Mode-transparent: a
    /// freshness-stamped passthrough when Open, ES256-signed when Authenticated.
    /// Embedded only.
    pub async fn sign(&self, bytes: &[u8]) -> Result<koi_common::envelope::Envelope, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.sign(bytes).await),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }

    /// Verify an `Envelope`, returning an `Assurance` (ADR-020 §3). Read a trusted
    /// identity only via `Assurance::identity()`. Embedded only.
    pub async fn verify(
        &self,
        env: &koi_common::envelope::Envelope,
    ) -> Result<koi_common::envelope::Assurance, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.verify(env).await),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }

    /// Seal `bytes` into a `Sealed` (ADR-020 §4). The confidentiality rung, today a
    /// signed-not-encrypted passthrough; the consumer codes against the final API
    /// now. Embedded only.
    pub async fn seal(&self, bytes: &[u8]) -> Result<koi_common::sealed::Sealed, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.seal(bytes).await),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }

    /// Open a `Sealed` → `Opened` (recovered bytes + trust state, ADR-020 §4). A
    /// tampered/rejected message errors rather than yielding bytes. Embedded only.
    pub async fn open(
        &self,
        sealed: &koi_common::sealed::Sealed,
    ) -> Result<koi_common::sealed::Opened, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.open(sealed).await?),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }

    /// Build a posture-keyed client to a discovered [`Peer`] (ADR-020 §6): plain
    /// HTTP to an Open peer, mTLS to a secure peer — the caller writes one code
    /// path. Embedded only (a remote handle has no local identity to present).
    ///
    /// Errors loudly (not via an opaque handshake failure) when the peer requires
    /// authentication but this node is Open, or when the peer anchors to a
    /// different mesh — see [`koi_certmesh::CertmeshCore::client_for`].
    pub async fn client_for(&self, peer: &Peer) -> Result<koi_certmesh::PeerClient, KoiError> {
        match &self.backend {
            CertmeshBackend::Embedded { core } => Ok(core.client_for(peer).await?),
            CertmeshBackend::Remote { .. } => Err(KoiError::DisabledCapability("certmesh")),
        }
    }
}

/// Announce this node's `service_type` on `port` with its current posture stamped
/// into the TXT (ADR-020 §8). Returns the registration id, or `None` if mDNS
/// registration failed. Used by [`participate`](KoiHandle::participate).
async fn announce_once(
    mdns: &Arc<MdnsCore>,
    certmesh: &Arc<koi_certmesh::CertmeshCore>,
    hostname: &str,
    service_type: &str,
    port: u16,
) -> Option<String> {
    let id = certmesh.local_identity().await;
    let mut txt = std::collections::HashMap::new();
    koi_common::peer::stamp(
        &mut txt,
        certmesh.posture(),
        id.as_ref().map(|i| i.ca_fingerprint.as_str()),
        id.as_ref().map(|i| i.renewal.expires_at),
    );
    let payload = RegisterPayload {
        name: hostname.to_string(),
        service_type: service_type.to_string(),
        port,
        ip: None,
        lease_secs: None,
        txt,
    };
    match mdns.register(payload) {
        Ok(result) => Some(result.id),
        Err(e) => {
            tracing::warn!(error = %e, "participate: mDNS announce failed");
            None
        }
    }
}

/// Maintain a posture-stamped mDNS announcement across posture flips until
/// `cancel` (ADR-020 §13). Re-announces on every transition so a peer discovering
/// this node always reads its *current* posture, then withdraws the record on
/// shutdown.
fn spawn_participate_announce(
    mdns: Arc<MdnsCore>,
    certmesh: Arc<koi_certmesh::CertmeshCore>,
    service_type: String,
    port: u16,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let hostname = hostname::get()
            .ok()
            .and_then(|os| os.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());
        let mut posture_rx = certmesh.watch_posture();
        let mut current_id = announce_once(&mdns, &certmesh, &hostname, &service_type, port).await;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = posture_rx.changed() => {
                    if changed.is_err() {
                        break; // the certmesh core was dropped
                    }
                    // Posture flipped → re-announce so the advertised posture is current.
                    if let Some(old) = current_id.take() {
                        let _ = mdns.unregister(&old);
                    }
                    current_id =
                        announce_once(&mdns, &certmesh, &hostname, &service_type, port).await;
                }
            }
        }
        if let Some(id) = current_id {
            let _ = mdns.unregister(&id);
        }
    });
}

/// Fold a stream of mDNS lifecycle events into a deduplicated peer snapshot
/// (ADR-020 §8). Resolved records (which carry TXT, hence the trust hints)
/// overwrite an earlier Found for the same name; a Removed drops it. Ordered by
/// name for deterministic output. Pure — unit-tested without the network.
fn fold_peers(events: impl IntoIterator<Item = MdnsEvent>) -> Vec<Peer> {
    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, ServiceRecord> = BTreeMap::new();
    for ev in events {
        match ev {
            MdnsEvent::Found(rec) => {
                by_name.entry(rec.name.clone()).or_insert(rec);
            }
            MdnsEvent::Resolved(rec) => {
                by_name.insert(rec.name.clone(), rec);
            }
            MdnsEvent::Removed { name, .. } => {
                by_name.remove(&name);
            }
        }
    }
    by_name.into_values().map(Peer::from_record).collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::posture::PostureLevel;
    use std::collections::HashMap;

    fn rec(name: &str, txt: &[(&str, &str)]) -> ServiceRecord {
        ServiceRecord {
            name: name.to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some(format!("{name}.local")),
            ip: Some("10.0.0.9".to_string()),
            port: Some(8443),
            txt: txt
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn fold_resolved_overwrites_found_for_txt_enrichment() {
        // Found arrives first (no TXT), then Resolved carries the trust hints.
        let peers = fold_peers([
            MdnsEvent::Found(rec("a", &[])),
            MdnsEvent::Resolved(rec("a", &[("fp", "CAFP"), ("posture", "authenticated")])),
        ]);
        assert_eq!(peers.len(), 1, "the two events collapse to one peer");
        assert_eq!(peers[0].level(), PostureLevel::Authenticated);
        assert_eq!(peers[0].fp.as_deref(), Some("CAFP"));
    }

    #[test]
    fn fold_removed_drops_the_peer() {
        let peers = fold_peers([
            MdnsEvent::Found(rec("b", &[])),
            MdnsEvent::Removed {
                name: "b".to_string(),
                service_type: "_http._tcp".to_string(),
            },
        ]);
        assert!(peers.is_empty(), "a removed peer is not in the snapshot");
    }

    #[test]
    fn fold_orders_peers_by_name() {
        let peers = fold_peers([
            MdnsEvent::Resolved(rec("z", &[])),
            MdnsEvent::Resolved(rec("a", &[])),
            MdnsEvent::Resolved(rec("m", &[])),
        ]);
        let names: Vec<_> = peers.iter().map(|p| p.record.name.clone()).collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn fold_open_peer_has_open_posture() {
        let peers = fold_peers([MdnsEvent::Resolved(rec("plain", &[]))]);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].level(), PostureLevel::Open);
        assert!(!peers[0].is_secure());
    }

    // ── participate (ADR-020 §13) ───────────────────────────────────

    #[tokio::test]
    async fn participate_remote_handle_is_disabled() {
        let client = Arc::new(KoiClient::new("http://127.0.0.1:1"));
        let (tx, _) = broadcast::channel(8);
        let handle = KoiHandle::new_remote(client, tx, CancellationToken::new(), Vec::new());
        let router = axum::Router::new();
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], 0).into();
        let err = handle
            .participate(router, addr, "_x._tcp", CancellationToken::new())
            .await
            .unwrap_err();
        assert!(matches!(err, KoiError::DisabledCapability(_)));
    }

    #[tokio::test]
    async fn participate_open_node_serves_plaintext() {
        // certmesh on (but no CA → Open), mDNS off (participate just serves plain),
        // isolated data dir. The Open node serves the consumer's router in plaintext
        // with no posture branching by the caller.
        let dir = std::env::temp_dir().join(format!("koi-emb-participate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let koi = crate::Builder::new()
            .data_dir(&dir)
            .service_mode(crate::ServiceMode::EmbeddedOnly)
            .mdns(false)
            .dns_enabled(false)
            .health(false)
            .certmesh(true)
            .proxy(false)
            .build()
            .expect("build");
        let handle = koi.start().await.expect("start");

        let addr = {
            let l = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            l.local_addr().unwrap()
        };
        let router = axum::Router::new().route("/ping", axum::routing::get(|| async { "pong" }));
        let cancel = CancellationToken::new();
        let _server = handle
            .participate(router, addr, "_koi-test._tcp", cancel.clone())
            .await
            .expect("participate");
        tokio::time::sleep(std::time::Duration::from_millis(75)).await;

        let (status, body) = koi_certmesh::mtls::get(&addr.ip().to_string(), addr.port(), "/ping")
            .await
            .expect("plain GET to an Open participating node");
        assert_eq!(status, 200);
        assert_eq!(body, "pong");

        cancel.cancel();
        handle.shutdown().await.expect("shutdown");
    }

    // ── seal/open (ADR-020 §4) ──────────────────────────────────────

    #[tokio::test]
    async fn seal_open_round_trip_on_open_node() {
        use koi_common::sealed::Confidentiality;
        let dir = std::env::temp_dir().join(format!("koi-emb-seal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let koi = crate::Builder::new()
            .data_dir(&dir)
            .service_mode(crate::ServiceMode::EmbeddedOnly)
            .mdns(false)
            .dns_enabled(false)
            .health(false)
            .certmesh(true)
            .proxy(false)
            .build()
            .expect("build");
        let handle = koi.start().await.expect("start");
        let cm = handle.certmesh().expect("certmesh handle");

        // Open node: seal is a passthrough (signed-not-encrypted); the same code path
        // round-trips the bytes back with an anonymous assurance.
        let sealed = cm.seal(b"hello seal").await.expect("seal");
        assert_eq!(sealed.confidentiality(), Confidentiality::None);
        let opened = cm.open(&sealed).await.expect("open");
        assert_eq!(opened.payload, b"hello seal");
        assert_eq!(opened.confidentiality, Confidentiality::None);
        assert!(
            opened.assurance.identity().is_none(),
            "an Open node's seal is anonymous, not a trusted identity"
        );

        handle.shutdown().await.expect("shutdown");
    }
}
