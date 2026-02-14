mod config;
mod events;
mod handle;

use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_client::KoiClient;

pub use config::{DnsConfigBuilder, KoiConfig, ServiceMode};
pub use events::KoiEvent;
pub use handle::{CertmeshHandle, DnsHandle, HealthHandle, KoiHandle, MdnsHandle, ProxyHandle};

// Re-export types needed by downstream consumers (registration, discovery, DNS, proxy, health)
pub use koi_common::types::ServiceRecord;
pub use koi_config::state::DnsEntry;
pub use koi_health::{HealthCheck, HealthSnapshot, ServiceCheckKind};
pub use koi_mdns::protocol::{RegisterPayload, RegistrationResult};
pub use koi_mdns::MdnsEvent;
pub use koi_proxy::ProxyEntry;

pub type Result<T> = std::result::Result<T, KoiError>;

#[derive(Debug, thiserror::Error)]
pub enum KoiError {
    #[error("capability disabled: {0}")]
    DisabledCapability(&'static str),
    #[error("mdns error: {0}")]
    Mdns(#[from] koi_mdns::MdnsError),
    #[error("dns error: {0}")]
    Dns(#[from] koi_dns::DnsError),
    #[error("health error: {0}")]
    Health(#[from] koi_health::HealthError),
    #[error("proxy error: {0}")]
    Proxy(#[from] koi_proxy::ProxyError),
    #[error("certmesh error: {0}")]
    Certmesh(#[from] koi_certmesh::CertmeshError),
    #[error("client error: {0}")]
    Client(#[from] koi_client::ClientError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Builder {
    config: KoiConfig,
    event_handler: Option<Arc<dyn Fn(KoiEvent) + Send + Sync>>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            config: KoiConfig::default(),
            event_handler: None,
        }
    }

    pub fn data_dir(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.config.data_dir = Some(path.into());
        self
    }

    pub fn service_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config.service_endpoint = endpoint.into();
        self
    }

    pub fn service_mode(mut self, mode: ServiceMode) -> Self {
        self.config.service_mode = mode;
        self
    }

    pub fn http(mut self, enabled: bool) -> Self {
        self.config.http_enabled = enabled;
        self
    }

    pub fn mdns(mut self, enabled: bool) -> Self {
        self.config.mdns_enabled = enabled;
        self
    }

    pub fn dns<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(DnsConfigBuilder) -> DnsConfigBuilder,
    {
        let builder = DnsConfigBuilder::new(self.config.dns_config.clone());
        self.config.dns_config = configure(builder).build();
        self
    }

    pub fn dns_enabled(mut self, enabled: bool) -> Self {
        self.config.dns_enabled = enabled;
        self
    }

    pub fn dns_auto_start(mut self, enabled: bool) -> Self {
        self.config.dns_auto_start = enabled;
        self
    }

    pub fn health(mut self, enabled: bool) -> Self {
        self.config.health_enabled = enabled;
        self
    }

    pub fn health_auto_start(mut self, enabled: bool) -> Self {
        self.config.health_auto_start = enabled;
        self
    }

    pub fn certmesh(mut self, enabled: bool) -> Self {
        self.config.certmesh_enabled = enabled;
        self
    }

    pub fn proxy(mut self, enabled: bool) -> Self {
        self.config.proxy_enabled = enabled;
        self
    }

    pub fn proxy_auto_start(mut self, enabled: bool) -> Self {
        self.config.proxy_auto_start = enabled;
        self
    }

    pub fn events<F>(mut self, handler: F) -> Self
    where
        F: Fn(KoiEvent) + Send + Sync + 'static,
    {
        self.event_handler = Some(Arc::new(handler));
        self
    }

    pub fn build(self) -> Result<KoiEmbedded> {
        Ok(KoiEmbedded {
            config: self.config,
            event_handler: self.event_handler,
        })
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct KoiEmbedded {
    config: KoiConfig,
    event_handler: Option<Arc<dyn Fn(KoiEvent) + Send + Sync>>,
}

impl KoiEmbedded {
    pub async fn start(self) -> Result<KoiHandle> {
        if let Some(dir) = &self.config.data_dir {
            std::env::set_var("KOI_DATA_DIR", dir);
        }

        let cancel = CancellationToken::new();
        let (event_tx, _) = broadcast::channel(256);
        let mut tasks: Vec<JoinHandle<()>> = Vec::new();

        if self.config.service_mode != ServiceMode::EmbeddedOnly {
            let client = Arc::new(KoiClient::new(&self.config.service_endpoint));
            match self.config.service_mode {
                ServiceMode::ClientOnly => {
                    tokio::task::spawn_blocking({
                        let client = Arc::clone(&client);
                        move || client.health()
                    })
                    .await
                    .map_err(map_join_error)??;
                    return Ok(KoiHandle::new_remote(client, event_tx, cancel, tasks));
                }
                ServiceMode::Auto => {
                    let health = tokio::task::spawn_blocking({
                        let client = Arc::clone(&client);
                        move || client.health()
                    })
                    .await;
                    if matches!(health, Ok(Ok(()))) {
                        return Ok(KoiHandle::new_remote(client, event_tx, cancel, tasks));
                    }
                }
                ServiceMode::EmbeddedOnly => {}
            }
        }

        let mdns = if self.config.mdns_enabled {
            Some(Arc::new(koi_mdns::MdnsCore::with_cancel(cancel.clone())?))
        } else {
            None
        };

        let certmesh = if self.config.certmesh_enabled {
            init_certmesh_core()
        } else {
            None
        };

        let dns = if self.config.dns_enabled {
            let core = koi_dns::DnsCore::new(
                self.config.dns_config.clone(),
                mdns.clone(),
                certmesh.clone(),
            )
            .await?;
            Some(Arc::new(koi_dns::DnsRuntime::new(core)))
        } else {
            None
        };

        let health = if self.config.health_enabled {
            let core = koi_health::HealthCore::new(mdns.clone(), dns.clone()).await;
            Some(Arc::new(koi_health::HealthRuntime::new(Arc::new(core))))
        } else {
            None
        };

        let proxy = if self.config.proxy_enabled {
            let core = Arc::new(koi_proxy::ProxyCore::new()?);
            Some(Arc::new(koi_proxy::ProxyRuntime::new(core)))
        } else {
            None
        };

        if let Some(runtime) = &dns {
            if self.config.dns_auto_start {
                let _ = runtime.start().await?;
            }
        }

        if let Some(runtime) = &health {
            if self.config.health_auto_start {
                let _ = runtime.start().await?;
            }
        }

        if let Some(runtime) = &proxy {
            if self.config.proxy_auto_start {
                runtime.start_all().await?;
            }
        }

        if let Some(core) = &mdns {
            let mut rx = core.subscribe();
            let tx = event_tx.clone();
            let token = cancel.clone();
            let handler = self.event_handler.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        msg = rx.recv() => {
                            let Ok(event) = msg else { continue; };
                            let mapped = map_mdns_event(event);
                            if let Some(mapped) = mapped {
                                emit_event(&tx, handler.as_ref(), mapped);
                            }
                        }
                    }
                }
            }));
        }

        if self.config.health_enabled {
            if let Some(runtime) = &health {
                let mut rx = runtime.core().subscribe();
                let tx = event_tx.clone();
                let token = cancel.clone();
                let handler = self.event_handler.clone();
                tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            msg = rx.recv() => {
                                let Ok(event) = msg else { continue; };
                                let mapped = map_health_event(event);
                                emit_event(&tx, handler.as_ref(), mapped);
                            }
                        }
                    }
                }));
            }
        }

        if self.config.dns_enabled {
            if let Some(runtime) = &dns {
                let mut rx = runtime.core().subscribe();
                let tx = event_tx.clone();
                let token = cancel.clone();
                let handler = self.event_handler.clone();
                tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            msg = rx.recv() => {
                                let Ok(event) = msg else { continue; };
                                let mapped = map_dns_event(event);
                                emit_event(&tx, handler.as_ref(), mapped);
                            }
                        }
                    }
                }));
            }
        }

        if self.config.certmesh_enabled {
            if let Some(core) = &certmesh {
                let mut rx = core.subscribe();
                let tx = event_tx.clone();
                let token = cancel.clone();
                let handler = self.event_handler.clone();
                tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            msg = rx.recv() => {
                                let Ok(event) = msg else { continue; };
                                let mapped = map_certmesh_event(event);
                                emit_event(&tx, handler.as_ref(), mapped);
                            }
                        }
                    }
                }));
            }
        }

        if self.config.proxy_enabled {
            if let Some(runtime) = &proxy {
                let mut rx = runtime.core().subscribe();
                let tx = event_tx.clone();
                let token = cancel.clone();
                let handler = self.event_handler.clone();
                tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            msg = rx.recv() => {
                                let Ok(event) = msg else { continue; };
                                let mapped = map_proxy_event(event);
                                emit_event(&tx, handler.as_ref(), mapped);
                            }
                        }
                    }
                }));
            }
        }

        Ok(KoiHandle::new_embedded(
            mdns, dns, health, certmesh, proxy, event_tx, cancel, tasks,
        ))
    }
}

fn init_certmesh_core() -> Option<Arc<koi_certmesh::CertmeshCore>> {
    if !koi_certmesh::ca::is_ca_initialized() {
        return Some(Arc::new(koi_certmesh::CertmeshCore::uninitialized()));
    }

    let roster_path = koi_certmesh::ca::roster_path();
    let roster = match koi_certmesh::roster::load_roster(&roster_path) {
        Ok(r) => r,
        Err(_) => {
            return Some(Arc::new(koi_certmesh::CertmeshCore::uninitialized()));
        }
    };

    let profile = roster.metadata.trust_profile;
    let core = koi_certmesh::CertmeshCore::locked(roster, profile);
    Some(Arc::new(core))
}

fn map_mdns_event(event: MdnsEvent) -> Option<KoiEvent> {
    match event {
        MdnsEvent::Found(record) => Some(KoiEvent::MdnsFound(record)),
        MdnsEvent::Resolved(record) => Some(KoiEvent::MdnsResolved(record)),
        MdnsEvent::Removed { name, service_type } => {
            Some(KoiEvent::MdnsRemoved { name, service_type })
        }
    }
}

fn map_health_event(event: koi_health::HealthEvent) -> KoiEvent {
    match event {
        koi_health::HealthEvent::StatusChanged { name, status } => {
            KoiEvent::HealthChanged { name, status }
        }
    }
}

fn map_dns_event(event: koi_dns::DnsEvent) -> KoiEvent {
    match event {
        koi_dns::DnsEvent::EntryUpdated { name, ip } => KoiEvent::DnsEntryUpdated { name, ip },
        koi_dns::DnsEvent::EntryRemoved { name } => KoiEvent::DnsEntryRemoved { name },
    }
}

fn map_certmesh_event(event: koi_certmesh::CertmeshEvent) -> KoiEvent {
    match event {
        koi_certmesh::CertmeshEvent::MemberJoined {
            hostname,
            fingerprint,
        } => KoiEvent::CertmeshMemberJoined {
            hostname,
            fingerprint,
        },
        koi_certmesh::CertmeshEvent::MemberRevoked { hostname } => {
            KoiEvent::CertmeshMemberRevoked { hostname }
        }
        koi_certmesh::CertmeshEvent::Destroyed => KoiEvent::CertmeshDestroyed,
    }
}

fn map_proxy_event(event: koi_proxy::ProxyEvent) -> KoiEvent {
    match event {
        koi_proxy::ProxyEvent::EntryUpdated { entry } => KoiEvent::ProxyEntryUpdated { entry },
        koi_proxy::ProxyEvent::EntryRemoved { name } => KoiEvent::ProxyEntryRemoved { name },
    }
}

fn emit_event(
    tx: &broadcast::Sender<KoiEvent>,
    handler: Option<&Arc<dyn Fn(KoiEvent) + Send + Sync>>,
    event: KoiEvent,
) {
    if let Some(handler) = handler {
        handler(event.clone());
    }
    let _ = tx.send(event);
}

pub(crate) fn map_join_error(err: tokio::task::JoinError) -> KoiError {
    KoiError::Io(std::io::Error::other(err.to_string()))
}
