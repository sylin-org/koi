mod config;
mod events;
mod handle;
pub(crate) mod http;
mod mdns_browse_adapter;

use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_client::KoiClient;

pub use config::{DnsConfigBuilder, KoiConfig, ServiceMode};
pub use events::KoiEvent;
pub use handle::{CertmeshHandle, DnsHandle, HealthHandle, KoiHandle, MdnsHandle, ProxyHandle};

// Re-export types needed by downstream consumers (registration, discovery, DNS, proxy, health)
pub use koi_common::firewall::{FirewallPort, FirewallProtocol};
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
    extra_firewall_ports: Vec<koi_common::firewall::FirewallPort>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            config: KoiConfig::default(),
            event_handler: None,
            extra_firewall_ports: Vec::new(),
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

    pub fn udp(mut self, enabled: bool) -> Self {
        self.config.udp_enabled = enabled;
        self
    }

    pub fn http_port(mut self, port: u16) -> Self {
        self.config.http_port = port;
        self
    }

    pub fn dashboard(mut self, enabled: bool) -> Self {
        self.config.dashboard_enabled = enabled;
        self
    }

    pub fn api_docs(mut self, enabled: bool) -> Self {
        self.config.api_docs_enabled = enabled;
        self
    }

    pub fn mdns_browser(mut self, enabled: bool) -> Self {
        self.config.mdns_browser_enabled = enabled;
        self
    }

    pub fn announce_http(mut self, enabled: bool) -> Self {
        self.config.announce_http = enabled;
        self
    }

    pub fn events<F>(mut self, handler: F) -> Self
    where
        F: Fn(KoiEvent) + Send + Sync + 'static,
    {
        self.event_handler = Some(Arc::new(handler));
        self
    }

    /// Register additional firewall ports that the host application needs
    /// opened (e.g. Moss discovery UDP, HTTP API).  These are merged with
    /// the ports from enabled Koi capabilities when `ensure_firewall_rules`
    /// is called.
    pub fn extra_firewall_ports(mut self, ports: Vec<koi_common::firewall::FirewallPort>) -> Self {
        self.extra_firewall_ports = ports;
        self
    }

    /// Best-effort ensure that Windows Firewall inbound-allow rules exist
    /// for every port required by the enabled capabilities **plus** any
    /// extra ports registered by the host application.
    ///
    /// * Idempotent — safe to call on every startup.
    /// * Non-fatal  — logs warnings but never fails the build.
    /// * No-op on non-Windows platforms.
    ///
    /// `prefix` is used in the firewall rule display-names
    /// (e.g. `"Zen Garden"` → `"Zen Garden mDNS (UDP 5353)"`).
    pub fn ensure_firewall_rules(self, prefix: &str) -> Self {
        let mut all_ports = self.config.firewall_ports();
        all_ports.extend(self.extra_firewall_ports.iter().cloned());

        let count = koi_common::firewall::ensure_firewall_rules(prefix, &all_ports);
        if count > 0 {
            tracing::info!(count, "Firewall rules ensured");
        }
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
            let data_dir = self.config.data_dir.clone();
            tokio::task::spawn_blocking(move || init_certmesh_core(data_dir.as_deref()))
                .await
                .map_err(|e| std::io::Error::other(format!("certmesh init: {e}")))?
        } else {
            None
        };

        // Integration bridges for cross-domain communication
        let mdns_bridge: Option<Arc<dyn koi_common::integration::MdnsSnapshot>> =
            if let Some(ref core) = mdns {
                Some(MdnsBridgeEmbedded::spawn(core.clone()).await)
            } else {
                None
            };

        let certmesh_bridge: Option<Arc<dyn koi_common::integration::CertmeshSnapshot>> =
            certmesh.as_ref().map(|core| {
                CertmeshBridgeEmbedded::new(core.clone())
                    as Arc<dyn koi_common::integration::CertmeshSnapshot>
            });

        let alias_feedback: Option<Arc<dyn koi_common::integration::AliasFeedback>> =
            certmesh.as_ref().map(|core| {
                AliasFeedbackBridgeEmbedded::new(core.clone())
                    as Arc<dyn koi_common::integration::AliasFeedback>
            });

        let dns = if self.config.dns_enabled {
            let mut dns_config = self.config.dns_config.clone();
            // Pin the state path to the data dir captured at construction time
            // so it is immune to KOI_DATA_DIR env var races in parallel tests.
            if let Some(dir) = &self.config.data_dir {
                dns_config.state_path = Some(dir.join("state").join("dns.json"));
            }
            let core = koi_dns::DnsCore::new(
                dns_config,
                mdns_bridge.clone(),
                certmesh_bridge.clone(),
                alias_feedback,
            )
            .await?;
            Some(Arc::new(koi_dns::DnsRuntime::new(core)))
        } else {
            None
        };

        let proxy = if self.config.proxy_enabled {
            let core = if let Some(dir) = &self.config.data_dir {
                Arc::new(koi_proxy::ProxyCore::with_data_dir(dir)?)
            } else {
                Arc::new(koi_proxy::ProxyCore::new()?)
            };
            Some(Arc::new(koi_proxy::ProxyRuntime::new(core)))
        } else {
            None
        };

        let dns_bridge: Option<Arc<dyn koi_common::integration::DnsProbe>> =
            dns.as_ref().map(|rt| {
                DnsBridgeEmbedded::new(rt.clone()) as Arc<dyn koi_common::integration::DnsProbe>
            });

        let proxy_bridge: Option<Arc<dyn koi_common::integration::ProxySnapshot>> =
            proxy.as_ref().map(|rt| {
                ProxyBridgeEmbedded::new(rt.core())
                    as Arc<dyn koi_common::integration::ProxySnapshot>
            });

        let health = if self.config.health_enabled {
            let core = koi_health::HealthCore::new(
                mdns_bridge.clone(),
                dns_bridge,
                certmesh_bridge,
                proxy_bridge,
            )
            .await;
            Some(Arc::new(koi_health::HealthRuntime::new(Arc::new(core))))
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

        let udp = if self.config.udp_enabled {
            Some(Arc::new(koi_udp::UdpRuntime::new(cancel.clone())))
        } else {
            None
        };

        // Build dashboard state if enabled
        let dashboard_state = if self.config.dashboard_enabled && self.config.http_enabled {
            let started_at = std::time::Instant::now();
            let snap_mdns = mdns.clone();
            let snap_certmesh = certmesh.clone();
            let snap_dns = dns.clone();
            let snap_health = health.clone();
            let snap_proxy = proxy.clone();
            let snap_udp = udp.clone();

            let snapshot_fn: koi_common::dashboard::SnapshotFn = Arc::new(move || {
                let m = snap_mdns.clone();
                let cm = snap_certmesh.clone();
                let d = snap_dns.clone();
                let h = snap_health.clone();
                let p = snap_proxy.clone();
                let u = snap_udp.clone();
                Box::pin(async move { build_embedded_snapshot(m, cm, d, h, p, u).await })
            });

            let (dash_event_tx, _) = broadcast::channel(256);
            let ds = koi_common::dashboard::DashboardState {
                identity: koi_common::dashboard::DashboardIdentity {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    platform: std::env::consts::OS.to_string(),
                },
                mode: "embedded",
                snapshot_fn,
                event_tx: dash_event_tx.clone(),
                started_at,
            };

            // Spawn event forwarder for dashboard SSE
            {
                let mut mdns_rx = mdns.as_ref().map(|c| c.subscribe());
                let mut health_rx = health.as_ref().map(|r| r.core().subscribe());
                let mut dns_rx = dns.as_ref().map(|r| r.core().subscribe());
                let mut certmesh_rx = certmesh.as_ref().map(|c| c.subscribe());
                let mut proxy_rx = proxy.as_ref().map(|r| r.core().subscribe());
                let tx = dash_event_tx;
                let token = cancel.clone();
                tasks.push(tokio::spawn(async move {
                    loop {
                        let sse_event: Option<koi_common::dashboard::DashboardSseEvent> = tokio::select! {
                            _ = token.cancelled() => break,
                            Some(Ok(ev)) = async { match mdns_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                                let id = uuid::Uuid::now_v7().to_string();
                                match ev {
                                    koi_mdns::MdnsEvent::Found(record) => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "mdns.found".to_string(), id,
                                        data: serde_json::to_value(record).unwrap_or_default(),
                                    }),
                                    koi_mdns::MdnsEvent::Resolved(record) => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "mdns.resolved".to_string(), id,
                                        data: serde_json::to_value(record).unwrap_or_default(),
                                    }),
                                    koi_mdns::MdnsEvent::Removed { name, service_type } => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "mdns.removed".to_string(), id,
                                        data: serde_json::json!({ "name": name, "service_type": service_type }),
                                    }),
                                }
                            },
                            Some(Ok(ev)) = async { match health_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                                let id = uuid::Uuid::now_v7().to_string();
                                match ev {
                                    koi_health::HealthEvent::StatusChanged { name, status } => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "health.changed".to_string(), id,
                                        data: serde_json::json!({ "name": name, "status": status }),
                                    }),
                                }
                            },
                            Some(Ok(ev)) = async { match dns_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                                let id = uuid::Uuid::now_v7().to_string();
                                match ev {
                                    koi_dns::DnsEvent::EntryUpdated { name, ip } => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "dns.updated".to_string(), id,
                                        data: serde_json::json!({ "name": name, "ip": ip }),
                                    }),
                                    koi_dns::DnsEvent::EntryRemoved { name } => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "dns.removed".to_string(), id,
                                        data: serde_json::json!({ "name": name }),
                                    }),
                                }
                            },
                            Some(Ok(ev)) = async { match certmesh_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                                let id = uuid::Uuid::now_v7().to_string();
                                match ev {
                                    koi_certmesh::CertmeshEvent::MemberJoined { hostname, fingerprint } => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "certmesh.joined".to_string(), id,
                                        data: serde_json::json!({ "hostname": hostname, "fingerprint": fingerprint }),
                                    }),
                                    koi_certmesh::CertmeshEvent::MemberRevoked { hostname } => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "certmesh.revoked".to_string(), id,
                                        data: serde_json::json!({ "hostname": hostname }),
                                    }),
                                    koi_certmesh::CertmeshEvent::Destroyed => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "certmesh.destroyed".to_string(), id,
                                        data: serde_json::json!({}),
                                    }),
                                }
                            },
                            Some(Ok(ev)) = async { match proxy_rx.as_mut() { Some(rx) => Some(rx.recv().await), None => None } } => {
                                let id = uuid::Uuid::now_v7().to_string();
                                match ev {
                                    koi_proxy::ProxyEvent::EntryUpdated { entry } => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "proxy.updated".to_string(), id,
                                        data: serde_json::to_value(entry).unwrap_or_default(),
                                    }),
                                    koi_proxy::ProxyEvent::EntryRemoved { name } => Some(koi_common::dashboard::DashboardSseEvent {
                                        event_type: "proxy.removed".to_string(), id,
                                        data: serde_json::json!({ "name": name }),
                                    }),
                                }
                            },
                        };
                        if let Some(ev) = sse_event {
                            let _ = tx.send(ev);
                        }
                    }
                }));
            }

            Some(ds)
        } else {
            None
        };

        // Build browser state if enabled (requires mDNS)
        let browser_state = if self.config.mdns_browser_enabled && self.config.http_enabled {
            if let Some(ref mdns_core) = mdns {
                let adapter =
                    mdns_browse_adapter::MdnsBrowseAdapter::new(mdns_core.clone(), cancel.clone());
                let cache = koi_common::browser::BrowserCache::new();
                let source = adapter.clone() as Arc<dyn koi_common::browser::BrowseSource>;
                let bc = cache.clone();
                let token = cancel.clone();
                tasks.push(tokio::spawn(async move {
                    koi_common::browser::worker(source, bc, token).await;
                }));
                Some(koi_common::browser::BrowserState {
                    source: adapter,
                    cache,
                })
            } else {
                tracing::warn!("mdns_browser enabled but mDNS is disabled — skipping browser");
                None
            }
        } else {
            None
        };

        // Spawn embedded HTTP adapter if enabled
        if self.config.http_enabled {
            let http_port = self.config.http_port;
            let http_cancel = cancel.clone();
            let http_mdns = mdns.clone();
            let http_dns = dns.clone();
            let http_health = health.clone();
            let http_certmesh = certmesh.clone();
            let http_proxy = proxy.clone();
            let http_udp = udp.clone();
            let http_api_docs = self.config.api_docs_enabled;
            tasks.push(tokio::spawn(async move {
                http::serve(
                    http_port,
                    http_mdns,
                    http_dns,
                    http_health,
                    http_certmesh,
                    http_proxy,
                    http_udp,
                    dashboard_state,
                    browser_state,
                    http_api_docs,
                    http_cancel,
                )
                .await;
            }));
        }

        // ── HTTP mDNS announcement (opt-in) ──
        let http_announce_id =
            if self.config.announce_http && self.config.http_enabled && self.config.mdns_enabled {
                if let Some(ref mdns_core) = mdns {
                    let hostname = hostname::get()
                        .ok()
                        .and_then(|os| os.into_string().ok())
                        .unwrap_or_else(|| "unknown".to_string());

                    let mut txt = std::collections::HashMap::new();
                    txt.insert("path".to_string(), "/".to_string());
                    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
                    txt.insert("api".to_string(), "v1".to_string());
                    txt.insert(
                        "dashboard".to_string(),
                        self.config.dashboard_enabled.to_string(),
                    );

                    let payload = koi_mdns::protocol::RegisterPayload {
                        name: format!("Koi ({hostname})"),
                        service_type: "_http._tcp".to_string(),
                        port: self.config.http_port,
                        ip: None,
                        lease_secs: None,
                        txt,
                    };
                    match mdns_core.register(payload) {
                        Ok(result) => {
                            tracing::info!(
                                id = %result.id,
                                port = self.config.http_port,
                                "HTTP server announced via mDNS"
                            );
                            Some(result.id)
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to announce HTTP server via mDNS");
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };

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
            mdns,
            dns,
            health,
            certmesh,
            proxy,
            udp,
            event_tx,
            cancel,
            tasks,
            http_announce_id,
        ))
    }
}

fn init_certmesh_core(
    data_dir: Option<&std::path::Path>,
) -> Option<Arc<koi_certmesh::CertmeshCore>> {
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

    // ── Auto-unlock at init: single source of truth ─────────────
    // If the auto-unlock key file exists, boot the core already
    // unlocked.  This collapses the "create locked -> read key ->
    // unlock" three-step into a single atomic construction.
    let resolved_data_dir = koi_common::paths::koi_data_dir_with_override(data_dir);
    let auto_key_path = resolved_data_dir.join("auto-unlock-key");
    if let Ok(pp) = std::fs::read_to_string(&auto_key_path) {
        if !pp.is_empty() {
            match koi_certmesh::ca::load_ca(&pp) {
                Ok(ca_state) => {
                    // Reload roster (fresh copy for the new Arc)
                    if let Ok(fresh_roster) = koi_certmesh::roster::load_roster(&roster_path) {
                        let auth_path = koi_certmesh::ca::auth_path();
                        let auth = if auth_path.exists() {
                            std::fs::read_to_string(&auth_path)
                                .ok()
                                .and_then(|json| {
                                    serde_json::from_str::<koi_crypto::auth::StoredAuth>(&json).ok()
                                })
                                .and_then(|stored| stored.unlock(&pp).ok())
                        } else {
                            None
                        };

                        tracing::info!("Certmesh CA auto-unlocked at init");
                        return Some(Arc::new(koi_certmesh::CertmeshCore::new(
                            ca_state,
                            fresh_roster,
                            auth,
                            profile,
                        )));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Auto-unlock key exists but decryption failed"
                    );
                }
            }
        }
    }

    // No auto-unlock key - boot locked
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

/// Build a dashboard snapshot from the embedded domain cores.
async fn build_embedded_snapshot(
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
) -> serde_json::Value {
    use koi_common::capability::Capability;

    let mut capabilities = Vec::new();

    if let Some(ref core) = mdns {
        let s = core.status();
        capabilities.push(serde_json::json!({
            "name": s.name, "enabled": true, "healthy": s.healthy, "summary": s.summary,
        }));
    } else {
        capabilities.push(serde_json::json!({
            "name": "mdns", "enabled": false, "healthy": false, "summary": "disabled",
        }));
    }

    if let Some(ref core) = certmesh {
        let s = core.status();
        capabilities.push(serde_json::json!({
            "name": s.name, "enabled": true, "healthy": s.healthy, "summary": s.summary,
        }));
    } else {
        capabilities.push(serde_json::json!({
            "name": "certmesh", "enabled": false, "healthy": false, "summary": "disabled",
        }));
    }

    if let Some(ref runtime) = dns {
        let running = runtime.status().await.running;
        if running {
            let s = runtime.core().status();
            capabilities.push(serde_json::json!({
                "name": s.name, "enabled": true, "healthy": s.healthy, "summary": s.summary,
            }));
        } else {
            capabilities.push(serde_json::json!({
                "name": "dns", "enabled": true, "healthy": false, "summary": "stopped",
            }));
        }
    } else {
        capabilities.push(serde_json::json!({
            "name": "dns", "enabled": false, "healthy": false, "summary": "disabled",
        }));
    }

    if let Some(ref runtime) = health {
        let running = runtime.status().await.running;
        if running {
            let s = runtime.core().status();
            capabilities.push(serde_json::json!({
                "name": s.name, "enabled": true, "healthy": s.healthy, "summary": s.summary,
            }));
        } else {
            capabilities.push(serde_json::json!({
                "name": "health", "enabled": true, "healthy": false, "summary": "stopped",
            }));
        }
    } else {
        capabilities.push(serde_json::json!({
            "name": "health", "enabled": false, "healthy": false, "summary": "disabled",
        }));
    }

    if let Some(ref runtime) = proxy {
        let status = runtime.status().await;
        capabilities.push(serde_json::json!({
            "name": "proxy", "enabled": true, "healthy": true,
            "summary": if status.is_empty() { "no listeners".to_string() } else { format!("{} listeners", status.len()) },
        }));
    } else {
        capabilities.push(serde_json::json!({
            "name": "proxy", "enabled": false, "healthy": false, "summary": "disabled",
        }));
    }

    if let Some(ref runtime) = udp {
        let s = Capability::status(runtime.as_ref());
        capabilities.push(serde_json::json!({
            "name": s.name, "enabled": true, "healthy": s.healthy, "summary": s.summary,
        }));
    } else {
        capabilities.push(serde_json::json!({
            "name": "udp", "enabled": false, "healthy": false, "summary": "disabled",
        }));
    }

    serde_json::json!({ "capabilities": capabilities })
}

// ── Embedded integration bridges ───────────────────────────────────
// Duplicated from the binary crate's integrations.rs because koi-embedded
// is a separate crate that directly imports all domain crates.

struct CertmeshBridgeEmbedded(#[allow(dead_code)] Arc<koi_certmesh::CertmeshCore>);

impl CertmeshBridgeEmbedded {
    fn new(core: Arc<koi_certmesh::CertmeshCore>) -> Arc<Self> {
        Arc::new(Self(core))
    }
}

impl koi_common::integration::CertmeshSnapshot for CertmeshBridgeEmbedded {
    fn active_members(&self) -> Vec<koi_common::integration::MemberSummary> {
        let roster_path = koi_certmesh::ca::roster_path();
        let Ok(roster) = koi_certmesh::roster::load_roster(&roster_path) else {
            return Vec::new();
        };
        roster
            .members
            .into_iter()
            .filter(|m| m.status == koi_certmesh::roster::MemberStatus::Active)
            .map(|m| koi_common::integration::MemberSummary {
                hostname: m.hostname,
                sans: m.cert_sans,
                cert_expires: Some(m.cert_expires),
                last_seen: m.last_seen,
                status: "active".to_string(),
                proxy_entries: m
                    .proxy_entries
                    .into_iter()
                    .map(|p| koi_common::integration::ProxyConfigSummary {
                        name: p.name,
                        listen_port: p.listen_port,
                        backend: p.backend,
                        allow_remote: p.allow_remote,
                    })
                    .collect(),
            })
            .collect()
    }
}

struct MdnsBridgeEmbedded {
    records: Arc<
        std::sync::RwLock<
            std::collections::HashMap<String, std::collections::HashMap<String, ServiceRecord>>,
        >,
    >,
    cancel: CancellationToken,
}

impl MdnsBridgeEmbedded {
    async fn spawn(core: Arc<koi_mdns::MdnsCore>) -> Arc<Self> {
        use koi_common::types::META_QUERY;
        let records = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let cancel = CancellationToken::new();

        let meta_core = Arc::clone(&core);
        let meta_records = Arc::clone(&records);
        let meta_cancel = cancel.clone();
        tokio::spawn(async move {
            if let Ok(handle) = meta_core.browse(META_QUERY).await {
                run_meta_browse_embedded(meta_core, handle, meta_records, meta_cancel).await;
            }
        });

        Arc::new(Self { records, cancel })
    }
}

impl Drop for MdnsBridgeEmbedded {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl koi_common::integration::MdnsSnapshot for MdnsBridgeEmbedded {
    fn host_ips(&self) -> std::collections::HashMap<String, std::net::IpAddr> {
        let guard = self.records.read().unwrap_or_else(|e| e.into_inner());
        let mut map = std::collections::HashMap::new();
        for type_map in guard.values() {
            for record in type_map.values() {
                let Some(host) = record.host.as_deref() else {
                    continue;
                };
                let Some(ip) = record.ip.as_deref().and_then(|ip| ip.parse().ok()) else {
                    continue;
                };
                let hostname = host.trim_end_matches('.').trim_end_matches(".local");
                if !hostname.is_empty() {
                    map.insert(hostname.to_string(), ip);
                }
            }
        }
        map
    }

    fn cached_records(&self) -> Vec<ServiceRecord> {
        let guard = self.records.read().unwrap_or_else(|e| e.into_inner());
        guard.values().flat_map(|m| m.values().cloned()).collect()
    }
}

struct DnsBridgeEmbedded(Arc<koi_dns::DnsRuntime>);

impl DnsBridgeEmbedded {
    fn new(runtime: Arc<koi_dns::DnsRuntime>) -> Arc<Self> {
        Arc::new(Self(runtime))
    }
}

impl koi_common::integration::DnsProbe for DnsBridgeEmbedded {
    fn resolve_local(&self, name: &str) -> Option<Vec<std::net::IpAddr>> {
        use hickory_proto::rr::RecordType;
        let core = self.0.core();
        let result = core
            .resolve_local(name, RecordType::A)
            .or_else(|| core.resolve_local(name, RecordType::AAAA));
        result.map(|r| r.ips)
    }
}

struct ProxyBridgeEmbedded(#[allow(dead_code)] Arc<koi_proxy::ProxyCore>);

impl ProxyBridgeEmbedded {
    fn new(core: Arc<koi_proxy::ProxyCore>) -> Arc<Self> {
        Arc::new(Self(core))
    }
}

impl koi_common::integration::ProxySnapshot for ProxyBridgeEmbedded {
    fn entries(&self) -> Vec<koi_common::integration::ProxyEntrySummary> {
        let Ok(entries) = koi_proxy::config::load_entries() else {
            return Vec::new();
        };
        entries
            .into_iter()
            .map(|e| koi_common::integration::ProxyEntrySummary {
                name: e.name,
                listen_port: e.listen_port,
                backend: e.backend,
            })
            .collect()
    }
}

struct AliasFeedbackBridgeEmbedded(Arc<koi_certmesh::CertmeshCore>);

impl AliasFeedbackBridgeEmbedded {
    fn new(core: Arc<koi_certmesh::CertmeshCore>) -> Arc<Self> {
        Arc::new(Self(core))
    }
}

impl koi_common::integration::AliasFeedback for AliasFeedbackBridgeEmbedded {
    fn record_alias(&self, hostname: &str, alias: &str) {
        let core = Arc::clone(&self.0);
        let hostname = hostname.to_string();
        let alias = alias.to_string();
        tokio::spawn(async move {
            let _ = core.add_alias_sans(&hostname, &[alias]).await;
        });
    }
}

async fn run_meta_browse_embedded(
    core: Arc<koi_mdns::MdnsCore>,
    handle: koi_mdns::BrowseHandle,
    records: Arc<
        std::sync::RwLock<
            std::collections::HashMap<String, std::collections::HashMap<String, ServiceRecord>>,
        >,
    >,
    cancel: CancellationToken,
) {
    let active = Arc::new(tokio::sync::Mutex::new(
        std::collections::HashSet::<String>::new(),
    ));
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
                                run_type_browse_embedded(handle, r, cancel_child).await;
                            }
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::types::ServiceRecord;
    use std::collections::HashMap;

    fn sample_record() -> ServiceRecord {
        ServiceRecord {
            name: "Test Service".to_string(),
            service_type: "_http._tcp".to_string(),
            host: Some("host.local".to_string()),
            ip: Some("10.0.0.1".to_string()),
            port: Some(8080),
            txt: HashMap::new(),
        }
    }

    // ── KoiError Display ───────────────────────────────────────────

    #[test]
    fn koi_error_disabled_capability_display() {
        let err = KoiError::DisabledCapability("mdns");
        assert_eq!(err.to_string(), "capability disabled: mdns");
    }

    #[test]
    fn koi_error_io_from_impl() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: KoiError = io_err.into();
        assert!(matches!(err, KoiError::Io(_)));
        assert!(err.to_string().contains("file missing"));
    }

    #[test]
    fn koi_error_debug_does_not_panic() {
        let err = KoiError::DisabledCapability("proxy");
        let debug = format!("{err:?}");
        assert!(debug.contains("DisabledCapability"));
    }

    // ── map_mdns_event ─────────────────────────────────────────────

    #[test]
    fn map_mdns_found() {
        let record = sample_record();
        let event = koi_mdns::MdnsEvent::Found(record.clone());
        let mapped = map_mdns_event(event);
        assert!(mapped.is_some());
        match mapped.unwrap() {
            KoiEvent::MdnsFound(r) => assert_eq!(r.name, "Test Service"),
            other => panic!("expected MdnsFound, got {other:?}"),
        }
    }

    #[test]
    fn map_mdns_resolved() {
        let record = sample_record();
        let event = koi_mdns::MdnsEvent::Resolved(record);
        let mapped = map_mdns_event(event);
        assert!(mapped.is_some());
        match mapped.unwrap() {
            KoiEvent::MdnsResolved(r) => {
                assert_eq!(r.port, Some(8080));
                assert_eq!(r.service_type, "_http._tcp");
            }
            other => panic!("expected MdnsResolved, got {other:?}"),
        }
    }

    #[test]
    fn map_mdns_removed() {
        let event = koi_mdns::MdnsEvent::Removed {
            name: "Gone Service".to_string(),
            service_type: "_http._tcp".to_string(),
        };
        let mapped = map_mdns_event(event);
        assert!(mapped.is_some());
        match mapped.unwrap() {
            KoiEvent::MdnsRemoved { name, service_type } => {
                assert_eq!(name, "Gone Service");
                assert_eq!(service_type, "_http._tcp");
            }
            other => panic!("expected MdnsRemoved, got {other:?}"),
        }
    }

    // ── map_health_event ───────────────────────────────────────────

    #[test]
    fn map_health_status_changed_up() {
        let event = koi_health::HealthEvent::StatusChanged {
            name: "api".to_string(),
            status: koi_health::HealthStatus::Up,
        };
        let mapped = map_health_event(event);
        match mapped {
            KoiEvent::HealthChanged { name, status } => {
                assert_eq!(name, "api");
                assert!(matches!(status, koi_health::HealthStatus::Up));
            }
            other => panic!("expected HealthChanged, got {other:?}"),
        }
    }

    #[test]
    fn map_health_status_changed_down() {
        let event = koi_health::HealthEvent::StatusChanged {
            name: "db".to_string(),
            status: koi_health::HealthStatus::Down,
        };
        let mapped = map_health_event(event);
        match mapped {
            KoiEvent::HealthChanged { name, status } => {
                assert_eq!(name, "db");
                assert!(matches!(status, koi_health::HealthStatus::Down));
            }
            other => panic!("expected HealthChanged, got {other:?}"),
        }
    }

    // ── map_dns_event ──────────────────────────────────────────────

    #[test]
    fn map_dns_entry_updated() {
        let event = koi_dns::DnsEvent::EntryUpdated {
            name: "grafana".to_string(),
            ip: "10.0.0.5".to_string(),
        };
        let mapped = map_dns_event(event);
        match mapped {
            KoiEvent::DnsEntryUpdated { name, ip } => {
                assert_eq!(name, "grafana");
                assert_eq!(ip, "10.0.0.5");
            }
            other => panic!("expected DnsEntryUpdated, got {other:?}"),
        }
    }

    #[test]
    fn map_dns_entry_removed() {
        let event = koi_dns::DnsEvent::EntryRemoved {
            name: "old-host".to_string(),
        };
        let mapped = map_dns_event(event);
        match mapped {
            KoiEvent::DnsEntryRemoved { name } => {
                assert_eq!(name, "old-host");
            }
            other => panic!("expected DnsEntryRemoved, got {other:?}"),
        }
    }

    // ── map_certmesh_event ─────────────────────────────────────────

    #[test]
    fn map_certmesh_member_joined() {
        let event = koi_certmesh::CertmeshEvent::MemberJoined {
            hostname: "node-a".to_string(),
            fingerprint: "sha256:abc".to_string(),
        };
        let mapped = map_certmesh_event(event);
        match mapped {
            KoiEvent::CertmeshMemberJoined {
                hostname,
                fingerprint,
            } => {
                assert_eq!(hostname, "node-a");
                assert_eq!(fingerprint, "sha256:abc");
            }
            other => panic!("expected CertmeshMemberJoined, got {other:?}"),
        }
    }

    #[test]
    fn map_certmesh_member_revoked() {
        let event = koi_certmesh::CertmeshEvent::MemberRevoked {
            hostname: "node-b".to_string(),
        };
        let mapped = map_certmesh_event(event);
        match mapped {
            KoiEvent::CertmeshMemberRevoked { hostname } => {
                assert_eq!(hostname, "node-b");
            }
            other => panic!("expected CertmeshMemberRevoked, got {other:?}"),
        }
    }

    #[test]
    fn map_certmesh_destroyed() {
        let event = koi_certmesh::CertmeshEvent::Destroyed;
        let mapped = map_certmesh_event(event);
        assert!(matches!(mapped, KoiEvent::CertmeshDestroyed));
    }

    // ── map_proxy_event ────────────────────────────────────────────

    #[test]
    fn map_proxy_entry_updated() {
        let entry = koi_proxy::ProxyEntry {
            name: "web".to_string(),
            listen_port: 443,
            backend: "http://localhost:3000".to_string(),
            allow_remote: true,
        };
        let event = koi_proxy::ProxyEvent::EntryUpdated {
            entry: entry.clone(),
        };
        let mapped = map_proxy_event(event);
        match mapped {
            KoiEvent::ProxyEntryUpdated { entry } => {
                assert_eq!(entry.name, "web");
                assert_eq!(entry.listen_port, 443);
                assert!(entry.allow_remote);
            }
            other => panic!("expected ProxyEntryUpdated, got {other:?}"),
        }
    }

    #[test]
    fn map_proxy_entry_removed() {
        let event = koi_proxy::ProxyEvent::EntryRemoved {
            name: "old-proxy".to_string(),
        };
        let mapped = map_proxy_event(event);
        match mapped {
            KoiEvent::ProxyEntryRemoved { name } => {
                assert_eq!(name, "old-proxy");
            }
            other => panic!("expected ProxyEntryRemoved, got {other:?}"),
        }
    }

    // ── map_join_error ─────────────────────────────────────────────

    #[test]
    fn map_join_error_produces_io_error() {
        // We can't easily create a real JoinError, but we can test the function
        // signature exists and the KoiError::Io variant wraps correctly.
        let io_err = std::io::Error::other("simulated join error");
        let koi_err = KoiError::Io(io_err);
        assert!(koi_err.to_string().contains("simulated join error"));
    }

    // ── Builder defaults ───────────────────────────────────────────

    #[test]
    fn builder_default_config() {
        let builder = Builder::new();
        let embedded = builder.build().expect("build should succeed");
        assert!(embedded.config.mdns_enabled);
        assert!(!embedded.config.http_enabled);
        assert_eq!(embedded.config.http_port, 5641);
    }

    #[test]
    fn builder_default_trait() {
        let builder = Builder::default();
        let embedded = builder.build().expect("build should succeed");
        assert_eq!(embedded.config.service_endpoint, "http://127.0.0.1:5641");
    }

    #[test]
    fn builder_fluent_overrides() {
        let embedded = Builder::new()
            .http(true)
            .mdns(false)
            .dns_enabled(false)
            .health(true)
            .certmesh(true)
            .proxy(true)
            .udp(true)
            .http_port(9000)
            .dashboard(true)
            .api_docs(true)
            .mdns_browser(true)
            .announce_http(true)
            .dns_auto_start(true)
            .health_auto_start(true)
            .proxy_auto_start(true)
            .service_endpoint("http://10.0.0.1:8080")
            .service_mode(ServiceMode::EmbeddedOnly)
            .data_dir("/tmp/koi-test")
            .build()
            .expect("build should succeed");

        assert!(embedded.config.http_enabled);
        assert!(!embedded.config.mdns_enabled);
        assert!(!embedded.config.dns_enabled);
        assert!(embedded.config.health_enabled);
        assert!(embedded.config.certmesh_enabled);
        assert!(embedded.config.proxy_enabled);
        assert!(embedded.config.udp_enabled);
        assert_eq!(embedded.config.http_port, 9000);
        assert!(embedded.config.dashboard_enabled);
        assert!(embedded.config.api_docs_enabled);
        assert!(embedded.config.mdns_browser_enabled);
        assert!(embedded.config.announce_http);
        assert!(embedded.config.dns_auto_start);
        assert!(embedded.config.health_auto_start);
        assert!(embedded.config.proxy_auto_start);
        assert_eq!(
            embedded.config.service_endpoint,
            "http://10.0.0.1:8080"
        );
        assert_eq!(embedded.config.service_mode, ServiceMode::EmbeddedOnly);
        assert_eq!(
            embedded.config.data_dir,
            Some(std::path::PathBuf::from("/tmp/koi-test"))
        );
    }

    #[test]
    fn builder_dns_configure_closure() {
        let embedded = Builder::new()
            .dns(|b| b.port(5353).zone("home").local_ttl(120))
            .build()
            .expect("build should succeed");

        assert_eq!(embedded.config.dns_config.port, 5353);
        assert_eq!(embedded.config.dns_config.zone, "home");
        assert_eq!(embedded.config.dns_config.local_ttl, 120);
    }

    #[test]
    fn builder_event_handler() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let embedded = Builder::new()
            .events(move |_event| {
                called_clone.store(true, Ordering::SeqCst);
            })
            .build()
            .expect("build should succeed");

        assert!(embedded.event_handler.is_some());
    }

    #[test]
    fn builder_extra_firewall_ports() {
        use koi_common::firewall::{FirewallPort, FirewallProtocol};
        let extra = vec![FirewallPort::new("Custom", FirewallProtocol::Tcp, 12345)];
        let _builder = Builder::new().extra_firewall_ports(extra);
        // Just verifying the method compiles and does not panic.
    }

    // ── Result type alias ──────────────────────────────────────────

    #[test]
    fn result_type_works_with_ok() {
        let result: Result<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn result_type_works_with_err() {
        let result: Result<i32> = Err(KoiError::DisabledCapability("test"));
        assert!(result.is_err());
    }
}

async fn run_type_browse_embedded(
    handle: koi_mdns::BrowseHandle,
    records: Arc<
        std::sync::RwLock<
            std::collections::HashMap<String, std::collections::HashMap<String, ServiceRecord>>,
        >,
    >,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            event = handle.recv() => {
                let Some(event) = event else { break; };
                match event {
                    koi_mdns::events::MdnsEvent::Resolved(record) => {
                        let mut guard = records.write().unwrap_or_else(|e| e.into_inner());
                        let entry = guard.entry(record.service_type.clone()).or_default();
                        entry.insert(record.name.clone(), record);
                    }
                    koi_mdns::events::MdnsEvent::Removed { name, service_type } => {
                        let mut guard = records.write().unwrap_or_else(|e| e.into_inner());
                        let st = if service_type.is_empty() {
                            name.find("._").map(|idx| {
                                let rest = &name[idx + 1..];
                                rest.trim_end_matches('.').trim_end_matches(".local").to_string()
                            })
                        } else {
                            Some(service_type)
                        };
                        if let Some(st) = st {
                            if let Some(map) = guard.get_mut(&st) {
                                let instance = name.find("._").map(|idx| name[..idx].to_string());
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
