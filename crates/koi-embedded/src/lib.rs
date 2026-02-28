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
            let mut dns_config = self.config.dns_config.clone();
            // Pin the state path to the data dir captured at construction time
            // so it is immune to KOI_DATA_DIR env var races in parallel tests.
            if let Some(dir) = &self.config.data_dir {
                dns_config.state_path = Some(dir.join("state").join("dns.json"));
            }
            let core = koi_dns::DnsCore::new(
                dns_config,
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
                Box::pin(async move {
                    build_embedded_snapshot(m, cm, d, h, p, u).await
                })
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
                let adapter = mdns_browse_adapter::MdnsBrowseAdapter::new(
                    mdns_core.clone(),
                    cancel.clone(),
                );
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
                    http_cancel,
                )
                .await;
            }));
        }

        // ── HTTP mDNS announcement (opt-in) ──
        let http_announce_id = if self.config.announce_http
            && self.config.http_enabled
            && self.config.mdns_enabled
        {
            if let Some(ref mdns_core) = mdns {
                let hostname = hostname::get()
                    .ok()
                    .and_then(|os| os.into_string().ok())
                    .unwrap_or_else(|| "unknown".to_string());

                let mut txt = std::collections::HashMap::new();
                txt.insert("path".to_string(), "/".to_string());
                txt.insert(
                    "version".to_string(),
                    env!("CARGO_PKG_VERSION").to_string(),
                );
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
            mdns, dns, health, certmesh, proxy, udp, event_tx, cancel, tasks,
            http_announce_id,
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

    // ── Auto-unlock at init: single source of truth ─────────────
    // If the auto-unlock key file exists, boot the core already
    // unlocked.  This collapses the "create locked → read key →
    // unlock" three-step into a single atomic construction.
    let auto_key_path = koi_common::paths::koi_data_dir().join("auto-unlock-key");
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
