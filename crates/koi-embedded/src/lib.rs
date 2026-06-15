mod config;
mod events;
mod handle;
pub(crate) mod http;

use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_client::KoiClient;
use koi_compose::bridges::{
    AliasFeedbackBridge, CertmeshBridge, DnsBridge, MdnsBridge, ProxyBridge,
};

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

// Vault: general-purpose encrypted secret storage
pub use koi_crypto::vault::{Vault, VaultError};

// Runtime adapter re-exports
pub use koi_runtime::{RuntimeBackendKind, RuntimeConfig};

pub type Result<T> = std::result::Result<T, KoiError>;

#[derive(Debug, thiserror::Error)]
pub enum KoiError {
    #[error("capability disabled: {0}")]
    DisabledCapability(&'static str),
    #[error("not available in client (remote) mode: {0}")]
    RemoteUnsupported(&'static str),
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
    #[error("runtime error: {0}")]
    Runtime(#[from] koi_runtime::RuntimeError),
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

    /// Enable the runtime adapter with the specified backend kind.
    ///
    /// Runtime is opt-in for embedded (unlike daemon where capabilities
    /// are enabled by default).
    pub fn runtime(mut self, kind: koi_runtime::RuntimeBackendKind) -> Self {
        self.config.runtime_enabled = true;
        self.config.runtime_backend = kind;
        self
    }

    /// Enable the runtime adapter with auto-detection.
    pub fn runtime_auto(mut self) -> Self {
        self.config.runtime_enabled = true;
        self.config.runtime_backend = koi_runtime::RuntimeBackendKind::Auto;
        self
    }

    /// Translate discovered runtime (container) lifecycle events into mDNS/DNS/health/proxy
    /// entries — the same orchestrator the daemon runs. Opt-in; requires the runtime
    /// adapter (`runtime`/`runtime_auto`) to be enabled to have any effect.
    pub fn orchestrator(mut self, enabled: bool) -> Self {
        self.config.orchestrator_enabled = enabled;
        self
    }

    /// Run the certmesh role-driven background loops (renewal, standby roster sync, member
    /// heartbeat, failover/announce) — the same loops the daemon runs. Opt-in; requires
    /// certmesh (`certmesh`) to be enabled. A clustered embedded CA host wants this; a leaf
    /// does not. Enrollment approval auto-denies (no interactive console).
    pub fn certmesh_background(mut self, enabled: bool) -> Self {
        self.config.certmesh_background_enabled = enabled;
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
            tokio::task::spawn_blocking(move || {
                koi_compose::cores::init_certmesh_core(data_dir.as_deref())
            })
            .await
            .map_err(|e| std::io::Error::other(format!("certmesh init: {e}")))?
        } else {
            None
        };

        // Integration bridges for cross-domain communication
        let mdns_bridge: Option<Arc<dyn koi_common::integration::MdnsSnapshot>> =
            if let Some(ref core) = mdns {
                Some(MdnsBridge::spawn(core.clone()).await)
            } else {
                None
            };

        let certmesh_bridge: Option<Arc<dyn koi_common::integration::CertmeshSnapshot>> =
            certmesh.as_ref().map(|core| {
                CertmeshBridge::new(core.clone())
                    as Arc<dyn koi_common::integration::CertmeshSnapshot>
            });

        let alias_feedback: Option<Arc<dyn koi_common::integration::AliasFeedback>> =
            certmesh.as_ref().map(|core| {
                AliasFeedbackBridge::new(core.clone())
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

        let dns_bridge: Option<Arc<dyn koi_common::integration::DnsProbe>> = dns
            .as_ref()
            .map(|rt| DnsBridge::new(rt.clone()) as Arc<dyn koi_common::integration::DnsProbe>);

        let proxy_bridge: Option<Arc<dyn koi_common::integration::ProxySnapshot>> =
            proxy.as_ref().map(|rt| {
                ProxyBridge::new(rt.core()) as Arc<dyn koi_common::integration::ProxySnapshot>
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

        let runtime = if self.config.runtime_enabled {
            let config = koi_runtime::RuntimeConfig {
                backend_kind: self.config.runtime_backend,
                socket_path: None,
            };
            let core = Arc::new(koi_runtime::RuntimeCore::new(config));
            match core.start_watching(cancel.clone()).await {
                Ok(()) => {
                    tracing::info!("Runtime adapter started");
                    Some(core)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Runtime backend unavailable — continuing without runtime adapter");
                    None
                }
            }
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
            let snap_runtime = runtime.clone();

            let snapshot_fn: koi_dashboard::dashboard::SnapshotFn = Arc::new(move || {
                let m = snap_mdns.clone();
                let cm = snap_certmesh.clone();
                let d = snap_dns.clone();
                let h = snap_health.clone();
                let p = snap_proxy.clone();
                let u = snap_udp.clone();
                let rt = snap_runtime.clone();
                Box::pin(async move { build_embedded_snapshot(m, cm, d, h, p, u, rt).await })
            });

            let (dash_event_tx, _) = broadcast::channel(256);
            let ds = koi_dashboard::dashboard::DashboardState {
                identity: koi_dashboard::dashboard::DashboardIdentity {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    platform: std::env::consts::OS.to_string(),
                },
                mode: "embedded",
                snapshot_fn,
                event_tx: dash_event_tx.clone(),
                started_at,
            };

            // Spawn the single unified event forwarder (superset incl. runtime),
            // shared with the daemon — no more inline copy here.
            tasks.push(koi_dashboard::forward::spawn_event_forwarder(
                koi_dashboard::forward::ForwarderCores {
                    mdns: mdns.clone(),
                    certmesh: certmesh.clone(),
                    dns: dns.clone(),
                    health: health.clone(),
                    proxy: proxy.clone(),
                    runtime: runtime.clone(),
                },
                dash_event_tx,
                cancel.clone(),
            ));

            Some(ds)
        } else {
            None
        };

        // Build browser state if enabled (requires mDNS). The LAN-wide meta-browse is
        // lazy — it starts on the first browser request, not here.
        let browser_state = if self.config.mdns_browser_enabled && self.config.http_enabled {
            if let Some(ref mdns_core) = mdns {
                Some(koi_dashboard::browser::build_state(
                    mdns_core.clone(),
                    cancel.clone(),
                ))
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
            let http_runtime = runtime.clone();
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
                    http_runtime,
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

        // ── Domain event → host KoiEvent forwarders ──
        // One shared spawn helper instead of six copies of the streaming select! skeleton.
        // Each domain core is present only when its capability is enabled, so `if let Some`
        // is the only gate needed.
        if let Some(core) = &mdns {
            spawn_event_mapper(
                core.subscribe(),
                map_mdns_event,
                event_tx.clone(),
                self.event_handler.clone(),
                cancel.clone(),
                &mut tasks,
            );
        }
        if let Some(runtime) = &health {
            spawn_event_mapper(
                runtime.core().subscribe(),
                |e| Some(map_health_event(e)),
                event_tx.clone(),
                self.event_handler.clone(),
                cancel.clone(),
                &mut tasks,
            );
        }
        if let Some(runtime) = &dns {
            spawn_event_mapper(
                runtime.core().subscribe(),
                |e| Some(map_dns_event(e)),
                event_tx.clone(),
                self.event_handler.clone(),
                cancel.clone(),
                &mut tasks,
            );
        }
        if let Some(core) = &certmesh {
            spawn_event_mapper(
                core.subscribe(),
                |e| Some(map_certmesh_event(e)),
                event_tx.clone(),
                self.event_handler.clone(),
                cancel.clone(),
                &mut tasks,
            );
        }
        if let Some(runtime_proxy) = &proxy {
            spawn_event_mapper(
                runtime_proxy.core().subscribe(),
                |e| Some(map_proxy_event(e)),
                event_tx.clone(),
                self.event_handler.clone(),
                cancel.clone(),
                &mut tasks,
            );
        }
        if let Some(runtime_core) = &runtime {
            spawn_event_mapper(
                runtime_core.subscribe(),
                map_runtime_event,
                event_tx.clone(),
                self.event_handler.clone(),
                cancel.clone(),
                &mut tasks,
            );
        }

        // ── Runtime orchestrator (opt-in) ──
        // Translate container lifecycle events into mDNS/DNS/health/proxy entries — the
        // same orchestrator the daemon runs. Off by default; a leaf host only wants events.
        if self.config.orchestrator_enabled {
            if let Some(ref runtime_core) = runtime {
                tasks.push(koi_compose::orchestrator::spawn_orchestrator(
                    runtime_core,
                    koi_compose::orchestrator::OrchestrationTargets {
                        mdns: mdns.clone(),
                        dns: dns.clone(),
                        health: health.clone(),
                        proxy: proxy.clone(),
                    },
                    cancel.clone(),
                ));
            } else {
                tracing::warn!(
                    "orchestrator enabled but the runtime adapter is not — skipping orchestrator"
                );
            }
        }

        // ── Certmesh background tasks (opt-in) ──
        // Renewal / roster sync / heartbeat / failover, same as the daemon. Off by default;
        // a clustered embedded CA host opts in. No console, so enrollment auto-denies.
        if self.config.certmesh_background_enabled {
            if let Some(ref certmesh_core) = certmesh {
                koi_compose::certmesh::spawn_enrollment_approval(
                    certmesh_core,
                    koi_compose::certmesh::deny_and_log_decider(),
                    &cancel,
                    &mut tasks,
                )
                .await;
                koi_compose::certmesh::spawn_certmesh_background_tasks(
                    certmesh_core,
                    &cancel,
                    &mut tasks,
                );
            } else {
                tracing::warn!(
                    "certmesh_background enabled but certmesh is not — skipping certmesh loops"
                );
            }
        }

        Ok(KoiHandle::new_embedded(
            mdns,
            dns,
            health,
            certmesh,
            proxy,
            udp,
            runtime,
            self.config.data_dir.clone(),
            event_tx,
            cancel,
            tasks,
            http_announce_id,
        ))
    }
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

fn map_runtime_event(event: koi_runtime::RuntimeEvent) -> Option<KoiEvent> {
    match event {
        koi_runtime::RuntimeEvent::Started(instance) => Some(KoiEvent::RuntimeInstanceStarted {
            name: instance.name,
            backend: instance.backend,
        }),
        koi_runtime::RuntimeEvent::Stopped { name, .. } => {
            Some(KoiEvent::RuntimeInstanceStopped { name })
        }
        // Updated, BackendDisconnected, BackendReconnected are operational events
        // not surfaced as KoiEvents (dashboard SSE covers them)
        _ => None,
    }
}

/// Spawn a task that maps a domain's broadcast events into the host `KoiEvent` stream until
/// cancellation. One shared skeleton replaces the six near-identical per-domain `select!`
/// loops that `start()` used to inline (the charter calls out duplicating that skeleton).
///
/// `map` returns `None` to drop an event (e.g. mDNS `Found`, which has no host-facing
/// variant); event types that always map wrap their mapper as `|e| Some(map_x(e))`.
fn spawn_event_mapper<E, F>(
    mut rx: broadcast::Receiver<E>,
    map: F,
    tx: broadcast::Sender<KoiEvent>,
    handler: Option<Arc<dyn Fn(KoiEvent) + Send + Sync>>,
    cancel: CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) where
    E: Clone + Send + 'static,
    F: Fn(E) -> Option<KoiEvent> + Send + 'static,
{
    tasks.push(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = rx.recv() => {
                    let Ok(event) = msg else { continue; };
                    if let Some(mapped) = map(event) {
                        emit_event(&tx, handler.as_ref(), mapped);
                    }
                }
            }
        }
    }));
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
    runtime: Option<Arc<koi_runtime::RuntimeCore>>,
) -> serde_json::Value {
    // The capability ladder is assembled once in koi-compose, shared with `/v1/status` and
    // the dashboard snapshot. The embedded snapshot includes `enabled` like the dashboard.
    let cores = koi_compose::cores::Cores {
        mdns,
        certmesh,
        dns,
        health,
        proxy,
        udp,
        runtime,
    };
    let capabilities: Vec<serde_json::Value> = koi_compose::status::assemble_capabilities(&cores)
        .await
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "name": c.status.name,
                "enabled": c.enabled,
                "healthy": c.status.healthy,
                "summary": c.status.summary,
            })
        })
        .collect();
    serde_json::json!({ "capabilities": capabilities })
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

    // ── certmesh data-dir SSOT (custom data_dir honored end-to-end) ──

    #[tokio::test]
    async fn init_certmesh_core_honors_custom_data_dir_end_to_end() {
        // The point of the path-SSOT refactor: a host that injects its own
        // data_dir gets the CA created, discovered, and unlocked under THAT
        // dir — never a split between the injected dir and an ambient default.
        let base = koi_common::test::ensure_data_dir("koi-embedded-datadir-tests");
        let data_dir = base.join("custom-pond");
        let paths = koi_certmesh::CertmeshPaths::with_data_dir(data_dir.clone());

        // Fresh machine: no CA yet. The uninitialized early-return must still
        // carry the injected paths — this is the regression the dropped-paths
        // bug (uninitialized branches dropping `paths`) used to fail.
        let fresh =
            koi_compose::cores::init_certmesh_core(Some(&data_dir)).expect("uninitialized core");
        assert_eq!(
            fresh.paths().data_dir(),
            data_dir.as_path(),
            "uninitialized core must keep the injected data_dir"
        );

        // Create a CA + roster UNDER the injected dir.
        koi_certmesh::ca::create_ca("pond-pass-strong", &[7u8; 32], &paths)
            .expect("create CA under injected dir");
        // My Organization posture: closed enrollment, approval required.
        let roster = koi_certmesh::roster::Roster::new(false, true, Some("ops".to_string()));
        koi_certmesh::roster::save_roster(&roster, &paths.roster_path())
            .expect("save roster under injected dir");

        // Reopen on the same injected dir: the CA is discovered there and the
        // core unlocks from it — proving the data root is honored end-to-end.
        let reopened =
            koi_compose::cores::init_certmesh_core(Some(&data_dir)).expect("locked core");
        assert_eq!(reopened.paths().data_dir(), data_dir.as_path());
        reopened
            .unlock("pond-pass-strong")
            .await
            .expect("unlock CA from the injected data_dir");
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
        assert_eq!(embedded.config.service_endpoint, "http://10.0.0.1:8080");
        assert_eq!(embedded.config.service_mode, ServiceMode::EmbeddedOnly);
        assert_eq!(
            embedded.config.data_dir,
            Some(std::path::PathBuf::from("/tmp/koi-test"))
        );
    }

    #[test]
    fn orchestrator_and_certmesh_background_are_opt_in() {
        // Default: both off (a leaf embedded host only wants the event stream).
        let default_cfg = Builder::new().build().expect("build should succeed");
        assert!(!default_cfg.config.orchestrator_enabled);
        assert!(!default_cfg.config.certmesh_background_enabled);

        // Opt-in: both on when requested.
        let opted = Builder::new()
            .runtime_auto()
            .orchestrator(true)
            .certmesh(true)
            .certmesh_background(true)
            .build()
            .expect("build should succeed");
        assert!(opted.config.orchestrator_enabled);
        assert!(opted.config.certmesh_background_enabled);
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
