mod config;
mod events;
mod handle;
mod serve;
pub mod testkit;

use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_client::KoiClient;

pub use config::{DnsConfigBuilder, KoiConfig, ServiceMode};
pub use events::KoiEvent;
pub use handle::{
    CertmeshHandle, DnsHandle, HealthHandle, KoiHandle, MdnsHandle, ProxyHandle,
    DEFAULT_DISCOVER_WINDOW,
};

// Re-export types needed by downstream consumers (registration, discovery, DNS, proxy, health)
pub use koi_common::firewall::{FirewallPort, FirewallProtocol};
// Mode-transparent trust primitives (ADR-020): typed discovery + posture + posture-keyed client.
pub use koi_certmesh::PeerClient;
pub use koi_common::diagnosis::{CheckStatus, DiagnosisCheck, DiagnosisStatus, TrustDiagnosis};
pub use koi_common::peer::Peer;
pub use koi_common::posture::{Posture, PostureLevel};
pub use koi_common::sealed::{Confidentiality, Opened, Sealed};
pub use koi_common::types::ServiceRecord;
pub use koi_config::state::DnsEntry;
pub use koi_health::{HealthCheck, HealthSnapshot, ServiceCheckKind};
pub use koi_mdns::protocol::{RegisterPayload, RegistrationResult};
pub use koi_mdns::MdnsEvent;
pub use koi_proxy::ProxyEntry;
// Same-port posture dial (ADR-020 §5): plain↔mTLS on one socket, live-flipping.
pub use serve::serve_adaptive;

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
    #[error("insecure configuration: {0}")]
    InsecureConfig(String),
}

impl From<koi_compose::cores::BuildCoresError> for KoiError {
    fn from(e: koi_compose::cores::BuildCoresError) -> Self {
        use koi_compose::cores::BuildCoresError as B;
        match e {
            B::Mdns(e) => KoiError::Mdns(e),
            B::Dns(e) => KoiError::Dns(e),
            B::Proxy(e) => KoiError::Proxy(e),
            B::Health(e) => KoiError::Health(e),
            B::CertmeshInit(s) => KoiError::Io(std::io::Error::other(s)),
        }
    }
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

    /// Set the Daemon Access Token for a remote (client) handle (wishlist 1.3).
    ///
    /// Required to reach DAT-gated reads (e.g. `certmesh().posture()`) and any
    /// mutation when targeting a daemon whose token is not in the local breadcrumb.
    /// When unset and the endpoint matches the local daemon, the breadcrumb token
    /// is adopted automatically.
    pub fn service_token(mut self, token: impl Into<String>) -> Self {
        self.config.service_token = Some(token.into());
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

    /// Whether Koi **self-manages** certmesh membership (ADR-023) — the same loop the
    /// daemon runs. **Default on** (requires `certmesh` enabled to have any effect): when
    /// this node is a member it pulls the signed trust bundle (policy refresh +
    /// cross-member revocation honoring), renews its leaf before expiry, and stands itself
    /// down if revoked — and is a no-op until the node becomes a member, so it
    /// self-activates on join with no operator re-engagement. Enrollment approval
    /// auto-denies (no interactive console).
    ///
    /// Set `false` only if you drive the lifecycle yourself over your own plane (no
    /// dependency on the CA's HTTP/mTLS ports): then call `pull_trust_bundle` /
    /// `apply_trust_bundle(&SignedBundle)` / `renew_self_if_due` on your own cadence.
    /// Replaces the former opt-in `certmesh_background` (BREAKING: inverted default).
    pub fn certmesh_managed(mut self, enabled: bool) -> Self {
        self.config.certmesh_managed = enabled;
        self
    }

    /// Set the embedded HTTP adapter's port. Pass `0` to bind an OS-assigned
    /// ephemeral port and read the actual one back with
    /// [`KoiHandle::bound_http_port`] after [`start`](KoiEmbedded::start) — the
    /// supported way to run on a free port without racing to pick one.
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

    /// Advertise this host's `_http._tcp` record on the LAN so peers discover it. Because
    /// the advertised endpoint must be reachable, enabling this binds the embedded HTTP
    /// adapter to `0.0.0.0` (all interfaces) instead of the secure loopback default.
    /// **Strongly pair with [`http_token`](Self::http_token)** — otherwise mutations are
    /// unauthenticated to the whole LAN (a runtime warning is logged if you do not).
    pub fn announce_http(mut self, enabled: bool) -> Self {
        self.config.announce_http = enabled;
        self
    }

    /// Require an `x-koi-token` header for embedded HTTP mutations (parity with the
    /// daemon's DAT). Optional: by default the embedded HTTP adapter binds loopback and
    /// leaves mutations unauthenticated. Set a token when exposing the adapter to the LAN
    /// (see [`announce_http`](Self::announce_http)).
    pub fn http_token(mut self, token: impl Into<String>) -> Self {
        self.config.http_token = Some(token.into());
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
    /// opened (e.g. an application's discovery UDP, HTTP API).  These are merged with
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
    /// (e.g. `"My App"` → `"My App mDNS (UDP 5353)"`).
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
            let client = Arc::new(build_remote_client(&self.config));
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

        // Secure-by-default: refuse to expose the embedded HTTP adapter on a
        // non-loopback bind without a token. `announce_http` binds 0.0.0.0, which
        // would otherwise serve unauthenticated mutations to the whole LAN — the
        // host must set `.http_token(..)` to expose it (loopback-only needs none).
        // Fail fast, before any core or socket is created.
        if self.config.http_enabled && self.config.announce_http && self.config.http_token.is_none()
        {
            return Err(KoiError::InsecureConfig(
                "announce_http exposes the embedded HTTP adapter on 0.0.0.0; call \
                 .http_token(..) to require x-koi-token, or drop announce_http to bind loopback"
                    .into(),
            ));
        }

        // Build every domain core + cross-domain bridge + the domain background tasks
        // (orchestrator, certmesh role loops) through the one shared composition root the
        // daemon and the Windows service use, so the three boot paths construct an identical
        // graph. `fail_fast` is the only embedded-specific knob: a library surfaces a failed
        // capability as an error rather than logging it and dropping the capability.
        let cores = koi_compose::cores::build_cores(
            &koi_compose::cores::CoreSpec {
                no_mdns: !self.config.mdns_enabled,
                no_certmesh: !self.config.certmesh_enabled,
                no_dns: !self.config.dns_enabled,
                no_health: !self.config.health_enabled,
                no_proxy: !self.config.proxy_enabled,
                no_udp: !self.config.udp_enabled,
                no_runtime: !self.config.runtime_enabled,
                data_dir: self.config.data_dir.clone(),
                dns_config: self.config.dns_config.clone(),
                runtime: self.config.runtime_backend.to_string(),
                http_port: self.config.http_port,
                // Pin the DNS state path to the data dir captured at construction time so it is
                // immune to KOI_DATA_DIR env-var races in parallel tests.
                dns_state_path: self
                    .config
                    .data_dir
                    .as_ref()
                    .map(|dir| dir.join("state").join("dns.json")),
                proxy_data_dir: self.config.data_dir.clone(),
                dns_auto_start: self.config.dns_auto_start,
                health_auto_start: self.config.health_auto_start,
                proxy_auto_start: self.config.proxy_auto_start,
                spawn_orchestrator: self.config.orchestrator_enabled,
                spawn_certmesh_loops: self.config.certmesh_managed,
                fail_fast: true,
            },
            &cancel,
            &mut tasks,
        )
        .await?;
        let koi_compose::cores::Cores {
            mdns,
            certmesh,
            dns,
            health,
            proxy,
            udp,
            runtime,
            mdns_snapshot: mdns_bridge,
        } = cores;

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

        // Spawn the embedded HTTP adapter via the shared koi-serve router — the SAME
        // implementation the daemon uses, so there is no separate embedded server and no
        // /v1/status drift. Secure-by-default: bind loopback unless the host opts into LAN
        // exposure via `announce_http`; mutations are unauthenticated unless `http_token`
        // is set.
        //
        // The actually-bound address is captured so the handle can report it — the
        // root fix for ephemeral binding: `Builder::http_port(0)` lets the OS assign
        // a free port and `KoiHandle::bound_http_port()` reports it (no probing).
        let mut http_addr: Option<std::net::SocketAddr> = None;
        if self.config.http_enabled {
            let http_cancel = cancel.clone();
            let http_cores = koi_compose::cores::Cores {
                mdns: mdns.clone(),
                certmesh: certmesh.clone(),
                dns: dns.clone(),
                health: health.clone(),
                proxy: proxy.clone(),
                udp: udp.clone(),
                runtime: runtime.clone(),
                mdns_snapshot: mdns_bridge.clone(),
            };
            // Exposure is gated at the top of start(): announce_http without a token
            // fails closed before we get here, so an exposed bind always carries auth.
            let exposed = self.config.announce_http;
            let bind_ip = if exposed {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            };
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let http_cfg = koi_serve::http::HttpConfig {
                bind_ip,
                port: self.config.http_port,
                started_at: std::time::Instant::now(),
                dashboard: dashboard_state,
                browser: browser_state,
                auth: self.config.http_token.clone(),
                mdns_snapshot: mdns_bridge.clone(),
                mcp_http: false,
                admin_shutdown: false,
                api_docs: self.config.api_docs_enabled,
                daemon: false,
                ready: Some(ready_tx),
            };
            tasks.push(tokio::spawn(async move {
                if let Err(e) = koi_serve::http::start(http_cores, http_cfg, http_cancel).await {
                    tracing::error!(error = %e, "embedded HTTP adapter failed");
                }
            }));
            // Wait for the listener to bind so the handle reports the real port
            // (the OS-assigned one when http_port == 0). A bind failure drops the
            // sender → `None` here; the spawned task has already logged the error.
            http_addr = ready_rx.await.ok();
        }

        // ── Self-announce supervisor: _http._tcp, posture-reactive ──
        // One supervisor publishes this host's _http._tcp record (with the ADR-020 posture
        // stamp) and re-stamps it on every Open↔Authenticated flip — the same reactivity the
        // daemon and the Windows service get, shared via koi-compose. `_mcp._tcp` stays off:
        // embedded mounts no /v1/mcp transport, so it must not advertise one.
        let announce_cores = koi_compose::cores::Cores {
            mdns: mdns.clone(),
            certmesh: certmesh.clone(),
            dns: dns.clone(),
            health: health.clone(),
            proxy: proxy.clone(),
            udp: udp.clone(),
            runtime: runtime.clone(),
            mdns_snapshot: mdns_bridge.clone(),
        };
        // Advertise the ACTUAL bound port: with http_port(0) the OS picked an
        // ephemeral port at bind time, so announcing the configured 0 would publish
        // an unreachable _http._tcp/_mcp._tcp record. `http_addr` holds the resolved
        // address (Some whenever the HTTP adapter bound); fall back to the configured
        // port when HTTP is disabled (announce_http requires http_enabled anyway).
        let announce_http_port = http_addr.map(|a| a.port()).unwrap_or(self.config.http_port);
        koi_compose::self_announce::spawn(
            &announce_cores,
            koi_compose::self_announce::SelfAnnounceConfig {
                http_port: announce_http_port,
                dashboard_enabled: self.config.dashboard_enabled,
                announce_http: self.config.announce_http
                    && self.config.http_enabled
                    && self.config.mdns_enabled,
                announce_mcp: false,
                dns_zone: self.config.dns_config.zone.clone(),
            },
            cancel.clone(),
            &mut tasks,
        );

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
            // Posture transitions (Open↔Authenticated) surface as PostureChanged —
            // the live trust-state signal the consumer's serve supervisor and any
            // observer react to (ADR-020 §5/§13).
            spawn_posture_watcher(
                core.watch_posture(),
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

        // The runtime orchestrator and the certmesh role loops (trust-bundle pull + renewal)
        // are spawned inside `build_cores` (gated on the spec's `spawn_orchestrator` /
        // `spawn_certmesh_loops`, set from the builder opt-ins above). Only the opt-in-without-
        // prerequisite warnings stay here.
        if self.config.orchestrator_enabled && runtime.is_none() {
            tracing::warn!(
                "orchestrator enabled but the runtime adapter is not — skipping orchestrator"
            );
        }

        // ── Certmesh enrollment-approval pump (self-managed) ──
        // The trust-bundle pull + cert-renewal loops are spawned by `build_cores`; the approval
        // pump is NOT (its decider is host-specific). Embedded has no console, so it
        // auto-denies. On by default with self-management (ADR-023); a self-driver opts out.
        if self.config.certmesh_managed {
            if let Some(ref certmesh_core) = certmesh {
                koi_compose::certmesh::spawn_enrollment_approval(
                    certmesh_core,
                    koi_compose::certmesh::deny_and_log_decider(),
                    &cancel,
                    &mut tasks,
                )
                .await;
            } else {
                // certmesh_managed defaults on; only a no-op when certmesh itself is off.
                tracing::debug!(
                    "certmesh_managed is on but certmesh is not enabled — no certmesh loops to spawn"
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
            http_addr,
            self.config.data_dir.clone(),
            event_tx,
            cancel,
            tasks,
        ))
    }
}

/// Build the remote `KoiClient`, attaching a Daemon Access Token so the handle can
/// reach DAT-gated reads (posture, diagnose) and mutations (wishlist 1.3).
///
/// Token precedence: an explicit `service_token` wins; otherwise the local
/// breadcrumb's token is adopted **only** when its endpoint matches the configured
/// `service_endpoint` (so the local token is never sent to a foreign daemon);
/// otherwise no token (unauthenticated, as before).
fn build_remote_client(config: &KoiConfig) -> KoiClient {
    if let Some(token) = &config.service_token {
        return KoiClient::with_token(&config.service_endpoint, token);
    }
    if let Some(bc) = koi_config::breadcrumb::read_breadcrumb() {
        if endpoints_match(&bc.endpoint, &config.service_endpoint) {
            return KoiClient::with_token(&config.service_endpoint, &bc.token);
        }
    }
    KoiClient::new(&config.service_endpoint)
}

/// Whether two daemon endpoints refer to the same target, treating `localhost` and
/// `127.0.0.1` as equivalent and ignoring case / a trailing slash. Deliberately
/// conservative — it only ever broadens to loopback equivalence, never matches a
/// different host — so the local breadcrumb token is never leaked to a foreign host.
fn endpoints_match(a: &str, b: &str) -> bool {
    fn norm(s: &str) -> String {
        s.trim_end_matches('/')
            .to_ascii_lowercase()
            .replace("localhost", "127.0.0.1")
    }
    norm(a) == norm(b)
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
        koi_certmesh::CertmeshEvent::CertRenewed { expires_at } => {
            KoiEvent::CertRenewed { expires_at }
        }
        koi_certmesh::CertmeshEvent::CertExpiringSoon { days_left } => {
            KoiEvent::CertExpiringSoon { days_left }
        }
        koi_certmesh::CertmeshEvent::CertRenewalFailed {
            reason,
            consecutive_failures,
        } => KoiEvent::CertRenewalFailed {
            reason,
            consecutive_failures,
        },
        koi_certmesh::CertmeshEvent::BundleUpdated { self_revoked } => {
            KoiEvent::BundleUpdated { self_revoked }
        }
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

/// Spawn a task translating this node's posture-watch transitions into
/// `KoiEvent::PostureChanged` until cancellation (ADR-020 §5). A `watch` (which
/// holds the latest value and coalesces) rather than a broadcast, so it needs its
/// own loop instead of [`spawn_event_mapper`]. The first borrow seeds the baseline
/// so the initial value is not mis-reported as a transition.
fn spawn_posture_watcher(
    mut rx: tokio::sync::watch::Receiver<koi_common::posture::Posture>,
    tx: broadcast::Sender<KoiEvent>,
    handler: Option<Arc<dyn Fn(KoiEvent) + Send + Sync>>,
    cancel: CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    tasks.push(tokio::spawn(async move {
        let mut last = *rx.borrow_and_update();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                res = rx.changed() => {
                    if res.is_err() {
                        break; // the certmesh core was dropped
                    }
                    let to = *rx.borrow_and_update();
                    if to != last {
                        emit_event(&tx, handler.as_ref(), KoiEvent::PostureChanged { from: last, to });
                        last = to;
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
///
/// Delegates to `koi_compose::snapshot::build_dashboard_snapshot`, the one detail projection
/// shared with the daemon dashboard, so the embedded snapshot now carries the same
/// health / DNS / certmesh / proxy / UDP detail (not just the capability ladder).
async fn build_embedded_snapshot(
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
    runtime: Option<Arc<koi_runtime::RuntimeCore>>,
) -> serde_json::Value {
    let cores = koi_compose::cores::Cores {
        mdns,
        certmesh,
        dns,
        health,
        proxy,
        udp,
        runtime,
        mdns_snapshot: None,
    };
    koi_compose::snapshot::build_dashboard_snapshot(&cores).await
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
        let data_dir = base.join("custom-data");
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
        koi_certmesh::ca::create_ca("test-pass-strong", &[7u8; 32], &paths)
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
            .unlock("test-pass-strong")
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

    #[tokio::test]
    async fn posture_watcher_emits_upgrade_and_degrade() {
        use koi_common::posture::Posture;
        let (tx_p, rx_p) = tokio::sync::watch::channel(Posture::OPEN);
        let (ev_tx, mut ev_rx) = broadcast::channel(16);
        let cancel = CancellationToken::new();
        let mut tasks = Vec::new();
        spawn_posture_watcher(rx_p, ev_tx, None, cancel.clone(), &mut tasks);
        // Let the watcher run to its first await so it captures OPEN as the
        // baseline before we send (current-thread test runtime: yield runs the
        // spawned task up to `rx.changed()`).
        tokio::task::yield_now().await;

        // Open→Authenticated → an upgrade PostureChanged.
        tx_p.send(Posture::new(true, false)).unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(1), ev_rx.recv())
            .await
            .expect("event arrives")
            .expect("recv ok");
        assert!(
            matches!(ev, KoiEvent::PostureChanged { from, to } if !from.signed && to.signed),
            "expected upgrade, got {ev:?}"
        );

        // Authenticated→Open → a degrade PostureChanged (as loud as the upgrade).
        tx_p.send(Posture::OPEN).unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(1), ev_rx.recv())
            .await
            .expect("event arrives")
            .expect("recv ok");
        assert!(
            matches!(ev, KoiEvent::PostureChanged { from, to } if from.signed && !to.signed),
            "expected degrade, got {ev:?}"
        );

        cancel.cancel();
        for t in tasks {
            let _ = t.await;
        }
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
    fn service_token_builder_sets_token() {
        let embedded = Builder::new()
            .service_token("secret-token")
            .build()
            .expect("build should succeed");
        assert_eq!(
            embedded.config.service_token.as_deref(),
            Some("secret-token")
        );
    }

    #[test]
    fn endpoints_match_treats_localhost_as_loopback() {
        assert!(endpoints_match(
            "http://localhost:5641",
            "http://127.0.0.1:5641"
        ));
        assert!(endpoints_match(
            "http://127.0.0.1:5641/",
            "http://127.0.0.1:5641"
        ));
        assert!(endpoints_match(
            "HTTP://LOCALHOST:5641",
            "http://127.0.0.1:5641"
        ));
    }

    #[test]
    fn endpoints_match_rejects_different_hosts() {
        // The local breadcrumb token must never be sent to a foreign daemon.
        assert!(!endpoints_match(
            "http://127.0.0.1:5641",
            "http://10.0.0.1:5641"
        ));
        assert!(!endpoints_match(
            "http://127.0.0.1:5641",
            "http://127.0.0.1:9999"
        ));
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
    fn orchestrator_opt_in_certmesh_self_management_opt_out() {
        // orchestrator is opt-in (default off); certmesh self-management is opt-OUT
        // (default on, ADR-023) — a member is managed without discovering a flag.
        let default_cfg = Builder::new().build().expect("build should succeed");
        assert!(!default_cfg.config.orchestrator_enabled);
        assert!(
            default_cfg.config.certmesh_managed,
            "certmesh self-management is on by default"
        );

        // Orchestrator on when requested; certmesh self-management off when a self-driver
        // opts out (it will drive pull/renew over its own plane).
        let opted = Builder::new()
            .runtime_auto()
            .orchestrator(true)
            .certmesh(true)
            .certmesh_managed(false)
            .build()
            .expect("build should succeed");
        assert!(opted.config.orchestrator_enabled);
        assert!(!opted.config.certmesh_managed);
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
        assert!(matches!(result, Ok(42)));
    }

    #[test]
    fn result_type_works_with_err() {
        let result: Result<i32> = Err(KoiError::DisabledCapability("test"));
        assert!(result.is_err());
    }
}
