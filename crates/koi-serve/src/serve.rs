//! The unified serving stack.
//!
//! [`serve`] spawns every transport + presence supervisor for a constructed
//! [`Cores`] under its [`RunningCores`] owner: the dashboard + event forwarder, the mDNS
//! browser, the HTTP adapter, the posture-reactive trust plane (mTLS + ACME +
//! `_certmesh._tcp`), the IPC adapter, and the posture-reactive `_http`/`_mcp`
//! self-announce. It is the single source for "serve these cores", shared verbatim by
//! the daemon and the Windows service so the two boot paths cannot drift (the ~90 lines
//! they used to duplicate).
//!
//! What it deliberately does **not** own — these stay with the caller because they
//! differ per host:
//! - the **lifecycle edge**: the daemon blocks on a Ctrl-C / admin-shutdown signal; the
//!   Windows service reports SCM status and waits on its stop channel; an embedded host
//!   returns a non-blocking handle. `serve` only admits work to the supplied owner.
//! - the **enrollment-approval pump**: its decider is host-specific (a foreground daemon
//!   prompts on stdin; consoleless hosts auto-deny-and-log).
//! - **pre-serve setup** (data dir, bind resolution, DAT mint, and startup diagnostics):
//!   small and subtly host-specific. The serving stack returns the exact acquired endpoint
//!   before a caller may publish a breadcrumb or report readiness.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use tokio_util::sync::CancellationToken;

use koi_compose::cores::{Cores, RunningCores};
use koi_config::local_access::LocalOperator;

/// Declarative description of which transports + presence to serve, plus the ports,
/// zone, and DAT the stack needs. Neutral (no `clap`/binary types) so any host — the
/// daemon, the Windows service, an embedded app — maps its own config into it.
pub struct ServeConfig {
    /// Immutable machine identity observed once by the application root.
    pub host: koi_compose::host::HostIdentity,
    /// Resolved HTTP bind address (loopback default; the caller resolves `--http-bind`).
    pub bind_ip: IpAddr,
    pub http_port: u16,
    pub no_http: bool,
    pub no_ipc: bool,
    pub no_mcp_http: bool,
    pub pipe_path: PathBuf,
    /// Principal authorized to connect to the trusted local-control transport.
    pub local_operator: LocalOperator,
    /// Resolved daemon storage root handed only to the authorized local operator.
    pub data_root: PathBuf,
    /// Config path selected by the host's launch precedence.
    pub config_path: PathBuf,
    pub mtls_port: u16,
    pub acme_port: u16,
    pub no_acme: bool,
    pub dns_zone: String,
    /// Advertise this host's own `_http._tcp` record (the self-announce supervisor).
    pub announce_http: bool,
    /// Serve the dashboard + browser (the daemon and the Windows service: `true`).
    pub dashboard: bool,
    /// The dashboard `mode` label (e.g. `"daemon"`).
    pub mode: &'static str,
    /// Daemon Access Token authenticating mutation requests on the HTTP adapter.
    pub dat_token: String,
    /// Webhook sinks for outbound event fan-out (ADR-028). Empty = disabled.
    pub webhooks: Vec<koi_compose::webhook::WebhookSink>,
    /// Disable the mTLS management plane (`/v1/mcp` behind principal
    /// authorization, ADR-026 §5). Independent of [`Self::no_mcp_http`]: that
    /// switch owns the loopback tool surface; this one owns the mutually
    /// authenticated remote surface the trust plane mounts.
    pub no_mgmt_mcp: bool,
    /// Published Pond UI directory. `Some` enables the in-process Pond
    /// desired-state adapter and its authenticated operator controls.
    pub ui_dir: Option<PathBuf>,
}

/// Resources that crossed the serving stack's startup fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReady {
    /// The exact socket acquired by the HTTP adapter, including an OS-assigned port.
    pub http_addr: Option<SocketAddr>,
    /// A routable machine-local endpoint for breadcrumbs and trusted local control.
    pub local_endpoint: Option<String>,
}

fn machine_local_endpoint(bound: SocketAddr) -> String {
    let ip = match bound.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    format!("http://{}", SocketAddr::new(ip, bound.port()))
}

/// Acquire configured serving resources and spawn the full stack under `cores`.
///
/// Success is the readiness fence: configured HTTP and local-control listeners are real, and
/// only then are discoverable endpoints armed. A startup error leaves all admitted work under
/// the existing [`RunningCores`] owner so the caller can run the ordinary ordered teardown.
pub async fn serve(
    cores: &RunningCores,
    started_at: Instant,
    cfg: ServeConfig,
    cancel: &CancellationToken,
) -> anyhow::Result<ServeReady> {
    // Bind before spawning presentation work or publishing an endpoint. This is both the
    // startup failure boundary and the source of truth for an OS-assigned port.
    let http_listener = if cfg.no_http {
        None
    } else {
        Some(tokio::net::TcpListener::bind((cfg.bind_ip, cfg.http_port)).await?)
    };
    let http_addr = http_listener
        .as_ref()
        .map(tokio::net::TcpListener::local_addr)
        .transpose()?;
    let local_endpoint = http_addr.map(machine_local_endpoint);
    let serving_http_port = http_addr.map_or(cfg.http_port, |address| address.port());

    // Acquire the trusted local transport alongside HTTP, before spawning any
    // presentation or presence work. The acquired owner is the readiness fact;
    // a partial acquisition drops both provisional listeners on this path.
    let local_control = if cfg.no_ipc {
        cores.publish_composition_status(koi_compose::status::CapabilityReport::disabled(
            "ipc", "--no-ipc",
        ));
        None
    } else {
        let local_data_root = cfg.data_root.to_string_lossy().into_owned();
        let config = crate::local_ipc::LocalControlConfig {
            path: cfg.pipe_path.clone(),
            operator: cfg.local_operator,
            access: local_endpoint.clone().map(|endpoint| {
                koi_common::local_control::LocalDaemonAccess {
                    version: koi_common::local_control::LOCAL_CONTROL_VERSION,
                    endpoint,
                    token: cfg.dat_token.clone(),
                    data_root: Some(local_data_root.clone()),
                }
            }),
            info: koi_common::local_control::LocalDaemonInfo {
                version: koi_common::local_control::LOCAL_CONTROL_VERSION,
                data_root: local_data_root,
                config_path: cfg.config_path.to_string_lossy().into_owned(),
            },
        };
        match crate::local_ipc::LocalControl::acquire(config) {
            Ok(owner) => Some(owner),
            Err(error) => {
                cores.publish_composition_status(
                    koi_compose::status::CapabilityReport::unavailable("ipc", error.to_string()),
                );
                return Err(error.context("acquiring the trusted local-control transport"));
            }
        }
    };
    if cancel.is_cancelled() {
        anyhow::bail!("serving startup was cancelled");
    }

    // ── Dashboard state + the single unified event forwarder ──
    let dashboard_state =
        crate::dashboard::build_dashboard_state(cores, &cfg.host, started_at, cfg.mode);
    cores.own_task(koi_dashboard::forward::spawn_event_forwarder(
        koi_dashboard::forward::ForwarderCores {
            mdns: cores.mdns.clone(),
            certmesh: cores.certmesh.clone(),
            trust: cores.trust.clone(),
            dns: cores.dns.clone(),
            health: cores.health.clone(),
            proxy: cores.proxy.clone(),
            runtime: cores.runtime.clone(),
            udp: cores.udp.clone(),
        },
        dashboard_state.event_tx.clone(),
        cancel.clone(),
    ));

    // ── Outbound webhook fan-out (ADR-028) ──
    // One worker per enabled sink, each subscribing to the same merged channel the
    // dashboard consumes. Spawned here (not in the binary) so every boot path that
    // uses `serve()` — daemon, Windows service — inherits it by construction.
    if !cfg.webhooks.is_empty() {
        let provenance =
            koi_compose::webhook::WebhookProvenance::from_host(&cfg.host, cfg.dns_zone.clone());
        for handle in koi_compose::webhook::spawn_webhook_fanout(
            &dashboard_state.event_tx,
            cfg.webhooks.clone(),
            provenance,
            Some(dashboard_state.event_tx.clone()),
            cancel.clone(),
        ) {
            cores.own_task(handle);
        }
    }

    // ── mDNS browser state (conditional on mDNS being enabled) ──
    // The LAN-wide meta-browse worker is NOT started here: it starts on the first
    // browser request and idles out (koi_dashboard::meta_browse).
    let browser_state = cores
        .mdns
        .as_ref()
        .map(|mdns| koi_dashboard::browser::build_state(mdns.clone(), cancel.clone()));

    // ── Pond: operator-armed, read-only LAN presentation adapter ──
    // Pond remains part of this serving monolith. Its public listener is a narrow
    // projection of the same cores, while intent and control stay on the full HTTP
    // adapter. A derived fourth port keeps deployment configuration coherent.
    let pond = if cfg.no_http {
        cores.publish_composition_status(koi_compose::status::CapabilityReport::disabled(
            "pond",
            "requires the operator HTTP adapter",
        ));
        None
    } else {
        match (
            cfg.ui_dir.clone(),
            crate::pond::port_for_http(serving_http_port),
        ) {
            (Some(ui_dir), Some(port)) => {
                let runtime = crate::pond::PondRuntime::new(crate::pond::PondConfig {
                    port,
                    ui_dir,
                    intent_path: cfg.data_root.join("state/pond.json"),
                    started_at,
                    browser: browser_state.clone(),
                    system_status: Arc::clone(&cores.system_status),
                    parent_cancel: cancel.clone(),
                });
                match runtime {
                    Ok(runtime) => {
                        let supervisor = runtime.clone();
                        cores.own_task(tokio::spawn(async move {
                            supervisor.supervise().await;
                        }));
                        spawn_pond_status_projection(cores, &runtime);
                        Some(runtime)
                    }
                    Err(error) => {
                        tracing::error!(%error, "Failed to initialize Pond");
                        cores.publish_composition_status(
                            koi_compose::status::CapabilityReport::unavailable(
                                "pond",
                                format!("could not initialize Pond: {error}"),
                            ),
                        );
                        None
                    }
                }
            }
            (None, _) => {
                cores.publish_composition_status(koi_compose::status::CapabilityReport::disabled(
                    "pond",
                    "no published UI directory is configured",
                ));
                None
            }
            (_, None) => {
                cores.publish_composition_status(
                    koi_compose::status::CapabilityReport::unavailable(
                        "pond",
                        "HTTP port leaves no room for the derived Pond port",
                    ),
                );
                None
            }
        }
    };

    // ── HTTP adapter (the full daemon surface: dashboard, DAT auth, MCP, admin-shutdown,
    // OpenAPI) ──
    if let Some(listener) = http_listener {
        let c = cores.cores().clone();
        let cancel_token = cancel.clone();
        let fatal_cancel = cancel.clone();
        let http_cfg = crate::http::HttpConfig {
            started_at,
            host: cfg.host.clone(),
            dashboard: Some(dashboard_state.clone()),
            browser: browser_state.clone(),
            auth: Some(cfg.dat_token.clone()),
            mcp_http: !cfg.no_mcp_http,
            webhooks: cfg.webhooks.clone(),
            admin_shutdown: true,
            api_docs: true,
            daemon: true,
            pond,
        };
        cores.own_task(tokio::spawn(async move {
            if let Err(e) = crate::http::serve(listener, c, http_cfg, cancel_token).await {
                tracing::error!(error = %e, "HTTP adapter failed");
                fatal_cancel.cancel();
            }
        }));
    }

    // ── Trust-plane presence (mTLS inter-node + ACME + _certmesh._tcp announce) ──
    // One posture-reactive supervisor owns all three and brings them up/down as the
    // certmesh CA appears or is destroyed — no restart (ADR-020 P4c / ADR-016 §2).
    crate::trust_plane::spawn(
        cores,
        crate::trust_plane::TrustPlaneConfig {
            host: cfg.host.clone(),
            mtls_port: cfg.mtls_port,
            acme_port: cfg.acme_port,
            no_acme: cfg.no_acme,
            dns_zone: cfg.dns_zone.clone(),
            announce_http_port: http_addr.map(|address| address.port()),
            mgmt_mcp: !cfg.no_mgmt_mcp,
        },
        cancel.clone(),
    );

    // ── Trusted local control + mDNS session transport ──
    if let Some(local_control) = local_control {
        cores.publish_composition_status(koi_compose::status::CapabilityReport::available(
            "ipc",
            "trusted local-control transport",
            true,
        ));
        let mdns = cores.mdns.clone();
        let status_cores = cores.cores().clone();
        let token = cancel.clone();
        let fatal_cancel = cancel.clone();
        cores.own_task(tokio::spawn(async move {
            supervise_local_ipc(status_cores, local_control.run(mdns, token), fatal_cancel).await;
        }));
    }

    if cancel.is_cancelled() {
        anyhow::bail!("serving startup was cancelled");
    }

    // ── Self-announce supervisor: _http._tcp (+ _mcp._tcp), posture-reactive ──
    // Publishes this host's _http._tcp record (with the ADR-020 posture stamp) and the
    // _mcp._tcp transport descriptor, re-stamps _http._tcp on every Open↔Authenticated
    // flip, and withdraws both on shutdown — so a node that boots Open and later runs
    // `certmesh create` updates its advertised posture without a restart. The
    // `_certmesh._tcp` CA discovery record is owned by the trust-plane supervisor above.
    koi_compose::self_announce::spawn(
        cores,
        koi_compose::self_announce::SelfAnnounceConfig {
            host: cfg.host,
            http_port: serving_http_port,
            dashboard_enabled: cfg.dashboard,
            announce_http: cfg.announce_http && !cfg.no_http,
            announce_mcp: !cfg.no_mcp_http && !cfg.no_http,
            dns_zone: cfg.dns_zone,
        },
        cancel.clone(),
    );

    Ok(ServeReady {
        http_addr,
        local_endpoint,
    })
}

/// Translate the acquired platform adapter's terminal result into the
/// composition-owned IPC rung. Acquisition already published the healthy
/// readiness fact; this function only projects retirement or failure.
async fn supervise_local_ipc<F>(cores: Cores, adapter: F, fatal_cancel: CancellationToken)
where
    F: Future<Output = anyhow::Result<()>>,
{
    match adapter.await {
        Ok(()) => {
            cores.publish_composition_status(koi_compose::status::CapabilityReport::available(
                "ipc", "stopped", false,
            ));
            if !fatal_cancel.is_cancelled() {
                tracing::error!("Local-control adapter stopped without a shutdown request");
                fatal_cancel.cancel();
            }
        }
        Err(error) => {
            tracing::error!(%error, "Local-control adapter failed");
            cores.publish_composition_status(koi_compose::status::CapabilityReport::unavailable(
                "ipc",
                error.to_string(),
            ));
            fatal_cancel.cancel();
        }
    }
}

fn spawn_pond_status_projection(cores: &RunningCores, pond: &crate::pond::PondRuntime) {
    let mut status = pond.watch_status();
    // Subscribe first, then project the receiver's current value. A transition
    // racing startup is either represented here or remains pending for the task.
    let initial = status.borrow_and_update().clone();
    cores.publish_pond_status(initial);
    let status_cores = cores.cores().clone();
    cores.own_task(tokio::spawn(async move {
        // Drain the final shutdown transition before the sender disappears. If this
        // task stopped directly on the shared cancellation token it could race Pond's
        // supervisor and leave the product aggregate claiming the listener still ran.
        while status.changed().await.is_ok() {
            let current = status.borrow_and_update().clone();
            status_cores.publish_pond_status(current);
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn serve_config(http_port: u16) -> ServeConfig {
        ServeConfig {
            host: koi_compose::host::HostIdentity::from_hostname("test-host").unwrap(),
            bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port,
            no_http: false,
            no_ipc: true,
            no_mcp_http: true,
            pipe_path: PathBuf::from("unused-test-control.sock"),
            local_operator: LocalOperator::UnixUid { uid: 0 },
            data_root: std::env::temp_dir().join("koi-serve-startup-test"),
            config_path: PathBuf::from("unused-test-config.toml"),
            mtls_port: 0,
            acme_port: 0,
            no_acme: true,
            dns_zone: "internal".to_string(),
            announce_http: false,
            dashboard: false,
            mode: "test",
            dat_token: "test-token".to_string(),
            webhooks: Vec::new(),
            no_mgmt_mcp: true,
            ui_dir: None,
        }
    }

    #[test]
    fn machine_local_endpoint_uses_the_acquired_address_and_port() {
        assert_eq!(
            machine_local_endpoint("0.0.0.0:43123".parse().unwrap()),
            "http://127.0.0.1:43123"
        );
        assert_eq!(
            machine_local_endpoint("[::]:43124".parse().unwrap()),
            "http://[::1]:43124"
        );
        assert_eq!(
            machine_local_endpoint("192.0.2.8:43125".parse().unwrap()),
            "http://192.0.2.8:43125"
        );
    }

    #[tokio::test]
    async fn startup_returns_the_real_http_listener_before_endpoint_publication() {
        let cores = RunningCores::default();
        let cancel = CancellationToken::new();
        let ready = serve(&cores, Instant::now(), serve_config(0), &cancel)
            .await
            .expect("serving startup");
        let address = ready.http_addr.expect("configured HTTP listener");
        assert_ne!(address.port(), 0);
        assert_eq!(ready.local_endpoint, Some(format!("http://{address}")));

        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to acquired listener");
        client
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_end(&mut response),
        )
        .await
        .expect("health response timeout")
        .unwrap();
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
            "readiness must name a serving socket"
        );

        koi_compose::cores::ordered_shutdown(
            &cancel,
            &cores,
            std::time::Duration::from_secs(2),
            std::time::Duration::ZERO,
        )
        .await;
    }

    #[tokio::test]
    async fn occupied_http_port_fails_before_any_endpoint_is_armed() {
        let occupied = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = occupied.local_addr().unwrap().port();
        let cores = RunningCores::default();
        let before = cores.system_status.status();
        let cancel = CancellationToken::new();

        let error = serve(&cores, Instant::now(), serve_config(port), &cancel)
            .await
            .expect_err("occupied port must reject serving startup");

        assert!(error.to_string().contains("address") || error.to_string().contains("use"));
        assert!(Arc::ptr_eq(&before, &cores.system_status.status()));
        assert!(!cancel.is_cancelled());
    }

    fn ipc_report(cores: &Cores) -> koi_compose::status::CapabilityReport {
        cores
            .system_status
            .status()
            .capabilities
            .iter()
            .find(|report| report.status.name == "ipc")
            .expect("IPC capability rung")
            .clone()
    }

    fn publish_ipc_acquired(cores: &Cores) {
        cores.publish_composition_status(koi_compose::status::CapabilityReport::available(
            "ipc",
            "trusted local-control transport",
            true,
        ));
    }

    #[tokio::test]
    async fn ipc_terminal_failure_replaces_acquired_health() {
        let cores = Cores::default();
        publish_ipc_acquired(&cores);
        let mut status = cores.system_status.watch_status();
        status.borrow_and_update();
        let fatal_cancel = CancellationToken::new();
        let adapter = async { Err(anyhow::anyhow!("late accept failure")) };
        let task_cores = cores.clone();
        let task_cancel = fatal_cancel.clone();
        let task = tokio::spawn(async move {
            supervise_local_ipc(task_cores, adapter, task_cancel).await;
        });

        task.await.expect("IPC supervisor task");
        tokio::time::timeout(std::time::Duration::from_secs(1), status.changed())
            .await
            .expect("failure projection timeout")
            .expect("status feed");
        assert!(fatal_cancel.is_cancelled());
        let failed = ipc_report(&cores);
        assert!(failed.enabled);
        assert!(!failed.status.healthy);
        assert!(failed.status.summary.contains("late accept failure"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_ipc_owner_rejects_startup_without_replacing_its_socket() {
        use std::os::unix::fs::MetadataExt as _;

        let root = std::env::temp_dir().join(format!(
            "koi-serve-ipc-owner-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("koi.sock");
        let owner = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let inode = std::fs::symlink_metadata(&path).unwrap().ino();
        let mut config = serve_config(0);
        config.no_ipc = false;
        config.pipe_path = path.clone();
        config.local_operator = LocalOperator::UnixUid {
            uid: std::fs::metadata(&root).unwrap().uid(),
        };
        config.data_root = root.clone();
        let cores = RunningCores::default();
        let cancel = CancellationToken::new();

        let error = serve(&cores, Instant::now(), config, &cancel)
            .await
            .expect_err("live local owner must reject a second generation");

        assert!(format!("{error:#}").contains("live owner"));
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
        let failed = ipc_report(cores.cores());
        assert!(!failed.status.healthy);
        assert!(failed.status.summary.contains("live owner"));
        assert!(!cancel.is_cancelled());

        drop(owner);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
