//! The unified serving stack.
//!
//! [`serve`] spawns every transport + presence supervisor for a constructed
//! [`Cores`] into a shared `(cancel, tasks)`: the dashboard + event forwarder, the mDNS
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
//!   returns a non-blocking handle. `serve` only spawns into `tasks`.
//! - the **enrollment-approval pump**: its decider is host-specific (a foreground daemon
//!   prompts on stdin; consoleless hosts auto-deny-and-log).
//! - **pre-serve setup** (data dir, bind resolution, DAT mint, startup diagnostics, the
//!   breadcrumb): small and subtly host-specific (e.g. the service safe-fails an invalid
//!   bind to loopback rather than aborting).

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use koi_compose::cores::Cores;

/// Declarative description of which transports + presence to serve, plus the ports,
/// zone, and DAT the stack needs. Neutral (no `clap`/binary types) so any host — the
/// daemon, the Windows service, an embedded app — maps its own config into it.
pub struct ServeConfig {
    /// Resolved HTTP bind address (loopback default; the caller resolves `--http-bind`).
    pub bind_ip: IpAddr,
    pub http_port: u16,
    pub no_http: bool,
    pub no_ipc: bool,
    pub no_mcp_http: bool,
    pub pipe_path: PathBuf,
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
}

/// Spawn the full serving stack for `cores` into `(cancel, tasks)`. The caller owns the
/// lifecycle edge and the enrollment-approval pump (see the module docs). Every spawned
/// task is pushed to `tasks` so the caller's `ordered_shutdown` awaits them, and every
/// supervisor reacts to `cancel` for graceful teardown.
pub fn serve(
    cores: &Cores,
    started_at: Instant,
    cfg: ServeConfig,
    cancel: &CancellationToken,
    tasks: &mut Vec<JoinHandle<()>>,
) {
    // ── Dashboard state + the single unified event forwarder ──
    let dashboard_state = crate::dashboard::build_dashboard_state(cores, started_at, cfg.mode);
    tasks.push(koi_dashboard::forward::spawn_event_forwarder(
        koi_dashboard::forward::ForwarderCores {
            mdns: cores.mdns.clone(),
            certmesh: cores.certmesh.clone(),
            dns: cores.dns.clone(),
            health: cores.health.clone(),
            proxy: cores.proxy.clone(),
            runtime: cores.runtime.clone(),
        },
        dashboard_state.event_tx.clone(),
        cancel.clone(),
    ));

    // ── mDNS browser state (conditional on mDNS being enabled) ──
    // The LAN-wide meta-browse worker is NOT started here: it starts on the first
    // browser request and idles out (koi_dashboard::meta_browse).
    let browser_state = cores
        .mdns
        .as_ref()
        .map(|mdns| koi_dashboard::browser::build_state(mdns.clone(), cancel.clone()));

    // ── HTTP adapter ──
    if !cfg.no_http {
        let c = cores.clone();
        let port = cfg.http_port;
        let bind_ip = cfg.bind_ip;
        let cancel_token = cancel.clone();
        let ds = dashboard_state.clone();
        let bs = browser_state.clone();
        let dat = cfg.dat_token.clone();
        let mdns_snap = cores.mdns_snapshot.clone();
        let mcp_http = !cfg.no_mcp_http;
        tasks.push(tokio::spawn(async move {
            if let Err(e) = crate::http::start(
                c,
                bind_ip,
                port,
                cancel_token,
                started_at,
                ds,
                bs,
                dat,
                mdns_snap,
                mcp_http,
            )
            .await
            {
                tracing::error!(error = %e, "HTTP adapter failed");
            }
        }));
    }

    // ── Trust-plane presence (mTLS inter-node + ACME + _certmesh._tcp announce) ──
    // One posture-reactive supervisor owns all three and brings them up/down as the
    // certmesh CA appears or is destroyed — no restart (ADR-020 P4c / ADR-016 §2).
    crate::trust_plane::spawn(
        cores,
        crate::trust_plane::TrustPlaneConfig {
            mtls_port: cfg.mtls_port,
            acme_port: cfg.acme_port,
            no_acme: cfg.no_acme,
            dns_zone: cfg.dns_zone.clone(),
            announce_http_port: (!cfg.no_http).then_some(cfg.http_port),
        },
        cancel.clone(),
        tasks,
    );

    // ── IPC adapter (only if mDNS is enabled - IPC speaks the mDNS NDJSON protocol) ──
    if !cfg.no_ipc {
        if let Some(ref mdns) = cores.mdns {
            let c = mdns.clone();
            let path = cfg.pipe_path.clone();
            let token = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = crate::pipe::start(c, path, token).await {
                    tracing::error!(error = %e, "IPC adapter failed");
                }
            }));
        } else {
            tracing::info!("IPC adapter: skipped (mDNS disabled)");
        }
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
            http_port: cfg.http_port,
            dashboard_enabled: cfg.dashboard,
            announce_http: cfg.announce_http && !cfg.no_http,
            announce_mcp: !cfg.no_mcp_http && !cfg.no_http,
            dns_zone: cfg.dns_zone,
        },
        cancel.clone(),
        tasks,
    );
}
