//! Daemon mode — constructs the daemon via koi-compose (`build_cores`), spawns the binary's
//! transport adapters, writes the breadcrumb, and runs the ordered shutdown; plus the stdin
//! enrollment-approval prompt. Moved from main.rs (P07 step 6b).

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::cli::Config;
use crate::infra::{
    breadcrumb_endpoint, resolve_http_bind_ip, shutdown_signal, startup_diagnostics,
};
use crate::{adapters, platform};

// ── Daemon mode ──────────────────────────────────────────────────────

pub(crate) async fn daemon_mode(config: Config) -> anyhow::Result<()> {
    koi_config::dirs::ensure_data_dir();

    // Resolve the HTTP bind address up front so startup logs and the breadcrumb
    // agree with what the adapter actually binds. Only meaningful when HTTP is on.
    let http_bind_ip = if config.no_http {
        None
    } else {
        Some(resolve_http_bind_ip(&config.http_bind)?)
    };
    startup_diagnostics(&config, http_bind_ip);

    // Generate a Daemon Access Token (DAT) for authenticating mutation requests
    let dat_token = crate::infra::mint_dat();

    // Write breadcrumb so clients can discover the daemon. Clients connect over a
    // routable address, so an unspecified bind (0.0.0.0) is advertised as loopback.
    if !config.no_http {
        let endpoint = breadcrumb_endpoint(http_bind_ip, config.http_port);
        koi_config::breadcrumb::write_breadcrumb(&endpoint, &dat_token);
    }

    let cancel = CancellationToken::new();
    let mut tasks = Vec::new();
    let started_at = std::time::Instant::now();

    // ── Build all domain cores + bridges + domain background tasks ──
    // The construction graph, the orchestrator, and the certmesh role loops live in
    // koi-compose so the Windows service constructs the identical daemon (P07).
    let cores = koi_compose::cores::build_cores(
        &koi_compose::cores::CoreSpec {
            no_mdns: config.no_mdns,
            no_certmesh: config.no_certmesh,
            no_dns: config.no_dns,
            no_health: config.no_health,
            no_proxy: config.no_proxy,
            no_udp: config.no_udp,
            no_runtime: config.no_runtime,
            data_dir: Some(config.data_dir.clone()),
            dns_config: config.dns_config(),
            runtime: config.runtime.clone(),
            http_port: config.http_port,
            ..koi_compose::cores::CoreSpec::daemon_defaults()
        },
        &cancel,
        &mut tasks,
    )
    .await
    // fail_fast = false (daemon default): build_cores logs+drops a failed capability and
    // always returns Ok, so this never falls back — Cores::default() is a panic-free guard.
    .unwrap_or_default();

    // ── Dashboard state ──
    let dashboard_state = adapters::dashboard::build_dashboard_state(&cores, started_at, "daemon");
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
    // browser request and idles out (koi_dashboard::meta_browse). Default daemon
    // startup performs no LAN-wide browsing.
    let browser_state = cores
        .mdns
        .as_ref()
        .map(|mdns| koi_dashboard::browser::build_state(mdns.clone(), cancel.clone()));

    // ── HTTP adapter ──
    if !config.no_http {
        let c = cores.clone();
        let port = config.http_port;
        let bind_ip = http_bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let cancel_token = cancel.clone();
        let ds = dashboard_state.clone();
        let bs = browser_state.clone();
        let dat = dat_token.clone();
        let mdns_snap = cores.mdns_snapshot.clone();
        let mcp_http = !config.no_mcp_http;
        tasks.push(tokio::spawn(async move {
            if let Err(e) = adapters::http::start(
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
    // Shared verbatim with the Windows service so the two boot paths cannot drift.
    adapters::trust_plane::spawn(
        &cores,
        adapters::trust_plane::TrustPlaneConfig {
            mtls_port: config.mtls_port,
            acme_port: config.acme_port,
            no_acme: config.no_acme,
            dns_zone: config.dns_zone.clone(),
            announce_http_port: (!config.no_http).then_some(config.http_port),
        },
        cancel.clone(),
        &mut tasks,
    );

    // ── IPC adapter (only if mDNS is enabled - IPC speaks mDNS NDJSON protocol) ──
    if !config.no_ipc {
        if let Some(ref mdns) = cores.mdns {
            let c = mdns.clone();
            let path = config.pipe_path.clone();
            let token = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = adapters::pipe::start(c, path, token).await {
                    tracing::error!(error = %e, "IPC adapter failed");
                }
            }));
        } else {
            tracing::info!("IPC adapter: skipped (mDNS disabled)");
        }
    }

    // ── Self-announce supervisor: _http._tcp (+ _mcp._tcp), posture-reactive ──
    // One supervisor publishes this host's _http._tcp record (with the ADR-020 posture stamp)
    // and the _mcp._tcp transport descriptor, re-stamps _http._tcp on every Open↔Authenticated
    // flip, and withdraws both on shutdown. Shared by all three boot paths so a node that boots
    // Open and later runs `certmesh create` updates its advertised posture without a restart —
    // the same reactivity the trust-plane gives _certmesh._tcp. The daemon always serves the
    // dashboard.
    koi_compose::self_announce::spawn(
        &cores,
        koi_compose::self_announce::SelfAnnounceConfig {
            http_port: config.http_port,
            dashboard_enabled: true,
            announce_http: config.announce_http && !config.no_http,
            announce_mcp: !config.no_mcp_http && !config.no_http,
            dns_zone: config.dns_zone.clone(),
        },
        cancel.clone(),
        &mut tasks,
    );

    // The `_certmesh._tcp` CA discovery record (ADR-017 F12) is published by the
    // posture-reactive trust-plane supervisor above (not here), so it appears the
    // moment a CA is created — even on a node that booted Open — without a restart.

    // ── Enrollment-approval pump ──
    // The certmesh role loops are spawned by build_cores (shared with the Windows service).
    // Only the approval pump is wired here, because its decider is host-specific: the
    // foreground daemon prompts on stdin; consoleless hosts use `deny_and_log_decider`.
    if let Some(ref certmesh) = cores.certmesh {
        let decider: koi_compose::certmesh::ApprovalDecider = Arc::new(prompt_enrollment_approval);
        koi_compose::certmesh::spawn_enrollment_approval(certmesh, decider, &cancel, &mut tasks)
            .await;
    }

    if let Err(e) = platform::register_service() {
        tracing::warn!(error = %e, "Platform service registration failed");
    }

    tracing::info!("Ready.");

    // Wait for shutdown signal
    shutdown_signal(cancel.clone()).await;
    tracing::info!("Shutting down...");

    // Ordered shutdown with hard timeout (shared with the Windows service via koi-compose).
    koi_compose::cores::ordered_shutdown(
        &cancel,
        tasks,
        &cores,
        crate::SHUTDOWN_TIMEOUT,
        crate::SHUTDOWN_DRAIN,
    )
    .await;

    koi_config::breadcrumb::delete_breadcrumb();

    Ok(())
}

fn prompt_enrollment_approval(
    hostname: &str,
    requires_approval: bool,
) -> koi_certmesh::ApprovalDecision {
    eprintln!("Enrollment approval requested for '{hostname}'");
    let approve = read_yes_no("Approve enrollment? [y/N]: ");
    if !approve {
        return koi_certmesh::ApprovalDecision::Denied;
    }

    // When approval is required, an accountable operator name must accompany it.
    let operator = if requires_approval {
        let operator = read_line("Operator name: ");
        if operator.is_empty() {
            return koi_certmesh::ApprovalDecision::Denied;
        }
        Some(operator)
    } else {
        None
    };

    koi_certmesh::ApprovalDecision::Approved { operator }
}

fn read_yes_no(prompt: &str) -> bool {
    let line = read_line(prompt);
    matches!(line.as_str(), "y" | "yes")
}

fn read_line(prompt: &str) -> String {
    eprintln!("{prompt}");
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_ok() {
        line.trim().to_string()
    } else {
        String::new()
    }
}
