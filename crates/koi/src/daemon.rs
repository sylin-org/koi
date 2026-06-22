//! Daemon mode — constructs the daemon via koi-compose (`build_cores`), spawns the serving
//! stack via koi-serve (`serve`), writes the breadcrumb, and runs the ordered shutdown; plus
//! the stdin enrollment-approval prompt. Moved from main.rs (P07 step 6b).

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::cli::Config;
use crate::infra::{
    breadcrumb_endpoint, resolve_http_bind_ip, shutdown_signal, startup_diagnostics,
};
use crate::platform;

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

    // ── Serving stack (shared verbatim with the Windows service via koi-serve) ──
    // Dashboard + event forwarder, the mDNS browser, the HTTP adapter, the
    // posture-reactive trust plane (mTLS + ACME + _certmesh._tcp), the IPC adapter, and
    // the posture-reactive _http/_mcp self-announce — one call so the two boot paths
    // cannot drift. The daemon always serves the dashboard.
    koi_serve::serve(
        &cores,
        started_at,
        koi_serve::ServeConfig {
            bind_ip: http_bind_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            http_port: config.http_port,
            no_http: config.no_http,
            no_ipc: config.no_ipc,
            no_mcp_http: config.no_mcp_http,
            pipe_path: config.pipe_path.clone(),
            mtls_port: config.mtls_port,
            acme_port: config.acme_port,
            no_acme: config.no_acme,
            dns_zone: config.dns_zone.clone(),
            announce_http: config.announce_http,
            dashboard: true,
            mode: "daemon",
            dat_token: dat_token.clone(),
        },
        &cancel,
        &mut tasks,
    );

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
