mod adapters;
mod admin;
pub(crate) mod cli;
mod client;
mod commands;
mod format;
mod integrations;
mod platform;
mod surface;

use std::sync::Arc;
use std::time::Duration;

use clap::CommandFactory;
use clap::Parser;
use tokio_util::sync::CancellationToken;

use cli::{
    CertmeshSubcommand, Cli, Command, Config, DnsSubcommand, HealthSubcommand, MdnsSubcommand,
    ProxySubcommand, UdpSubcommand,
};
use commands::status::try_daemon_status;

/// Maximum time to wait for orderly shutdown before forcing exit.
pub(crate) const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Brief pause after cancellation to let in-flight requests complete.
pub(crate) const SHUTDOWN_DRAIN: Duration = Duration::from_millis(500);

fn main() -> anyhow::Result<()> {
    // ── Windows Service dispatch ────────────────────────────────────
    // Must happen before anything else - the SCM expects the service
    // process to connect to the dispatcher almost immediately.
    #[cfg(windows)]
    {
        if platform::windows::try_run_as_service() {
            return Ok(());
        }
    }

    // ── Help query syntax: koi certmesh backup? ─────────────────────
    // Intercept before Clap so we can handle "command?" without Clap
    // treating the `?` as an unknown subcommand.
    {
        let raw_args: Vec<String> = std::env::args().skip(1).collect();
        if let Some(cmd_name) = extract_help_query(&raw_args) {
            if let Some(def) = surface::MANIFEST.get(&cmd_name) {
                if let Err(e) = surface::print_command_detail(def) {
                    eprintln!("Error: {e}");
                }
            } else {
                eprintln!("Unknown command: {cmd_name}");
                eprintln!("Run koi to see available commands.");
                std::process::exit(1);
            }
            return Ok(());
        }
    }

    let cli = Cli::parse();
    let config = Config::from_cli(&cli);

    // Initialize logging
    let level = match cli.verbose {
        0 => cli.log_level.as_str(),
        1 => "debug",
        _ => "trace",
    };
    let env_filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    // Hold the non-blocking guards for the lifetime of main so logs flush on exit.
    let _log_guards = init_logging(env_filter, cli.log_file.as_deref())?;

    // ── Trivially synchronous subcommands ────────────────────────────
    if let Some(command) = &cli.command {
        match command {
            Command::Install => {
                return {
                    #[cfg(windows)]
                    {
                        platform::windows::install()
                    }
                    #[cfg(target_os = "linux")]
                    {
                        platform::unix::install()
                    }
                    #[cfg(target_os = "macos")]
                    {
                        platform::macos::install()
                    }
                    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
                    {
                        anyhow::bail!("Service install is not supported on this platform.")
                    }
                };
            }
            Command::Uninstall => {
                return {
                    #[cfg(windows)]
                    {
                        platform::windows::uninstall()
                    }
                    #[cfg(target_os = "linux")]
                    {
                        platform::unix::uninstall()
                    }
                    #[cfg(target_os = "macos")]
                    {
                        platform::macos::uninstall()
                    }
                    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
                    {
                        anyhow::bail!("Service uninstall is not supported on this platform.")
                    }
                };
            }
            Command::Version => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "version": env!("CARGO_PKG_VERSION"),
                            "platform": std::env::consts::OS,
                        })
                    );
                } else {
                    println!("koi {}", env!("CARGO_PKG_VERSION"));
                }
                return Ok(());
            }
            Command::Launch => {
                let port = cli.port;
                let url = format!("http://localhost:{port}");
                println!("Opening dashboard at {url}");
                if let Err(e) = open::that(&url) {
                    eprintln!("Failed to open browser: {e}");
                    eprintln!("Open manually: {url}");
                }
                return Ok(());
            }
            Command::FactoryReset => {
                return commands::factory_reset::run(cli.json);
            }
            _ => {} // All other commands go through the runtime
        }
    }

    // ── Everything runs in the runtime ────────────────────────────────
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(cli, config))
}

// ── Async entry point ────────────────────────────────────────────────

async fn run(cli: Cli, config: Config) -> anyhow::Result<()> {
    if let Some(command) = &cli.command {
        return match command {
            Command::Status => commands::status::status(&cli, &config),
            Command::Mdns(mdns_cmd) => {
                config.require_capability("mdns")?;
                match &mdns_cmd.command {
                    None => {
                        surface::print_category_catalog(surface::KoiCategory::Discovery, None)?;
                        Ok(())
                    }
                    Some(MdnsSubcommand::Admin(admin_cmd)) => match &admin_cmd.command {
                        Some(admin) => commands::mdns::admin(admin, &cli),
                        None => {
                            surface::print_category_catalog(
                                surface::KoiCategory::Discovery,
                                Some(surface::KoiScope::Admin),
                            )?;
                            Ok(())
                        }
                    },
                    Some(MdnsSubcommand::Discover { service_type }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::discover(
                            service_type.as_deref(),
                            cli.json,
                            cli.timeout,
                            mode,
                        )
                        .await
                    }
                    Some(MdnsSubcommand::Announce {
                        name,
                        service_type,
                        port,
                        ip,
                        txt,
                    }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::announce(
                            name,
                            service_type,
                            *port,
                            ip.as_deref(),
                            txt,
                            cli.json,
                            cli.timeout,
                            mode,
                        )
                        .await
                    }
                    Some(MdnsSubcommand::Unregister { id }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::unregister(id, cli.json, mode).await
                    }
                    Some(MdnsSubcommand::Resolve { instance }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::resolve(instance, cli.json, mode).await
                    }
                    Some(MdnsSubcommand::Subscribe { service_type }) => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::subscribe(service_type, cli.json, cli.timeout, mode).await
                    }
                }
            }
            Command::Certmesh(cm_cmd) => {
                config.require_capability("certmesh")?;
                let ep = cli.endpoint.as_deref();
                match &cm_cmd.command {
                    None => {
                        surface::print_category_catalog(surface::KoiCategory::Trust, None)?;
                        Ok(())
                    }
                    Some(CertmeshSubcommand::Create {
                        profile,
                        operator,
                        enrollment,
                        require_approval,
                        passphrase,
                    }) => commands::certmesh::create(
                        profile.as_deref(),
                        operator.as_deref(),
                        enrollment.as_deref(),
                        *require_approval,
                        passphrase.as_deref(),
                        cli.json,
                        ep,
                    ),
                    Some(CertmeshSubcommand::Status) => commands::certmesh::status(cli.json, ep),
                    Some(CertmeshSubcommand::Log) => commands::certmesh::log(ep),
                    Some(CertmeshSubcommand::Compliance) => {
                        commands::certmesh::compliance(cli.json, ep)
                    }
                    Some(CertmeshSubcommand::Unlock) => commands::certmesh::unlock(ep),
                    Some(CertmeshSubcommand::SetHook { reload }) => {
                        commands::certmesh::set_hook(reload, cli.json, ep)
                    }
                    Some(CertmeshSubcommand::Join { endpoint }) => {
                        commands::certmesh::join(endpoint.as_deref(), cli.json, ep).await
                    }
                    Some(CertmeshSubcommand::Promote { endpoint }) => {
                        commands::certmesh::promote(endpoint.as_deref(), cli.json, ep).await
                    }
                    Some(CertmeshSubcommand::OpenEnrollment { until }) => {
                        commands::certmesh::open_enrollment(until.as_deref(), cli.json, ep)
                    }
                    Some(CertmeshSubcommand::CloseEnrollment) => {
                        commands::certmesh::close_enrollment(cli.json, ep)
                    }
                    Some(CertmeshSubcommand::SetPolicy {
                        domain,
                        subnet,
                        clear,
                    }) => commands::certmesh::set_policy(
                        domain.as_deref(),
                        subnet.as_deref(),
                        *clear,
                        cli.json,
                        ep,
                    ),
                    Some(CertmeshSubcommand::RotateAuth) => {
                        commands::certmesh::rotate_auth(cli.json, ep)
                    }
                    Some(CertmeshSubcommand::Backup { path }) => {
                        commands::certmesh::backup(path, cli.json, ep)
                    }
                    Some(CertmeshSubcommand::Restore { path }) => {
                        commands::certmesh::restore(path, cli.json, ep)
                    }
                    Some(CertmeshSubcommand::Revoke { hostname, reason }) => {
                        commands::certmesh::revoke(hostname, reason.as_deref(), cli.json, ep)
                    }
                    Some(CertmeshSubcommand::Destroy) => commands::certmesh::destroy(cli.json, ep),
                }
            }
            Command::Dns(dns_cmd) => {
                config.require_capability("dns")?;
                let mode = commands::detect_mode(&cli);
                match &dns_cmd.command {
                    None => {
                        surface::print_category_catalog(surface::KoiCategory::Dns, None)?;
                        Ok(())
                    }
                    Some(DnsSubcommand::Serve) => commands::dns::serve(&config, mode).await,
                    Some(DnsSubcommand::Stop) => commands::dns::stop(mode).await,
                    Some(DnsSubcommand::Status) => {
                        commands::dns::status(&config, mode, cli.json).await
                    }
                    Some(DnsSubcommand::Lookup { name, record_type }) => {
                        commands::dns::lookup(name, record_type, mode, cli.json, &config).await
                    }
                    Some(DnsSubcommand::Add { name, ip, ttl }) => {
                        commands::dns::add(name, ip, *ttl, mode, cli.json, &config.dns_zone)
                    }
                    Some(DnsSubcommand::Remove { name }) => {
                        commands::dns::remove(name, mode, cli.json, &config.dns_zone)
                    }
                    Some(DnsSubcommand::List) => commands::dns::list(mode, cli.json, &config).await,
                }
            }
            Command::Health(health_cmd) => {
                config.require_capability("health")?;
                let mode = commands::detect_mode(&cli);
                match &health_cmd.command {
                    None => {
                        surface::print_category_catalog(surface::KoiCategory::Health, None)?;
                        Ok(())
                    }
                    Some(HealthSubcommand::Status) => {
                        commands::health::status(&config, mode, cli.json).await
                    }
                    Some(HealthSubcommand::Watch { interval }) => {
                        commands::health::watch(&config, mode, *interval).await
                    }
                    Some(HealthSubcommand::Add {
                        name,
                        http,
                        tcp,
                        interval,
                        timeout,
                    }) => {
                        commands::health::add(
                            name,
                            http.as_deref(),
                            tcp.as_deref(),
                            *interval,
                            *timeout,
                            mode,
                            cli.json,
                            &config,
                        )
                        .await
                    }
                    Some(HealthSubcommand::Remove { name }) => {
                        commands::health::remove(name, mode, cli.json, &config).await
                    }
                    Some(HealthSubcommand::Log) => commands::health::log(),
                }
            }
            Command::Proxy(proxy_cmd) => {
                config.require_capability("proxy")?;
                let mode = commands::detect_mode(&cli);
                match &proxy_cmd.command {
                    None => {
                        surface::print_category_catalog(surface::KoiCategory::Proxy, None)?;
                        Ok(())
                    }
                    Some(ProxySubcommand::Add {
                        name,
                        listen,
                        backend,
                        backend_remote,
                    }) => {
                        commands::proxy::add(
                            name,
                            *listen,
                            backend,
                            *backend_remote,
                            mode,
                            cli.json,
                        )
                        .await
                    }
                    Some(ProxySubcommand::Remove { name }) => {
                        commands::proxy::remove(name, mode, cli.json).await
                    }
                    Some(ProxySubcommand::Status) => commands::proxy::status(mode, cli.json).await,
                    Some(ProxySubcommand::List) => commands::proxy::list(mode, cli.json).await,
                }
            }
            Command::Udp(udp_cmd) => {
                config.require_capability("udp")?;
                let mode = commands::detect_mode(&cli);
                match &udp_cmd.command {
                    None => {
                        surface::print_category_catalog(surface::KoiCategory::Udp, None)?;
                        Ok(())
                    }
                    Some(UdpSubcommand::Bind { port, addr, lease }) => {
                        commands::udp::bind(*port, addr, *lease, mode, cli.json).await
                    }
                    Some(UdpSubcommand::Unbind { id }) => {
                        commands::udp::unbind(id, mode, cli.json).await
                    }
                    Some(UdpSubcommand::Send { id, dest, payload }) => {
                        commands::udp::send(id, dest, payload, mode, cli.json).await
                    }
                    Some(UdpSubcommand::Status) => commands::udp::status(mode, cli.json).await,
                    Some(UdpSubcommand::Heartbeat { id }) => {
                        commands::udp::heartbeat(id, mode, cli.json).await
                    }
                }
            }
            Command::Token(token_cmd) => commands::token::run(token_cmd, cli.json),
            // Install, Uninstall, Version, Launch, FactoryReset handled before runtime
            Command::Install
            | Command::Uninstall
            | Command::Version
            | Command::Launch
            | Command::FactoryReset => Ok(()),
        };
    }

    // ── No subcommand provided ─────────────────────────────────────

    // Explicit daemon request: start services
    if cli.daemon {
        return daemon_mode(config).await;
    }

    // Piped CLI mode still works without a subcommand
    if is_piped_stdin() {
        if config.no_mdns {
            anyhow::bail!(
                "Piped mode requires the mDNS capability. \
                 Remove --no-mdns or unset KOI_NO_MDNS to enable it."
            );
        }
        let core = Arc::new(koi_mdns::MdnsCore::new()?);
        adapters::cli::start(core.clone()).await?;
        let _ = core.shutdown().await;
        return Ok(());
    }

    // Try to show daemon status if a healthy daemon is reachable; otherwise stay quiet
    if let Some(status_json) = try_daemon_status(&cli) {
        if cli.json {
            if let Ok(body) = serde_json::to_string_pretty(&status_json) {
                println!("{body}");
            }
        } else {
            print!("{}", format::unified_status(&status_json));
        }
    }

    // Always show available commands/help for discoverability
    let api_endpoint = cli
        .endpoint
        .clone()
        .or_else(koi_config::breadcrumb::read_breadcrumb_endpoint)
        .unwrap_or_else(|| "http://localhost:5641".to_string());
    print_top_level_help(&api_endpoint);
    Ok(())
}

// ── Daemon mode ──────────────────────────────────────────────────────

async fn daemon_mode(config: Config) -> anyhow::Result<()> {
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
    let dat_token = {
        use base64::Engine;
        use rand::RngCore;
        let mut token_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut token_bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
    };

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
            data_dir: config.data_dir.clone(),
            dns_config: config.dns_config(),
            runtime: config.runtime.clone(),
            http_port: config.http_port,
        },
        &cancel,
        &mut tasks,
    )
    .await;

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
        tasks.push(tokio::spawn(async move {
            if let Err(e) =
                adapters::http::start(c, bind_ip, port, cancel_token, started_at, ds, bs, dat).await
            {
                tracing::error!(error = %e, "HTTP adapter failed");
            }
        }));
    }

    // ── mTLS adapter (only if certmesh CA is initialized and unlocked) ──
    if let Some(ref certmesh) = cores.certmesh {
        match certmesh.self_enroll().await {
            Ok(enrollment) => {
                let cm = certmesh.clone();
                let port = config.mtls_port;
                let token = cancel.clone();
                tasks.push(tokio::spawn(async move {
                    if let Err(e) = adapters::mtls::start(
                        port,
                        cm,
                        &enrollment.cert_pem,
                        &enrollment.key_pem,
                        &enrollment.ca_cert_pem,
                        token,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "mTLS adapter failed");
                    }
                }));
            }
            Err(e) => {
                tracing::info!(
                    reason = %e,
                    "mTLS adapter: skipped (CA not available for self-enrollment)"
                );
            }
        }
    }

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

    // ── HTTP mDNS announcement (opt-in) ──
    let mut http_announce_id: Option<String> = None;
    if config.announce_http && !config.no_http {
        if let Some(ref mdns) = cores.mdns {
            let hostname = hostname::get()
                .ok()
                .and_then(|os| os.into_string().ok())
                .unwrap_or_else(|| "unknown".to_string());

            let mut txt = std::collections::HashMap::new();
            txt.insert("path".to_string(), "/".to_string());
            txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
            txt.insert("api".to_string(), "v1".to_string());
            txt.insert("dashboard".to_string(), "true".to_string());

            let payload = koi_mdns::protocol::RegisterPayload {
                name: format!("Koi ({hostname})"),
                service_type: "_http._tcp".to_string(),
                port: config.http_port,
                ip: None,
                lease_secs: None,
                txt,
            };
            match mdns.register(payload) {
                Ok(result) => {
                    tracing::info!(
                        id = %result.id,
                        port = config.http_port,
                        "HTTP server announced via mDNS"
                    );
                    http_announce_id = Some(result.id);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to announce HTTP server via mDNS");
                }
            }
        } else {
            tracing::debug!("--announce-http set but mDNS is disabled — skipping");
        }
    }

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
        http_announce_id,
        SHUTDOWN_TIMEOUT,
        SHUTDOWN_DRAIN,
    )
    .await;

    koi_config::breadcrumb::delete_breadcrumb();

    Ok(())
}

// ── Daemon cores ──────────────────────────────────────────────────────

/// Runtime state for a running daemon — the set of constructed domain cores. Defined in
/// koi-compose (built by `build_cores`); re-exported under the historical `DaemonCores`
/// name so the binary's adapters keep their existing references.
pub(crate) use koi_compose::cores::Cores as DaemonCores;

fn prompt_enrollment_approval(
    hostname: &str,
    profile: koi_certmesh::profiles::TrustProfile,
) -> koi_certmesh::ApprovalDecision {
    eprintln!("Enrollment approval requested for '{hostname}' (profile: {profile})");
    let approve = read_yes_no("Approve enrollment? [y/N]: ");
    if !approve {
        return koi_certmesh::ApprovalDecision::Denied;
    }

    let operator = if profile.requires_operator() {
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

// ── Infrastructure helpers ──────────────────────────────────────────

/// Check if stdin is piped (not a terminal).
fn is_piped_stdin() -> bool {
    use std::io::IsTerminal;
    !std::io::stdin().is_terminal()
}

/// Print the top-level help (command list) without exiting with an error.
fn print_top_level_help(api_endpoint: &str) {
    if let Err(err) = surface::print_catalog(api_endpoint) {
        tracing::debug!(error = %err, "Failed to render catalog, falling back to clap help");
        // Clap prints to stdout by default; ignore errors because help display should be best-effort
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        println!();
    }
}

/// Extract a command name from `?`-suffixed args.
///
/// Supports:
/// - `["certmesh", "backup?"]` → `"certmesh backup"`
/// - `["backup?"]`             → `"backup"`
/// - `["?certmesh"]`           → `"certmesh"`  (leading ? also works)
///
/// Returns `None` if no `?` query was detected.
fn extract_help_query(raw_args: &[String]) -> Option<String> {
    if raw_args.is_empty() {
        return None;
    }

    // Check if the last arg ends with '?'
    if let Some(last) = raw_args.last() {
        if last.ends_with('?') && last.len() > 1 {
            let mut parts: Vec<&str> = raw_args[..raw_args.len() - 1]
                .iter()
                .map(|s| s.as_str())
                .collect();
            let trimmed = last.trim_end_matches('?');
            if !trimmed.is_empty() {
                parts.push(trimmed);
            }
            // Skip global flags like --json, --verbose etc.
            let parts: Vec<&str> = parts.into_iter().filter(|p| !p.starts_with('-')).collect();
            if !parts.is_empty() {
                return Some(parts.join(" "));
            }
        }
    }

    // Check if the first arg starts with '?'
    if let Some(first) = raw_args.first() {
        if first.starts_with('?') && first.len() > 1 {
            let cmd_name = first.trim_start_matches('?');
            // Remaining args joined
            let mut parts = vec![cmd_name];
            for arg in &raw_args[1..] {
                if !arg.starts_with('-') {
                    parts.push(arg);
                }
            }
            return Some(parts.join(" "));
        }
    }

    None
}

/// Wait for Ctrl+C or platform-specific shutdown signal.
async fn shutdown_signal(cancel: CancellationToken) {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Failed to listen for Ctrl+C");
            }
        }
        _ = cancel.cancelled() => {
            // Admin shutdown endpoint requests a cancel.
        }
    }
}

// ── Daemon startup diagnostics ──────────────────────────────────────

pub(crate) fn startup_diagnostics(config: &Config, http_bind_ip: Option<std::net::IpAddr>) {
    tracing::info!("Koi v{} starting", env!("CARGO_PKG_VERSION"));
    tracing::info!("Platform: {}", std::env::consts::OS);

    match hostname::get() {
        Ok(h) => tracing::info!("Hostname: {}", h.to_string_lossy()),
        Err(e) => tracing::warn!(error = %e, "Could not determine hostname"),
    }

    if config.no_mdns {
        tracing::info!("mDNS capability: disabled");
    } else {
        tracing::info!("mDNS engine: mdns-sd");
    }

    if config.no_certmesh {
        tracing::info!("Certmesh capability: disabled");
    }

    if config.no_dns {
        tracing::info!("DNS capability: disabled");
    } else {
        tracing::info!(
            "DNS: {}:{} (zone {})",
            "0.0.0.0",
            config.dns_port,
            config.dns_zone
        );
    }

    if config.no_health {
        tracing::info!("Health capability: disabled");
    } else {
        tracing::info!("Health: service checks enabled");
    }

    if config.no_proxy {
        tracing::info!("Proxy capability: disabled");
    }

    if let Some(bind_ip) = http_bind_ip {
        log_http_bind(config, bind_ip);
    } else {
        tracing::info!("HTTP adapter: disabled");
    }

    if !config.no_ipc {
        tracing::info!("IPC: {}", config.pipe_path.display());
    } else {
        tracing::info!("IPC adapter: disabled");
    }

    #[cfg(windows)]
    platform::windows::check_firewall(config);
}

// ── HTTP bind resolution ────────────────────────────────────────────

/// Emits the HTTP bind log line(s) with mode-appropriate exposure warnings.
/// Loopback is quiet; non-loopback binds are loud and always note that
/// mutations still require the daemon token (charter principle 5).
fn log_http_bind(config: &Config, bind_ip: std::net::IpAddr) {
    let port = config.http_port;

    if bind_ip.is_loopback() {
        tracing::info!("HTTP: {bind_ip}:{port} (loopback only — use --http-bind to expose)");
        return;
    }

    if bind_ip.is_unspecified() {
        tracing::warn!(
            "WARNING: Koi is reachable from your entire LAN. Mutations still require the \
             daemon token; GET endpoints are readable by any device. (--http-bind 0.0.0.0)"
        );
        tracing::info!("HTTP: {bind_ip}:{port} (exposed) — mutations require x-koi-token");
    } else if config.http_bind == "bridge" {
        tracing::info!("HTTP: {bind_ip}:{port} (docker bridge) — mutations require x-koi-token");
    } else {
        tracing::warn!(
            "WARNING: Koi is reachable on interface {bind_ip}. Mutations still require the \
             daemon token; GET endpoints are readable by any device. (--http-bind {})",
            config.http_bind
        );
        tracing::info!("HTTP: {bind_ip}:{port} (exposed) — mutations require x-koi-token");
    }
    tracing::info!("hint: containers read the token from a mounted secret; see `koi token --help`");
}

/// Builds the breadcrumb endpoint clients connect to. An unspecified bind
/// (0.0.0.0) is advertised as loopback since clients need a routable address.
pub(crate) fn breadcrumb_endpoint(http_bind_ip: Option<std::net::IpAddr>, port: u16) -> String {
    match http_bind_ip {
        Some(ip) if !ip.is_unspecified() => format!("http://{ip}:{port}"),
        _ => format!("http://127.0.0.1:{port}"),
    }
}

/// Resolves the `--http-bind` mode string to a concrete bind address:
/// `loopback` → 127.0.0.1, `0.0.0.0` → all interfaces, `bridge` → the
/// docker/podman bridge IPv4 (errors if none), `<ip>` → parsed literally.
pub(crate) fn resolve_http_bind_ip(mode: &str) -> anyhow::Result<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr};
    match mode {
        "loopback" => Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "0.0.0.0" => Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        "bridge" => resolve_bridge_ip(),
        other => other.parse::<IpAddr>().map_err(|_| {
            anyhow::anyhow!(
                "invalid --http-bind value '{other}': expected loopback, bridge, \
                 an IP address, or 0.0.0.0"
            )
        }),
    }
}

/// Finds the IPv4 address of the local docker/podman bridge interface.
fn resolve_bridge_ip() -> anyhow::Result<std::net::IpAddr> {
    use std::net::IpAddr;
    let ifaces = if_addrs::get_if_addrs()
        .map_err(|e| anyhow::anyhow!("could not enumerate network interfaces: {e}"))?;

    let is_v4 = |iface: &if_addrs::Interface| matches!(iface.addr.ip(), IpAddr::V4(_));

    // Prefer well-known bridge interface names…
    for name in ["docker0", "podman0", "cni-podman0"] {
        if let Some(iface) = ifaces.iter().find(|i| i.name == name && is_v4(i)) {
            return Ok(iface.addr.ip());
        }
    }
    // …then common bridge name prefixes (user-defined docker networks are `br-*`).
    for iface in &ifaces {
        if iface.is_loopback() || !is_v4(iface) {
            continue;
        }
        let n = &iface.name;
        if n.starts_with("docker")
            || n.starts_with("podman")
            || n.starts_with("br-")
            || n.starts_with("cni-")
        {
            return Ok(iface.addr.ip());
        }
    }
    anyhow::bail!(
        "no docker/podman bridge interface found (looked for docker0, podman0, br-*, …). \
         Use --http-bind <ip> with the host IP that containers should reach."
    )
}

#[cfg(test)]
mod http_bind_tests {
    use super::{breadcrumb_endpoint, resolve_http_bind_ip};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn loopback_mode_resolves_to_localhost() {
        assert_eq!(
            resolve_http_bind_ip("loopback").unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn unspecified_mode_resolves_to_all_interfaces() {
        assert_eq!(
            resolve_http_bind_ip("0.0.0.0").unwrap(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn explicit_ipv4_is_parsed() {
        assert_eq!(
            resolve_http_bind_ip("192.168.1.42").unwrap(),
            "192.168.1.42".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn explicit_ipv6_is_parsed() {
        assert_eq!(
            resolve_http_bind_ip("::1").unwrap(),
            "::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(resolve_http_bind_ip("not-an-ip").is_err());
        assert!(resolve_http_bind_ip("999.999.999.999").is_err());
    }

    #[test]
    fn breadcrumb_advertises_loopback_for_unspecified() {
        assert_eq!(
            breadcrumb_endpoint(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 5641),
            "http://127.0.0.1:5641"
        );
    }

    #[test]
    fn breadcrumb_uses_specific_bind_ip() {
        let ip: IpAddr = "172.17.0.1".parse().unwrap();
        assert_eq!(
            breadcrumb_endpoint(Some(ip), 5641),
            "http://172.17.0.1:5641"
        );
    }
}

// ── Logging setup ───────────────────────────────────────────────────

/// Initialize tracing with stderr + optional file output.
/// Returns guards that must be held for the lifetime of the program
/// to ensure the non-blocking writers flush on shutdown.
pub(crate) fn init_logging(
    env_filter: tracing_subscriber::EnvFilter,
    log_file: Option<&std::path::Path>,
) -> anyhow::Result<Vec<tracing_appender::non_blocking::WorkerGuard>> {
    use tracing_subscriber::prelude::*;

    // Always use non-blocking stderr to avoid deadlocks when stderr is a
    // redirected pipe that nobody reads (e.g. Windows service, test harness).
    let (nb_stderr, stderr_guard) = tracing_appender::non_blocking(std::io::stderr());
    let stderr_layer = tracing_subscriber::fmt::layer().with_writer(nb_stderr);

    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let (nb_file, file_guard) = tracing_appender::non_blocking(file);
        let file_layer = tracing_subscriber::fmt::layer().with_writer(nb_file);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();

        Ok(vec![stderr_guard, file_guard])
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(stderr_layer)
            .init();

        Ok(vec![stderr_guard])
    }
}
