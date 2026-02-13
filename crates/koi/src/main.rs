mod adapters;
mod admin;
pub(crate) mod cli;
mod client;
mod commands;
mod format;
mod openapi;
mod platform;
mod surface;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::CommandFactory;
use clap::Parser;
use tokio_util::sync::CancellationToken;

use cli::{
    CertmeshSubcommand, Cli, Command, Config, DnsSubcommand, HealthSubcommand, MdnsSubcommand,
    ProxySubcommand,
};
use commands::status::try_daemon_status;
use koi_common::types::ServiceRecord;

/// Maximum time to wait for orderly shutdown before forcing exit.
pub(crate) const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Brief pause after cancellation to let in-flight requests complete.
pub(crate) const SHUTDOWN_DRAIN: Duration = Duration::from_millis(500);

fn main() -> anyhow::Result<()> {
    // ── Windows Service dispatch ────────────────────────────────────
    // Must happen before anything else — the SCM expects the service
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
                        entropy,
                        passphrase,
                    }) => commands::certmesh::create(
                        profile.as_deref(),
                        operator.as_deref(),
                        entropy,
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
                    Some(CertmeshSubcommand::RotateTotp) => {
                        commands::certmesh::rotate_totp(cli.json, ep)
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
            // Install, Uninstall, Version handled before runtime
            Command::Install | Command::Uninstall | Command::Version => Ok(()),
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
        .or_else(koi_config::breadcrumb::read_breadcrumb)
        .unwrap_or_else(|| "http://localhost:5641".to_string());
    print_top_level_help(&api_endpoint);
    Ok(())
}

// ── Daemon mode ──────────────────────────────────────────────────────

async fn daemon_mode(config: Config) -> anyhow::Result<()> {
    koi_config::dirs::ensure_data_dir();
    startup_diagnostics(&config);

    // Write breadcrumb so clients can discover the daemon
    if !config.no_http {
        let endpoint = format!("http://localhost:{}", config.http_port);
        koi_config::breadcrumb::write_breadcrumb(&endpoint);
    }

    let cancel = CancellationToken::new();
    let mut tasks = Vec::new();
    let started_at = std::time::Instant::now();

    // ── Create domain cores based on config ──
    let mdns_core = if !config.no_mdns {
        match koi_mdns::MdnsCore::with_cancel(cancel.clone()) {
            Ok(core) => Some(Arc::new(core)),
            Err(e) => {
                tracing::error!(error = %e, "Failed to initialize mDNS core");
                None
            }
        }
    } else {
        tracing::info!("mDNS capability: disabled");
        None
    };

    let certmesh_core = if !config.no_certmesh {
        init_certmesh_core()
    } else {
        tracing::info!("Certmesh capability: disabled");
        None
    };

    let dns_runtime = if !config.no_dns {
        let core = koi_dns::DnsCore::new(
            config.dns_config(),
            mdns_core.clone(),
            certmesh_core.clone(),
        )
        .await;
        match core {
            Ok(core) => {
                let runtime = Arc::new(koi_dns::DnsRuntime::new(core));
                if let Err(e) = runtime.start().await {
                    tracing::error!(error = %e, "Failed to start DNS server");
                }
                Some(runtime)
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to initialize DNS core");
                None
            }
        }
    } else {
        tracing::info!("DNS capability: disabled");
        None
    };

    let health_runtime = if !config.no_health {
        let core =
            Arc::new(koi_health::HealthCore::new(mdns_core.clone(), dns_runtime.clone()).await);
        let runtime = Arc::new(koi_health::HealthRuntime::new(core));
        if let Err(e) = runtime.start().await {
            tracing::error!(error = %e, "Failed to start health checks");
        }
        Some(runtime)
    } else {
        tracing::info!("Health capability: disabled");
        None
    };

    let proxy_runtime = if !config.no_proxy {
        match koi_proxy::ProxyCore::new() {
            Ok(core) => {
                let runtime = Arc::new(koi_proxy::ProxyRuntime::new(Arc::new(core)));
                if let Err(e) = runtime.start_all().await {
                    tracing::error!(error = %e, "Failed to start proxy listeners");
                }
                Some(runtime)
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to initialize proxy core");
                None
            }
        }
    } else {
        tracing::info!("Proxy capability: disabled");
        None
    };

    let cores = DaemonCores {
        mdns: mdns_core.clone(),
        certmesh: certmesh_core,
        dns: dns_runtime.clone(),
        health: health_runtime.clone(),
        proxy: proxy_runtime.clone(),
    };

    // ── HTTP adapter ──
    if !config.no_http {
        let c = cores.clone();
        let port = config.http_port;
        let token = cancel.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = adapters::http::start(c, port, token, started_at).await {
                tracing::error!(error = %e, "HTTP adapter failed");
            }
        }));
    }

    // ── IPC adapter (only if mDNS is enabled — IPC speaks mDNS NDJSON protocol) ──
    if !config.no_ipc {
        if let Some(ref mdns) = mdns_core {
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

    // ── Phase 3: Background tasks based on certmesh role ──
    if let Some(ref certmesh) = cores.certmesh {
        spawn_enrollment_approval_prompt(certmesh, &cancel, &mut tasks).await;
        spawn_certmesh_background_tasks(
            certmesh,
            mdns_core.clone(),
            config.http_port,
            &cancel,
            &mut tasks,
        );
    }

    if let Err(e) = platform::register_service() {
        tracing::warn!(error = %e, "Platform service registration failed");
    }

    tracing::info!("Ready.");

    // Wait for shutdown signal
    shutdown_signal(cancel.clone()).await;
    tracing::info!("Shutting down...");

    // Ordered shutdown with hard timeout
    let shutdown = async {
        cancel.cancel();
        tokio::time::sleep(SHUTDOWN_DRAIN).await;
        for task in tasks {
            let _ = task.await;
        }
        if let Some(ref core) = mdns_core {
            if let Err(e) = core.shutdown().await {
                tracing::warn!(error = %e, "Error during mDNS shutdown");
            }
        }
        if let Some(dns) = dns_runtime {
            dns.stop().await;
        }
        if let Some(health) = health_runtime {
            let _ = health.stop().await;
        }
        if let Some(proxy) = proxy_runtime {
            proxy.stop_all().await;
        }
    };
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, shutdown)
        .await
        .is_err()
    {
        tracing::warn!(
            "Shutdown timed out after {:?} — forcing exit",
            SHUTDOWN_TIMEOUT
        );
    }

    koi_config::breadcrumb::delete_breadcrumb();

    Ok(())
}

// ── Daemon cores ──────────────────────────────────────────────────────

/// Runtime state for a running daemon. Each domain core is present
/// only if its capability is enabled via Config.
#[derive(Clone)]
pub(crate) struct DaemonCores {
    pub(crate) mdns: Option<Arc<koi_mdns::MdnsCore>>,
    pub(crate) certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    pub(crate) dns: Option<Arc<koi_dns::DnsRuntime>>,
    pub(crate) health: Option<Arc<koi_health::HealthRuntime>>,
    pub(crate) proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
}

/// Initialize the certmesh core for daemon mode.
///
/// Always returns `Some` so HTTP routes are mounted even before `koi certmesh create`.
/// If a CA is initialized, creates a locked core with the roster.
/// If not initialized, creates an uninitialized core (routes are reachable for `/create`).
pub(crate) fn init_certmesh_core() -> Option<Arc<koi_certmesh::CertmeshCore>> {
    if !koi_certmesh::ca::is_ca_initialized() {
        tracing::info!("Certmesh: CA not initialized — routes mounted for /create");
        return Some(Arc::new(koi_certmesh::CertmeshCore::uninitialized()));
    }

    let roster_path = koi_certmesh::ca::roster_path();
    let roster = match koi_certmesh::roster::load_roster(&roster_path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to load certmesh roster — using uninitialized state");
            return Some(Arc::new(koi_certmesh::CertmeshCore::uninitialized()));
        }
    };

    let profile = roster.metadata.trust_profile;
    let core = koi_certmesh::CertmeshCore::locked(roster, profile);
    tracing::info!("Certmesh: CA initialized (locked, use `koi certmesh unlock` to decrypt)");
    Some(Arc::new(core))
}

/// Spawn certmesh background tasks based on the node's role.
///
/// - **Primary (unlocked)**: hourly renewal check loop
/// - **Standby**: periodic roster sync from primary
/// - **Member**: periodic health heartbeat to CA
///
/// All loops respect `CancellationToken` for orderly shutdown.
fn spawn_certmesh_background_tasks(
    certmesh: &Arc<koi_certmesh::CertmeshCore>,
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    http_port: u16,
    cancel: &CancellationToken,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    // ── Renewal check loop ──────────────────────────────────────────
    // Runs on the primary when the CA is unlocked. If the CA is still
    // locked at startup, the loop checks periodically and skips gracefully.
    let cm = Arc::clone(certmesh);
    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let interval = Duration::from_secs(koi_certmesh::lifecycle::RENEWAL_CHECK_INTERVAL_SECS);
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    let results = cm.renew_all_due().await;
                    for (hostname, result) in &results {
                        match result {
                            Ok(hook) => {
                                let hook_ok = hook.as_ref().map(|h| h.success).unwrap_or(true);
                                if hook_ok {
                                    tracing::info!(hostname, "Certificate renewed");
                                } else {
                                    tracing::warn!(hostname, "Certificate renewed but hook failed");
                                }
                            }
                            Err(e) => {
                                tracing::error!(hostname, error = %e, "Certificate renewal failed");
                            }
                        }
                    }
                    if !results.is_empty() {
                        tracing::info!(count = results.len(), "Renewal check complete");
                    }
                }
            }
        }
    }));

    // ── Standby roster sync loop ────────────────────────────────────
    // Periodically pulls the signed roster manifest from the primary
    // and installs it locally. Uses KoiClient (blocking) via spawn_blocking.
    let cm = Arc::clone(certmesh);
    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let interval = Duration::from_secs(
            koi_certmesh::failover::ROSTER_SYNC_INTERVAL_SECS,
        );
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    // Only run if this node is a standby
                    if cm.node_role().await != Some(koi_certmesh::roster::MemberRole::Standby) {
                        continue;
                    }

                    let endpoint = match koi_config::breadcrumb::read_breadcrumb() {
                        Some(ep) => ep,
                        None => {
                            tracing::debug!("Roster sync: no primary endpoint found");
                            continue;
                        }
                    };

                    // KoiClient is blocking (ureq) — run in a blocking task
                    let manifest_json = tokio::task::spawn_blocking(move || {
                        let client = client::KoiClient::new(&endpoint);
                        client.get_roster_manifest()
                    })
                    .await;

                    let manifest_json = match manifest_json {
                        Ok(Ok(json)) => json,
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "Roster sync: failed to fetch manifest");
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Roster sync: blocking task panicked");
                            continue;
                        }
                    };

                    // Deserialize and verify the manifest
                    match serde_json::from_value::<koi_certmesh::protocol::RosterManifest>(manifest_json) {
                        Ok(manifest) => {
                            if let Err(e) = cm.accept_roster_sync(&manifest).await {
                                tracing::warn!(error = %e, "Roster sync: verification failed");
                            } else {
                                tracing::debug!("Roster synced from primary");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Roster sync: invalid manifest format");
                        }
                    }
                }
            }
        }
    }));

    // ── Member health heartbeat loop ────────────────────────────────
    // Members periodically POST their pinned CA fingerprint to the CA
    // endpoint. This validates the cert chain is still trusted.
    let cm = Arc::clone(certmesh);
    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let interval = Duration::from_secs(
            koi_certmesh::health::HEARTBEAT_INTERVAL_SECS,
        );
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    // Only run if this node is a regular member (not primary/standby)
                    if cm.node_role().await != Some(koi_certmesh::roster::MemberRole::Member) {
                        continue;
                    }

                    let hostname = match koi_certmesh::CertmeshCore::local_hostname() {
                        Some(h) => h,
                        None => continue,
                    };

                    let pinned_fp = match cm.pinned_ca_fingerprint().await {
                        Some(fp) => fp,
                        None => {
                            tracing::debug!("Health heartbeat: no pinned CA fingerprint");
                            continue;
                        }
                    };

                    let endpoint = match koi_config::breadcrumb::read_breadcrumb() {
                        Some(ep) => ep,
                        None => {
                            tracing::debug!("Health heartbeat: no CA endpoint found");
                            continue;
                        }
                    };

                    let request = serde_json::json!({
                        "hostname": hostname,
                        "pinned_ca_fingerprint": pinned_fp,
                    });

                    // KoiClient is blocking (ureq) — run in a blocking task
                    let result = tokio::task::spawn_blocking(move || {
                        let c = client::KoiClient::new(&endpoint);
                        c.health_heartbeat(&request)
                    })
                    .await;

                    match result {
                        Ok(Ok(resp)) => {
                            let valid = resp.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
                            if valid {
                                tracing::debug!("Health heartbeat: valid");
                            } else {
                                tracing::warn!("Health heartbeat: CA fingerprint mismatch");
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "Health heartbeat: request failed");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Health heartbeat: blocking task panicked");
                        }
                    }
                }
            }
        }
    }));

    // ── Failover detection loop ───────────────────────────────────
    // Watches for a primary on mDNS, promotes the lowest standby after grace,
    // and manages CA announcements based on current role/lock state.
    let cm = Arc::clone(certmesh);
    let mdns = mdns.clone();
    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let mdns = match mdns {
            Some(core) => core,
            None => {
                tracing::debug!("Failover monitor: mDNS disabled");
                return;
            }
        };

        let browse = match mdns.browse(koi_certmesh::CERTMESH_SERVICE_TYPE).await {
            Ok(handle) => handle,
            Err(e) => {
                tracing::warn!(error = %e, "Failover monitor: browse failed");
                return;
            }
        };

        let mut services: HashMap<String, ServiceRecord> = HashMap::new();
        let mut primary_absent_since: Option<Instant> = None;
        let mut announce_id: Option<String> = None;
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                event = browse.recv() => {
                    let Some(event) = event else {
                        break;
                    };
                    match event {
                        koi_mdns::MdnsEvent::Resolved(record) => {
                            services.insert(record.name.clone(), record);
                        }
                        koi_mdns::MdnsEvent::Removed { name, .. } => {
                            services.remove(&name);
                        }
                        koi_mdns::MdnsEvent::Found(_) => {}
                    }
                }
                _ = interval.tick() => {
                    let pinned_fp = cm
                        .pinned_ca_fingerprint()
                        .await
                        .or_else(|| koi_certmesh::ca::ca_fingerprint_from_disk().ok());

                    let Some(pinned_fp) = pinned_fp else {
                        continue;
                    };

                    let hostname = match koi_certmesh::CertmeshCore::local_hostname() {
                        Some(h) => h,
                        None => continue,
                    };

                    let expected_instance = format!("koi-ca-{hostname}");
                    let mut active_primary: Option<ServiceRecord> = None;

                    for record in services.values() {
                        let is_primary = record
                            .txt
                            .get("role")
                            .map(|r| r == "primary")
                            .unwrap_or(false);
                        let fp_matches = record
                            .txt
                            .get("fingerprint")
                            .map(|fp| koi_crypto::pinning::fingerprints_match(fp, &pinned_fp))
                            .unwrap_or(false);

                        if is_primary && fp_matches {
                            active_primary = Some(record.clone());
                            break;
                        }
                    }

                    let active_primary_is_self = active_primary
                        .as_ref()
                        .map(|record| record.name == expected_instance)
                        .unwrap_or(false);

                    let role = cm.node_role().await;

                    match (role, active_primary.is_some()) {
                        (Some(koi_certmesh::roster::MemberRole::Standby), true) => {
                            primary_absent_since = None;
                        }
                        (Some(koi_certmesh::roster::MemberRole::Standby), false) => {
                            if primary_absent_since.is_none() {
                                primary_absent_since = Some(Instant::now());
                            }

                            let grace = Duration::from_secs(
                                koi_certmesh::failover::FAILOVER_GRACE_SECS,
                            );
                            if koi_certmesh::failover::should_promote(primary_absent_since, grace) {
                                let wins = cm
                                    .standby_hostnames()
                                    .await
                                    .into_iter()
                                    .filter(|h| h != &hostname)
                                    .all(|other| {
                                        koi_certmesh::failover::tiebreaker_wins(
                                            &hostname,
                                            &other,
                                        )
                                    });

                                if wins {
                                    match cm.promote_self_to_primary().await {
                                        Ok(true) => {
                                            primary_absent_since = None;
                                            let _ = koi_certmesh::audit::append_entry(
                                                "failover_promoted",
                                                &[("hostname", &hostname)],
                                            );
                                            tracing::warn!(hostname, "Failover: promoted to primary");
                                        }
                                        Ok(false) => {}
                                        Err(e) => {
                                            tracing::warn!(error = %e, "Failover: promotion failed");
                                        }
                                    }
                                }
                            }
                        }
                        (Some(koi_certmesh::roster::MemberRole::Primary), true) => {
                            if !active_primary_is_self {
                                match cm.demote_self_to_standby().await {
                                    Ok(true) => {
                                        primary_absent_since = None;
                                        let _ = koi_certmesh::audit::append_entry(
                                            "failover_demoted",
                                            &[("hostname", &hostname)],
                                        );
                                        tracing::warn!(
                                            hostname,
                                            "Failover: detected another primary, demoting to standby"
                                        );
                                    }
                                    Ok(false) => {}
                                    Err(e) => {
                                        tracing::warn!(error = %e, "Failover: demotion failed");
                                    }
                                }
                            }
                        }
                        _ => {
                            primary_absent_since = None;
                        }
                    }

                    if let Some(ann) = cm.ca_announcement(http_port).await {
                        if announce_id.is_none() {
                            let payload = koi_mdns::protocol::RegisterPayload {
                                name: ann.name.clone(),
                                service_type: koi_certmesh::CERTMESH_SERVICE_TYPE.to_string(),
                                port: ann.port,
                                ip: None,
                                lease_secs: None,
                                txt: ann.txt,
                            };
                            match mdns.register(payload) {
                                Ok(result) => {
                                    tracing::info!(
                                        name = %ann.name,
                                        id = %result.id,
                                        "CA announced via mDNS",
                                    );
                                    announce_id = Some(result.id);
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to announce CA via mDNS");
                                }
                            }
                        }
                    } else if let Some(id) = announce_id.take() {
                        if let Err(e) = mdns.unregister(&id) {
                            tracing::warn!(error = %e, "Failed to withdraw CA mDNS announcement");
                        }
                    }
                }
            }
        }

        if let Some(id) = announce_id {
            let _ = mdns.unregister(&id);
        }
    }));

    tracing::debug!("Certmesh background tasks spawned");
}

async fn spawn_enrollment_approval_prompt(
    certmesh: &Arc<koi_certmesh::CertmeshCore>,
    cancel: &CancellationToken,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    certmesh.set_approval_channel(tx).await;

    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                request = rx.recv() => {
                    let Some(request) = request else {
                        break;
                    };
                    let koi_certmesh::ApprovalRequest { hostname, profile, respond_to } = request;
                    let decision = tokio::task::spawn_blocking(move || {
                        prompt_enrollment_approval(&hostname, profile)
                    })
                    .await
                    .unwrap_or(koi_certmesh::ApprovalDecision::Denied);
                    let _ = respond_to.send(decision);
                }
            }
        }
    }));
}

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

pub(crate) fn startup_diagnostics(config: &Config) {
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

    if !config.no_http {
        tracing::info!("TCP {}: listening (HTTP adapter)", config.http_port);
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
