mod adapters;
mod admin;
mod client;
pub(crate) mod cli;
mod commands;
mod format;
mod platform;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio_util::sync::CancellationToken;

use cli::{CertmeshSubcommand, Cli, Command, Config, MdnsSubcommand};

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
                    MdnsSubcommand::Admin(admin_cmd) => {
                        commands::mdns::admin(&admin_cmd.command, &cli)
                    }
                    MdnsSubcommand::Discover { service_type } => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::discover(
                            service_type.as_deref(), cli.json, cli.timeout, mode,
                        ).await
                    }
                    MdnsSubcommand::Announce { name, service_type, port, ip, txt } => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::announce(
                            name, service_type, *port, ip.as_deref(), txt,
                            cli.json, cli.timeout, mode,
                        ).await
                    }
                    MdnsSubcommand::Unregister { id } => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::unregister(id, cli.json, mode).await
                    }
                    MdnsSubcommand::Resolve { instance } => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::resolve(instance, cli.json, mode).await
                    }
                    MdnsSubcommand::Subscribe { service_type } => {
                        let mode = commands::detect_mode(&cli);
                        commands::mdns::subscribe(
                            service_type, cli.json, cli.timeout, mode,
                        ).await
                    }
                }
            }
            Command::Certmesh(cm_cmd) => {
                config.require_capability("certmesh")?;
                let ep = cli.endpoint.as_deref();
                match &cm_cmd.command {
                    CertmeshSubcommand::Create { profile, operator, entropy, passphrase } => {
                        commands::certmesh::create(
                            profile.as_deref(), operator.as_deref(), entropy,
                            passphrase.as_deref(), cli.json, ep,
                        )
                    }
                    CertmeshSubcommand::Status => commands::certmesh::status(cli.json, ep),
                    CertmeshSubcommand::Log => commands::certmesh::log(ep),
                    CertmeshSubcommand::Unlock => commands::certmesh::unlock(ep),
                    CertmeshSubcommand::SetHook { reload } => {
                        commands::certmesh::set_hook(reload, cli.json, ep)
                    }
                    CertmeshSubcommand::Join { endpoint } => {
                        commands::certmesh::join(endpoint.as_deref(), cli.json, ep).await
                    }
                    CertmeshSubcommand::Promote { endpoint } => {
                        commands::certmesh::promote(endpoint.as_deref(), cli.json, ep).await
                    }
                    CertmeshSubcommand::OpenEnrollment { until } => {
                        commands::certmesh::open_enrollment(until.as_deref(), cli.json, ep)
                    }
                    CertmeshSubcommand::CloseEnrollment => {
                        commands::certmesh::close_enrollment(cli.json, ep)
                    }
                    CertmeshSubcommand::SetPolicy { domain, subnet, clear } => {
                        commands::certmesh::set_policy(
                            domain.as_deref(), subnet.as_deref(), *clear, cli.json, ep,
                        )
                    }
                    CertmeshSubcommand::RotateTotp => {
                        commands::certmesh::rotate_totp(cli.json, ep)
                    }
                }
            }
            // Install, Uninstall, Version handled before runtime
            Command::Install | Command::Uninstall | Command::Version => Ok(()),
        };
    }

    // ── Piped CLI mode ──────────────────────────────────────────────
    if is_piped_stdin() && !cli.daemon {
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

    // ── Daemon mode ─────────────────────────────────────────────────
    daemon_mode(config).await
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

    // ── Cross-domain wiring: certmesh → mDNS announcement ──
    if let (Some(ref mdns), Some(ref certmesh)) = (&mdns_core, &certmesh_core) {
        if let Some(ann) = certmesh.ca_announcement(config.http_port).await {
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
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to announce CA via mDNS");
                }
            }
        }
    }

    let cores = DaemonCores {
        mdns: mdns_core.clone(),
        certmesh: certmesh_core,
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
        spawn_certmesh_background_tasks(certmesh, &cancel, &mut tasks);
    }

    if let Err(e) = platform::register_service() {
        tracing::warn!(error = %e, "Platform service registration failed");
    }

    tracing::info!("Ready.");

    // Wait for shutdown signal
    shutdown_signal().await;
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
    cancel: &CancellationToken,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    // ── Renewal check loop ──────────────────────────────────────────
    // Runs on the primary when the CA is unlocked. If the CA is still
    // locked at startup, the loop checks periodically and skips gracefully.
    let cm = Arc::clone(certmesh);
    let token = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let interval = Duration::from_secs(
            koi_certmesh::lifecycle::RENEWAL_CHECK_INTERVAL_SECS,
        );
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

    tracing::debug!("Certmesh background tasks spawned");
}

// ── Infrastructure helpers ──────────────────────────────────────────

/// Check if stdin is piped (not a terminal).
fn is_piped_stdin() -> bool {
    use std::io::IsTerminal;
    !std::io::stdin().is_terminal()
}

/// Wait for Ctrl+C or platform-specific shutdown signal.
async fn shutdown_signal() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %e, "Failed to listen for Ctrl+C");
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
    platform::windows::check_firewall(config.http_port);
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
