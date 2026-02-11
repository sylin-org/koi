mod adapters;
mod admin;
mod client;
pub(crate) mod cli;
mod commands;
mod format;
mod platform;
mod wiring;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio_util::sync::CancellationToken;

use cli::{AdminSubcommand, Cli, Command, Config, MdnsSubcommand};

/// Maximum time to wait for orderly shutdown before forcing exit.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Brief pause after cancellation to let in-flight requests complete.
const SHUTDOWN_DRAIN: Duration = Duration::from_millis(500);

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

    // ── Synchronous subcommands (no runtime needed) ──────────────────
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
            Command::Status => {
                return dispatch_status(&cli);
            }
            #[cfg(feature = "mdns")]
            Command::Mdns(mdns_cmd) => {
                // Admin subcommands are sync — handle before runtime
                if let MdnsSubcommand::Admin(admin_cmd) = &mdns_cmd.command {
                    let endpoint = resolve_endpoint(&cli)?;
                    return dispatch_mdns_admin(&admin_cmd.command, &endpoint, cli.json);
                }
            }
        }
    }

    // ── Everything below needs a Tokio runtime ──────────────────────
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    // ── Moniker subcommands (async) ─────────────────────────────────
    if let Some(command) = &cli.command {
        #[cfg(feature = "mdns")]
        if let Command::Mdns(mdns_cmd) = command {
            return match detect_mode(&cli) {
                RunMode::Standalone => dispatch_mdns_standalone(&mdns_cmd.command, &cli).await,
                RunMode::Client { endpoint } => {
                    dispatch_mdns_client(&mdns_cmd.command, &endpoint, &cli).await
                }
            };
        }

        // Non-moniker commands already handled in main()
        return Ok(());
    }

    // ── Piped CLI mode ──────────────────────────────────────────────
    #[cfg(feature = "mdns")]
    if is_piped_stdin() && !cli.daemon {
        let core = Arc::new(koi_mdns::MdnsCore::new()?);
        adapters::cli::start(core.clone()).await?;
        let _ = core.shutdown().await;
        return Ok(());
    }

    // ── Daemon mode ─────────────────────────────────────────────────
    let config = Config::from_cli(&cli);
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

    #[cfg(feature = "mdns")]
    let core = Arc::new(koi_mdns::MdnsCore::with_cancel(cancel.clone())?);

    #[cfg(feature = "mdns")]
    if !config.no_http {
        let c = core.clone();
        let port = config.http_port;
        let token = cancel.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = start_http(c, port, token, started_at).await {
                tracing::error!(error = %e, "HTTP adapter failed");
            }
        }));
    }

    if !config.no_ipc {
        #[cfg(feature = "mdns")]
        {
            let c = core.clone();
            let path = config.pipe_path.clone();
            let token = cancel.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = adapters::pipe::start(c, path, token).await {
                    tracing::error!(error = %e, "IPC adapter failed");
                }
            }));
        }
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
        #[cfg(feature = "mdns")]
        if let Err(e) = core.shutdown().await {
            tracing::warn!(error = %e, "Error during shutdown");
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

// ── HTTP server startup ─────────────────────────────────────────────

#[cfg(feature = "mdns")]
pub(crate) async fn start_http(
    core: Arc<koi_mdns::MdnsCore>,
    port: u16,
    cancel: CancellationToken,
    started_at: std::time::Instant,
) -> anyhow::Result<()> {
    use axum::extract::State as AxumState;
    use axum::response::Json;
    use axum::routing::get;
    use axum::Router;
    use koi_common::capability::Capability;
    use tower_http::cors::CorsLayer;

    #[derive(Clone)]
    struct AppState {
        core: Arc<koi_mdns::MdnsCore>,
        started_at: std::time::Instant,
    }

    async fn unified_status_handler(
        AxumState(state): AxumState<AppState>,
    ) -> Json<serde_json::Value> {
        let capabilities = vec![state.core.status()];
        let uptime_secs = state.started_at.elapsed().as_secs();
        Json(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "platform": std::env::consts::OS,
            "uptime_secs": uptime_secs,
            "daemon": true,
            "capabilities": capabilities,
        }))
    }

    let app_state = AppState {
        core: core.clone(),
        started_at,
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/status", get(unified_status_handler))
        .with_state(app_state)
        .nest("/v1/mdns", koi_mdns::http::routes(core))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("HTTP adapter listening on port {}", port);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel.cancelled().await;
        })
        .await?;

    tracing::debug!("HTTP adapter stopped");
    Ok(())
}

async fn health() -> &'static str {
    "OK"
}

// ── Mode detection ───────────────────────────────────────────────────

enum RunMode {
    Standalone,
    Client { endpoint: String },
}

/// Determine whether to run standalone (local mDNS core) or as a client
/// talking to an already-running daemon.
fn detect_mode(cli: &Cli) -> RunMode {
    if cli.standalone {
        return RunMode::Standalone;
    }
    if let Some(endpoint) = &cli.endpoint {
        return RunMode::Client {
            endpoint: endpoint.clone(),
        };
    }
    // Check breadcrumb — if a daemon is advertising its endpoint, use client mode
    if let Some(endpoint) = koi_config::breadcrumb::read_breadcrumb() {
        let c = client::KoiClient::new(&endpoint);
        if c.health().is_ok() {
            return RunMode::Client { endpoint };
        }
    }
    RunMode::Standalone
}

/// Resolve an endpoint for admin commands (which always need a daemon).
fn resolve_endpoint(cli: &Cli) -> anyhow::Result<String> {
    if let Some(endpoint) = &cli.endpoint {
        return Ok(endpoint.clone());
    }
    if let Some(endpoint) = koi_config::breadcrumb::read_breadcrumb() {
        return Ok(endpoint);
    }
    anyhow::bail!("No daemon endpoint found. Is the daemon running? Use --endpoint to specify.")
}

// ── mDNS command dispatch ────────────────────────────────────────────

#[cfg(feature = "mdns")]
async fn dispatch_mdns_standalone(
    subcmd: &MdnsSubcommand,
    cli: &Cli,
) -> anyhow::Result<()> {
    let core = Arc::new(koi_mdns::MdnsCore::new()?);
    match subcmd {
        MdnsSubcommand::Discover { service_type } => {
            commands::standalone::browse(core, service_type.as_deref(), cli.json, cli.timeout).await
        }
        MdnsSubcommand::Announce {
            name,
            service_type,
            port,
            ip,
            txt,
        } => {
            commands::standalone::register(
                core,
                name,
                service_type,
                *port,
                ip.as_deref(),
                txt,
                cli.json,
                cli.timeout,
            )
            .await
        }
        MdnsSubcommand::Unregister { id } => {
            commands::standalone::unregister(core, id, cli.json).await
        }
        MdnsSubcommand::Resolve { instance } => {
            commands::standalone::resolve(core, instance, cli.json).await
        }
        MdnsSubcommand::Subscribe { service_type } => {
            commands::standalone::subscribe(core, service_type, cli.json, cli.timeout).await
        }
        MdnsSubcommand::Admin(_) => unreachable!("handled in main()"),
    }
}

#[cfg(feature = "mdns")]
async fn dispatch_mdns_client(
    subcmd: &MdnsSubcommand,
    endpoint: &str,
    cli: &Cli,
) -> anyhow::Result<()> {
    match subcmd {
        MdnsSubcommand::Discover { service_type } => {
            commands::client::browse(endpoint, service_type.as_deref(), cli.json, cli.timeout).await
        }
        MdnsSubcommand::Announce {
            name,
            service_type,
            port,
            ip,
            txt,
        } => {
            commands::client::register(
                endpoint,
                name,
                service_type,
                *port,
                ip.as_deref(),
                txt,
                cli.json,
                cli.timeout,
            )
            .await
        }
        MdnsSubcommand::Unregister { id } => {
            commands::client::unregister(endpoint, id, cli.json)
        }
        MdnsSubcommand::Resolve { instance } => {
            commands::client::resolve(endpoint, instance, cli.json)
        }
        MdnsSubcommand::Subscribe { service_type } => {
            commands::client::subscribe(endpoint, service_type, cli.json, cli.timeout).await
        }
        MdnsSubcommand::Admin(_) => unreachable!("handled in main()"),
    }
}

#[cfg(feature = "mdns")]
fn dispatch_mdns_admin(
    admin_cmd: &AdminSubcommand,
    endpoint: &str,
    json: bool,
) -> anyhow::Result<()> {
    match admin_cmd {
        AdminSubcommand::Status => admin::status(endpoint, json),
        AdminSubcommand::List => admin::list(endpoint, json),
        AdminSubcommand::Inspect { id } => admin::inspect(endpoint, id, json),
        AdminSubcommand::Unregister { id } => admin::unregister(endpoint, id, json),
        AdminSubcommand::Drain { id } => admin::drain(endpoint, id, json),
        AdminSubcommand::Revive { id } => admin::revive(endpoint, id, json),
    }
}

// ── Status command ──────────────────────────────────────────────────

fn offline_capabilities() -> Vec<koi_common::capability::CapabilityStatus> {
    #[cfg(feature = "mdns")]
    {
        vec![koi_common::capability::CapabilityStatus {
            name: "mdns".to_string(),
            summary: "not running".to_string(),
            healthy: false,
        }]
    }
    #[cfg(not(feature = "mdns"))]
    {
        vec![]
    }
}

fn dispatch_status(cli: &Cli) -> anyhow::Result<()> {
    use koi_common::capability::CapabilityStatus;
    use serde::Serialize;

    #[derive(Serialize)]
    struct UnifiedStatus {
        version: String,
        platform: String,
        daemon: bool,
        capabilities: Vec<CapabilityStatus>,
    }

    // Try to connect to daemon first
    if !cli.standalone {
        if let Some(endpoint) = cli
            .endpoint
            .clone()
            .or_else(koi_config::breadcrumb::read_breadcrumb)
        {
            let c = client::KoiClient::new(&endpoint);
            if c.health().is_ok() {
                match c.unified_status() {
                    Ok(status_json) => {
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&status_json)?);
                        } else {
                            format_unified_status(&status_json);
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Could not fetch unified status");
                    }
                }
            }
        }
    }

    // No daemon — report offline status with compile-time capabilities
    let capabilities = offline_capabilities();

    let status = UnifiedStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        daemon: false,
        capabilities,
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Koi v{}", status.version);
        println!("  Platform:  {}", status.platform);
        println!("  Daemon:    not running");
        for cap in &status.capabilities {
            let marker = if cap.healthy { "+" } else { "-" };
            println!("  [{}] {}:  {}", marker, cap.name, cap.summary);
        }
    }

    Ok(())
}

fn format_unified_status(json: &serde_json::Value) {
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let platform = json
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let uptime = json.get("uptime_secs").and_then(|v| v.as_u64());

    println!("Koi v{version}");
    println!("  Platform:  {platform}");
    if let Some(secs) = uptime {
        println!("  Uptime:    {secs}s");
    }
    println!("  Daemon:    running");

    if let Some(caps) = json.get("capabilities").and_then(|v| v.as_array()) {
        for cap in caps {
            let name = cap.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let summary = cap.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let healthy = cap.get("healthy").and_then(|v| v.as_bool()).unwrap_or(false);
            let marker = if healthy { "+" } else { "-" };
            println!("  [{marker}] {name}:  {summary}");
        }
    }
}

// ── Infrastructure helpers ──────────────────────────────────────────

/// Check if stdin is piped (not a terminal).
fn is_piped_stdin() -> bool {
    use std::io::IsTerminal;
    !std::io::stdin().is_terminal()
}

/// Wait for Ctrl+C or platform-specific shutdown signal.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");
}

// ── Daemon startup diagnostics ──────────────────────────────────────

pub(crate) fn startup_diagnostics(config: &Config) {
    tracing::info!("Koi v{} starting", env!("CARGO_PKG_VERSION"));
    tracing::info!("Platform: {}", std::env::consts::OS);

    match hostname::get() {
        Ok(h) => tracing::info!("Hostname: {}", h.to_string_lossy()),
        Err(e) => tracing::warn!(error = %e, "Could not determine hostname"),
    }

    tracing::info!("mDNS engine: mdns-sd");

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
