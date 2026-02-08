mod adapters;
mod admin;
mod client;
mod commands;
mod config;
mod core;
mod format;
mod platform;
mod protocol;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio_util::sync::CancellationToken;

use config::{AdminCommand, Cli, Command, Config};

/// Maximum time to wait for orderly shutdown before forcing exit.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Brief pause after cancellation to let in-flight requests complete.
const SHUTDOWN_DRAIN: Duration = Duration::from_millis(500);

fn main() -> anyhow::Result<()> {
    // ── Windows Service dispatch ────────────────────────────────────
    // Must happen before anything else — the SCM expects the service
    // process to connect to the dispatcher almost immediately.
    // try_run_as_service() calls service_dispatcher::start(), which
    // returns Ok (and blocks) only when the SCM launched this process;
    // otherwise it returns Err instantly and we fall through to normal CLI.
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
            Command::Admin { command: admin_cmd } => {
                let endpoint = resolve_endpoint(&cli)?;
                return dispatch_admin(admin_cmd, &endpoint, cli.json);
            }
            _ => {} // handled below in the async runtime
        }
    }

    // ── Everything below needs a Tokio runtime ──────────────────────
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    // ── Verb subcommands (async) ─────────────────────────────────────
    if let Some(command) = &cli.command {
        return match detect_mode(&cli) {
            RunMode::Standalone => dispatch_standalone(command, &cli).await,
            RunMode::Client { endpoint } => dispatch_client(command, &endpoint, &cli).await,
        };
    }

    // ── Piped CLI mode ──────────────────────────────────────────────
    if is_piped_stdin() && !cli.daemon {
        let core = Arc::new(core::MdnsCore::new()?);
        adapters::cli::start(core.clone()).await?;
        let _ = core.shutdown().await;
        return Ok(());
    }

    // ── Daemon mode ─────────────────────────────────────────────────
    let config = Config::from_cli(&cli);
    startup_diagnostics(&config);

    // Write breadcrumb so clients can discover the daemon
    if !config.no_http {
        let endpoint = format!("http://localhost:{}", config.http_port);
        config::write_breadcrumb(&endpoint);
    }

    let cancel = CancellationToken::new();
    let core = Arc::new(core::MdnsCore::with_cancel(cancel.clone())?);
    let mut tasks = Vec::new();

    if !config.no_http {
        let c = core.clone();
        let port = config.http_port;
        let token = cancel.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = adapters::http::start(c, port, token).await {
                tracing::error!(error = %e, "HTTP adapter failed");
            }
        }));
    }

    if !config.no_ipc {
        let c = core.clone();
        let path = config.pipe_path.clone();
        let token = cancel.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = adapters::pipe::start(c, path, token).await {
                tracing::error!(error = %e, "IPC adapter failed");
            }
        }));
    }

    if let Err(e) = platform::register_service() {
        tracing::warn!(error = %e, "Platform service registration failed");
    }

    tracing::info!("Ready.");

    // Wait for shutdown signal
    shutdown_signal().await;
    tracing::info!("Shutting down...");

    // Ordered shutdown with hard timeout
    let shutdown = shutdown_sequence(cancel, tasks, &core);
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, shutdown)
        .await
        .is_err()
    {
        tracing::warn!(
            "Shutdown timed out after {:?} — forcing exit",
            SHUTDOWN_TIMEOUT
        );
    }

    config::delete_breadcrumb();

    Ok(())
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
    if let Some(endpoint) = config::read_breadcrumb() {
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
    if let Some(endpoint) = config::read_breadcrumb() {
        return Ok(endpoint);
    }
    anyhow::bail!("No daemon endpoint found. Is the daemon running? Use --endpoint to specify.")
}

// ── Command dispatch ─────────────────────────────────────────────────

async fn dispatch_standalone(command: &Command, cli: &Cli) -> anyhow::Result<()> {
    let core = Arc::new(core::MdnsCore::new()?);
    match command {
        Command::Browse { service_type } => {
            commands::standalone::browse(core, service_type.as_deref(), cli.json, cli.timeout).await
        }
        Command::Register {
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
        Command::Unregister { id } => commands::standalone::unregister(core, id, cli.json).await,
        Command::Resolve { instance } => {
            commands::standalone::resolve(core, instance, cli.json).await
        }
        Command::Subscribe { service_type } => {
            commands::standalone::subscribe(core, service_type, cli.json, cli.timeout).await
        }
        _ => unreachable!(),
    }
}

async fn dispatch_client(command: &Command, endpoint: &str, cli: &Cli) -> anyhow::Result<()> {
    match command {
        Command::Browse { service_type } => {
            commands::client::browse(endpoint, service_type.as_deref(), cli.json, cli.timeout).await
        }
        Command::Register {
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
        Command::Unregister { id } => commands::client::unregister(endpoint, id, cli.json),
        Command::Resolve { instance } => commands::client::resolve(endpoint, instance, cli.json),
        Command::Subscribe { service_type } => {
            commands::client::subscribe(endpoint, service_type, cli.json, cli.timeout).await
        }
        _ => unreachable!(),
    }
}

fn dispatch_admin(admin_cmd: &AdminCommand, endpoint: &str, json: bool) -> anyhow::Result<()> {
    match admin_cmd {
        AdminCommand::Status => admin::status(endpoint, json),
        AdminCommand::List => admin::list(endpoint, json),
        AdminCommand::Inspect { id } => admin::inspect(endpoint, id, json),
        AdminCommand::Unregister { id } => admin::unregister(endpoint, id, json),
        AdminCommand::Drain { id } => admin::drain(endpoint, id, json),
        AdminCommand::Revive { id } => admin::revive(endpoint, id, json),
    }
}

// ── Infrastructure helpers ──────────────────────────────────────────

/// Check if stdin is piped (not a terminal).
fn is_piped_stdin() -> bool {
    use std::io::IsTerminal;
    !std::io::stdin().is_terminal()
}

/// Ordered shutdown: cancel adapters → drain in-flight → wait for tasks → core goodbye.
async fn shutdown_sequence(
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    core: &core::MdnsCore,
) {
    cancel.cancel();

    // Brief drain period for in-flight requests to complete
    tokio::time::sleep(SHUTDOWN_DRAIN).await;

    for task in tasks {
        let _ = task.await;
    }

    if let Err(e) = core.shutdown().await {
        tracing::warn!(error = %e, "Error during shutdown");
    }
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
