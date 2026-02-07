mod adapters;
mod commands;
mod config;
mod core;
mod format;
mod platform;
mod protocol;

use std::sync::Arc;

use clap::Parser;
use config::{Cli, Command, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let env_filter = tracing_subscriber::EnvFilter::try_new(&cli.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .init();

    // ── Verb subcommands ────────────────────────────────────────────
    if let Some(command) = &cli.command {
        return match command {
            Command::Install => {
                #[cfg(windows)]
                {
                    platform::windows::install()
                }
                #[cfg(not(windows))]
                {
                    anyhow::bail!("Service install is only supported on Windows. Use the systemd unit file on Linux.");
                }
            }
            Command::Uninstall => {
                #[cfg(windows)]
                {
                    platform::windows::uninstall()
                }
                #[cfg(not(windows))]
                {
                    anyhow::bail!("Service uninstall is only supported on Windows. Use systemctl on Linux.");
                }
            }
            Command::Browse { service_type } => {
                let core = Arc::new(core::MdnsCore::new()?);
                commands::browse(core, service_type.as_deref(), cli.json, cli.timeout).await
            }
            Command::Register {
                name,
                service_type,
                port,
                txt,
            } => {
                let core = Arc::new(core::MdnsCore::new()?);
                commands::register(core, name, service_type, *port, txt, cli.json, cli.timeout)
                    .await
            }
            Command::Unregister { id } => {
                let core = Arc::new(core::MdnsCore::new()?);
                commands::unregister(core, id, cli.json)
            }
            Command::Resolve { instance } => {
                let core = Arc::new(core::MdnsCore::new()?);
                commands::resolve(core, instance, cli.json).await
            }
            Command::Subscribe { service_type } => {
                let core = Arc::new(core::MdnsCore::new()?);
                commands::subscribe(core, service_type, cli.json, cli.timeout).await
            }
        };
    }

    // ── Windows Service dispatch ────────────────────────────────────
    #[cfg(windows)]
    {
        if !cli.daemon && !is_piped_stdin() {
            if platform::windows::try_run_as_service() {
                return Ok(());
            }
        }
    }

    // ── Piped CLI mode ──────────────────────────────────────────────
    if is_piped_stdin() && !cli.daemon {
        let core = Arc::new(core::MdnsCore::new()?);
        adapters::cli::start(core.clone()).await?;
        let _ = core.shutdown();
        return Ok(());
    }

    // ── Daemon mode ─────────────────────────────────────────────────
    let config = Config::from_cli(&cli);
    startup_diagnostics(&config);

    let core = Arc::new(core::MdnsCore::new()?);
    let mut tasks = Vec::new();

    if !config.no_http {
        let c = core.clone();
        let port = config.http_port;
        tasks.push(tokio::spawn(async move {
            if let Err(e) = adapters::http::start(c, port).await {
                tracing::error!(error = %e, "HTTP adapter failed");
            }
        }));
    }

    if !config.no_ipc {
        let c = core.clone();
        let path = config.pipe_path.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = adapters::pipe::start(c, path).await {
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

    // Graceful shutdown: stop adapters first, then core sends goodbye packets
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }

    if let Err(e) = core.shutdown() {
        tracing::warn!(error = %e, "Error during shutdown");
    }

    Ok(())
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

fn startup_diagnostics(config: &Config) {
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
    check_firewall_windows(config.http_port);
}

#[cfg(windows)]
fn check_firewall_windows(http_port: u16) {
    use std::process::Command as Cmd;

    let udp_check = Cmd::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=all", "dir=in"])
        .output();

    match udp_check {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("5353") && stdout.contains("UDP") {
                tracing::info!("Firewall: UDP 5353 rule found");
            } else {
                tracing::warn!("Koi may not receive mDNS traffic — no UDP 5353 inbound rule found.");
                tracing::warn!("Run as administrator or execute:");
                tracing::warn!(
                    "  netsh advfirewall firewall add rule name=\"Koi mDNS (UDP)\" dir=in action=allow protocol=UDP localport=5353"
                );
            }
            if stdout.contains(&http_port.to_string()) && stdout.contains("TCP") {
                tracing::info!("Firewall: TCP {} rule found", http_port);
            } else {
                tracing::warn!(
                    "  netsh advfirewall firewall add rule name=\"Koi HTTP (TCP)\" dir=in action=allow protocol=TCP localport={}",
                    http_port
                );
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "Could not check firewall rules");
        }
    }
}
