mod admin;
pub(crate) mod cli;
mod client;
mod commands;
mod daemon;
mod dispatch;
mod format;
mod help;
mod infra;
mod integrations;
mod platform;

use std::time::Duration;

use clap::Parser;

use cli::{Cli, Command, Config};
use dispatch::run;
use infra::{extract_help_query, init_logging};

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
            if let Some(meta) = help::get(&cmd_name) {
                if let Err(e) = help::print_command_detail(meta) {
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
                return commands::factory_reset::run(cli.json, cli.yes);
            }
            _ => {} // All other commands go through the runtime
        }
    }

    // ── Everything runs in the runtime ────────────────────────────────
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(cli, config))
}
