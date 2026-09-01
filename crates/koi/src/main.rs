mod admin;
pub(crate) mod cli;
mod client;
mod commands;
mod config_file;
mod daemon;
mod dispatch;
mod format;
mod help;
mod infra;
mod integrations;
mod platform;
mod welcome;

use std::time::Duration;

use clap::{CommandFactory, FromArgMatches};

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

    // ── Two-phase parse: config-file precedence needs arg sources ──
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };

    let config_file_path =
        config_file::discover(cli.config.as_deref()).map_err(|e| anyhow::anyhow!(e))?;

    let mut config = Config::from_cli(&cli);
    if let Some(path) = &config_file_path {
        if let Some(file) = config_file::load(path).map_err(|e| anyhow::anyhow!(e))? {
            config_file::apply(&file, &matches, &mut config);
            tracing::info!(
                path = %path.display(),
                "configuration file applied (CLI > env > file > default)"
            );
        }
    }

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
            Command::Config { action } => {
                return config_file::run_action(action, cli.config.as_deref());
            }
            Command::Install { user, operator } => {
                return {
                    #[cfg(windows)]
                    {
                        platform::windows::install(*user, operator.as_deref(), &config.data_dir)
                    }
                    #[cfg(target_os = "linux")]
                    {
                        platform::unix::install(*user, operator.as_deref(), &config.data_dir)
                    }
                    #[cfg(target_os = "macos")]
                    {
                        platform::macos::install(*user, operator.as_deref(), &config.data_dir)
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
