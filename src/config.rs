use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "koi", version, about = "Local service discovery for everyone")]
pub struct Cli {
    /// Run in daemon mode (HTTP + IPC adapters)
    #[arg(long)]
    pub daemon: bool,

    /// HTTP API port
    #[arg(long, env = "KOI_PORT", default_value = "5353")]
    pub port: u16,

    /// IPC socket/pipe path (default: platform-specific)
    #[arg(long, env = "KOI_PIPE")]
    pub pipe: Option<PathBuf>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, env = "KOI_LOG", default_value = "info")]
    pub log_level: String,

    /// Disable the HTTP adapter
    #[arg(long, env = "KOI_NO_HTTP")]
    pub no_http: bool,

    /// Disable the IPC adapter
    #[arg(long, env = "KOI_NO_IPC")]
    pub no_ipc: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Install Koi as a system service
    Install,
    /// Uninstall the Koi system service
    Uninstall,
}

/// Resolved configuration used at runtime.
pub struct Config {
    pub http_port: u16,
    pub pipe_path: PathBuf,
    pub no_http: bool,
    pub no_ipc: bool,
    pub daemon: bool,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Self {
        let pipe_path = cli.pipe.clone().unwrap_or_else(default_pipe_path);
        Self {
            http_port: cli.port,
            pipe_path,
            no_http: cli.no_http,
            no_ipc: cli.no_ipc,
            daemon: cli.daemon,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_port: 5353,
            pipe_path: default_pipe_path(),
            no_http: false,
            no_ipc: false,
            daemon: true,
        }
    }
}

fn default_pipe_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\koi")
    }
    #[cfg(unix)]
    {
        // Prefer XDG_RUNTIME_DIR, fall back to /var/run
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join("koi.sock")
        } else {
            PathBuf::from("/var/run/koi.sock")
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("koi.sock")
    }
}
