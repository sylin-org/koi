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

    /// Output JSON instead of human-readable text (for verb subcommands)
    #[arg(long, global = true)]
    pub json: bool,

    /// Auto-exit after N seconds (browse/subscribe default: 5s, register: infinite, 0 = run forever)
    #[arg(long, global = true, value_name = "SECONDS")]
    pub timeout: Option<u64>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Install Koi as a system service
    Install,
    /// Uninstall the Koi system service
    Uninstall,
    /// Browse for services of a given type on the local network
    Browse {
        /// Service type (e.g. "http", "_http._tcp"). Omit to discover all types.
        service_type: Option<String>,
    },
    /// Register (advertise) a service on the local network
    Register {
        /// Service instance name
        name: String,
        /// Service type (e.g. "http", "_http._tcp")
        service_type: String,
        /// Port number
        port: u16,
        /// TXT record entries as KEY=VALUE pairs
        #[arg(trailing_var_arg = true)]
        txt: Vec<String>,
    },
    /// Unregister a previously registered service by its ID
    Unregister {
        /// Registration ID returned by the register command
        id: String,
    },
    /// Resolve a specific service instance by its full name
    Resolve {
        /// Full instance name (e.g. "My Server._http._tcp.local.")
        instance: String,
    },
    /// Subscribe to lifecycle events for a service type
    Subscribe {
        /// Service type (e.g. "http", "_http._tcp")
        service_type: String,
    },
}

/// Resolved configuration used at runtime.
pub struct Config {
    pub http_port: u16,
    pub pipe_path: PathBuf,
    pub no_http: bool,
    pub no_ipc: bool,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Self {
        let pipe_path = cli.pipe.clone().unwrap_or_else(default_pipe_path);
        Self {
            http_port: cli.port,
            pipe_path,
            no_http: cli.no_http,
            no_ipc: cli.no_ipc,
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
