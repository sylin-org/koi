use clap::{ArgAction, Parser, Subcommand};
use std::path::PathBuf;

/// Default HTTP API port — "KOI" on a phone keypad (K=5, O=6, I=4).
pub const DEFAULT_HTTP_PORT: u16 = 5641;

/// Breadcrumb filename written by the daemon for client discovery.
const BREADCRUMB_FILENAME: &str = "koi.endpoint";

/// Application directory name used for breadcrumb storage.
const APP_DIR_NAME: &str = "koi";

/// Windows Named Pipe name for IPC.
#[cfg(windows)]
const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\koi";

/// Unix domain socket filename for IPC.
#[cfg(unix)]
const UNIX_SOCKET_FILENAME: &str = "koi.sock";

/// Unix fallback runtime directory when XDG_RUNTIME_DIR is unset.
#[cfg(unix)]
const UNIX_FALLBACK_RUNTIME_DIR: &str = "/var/run";

#[derive(Parser, Debug)]
#[command(name = "koi", version, about = "Local service discovery for everyone")]
pub struct Cli {
    /// Run in daemon mode (HTTP + IPC adapters)
    #[arg(long)]
    pub daemon: bool,

    /// HTTP API port
    #[arg(long, env = "KOI_PORT", default_value = "5641")]
    pub port: u16,

    /// IPC socket/pipe path (default: platform-specific)
    #[arg(long, env = "KOI_PIPE")]
    pub pipe: Option<PathBuf>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, env = "KOI_LOG", default_value = "info")]
    pub log_level: String,

    /// Increase verbosity (-v = debug, -vv = trace)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Write logs to file (in addition to stderr)
    #[arg(long, env = "KOI_LOG_FILE", value_name = "PATH", global = true)]
    pub log_file: Option<PathBuf>,

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

    /// Daemon endpoint for client/admin mode (e.g. "http://localhost:5641")
    #[arg(long, env = "KOI_ENDPOINT", global = true)]
    pub endpoint: Option<String>,

    /// Force standalone mode (skip daemon detection)
    #[arg(long, global = true)]
    pub standalone: bool,

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
    /// Admin operations on a running daemon
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Show daemon status
    Status,
    /// List all registrations
    #[command(name = "ls")]
    List,
    /// Inspect a registration by ID or prefix
    Inspect {
        /// Registration ID or prefix
        id: String,
    },
    /// Force-unregister a registration
    Unregister {
        /// Registration ID or prefix
        id: String,
    },
    /// Force-drain a registration
    Drain {
        /// Registration ID or prefix
        id: String,
    },
    /// Revive a draining registration
    Revive {
        /// Registration ID or prefix
        id: String,
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

    /// Build config from environment variables only.
    /// Used by service mode where CLI args aren't available.
    /// Reads: KOI_PORT, KOI_PIPE, KOI_NO_HTTP, KOI_NO_IPC.
    pub fn from_env() -> Self {
        let http_port = std::env::var("KOI_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_HTTP_PORT);

        let pipe_path = std::env::var("KOI_PIPE")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(default_pipe_path);

        let no_http = std::env::var("KOI_NO_HTTP")
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let no_ipc = std::env::var("KOI_NO_IPC")
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            http_port,
            pipe_path,
            no_http,
            no_ipc,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_port: DEFAULT_HTTP_PORT,
            pipe_path: default_pipe_path(),
            no_http: false,
            no_ipc: false,
        }
    }
}

// ── Breadcrumb ───────────────────────────────────────────────────────

/// Path to the breadcrumb file that advertises the daemon's endpoint.
pub fn breadcrumb_path() -> PathBuf {
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(local)
            .join(APP_DIR_NAME)
            .join(BREADCRUMB_FILENAME)
    }
    #[cfg(unix)]
    {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join(BREADCRUMB_FILENAME)
        } else {
            PathBuf::from(UNIX_FALLBACK_RUNTIME_DIR).join(BREADCRUMB_FILENAME)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from(BREADCRUMB_FILENAME)
    }
}

/// Write the daemon endpoint to the breadcrumb file.
pub fn write_breadcrumb(endpoint: &str) {
    let path = breadcrumb_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&path, endpoint) {
        Ok(()) => tracing::debug!(path = %path.display(), "Breadcrumb written"),
        Err(e) => tracing::warn!(error = %e, path = %path.display(), "Failed to write breadcrumb"),
    }
}

/// Delete the breadcrumb file.
pub fn delete_breadcrumb() {
    let path = breadcrumb_path();
    match std::fs::remove_file(&path) {
        Ok(()) => tracing::debug!(path = %path.display(), "Breadcrumb deleted"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, path = %path.display(), "Failed to delete breadcrumb"),
    }
}

/// Read the daemon endpoint from the breadcrumb file.
pub fn read_breadcrumb() -> Option<String> {
    std::fs::read_to_string(breadcrumb_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ── Service log paths (Windows) ──────────────────────────────────────

/// Well-known service log directory name under ProgramData.
#[cfg(windows)]
const SERVICE_LOG_DIR: &str = "koi\\logs";

/// Well-known service log filename.
#[cfg(windows)]
const SERVICE_LOG_FILENAME: &str = "koi.log";

/// Returns the well-known log file path for service mode.
/// `%ProgramData%\koi\logs\koi.log`
#[cfg(windows)]
pub fn service_log_path() -> PathBuf {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data)
        .join(SERVICE_LOG_DIR)
        .join(SERVICE_LOG_FILENAME)
}

/// Returns the well-known log directory for service mode.
/// `%ProgramData%\koi\logs\`
#[cfg(windows)]
pub fn service_log_dir() -> PathBuf {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data).join(SERVICE_LOG_DIR)
}

/// Returns the app data directory under ProgramData.
/// `%ProgramData%\koi\`
#[cfg(windows)]
pub fn service_data_dir() -> PathBuf {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data).join(APP_DIR_NAME)
}

// ── Default paths ────────────────────────────────────────────────────

fn default_pipe_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(WINDOWS_PIPE_NAME)
    }
    #[cfg(unix)]
    {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join(UNIX_SOCKET_FILENAME)
        } else {
            PathBuf::from(UNIX_FALLBACK_RUNTIME_DIR).join(UNIX_SOCKET_FILENAME)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from(UNIX_SOCKET_FILENAME)
    }
}
