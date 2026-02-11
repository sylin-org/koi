use clap::{ArgAction, Args, Parser, Subcommand};
use std::path::PathBuf;

/// Default HTTP API port — "KOI" on a phone keypad (K=5, O=6, I=4).
pub const DEFAULT_HTTP_PORT: u16 = 5641;

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

    /// Disable the mDNS capability
    #[arg(long, env = "KOI_NO_MDNS")]
    pub no_mdns: bool,

    /// Disable the certmesh capability
    #[arg(long, env = "KOI_NO_CERTMESH")]
    pub no_certmesh: bool,

    /// Output JSON instead of human-readable text
    #[arg(long, global = true)]
    pub json: bool,

    /// Auto-exit after N seconds (0 = run forever)
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
    /// Show version information
    Version,
    /// Show status of all capabilities
    Status,
    /// mDNS service discovery
    Mdns(MdnsCommand),
    /// Certificate mesh (private CA, enrollment, trust)
    Certmesh(CertmeshCommand),
}

#[derive(Args, Debug)]
pub struct MdnsCommand {
    #[command(subcommand)]
    pub command: MdnsSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum MdnsSubcommand {
    /// Discover services on the local network
    Discover {
        /// Service type (e.g. "http", "_http._tcp"). Omit to discover all types.
        service_type: Option<String>,
    },
    /// Announce (register) a service on the local network
    Announce {
        /// Service instance name
        name: String,
        /// Service type (e.g. "http", "_http._tcp")
        service_type: String,
        /// Port number
        port: u16,
        /// Pin the A record to a specific IP (default: advertise all)
        #[arg(long)]
        ip: Option<String>,
        /// TXT record entries as KEY=VALUE pairs
        #[arg(trailing_var_arg = true)]
        txt: Vec<String>,
    },
    /// Unregister a previously registered service by its ID
    Unregister {
        /// Registration ID returned by the announce command
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
    Admin(MdnsAdminCommand),
}

#[derive(Args, Debug)]
pub struct MdnsAdminCommand {
    #[command(subcommand)]
    pub command: AdminSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum AdminSubcommand {
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

#[derive(Args, Debug)]
pub struct CertmeshCommand {
    #[command(subcommand)]
    pub command: CertmeshSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum CertmeshSubcommand {
    /// Create a new certificate mesh (initializes CA)
    Create {
        /// Trust profile: just-me, team, organization
        #[arg(long)]
        profile: Option<String>,
        /// Operator name (required for team/organization profiles)
        #[arg(long)]
        operator: Option<String>,
        /// Entropy mode: keyboard, passphrase, manual
        #[arg(long, default_value = "passphrase")]
        entropy: String,
        /// Manual passphrase (only used with --entropy=manual)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Join an existing certificate mesh
    Join {
        /// CA endpoint (e.g. "http://ca-host:5641")
        endpoint: String,
    },
    /// Show certificate mesh status
    Status,
    /// Show the audit log
    Log,
    /// Unlock the CA (decrypt key from passphrase)
    Unlock,
}

/// Resolved configuration used at runtime.
pub struct Config {
    pub http_port: u16,
    pub pipe_path: PathBuf,
    pub no_http: bool,
    pub no_ipc: bool,
    pub no_mdns: bool,
    pub no_certmesh: bool,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Self {
        let pipe_path = cli.pipe.clone().unwrap_or_else(default_pipe_path);
        Self {
            http_port: cli.port,
            pipe_path,
            no_http: cli.no_http,
            no_ipc: cli.no_ipc,
            no_mdns: cli.no_mdns,
            no_certmesh: cli.no_certmesh,
        }
    }

    /// Returns an error if the named capability is disabled.
    pub fn require_capability(&self, name: &str) -> anyhow::Result<()> {
        let disabled = match name {
            "mdns" => self.no_mdns,
            "certmesh" => self.no_certmesh,
            _ => false,
        };
        if disabled {
            anyhow::bail!(
                "The '{name}' capability is disabled. \
                 Remove --no-{name} or unset KOI_NO_{} to enable it.",
                name.to_uppercase().replace('-', "_")
            );
        }
        Ok(())
    }

    /// Build config from environment variables only.
    /// Used by service mode where CLI args aren't available.
    #[cfg(windows)]
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

        let no_mdns = std::env::var("KOI_NO_MDNS")
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let no_certmesh = std::env::var("KOI_NO_CERTMESH")
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            http_port,
            pipe_path,
            no_http,
            no_ipc,
            no_mdns,
            no_certmesh,
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
            no_mdns: false,
            no_certmesh: false,
        }
    }
}

// ── Service log paths (Windows) ──────────────────────────────────────

#[cfg(windows)]
const APP_DIR_NAME: &str = "koi";
#[cfg(windows)]
const SERVICE_LOG_DIR: &str = "koi\\logs";
#[cfg(windows)]
const SERVICE_LOG_FILENAME: &str = "koi.log";

#[cfg(windows)]
pub fn service_log_path() -> PathBuf {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data)
        .join(SERVICE_LOG_DIR)
        .join(SERVICE_LOG_FILENAME)
}

#[cfg(windows)]
pub fn service_log_dir() -> PathBuf {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data).join(SERVICE_LOG_DIR)
}

#[cfg(windows)]
pub fn service_data_dir() -> PathBuf {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    PathBuf::from(program_data).join(APP_DIR_NAME)
}

// ── Service paths (Linux/systemd) ────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn unit_file_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/koi.service")
}

#[cfg(target_os = "linux")]
pub fn install_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/koi")
}

// ── Service paths (macOS/launchd) ────────────────────────────────────

#[cfg(target_os = "macos")]
pub fn plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons/org.sylin.koi.plist")
}

#[cfg(target_os = "macos")]
pub fn install_bin_path() -> PathBuf {
    PathBuf::from("/usr/local/bin/koi")
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
