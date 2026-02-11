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
        /// CA endpoint (e.g. "http://ca-host:5641"). Omit to discover via mDNS.
        endpoint: Option<String>,
    },
    /// Show certificate mesh status
    Status,
    /// Show the audit log
    Log,
    /// Unlock the CA (decrypt key from passphrase)
    Unlock,
    /// Set a post-renewal reload hook for this host
    SetHook {
        /// Shell command to run after certificate renewal
        #[arg(long)]
        reload: String,
    },
    /// Promote a member to standby CA (transfers encrypted CA key)
    Promote {
        /// CA endpoint (e.g. "http://ca-host:5641"). Omit to discover via mDNS.
        endpoint: Option<String>,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Config::require_capability tests ─────────────────────────────

    #[test]
    fn require_capability_passes_when_enabled() {
        let config = Config::default();
        assert!(config.require_capability("mdns").is_ok());
        assert!(config.require_capability("certmesh").is_ok());
    }

    #[test]
    fn require_capability_fails_when_mdns_disabled() {
        let config = Config {
            no_mdns: true,
            ..Config::default()
        };
        let result = config.require_capability("mdns");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("mdns"), "error message should mention 'mdns': {msg}");
        assert!(msg.contains("disabled"), "error message should mention 'disabled': {msg}");
    }

    #[test]
    fn require_capability_fails_when_certmesh_disabled() {
        let config = Config {
            no_certmesh: true,
            ..Config::default()
        };
        let result = config.require_capability("certmesh");
        assert!(result.is_err());
    }

    #[test]
    fn require_capability_unknown_name_passes() {
        let config = Config::default();
        assert!(config.require_capability("unknown").is_ok());
    }

    // ── Config::default tests ────────────────────────────────────────

    #[test]
    fn config_default_values() {
        let config = Config::default();
        assert_eq!(config.http_port, DEFAULT_HTTP_PORT);
        assert!(!config.no_http);
        assert!(!config.no_ipc);
        assert!(!config.no_mdns);
        assert!(!config.no_certmesh);
    }

    #[test]
    fn default_http_port_is_5641() {
        assert_eq!(DEFAULT_HTTP_PORT, 5641);
    }

    // ── CLI parsing tests ───────────────────────────────────────────

    #[test]
    fn parse_certmesh_promote_no_endpoint() {
        let cli = Cli::try_parse_from(["koi", "certmesh", "promote"]).unwrap();
        match cli.command {
            Some(Command::Certmesh(CertmeshCommand {
                command: CertmeshSubcommand::Promote { endpoint },
            })) => {
                assert!(endpoint.is_none());
            }
            other => panic!("Expected Certmesh Promote, got: {other:?}"),
        }
    }

    #[test]
    fn parse_certmesh_promote_with_endpoint() {
        let cli =
            Cli::try_parse_from(["koi", "certmesh", "promote", "http://ca:5641"]).unwrap();
        match cli.command {
            Some(Command::Certmesh(CertmeshCommand {
                command: CertmeshSubcommand::Promote { endpoint },
            })) => {
                assert_eq!(endpoint.as_deref(), Some("http://ca:5641"));
            }
            other => panic!("Expected Certmesh Promote, got: {other:?}"),
        }
    }

    #[test]
    fn parse_certmesh_set_hook() {
        let cli = Cli::try_parse_from([
            "koi",
            "certmesh",
            "set-hook",
            "--reload",
            "systemctl restart nginx",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Certmesh(CertmeshCommand {
                command: CertmeshSubcommand::SetHook { reload },
            })) => {
                assert_eq!(reload, "systemctl restart nginx");
            }
            other => panic!("Expected Certmesh SetHook, got: {other:?}"),
        }
    }

    #[test]
    fn parse_certmesh_create_with_all_options() {
        let cli = Cli::try_parse_from([
            "koi",
            "certmesh",
            "create",
            "--profile",
            "team",
            "--operator",
            "ops",
            "--entropy",
            "manual",
            "--passphrase",
            "my-secret",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Certmesh(CertmeshCommand {
                command:
                    CertmeshSubcommand::Create {
                        profile,
                        operator,
                        entropy,
                        passphrase,
                    },
            })) => {
                assert_eq!(profile.as_deref(), Some("team"));
                assert_eq!(operator.as_deref(), Some("ops"));
                assert_eq!(entropy, "manual");
                assert_eq!(passphrase.as_deref(), Some("my-secret"));
            }
            other => panic!("Expected Certmesh Create, got: {other:?}"),
        }
    }

    #[test]
    fn parse_global_json_flag() {
        let cli = Cli::try_parse_from(["koi", "--json", "certmesh", "status"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn parse_global_endpoint_flag() {
        let cli = Cli::try_parse_from([
            "koi",
            "--endpoint",
            "http://localhost:5641",
            "certmesh",
            "status",
        ])
        .unwrap();
        assert_eq!(
            cli.endpoint.as_deref(),
            Some("http://localhost:5641")
        );
    }

    // ── mDNS CLI parsing tests ──────────────────────────────────────

    #[test]
    fn parse_mdns_discover_no_type() {
        let cli = Cli::try_parse_from(["koi", "mdns", "discover"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Discover { service_type },
            })) => {
                assert!(service_type.is_none());
            }
            other => panic!("Expected Mdns Discover, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_discover_with_type() {
        let cli = Cli::try_parse_from(["koi", "mdns", "discover", "_http._tcp"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Discover { service_type },
            })) => {
                assert_eq!(service_type.as_deref(), Some("_http._tcp"));
            }
            other => panic!("Expected Mdns Discover, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_announce_all_args() {
        let cli = Cli::try_parse_from([
            "koi", "mdns", "announce", "My App", "_http._tcp", "8080",
            "--ip", "10.0.0.1", "version=1.0", "env=prod",
        ]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Announce { name, service_type, port, ip, txt },
            })) => {
                assert_eq!(name, "My App");
                assert_eq!(service_type, "_http._tcp");
                assert_eq!(port, 8080);
                assert_eq!(ip.as_deref(), Some("10.0.0.1"));
                assert_eq!(txt, vec!["version=1.0", "env=prod"]);
            }
            other => panic!("Expected Mdns Announce, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_announce_minimal() {
        let cli = Cli::try_parse_from([
            "koi", "mdns", "announce", "Svc", "_ssh._tcp", "22",
        ]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Announce { name, service_type, port, ip, txt },
            })) => {
                assert_eq!(name, "Svc");
                assert_eq!(service_type, "_ssh._tcp");
                assert_eq!(port, 22);
                assert!(ip.is_none());
                assert!(txt.is_empty());
            }
            other => panic!("Expected Mdns Announce, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_unregister() {
        let cli = Cli::try_parse_from(["koi", "mdns", "unregister", "abc12345"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Unregister { id },
            })) => {
                assert_eq!(id, "abc12345");
            }
            other => panic!("Expected Mdns Unregister, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_resolve() {
        let cli = Cli::try_parse_from([
            "koi", "mdns", "resolve", "My Server._http._tcp.local.",
        ]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Resolve { instance },
            })) => {
                assert_eq!(instance, "My Server._http._tcp.local.");
            }
            other => panic!("Expected Mdns Resolve, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_subscribe() {
        let cli = Cli::try_parse_from(["koi", "mdns", "subscribe", "_http._tcp"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Subscribe { service_type },
            })) => {
                assert_eq!(service_type, "_http._tcp");
            }
            other => panic!("Expected Mdns Subscribe, got: {other:?}"),
        }
    }

    // ── Admin subcommand parsing ────────────────────────────────────

    #[test]
    fn parse_mdns_admin_status() {
        let cli = Cli::try_parse_from(["koi", "mdns", "admin", "status"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Admin(MdnsAdminCommand {
                    command: AdminSubcommand::Status,
                }),
            })) => {}
            other => panic!("Expected Admin Status, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_admin_ls() {
        let cli = Cli::try_parse_from(["koi", "mdns", "admin", "ls"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Admin(MdnsAdminCommand {
                    command: AdminSubcommand::List,
                }),
            })) => {}
            other => panic!("Expected Admin List, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_admin_inspect() {
        let cli = Cli::try_parse_from(["koi", "mdns", "admin", "inspect", "a1b2c3"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Admin(MdnsAdminCommand {
                    command: AdminSubcommand::Inspect { id },
                }),
            })) => {
                assert_eq!(id, "a1b2c3");
            }
            other => panic!("Expected Admin Inspect, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_admin_unregister() {
        let cli = Cli::try_parse_from(["koi", "mdns", "admin", "unregister", "xyz"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Admin(MdnsAdminCommand {
                    command: AdminSubcommand::Unregister { id },
                }),
            })) => {
                assert_eq!(id, "xyz");
            }
            other => panic!("Expected Admin Unregister, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_admin_drain() {
        let cli = Cli::try_parse_from(["koi", "mdns", "admin", "drain", "abc"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Admin(MdnsAdminCommand {
                    command: AdminSubcommand::Drain { id },
                }),
            })) => {
                assert_eq!(id, "abc");
            }
            other => panic!("Expected Admin Drain, got: {other:?}"),
        }
    }

    #[test]
    fn parse_mdns_admin_revive() {
        let cli = Cli::try_parse_from(["koi", "mdns", "admin", "revive", "def"]).unwrap();
        match cli.command {
            Some(Command::Mdns(MdnsCommand {
                command: MdnsSubcommand::Admin(MdnsAdminCommand {
                    command: AdminSubcommand::Revive { id },
                }),
            })) => {
                assert_eq!(id, "def");
            }
            other => panic!("Expected Admin Revive, got: {other:?}"),
        }
    }

    // ── Global flags with mDNS ──────────────────────────────────────

    #[test]
    fn parse_mdns_with_timeout() {
        let cli = Cli::try_parse_from([
            "koi", "--timeout", "30", "mdns", "discover",
        ]).unwrap();
        assert_eq!(cli.timeout, Some(30));
    }

    #[test]
    fn parse_mdns_with_json_flag() {
        let cli = Cli::try_parse_from(["koi", "--json", "mdns", "subscribe", "_http._tcp"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn parse_mdns_with_verbose() {
        let cli = Cli::try_parse_from(["koi", "-vv", "mdns", "discover"]).unwrap();
        assert_eq!(cli.verbose, 2);
    }

    // ── Top-level commands ──────────────────────────────────────────

    #[test]
    fn parse_daemon_flag() {
        let cli = Cli::try_parse_from(["koi", "--daemon"]).unwrap();
        assert!(cli.daemon);
    }

    #[test]
    fn parse_no_subcommand() {
        let cli = Cli::try_parse_from(["koi"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn parse_version_subcommand() {
        let cli = Cli::try_parse_from(["koi", "version"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Version)));
    }

    #[test]
    fn parse_status_subcommand() {
        let cli = Cli::try_parse_from(["koi", "status"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Status)));
    }

    #[test]
    fn parse_install_subcommand() {
        let cli = Cli::try_parse_from(["koi", "install"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Install)));
    }

    #[test]
    fn parse_standalone_flag() {
        let cli = Cli::try_parse_from(["koi", "--standalone", "mdns", "discover"]).unwrap();
        assert!(cli.standalone);
    }

    // ── require_capability edge cases ───────────────────────────────

    #[test]
    fn require_capability_error_message_includes_env_var_hint() {
        let config = Config {
            no_mdns: true,
            ..Config::default()
        };
        let msg = config.require_capability("mdns").unwrap_err().to_string();
        assert!(
            msg.contains("KOI_NO_MDNS"),
            "error should mention env var: {msg}"
        );
    }

    #[test]
    fn require_capability_mdns_enabled_certmesh_disabled_mdns_works() {
        let config = Config {
            no_certmesh: true,
            ..Config::default()
        };
        assert!(config.require_capability("mdns").is_ok());
        assert!(config.require_capability("certmesh").is_err());
    }

    #[test]
    fn config_default_pipe_path_is_not_empty() {
        let config = Config::default();
        assert!(
            config.pipe_path.components().count() > 0,
            "pipe path should not be empty"
        );
    }
}
