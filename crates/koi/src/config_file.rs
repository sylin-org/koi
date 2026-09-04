//! Versioned TOML config file (ADR-031 §Config substrate).
//!
//! The file may express only what CLI flags already express — it introduces no
//! new semantics. Precedence is **CLI flag > env var > config file > built-in
//! default**, implemented by writing file values only where the parsed arg's
//! source is `DefaultValue` (i.e., neither flag nor env provided it).
//!
//! Unknown keys are a loud startup error (typo protection), matching the
//! ADR-028 manifest precedent. Secrets do not belong in this file.

use std::path::{Path, PathBuf};

use clap::parser::ValueSource;
use clap::ArgMatches;
use serde::Deserialize;

pub const CONFIG_VERSION: u32 = 1;

/// The documented, commented template written by `koi config init`.
pub const TEMPLATE: &str = r#"# Koi daemon configuration (ADR-031).
# Precedence: CLI flag > environment variable > this file > built-in default.
# Every key below is shown commented at its built-in default value.
version = 1

# HTTP API / dashboard port and bind mode:
#   loopback (default) | bridge | <ip> | 0.0.0.0
#port = 5641
#http_bind = "loopback"
#announce_http = false

# Inter-node mTLS and ACME ports.
#mtls_port = 5642
#acme_port = 5643

# Certmesh: disable entirely with no_certmesh = true.
#no_certmesh = false

# DNS zone serving (requires --dns-public equivalent to answer for other hosts).
#no_dns = false
#dns_port = 53
#dns_zone = "internal"
#dns_public = false
#dns_qps = 200

# mDNS discovery (skips automatically when another stack holds 5353 - ADR-030).
#no_mdns = false

# Health checks.
#no_health = false

# TLS proxy.
#no_proxy = false

# UDP bridge.
#no_udp = false

# Container runtime adapter ("auto" | "docker" | "none").
#no_runtime = false
#runtime = "auto"

# Unix-socket / named-pipe IPC adapter.
#no_ipc = false

# MCP transports: loopback HTTP and the mTLS management plane (ADR-026).
#no_mcp_http = false
#no_mgmt_mcp = false

# Outbound webhook fan-out (ADR-028): manifest path, or hard-disable.
#webhooks_manifest = "/etc/koi/webhooks.json"
#no_webhooks = false
"#;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub version: u32,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub http_bind: Option<String>,
    #[serde(default)]
    pub announce_http: Option<bool>,
    #[serde(default)]
    pub mtls_port: Option<u16>,
    #[serde(default)]
    pub acme_port: Option<u16>,
    #[serde(default)]
    pub no_acme: Option<bool>,
    #[serde(default)]
    pub dns_port: Option<u16>,
    #[serde(default)]
    pub dns_zone: Option<String>,
    #[serde(default)]
    pub dns_public: Option<bool>,
    #[serde(default)]
    pub dns_qps: Option<u32>,
    #[serde(default)]
    pub no_dns: Option<bool>,
    #[serde(default)]
    pub no_mdns: Option<bool>,
    #[serde(default)]
    pub no_health: Option<bool>,
    #[serde(default)]
    pub no_proxy: Option<bool>,
    #[serde(default)]
    pub no_udp: Option<bool>,
    #[serde(default)]
    pub no_runtime: Option<bool>,
    #[serde(default)]
    pub runtime: Option<String>,
    #[serde(default)]
    pub no_ipc: Option<bool>,
    #[serde(default)]
    pub no_certmesh: Option<bool>,
    #[serde(default)]
    pub no_http: Option<bool>,
    #[serde(default)]
    pub no_mcp_http: Option<bool>,
    #[serde(default)]
    pub no_mgmt_mcp: Option<bool>,
    #[serde(default)]
    pub webhooks_manifest: Option<PathBuf>,
    #[serde(default)]
    pub no_webhooks: Option<bool>,
}

/// Platform default location: `%PROGRAMDATA%\koi\config.toml` on Windows,
/// `$XDG_CONFIG_HOME|$HOME/.config` + `/koi/config.toml` elsewhere.
pub fn default_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(pd) = std::env::var_os("PROGRAMDATA") {
            return PathBuf::from(pd).join("koi").join("config.toml");
        }
        PathBuf::from("C:\\ProgramData\\koi\\config.toml")
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(xdg).join("koi").join("config.toml");
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".config").join("koi").join("config.toml")
    }
}

/// Resolve which file governs this run: explicit `--config <path>` wins and
/// must exist; otherwise the platform default when present.
pub fn discover(explicit: Option<&Path>) -> Result<Option<PathBuf>, String> {
    match explicit {
        Some(p) => {
            if !p.exists() {
                return Err(format!("--config {}: file does not exist", p.display()));
            }
            Ok(Some(p.to_path_buf()))
        }
        None => {
            let p = default_path();
            Ok(p.exists().then_some(p))
        }
    }
}

/// Parse + validate a config file body. Unknown keys fail loudly; a wrong
/// `version` fails loudly with the supported version named.
pub fn parse(body: &str) -> Result<FileConfig, String> {
    let mut root: toml::Table =
        toml::from_str(body).map_err(|e| format!("invalid config file: {e}"))?;
    if let Some(proxy) = root.remove("proxy") {
        let _: koi_proxy::ProxyConfig = proxy
            .try_into()
            .map_err(|e| format!("invalid config file: {e}"))?;
    }
    let cfg: FileConfig = toml::Value::Table(root)
        .try_into()
        .map_err(|e| format!("invalid config file: {e}"))?;
    if cfg.version != CONFIG_VERSION {
        return Err(format!(
            "unsupported config version {} (supported: {CONFIG_VERSION})",
            cfg.version
        ));
    }
    Ok(cfg)
}

/// Load from `path`, or `None` when absent (explicit paths already validated).
pub fn load(path: &Path) -> Result<Option<FileConfig>, String> {
    match std::fs::read_to_string(path) {
        Ok(body) => parse(&body).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read config {}: {e}", path.display())),
    }
}

/// Write the documented template. Refuses to clobber an existing file unless
/// `force` — operator config is never silently destroyed.
pub fn init(path: &Path, force: bool) -> Result<PathBuf, String> {
    if path.exists() && !force {
        return Err(format!(
            "{} already exists; pass --force to overwrite",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, TEMPLATE).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path.to_path_buf())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionPathSource {
    Explicit,
    ActiveDaemon,
    InvocationDefault,
}

struct ActionPath {
    path: PathBuf,
    source: ActionPathSource,
}

fn select_action_path(
    explicit: Option<PathBuf>,
    active_daemon: Option<PathBuf>,
    invocation_default: PathBuf,
) -> ActionPath {
    if let Some(path) = explicit {
        return ActionPath {
            path,
            source: ActionPathSource::Explicit,
        };
    }
    if let Some(path) = active_daemon {
        return ActionPath {
            path,
            source: ActionPathSource::ActiveDaemon,
        };
    }
    ActionPath {
        path: invocation_default,
        source: ActionPathSource::InvocationDefault,
    }
}

fn resolve_action_path(explicit: Option<&Path>) -> anyhow::Result<ActionPath> {
    let explicit = match explicit {
        Some(path) => discover(Some(path)).map_err(anyhow::Error::msg)?,
        None => None,
    };
    let active_daemon = if explicit.is_none() {
        match koi_client::observe_local_daemon_info() {
            koi_client::LocalDaemonObservation::Present(info) => {
                Some(PathBuf::from(info.config_path))
            }
            koi_client::LocalDaemonObservation::Absent => None,
            koi_client::LocalDaemonObservation::Uncertain(error) => {
                anyhow::bail!(
                    "cannot determine the active daemon config path: {error}. Pass --config explicitly or repair local service discovery"
                )
            }
        }
    } else {
        None
    };
    Ok(select_action_path(explicit, active_daemon, default_path()))
}

/// Execute `koi config init|show|path`.
pub fn run_action(
    action: &crate::cli::ConfigAction,
    explicit: Option<&Path>,
) -> anyhow::Result<()> {
    use crate::cli::ConfigAction;
    match action {
        ConfigAction::Init { force } => {
            let path = match explicit {
                Some(p) => p.to_path_buf(),
                None => default_path(),
            };
            let written = init(&path, *force).map_err(|e| anyhow::anyhow!(e))?;
            println!("Wrote {}", written.display());
        }
        ConfigAction::Show => {
            let resolved = resolve_action_path(explicit)?;
            match std::fs::read_to_string(&resolved.path) {
                Ok(body) => {
                    println!("# {}", resolved.path.display());
                    print!("{body}");
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let label = match resolved.source {
                        ActionPathSource::ActiveDaemon => "active daemon location",
                        ActionPathSource::InvocationDefault => "default location",
                        ActionPathSource::Explicit => {
                            anyhow::bail!(
                                "--config {} disappeared before it could be read",
                                resolved.path.display()
                            )
                        }
                    };
                    println!("none ({label}: {})", resolved.path.display());
                }
                Err(error) => anyhow::bail!("cannot read {}: {error}", resolved.path.display()),
            }
        }
        ConfigAction::Path => {
            println!("{}", resolve_action_path(explicit)?.path.display());
        }
    }
    Ok(())
}

/// Apply file values onto the resolved config where BOTH the CLI arg and its
/// env var were absent (source == `DefaultValue`) — the ADR-031 precedence
/// **CLI > env > file > default** in one rule per key.
pub fn apply(file: &FileConfig, matches: &ArgMatches, config: &mut crate::cli::Config) {
    macro_rules! set {
        ($id:literal, $src:expr, $dst:expr) => {
            if matches.value_source($id) == Some(ValueSource::DefaultValue) {
                if let Some(v) = $src.clone() {
                    $dst = v;
                }
            }
        };
    }
    let file_cfg = file;
    set!("port", file_cfg.port, config.http_port);
    set!("http_bind", file_cfg.http_bind, config.http_bind);
    set!(
        "announce_http",
        file_cfg.announce_http,
        config.announce_http
    );
    set!("mtls_port", file_cfg.mtls_port, config.mtls_port);
    set!("acme_port", file_cfg.acme_port, config.acme_port);
    set!("no_acme", file_cfg.no_acme, config.no_acme);
    set!("dns_port", file_cfg.dns_port, config.dns_port);
    set!("dns_zone", file_cfg.dns_zone, config.dns_zone);
    set!("dns_public", file_cfg.dns_public, config.dns_public);
    set!("dns_qps", file_cfg.dns_qps, config.dns_qps);
    set!("no_dns", file_cfg.no_dns, config.no_dns);
    set!("no_mdns", file_cfg.no_mdns, config.no_mdns);
    set!("no_health", file_cfg.no_health, config.no_health);
    set!("no_proxy", file_cfg.no_proxy, config.no_proxy);
    set!("no_udp", file_cfg.no_udp, config.no_udp);
    set!("no_runtime", file_cfg.no_runtime, config.no_runtime);
    set!("runtime", file_cfg.runtime, config.runtime);
    set!("no_ipc", file_cfg.no_ipc, config.no_ipc);
    set!("no_certmesh", file_cfg.no_certmesh, config.no_certmesh);
    set!("no_http", file_cfg.no_http, config.no_http);
    set!("no_mcp_http", file_cfg.no_mcp_http, config.no_mcp_http);
    set!("no_mgmt_mcp", file_cfg.no_mgmt_mcp, config.no_mgmt_mcp);
    set!("no_webhooks", file_cfg.no_webhooks, config.no_webhooks);
    // Option-valued target: replace wholesale, never unwrap.
    if matches.value_source("webhooks_manifest") == Some(ValueSource::DefaultValue)
        && file.webhooks_manifest.is_some()
    {
        config.webhooks_manifest = file.webhooks_manifest.clone();
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parses_and_is_versioned() {
        let cfg = parse(TEMPLATE).expect("template must parse");
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert!(cfg.port.is_none(), "template keys stay commented");
    }

    #[test]
    fn fully_populated_file_parses_every_key() {
        // Guards the key set: every supported key present at once.
        let body = r#"
version = 1
port = 6001
http_bind = "bridge"
announce_http = true
mtls_port = 6002
acme_port = 6003
no_acme = true
dns_port = 5311
dns_zone = "lan"
dns_public = true
dns_qps = 111
no_dns = true
no_mdns = true
no_health = true
no_proxy = true
no_udp = true
no_runtime = true
runtime = "docker"
no_ipc = true
no_certmesh = true
no_http = true
no_mcp_http = true
no_mgmt_mcp = true
webhooks_manifest = "/tmp/w.json"
no_webhooks = true
"#;
        let cfg = parse(body).expect("full file parses");
        assert_eq!(cfg.port, Some(6001));
        assert_eq!(cfg.runtime.as_deref(), Some("docker"));
        assert_eq!(cfg.webhooks_manifest, Some(PathBuf::from("/tmp/w.json")));
    }

    #[test]
    fn unknown_keys_are_a_loud_error() {
        let err = parse("version = 1\nno_such_key = true\n").unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn proxy_owned_section_parses_without_weakening_top_level_validation() {
        parse(
            r#"
version = 1

[proxy]
entries = [
  { name = "dashboard", listen_port = 8443, backend = "127.0.0.1:3000" },
]
"#,
        )
        .expect("the proxy-owned section written by koi-proxy must remain launchable");

        let err = parse("version = 1\n[proxy]\nunknown = true\n").unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn wrong_version_is_a_loud_error() {
        let err = parse("version = 99\n").unwrap_err();
        assert!(err.contains("unsupported config version"), "{err}");
    }

    #[test]
    fn init_writes_then_refuses_without_force() {
        let dir = koi_common::test::ensure_data_dir("koi-config-file-tests");
        let path = dir.join("init-roundtrip.toml");
        let _ = std::fs::remove_file(&path);
        init(&path, false).expect("first init");
        assert!(init(&path, false).is_err(), "second init refuses");
        assert!(load(&path).is_ok(), "written template loads");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn action_path_precedence_is_explicit_then_daemon_then_default() {
        let explicit = PathBuf::from("/explicit/config.toml");
        let daemon = PathBuf::from("/service/config.toml");
        let fallback = PathBuf::from("/user/config.toml");

        let selected = select_action_path(
            Some(explicit.clone()),
            Some(daemon.clone()),
            fallback.clone(),
        );
        assert_eq!(selected.path, explicit);
        assert_eq!(selected.source, ActionPathSource::Explicit);

        let selected = select_action_path(None, Some(daemon.clone()), fallback.clone());
        assert_eq!(selected.path, daemon);
        assert_eq!(selected.source, ActionPathSource::ActiveDaemon);

        let selected = select_action_path(None, None, fallback.clone());
        assert_eq!(selected.path, fallback);
        assert_eq!(selected.source, ActionPathSource::InvocationDefault);
    }
}
