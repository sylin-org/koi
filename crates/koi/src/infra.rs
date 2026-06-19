//! Infrastructure helpers — stdin/tty checks, help rendering, the shutdown signal, startup
//! diagnostics, HTTP-bind resolution, the breadcrumb endpoint, and logging setup. Moved from
//! main.rs (P07 step 6b).

use clap::CommandFactory;
use tokio_util::sync::CancellationToken;

use crate::cli::{Cli, Config};
use crate::{help, platform};

// ── Infrastructure helpers ──────────────────────────────────────────

/// Check if stdin is piped (not a terminal).
pub(crate) fn is_piped_stdin() -> bool {
    use std::io::IsTerminal;
    !std::io::stdin().is_terminal()
}

/// Print the top-level help (command list) without exiting with an error.
pub(crate) fn print_top_level_help(api_endpoint: &str) {
    if let Err(err) = help::print_catalog(api_endpoint) {
        tracing::debug!(error = %err, "Failed to render catalog, falling back to clap help");
        // Clap prints to stdout by default; ignore errors because help display should be best-effort
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        println!();
    }
}

/// Extract a command name from `?`-suffixed args.
///
/// Supports:
/// - `["certmesh", "backup?"]` → `"certmesh backup"`
/// - `["backup?"]`             → `"backup"`
/// - `["?certmesh"]`           → `"certmesh"`  (leading ? also works)
///
/// Returns `None` if no `?` query was detected.
pub(crate) fn extract_help_query(raw_args: &[String]) -> Option<String> {
    if raw_args.is_empty() {
        return None;
    }

    // Check if the last arg ends with '?'
    if let Some(last) = raw_args.last() {
        if last.ends_with('?') && last.len() > 1 {
            let mut parts: Vec<&str> = raw_args[..raw_args.len() - 1]
                .iter()
                .map(|s| s.as_str())
                .collect();
            let trimmed = last.trim_end_matches('?');
            if !trimmed.is_empty() {
                parts.push(trimmed);
            }
            // Skip global flags like --json, --verbose etc.
            let parts: Vec<&str> = parts.into_iter().filter(|p| !p.starts_with('-')).collect();
            if !parts.is_empty() {
                return Some(parts.join(" "));
            }
        }
    }

    // Check if the first arg starts with '?'
    if let Some(first) = raw_args.first() {
        if first.starts_with('?') && first.len() > 1 {
            let cmd_name = first.trim_start_matches('?');
            // Remaining args joined
            let mut parts = vec![cmd_name];
            for arg in &raw_args[1..] {
                if !arg.starts_with('-') {
                    parts.push(arg);
                }
            }
            return Some(parts.join(" "));
        }
    }

    None
}

/// Wait for Ctrl+C or platform-specific shutdown signal.
pub(crate) async fn shutdown_signal(cancel: CancellationToken) {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "Failed to listen for Ctrl+C");
            }
        }
        _ = cancel.cancelled() => {
            // Admin shutdown endpoint requests a cancel.
        }
    }
}

// ── Daemon startup diagnostics ──────────────────────────────────────

pub(crate) fn startup_diagnostics(config: &Config, http_bind_ip: Option<std::net::IpAddr>) {
    tracing::info!("Koi v{} starting", env!("CARGO_PKG_VERSION"));
    tracing::info!("Platform: {}", std::env::consts::OS);

    match hostname::get() {
        Ok(h) => tracing::info!("Hostname: {}", h.to_string_lossy()),
        Err(e) => tracing::warn!(error = %e, "Could not determine hostname"),
    }

    if config.no_mdns {
        tracing::info!("mDNS capability: disabled");
    } else {
        tracing::info!("mDNS engine: mdns-sd");
    }

    if config.no_certmesh {
        tracing::info!("Certmesh capability: disabled");
    }

    if config.no_dns {
        tracing::info!("DNS capability: disabled");
    } else {
        tracing::info!(
            "DNS: {}:{} (zone {})",
            "0.0.0.0",
            config.dns_port,
            config.dns_zone
        );
    }

    if config.no_health {
        tracing::info!("Health capability: disabled");
    } else {
        tracing::info!("Health: service checks enabled");
    }

    if config.no_proxy {
        tracing::info!("Proxy capability: disabled");
    }

    if let Some(bind_ip) = http_bind_ip {
        log_http_bind(config, bind_ip);
    } else {
        tracing::info!("HTTP adapter: disabled");
    }

    if !config.no_ipc {
        tracing::info!("IPC: {}", config.pipe_path.display());
    } else {
        tracing::info!("IPC adapter: disabled");
    }

    #[cfg(windows)]
    platform::windows::check_firewall(config);
}

// ── HTTP bind resolution ────────────────────────────────────────────

/// Emits the HTTP bind log line(s) with mode-appropriate exposure warnings.
/// Loopback is quiet; non-loopback binds are loud and always note that
/// mutations still require the daemon token (charter principle 5).
fn log_http_bind(config: &Config, bind_ip: std::net::IpAddr) {
    let port = config.http_port;

    if bind_ip.is_loopback() {
        tracing::info!("HTTP: {bind_ip}:{port} (loopback only — use --http-bind to expose)");
        return;
    }

    if bind_ip.is_unspecified() {
        tracing::warn!(
            "WARNING: Koi is reachable from your entire LAN. Mutations still require the \
             daemon token; GET endpoints are readable by any device. (--http-bind 0.0.0.0)"
        );
        tracing::info!("HTTP: {bind_ip}:{port} (exposed) — mutations require x-koi-token");
    } else if config.http_bind == "bridge" {
        tracing::info!("HTTP: {bind_ip}:{port} (docker bridge) — mutations require x-koi-token");
    } else {
        tracing::warn!(
            "WARNING: Koi is reachable on interface {bind_ip}. Mutations still require the \
             daemon token; GET endpoints are readable by any device. (--http-bind {})",
            config.http_bind
        );
        tracing::info!("HTTP: {bind_ip}:{port} (exposed) — mutations require x-koi-token");
    }
    tracing::info!("hint: containers read the token from a mounted secret; see `koi token --help`");
}

/// Builds the breadcrumb endpoint clients connect to. An unspecified bind
/// (0.0.0.0) is advertised as loopback since clients need a routable address.
pub(crate) fn breadcrumb_endpoint(http_bind_ip: Option<std::net::IpAddr>, port: u16) -> String {
    match http_bind_ip {
        Some(ip) if !ip.is_unspecified() => format!("http://{ip}:{port}"),
        _ => format!("http://127.0.0.1:{port}"),
    }
}

/// Advertise the in-process MCP HTTP endpoint on the LAN, gated on the transport.
///
/// Publishes EXACTLY ONE `_mcp._tcp` mDNS record per host (the daemon — never one
/// per service, which would flood the link) advertising the endpoint, plus an
/// in-zone `_mcp.<host>.<zone>` unicast TXT when DNS serves the zone. Returns the
/// mDNS registration id (the record is withdrawn by the mDNS goodbye on shutdown).
/// No-op when the transport is disabled or mDNS is absent. Shared by the foreground
/// daemon and the Windows service so the two never diverge.
pub(crate) fn announce_mcp_endpoint(
    cores: &crate::DaemonCores,
    http_port: u16,
    dns_zone: &str,
    enabled: bool,
) -> Option<String> {
    if !enabled {
        return None;
    }
    let hostname = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    // Unicast in-zone descriptor (only meaningful when DNS serves the zone).
    if let Some(ref dns) = cores.dns {
        let name = format!("_mcp.{hostname}.{dns_zone}");
        dns.core()
            .add_txt(&name, "transport=streamable-http;path=/v1/mcp");
        tracing::debug!(name = %name, "published in-zone MCP TXT descriptor");
    }

    // One `_mcp._tcp` record per host. TXT vocabulary matches what koi-mcp's own
    // `mcp_servers_on_lan` tool reads back (transport=/path=/name=).
    let mdns = cores.mdns.as_ref()?;
    let mut txt = std::collections::HashMap::new();
    txt.insert("transport".to_string(), "streamable-http".to_string());
    txt.insert("path".to_string(), "/v1/mcp".to_string());
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt.insert("name".to_string(), format!("Koi MCP ({hostname})"));
    let payload = koi_mdns::protocol::RegisterPayload {
        name: format!("Koi MCP ({hostname})"),
        service_type: "_mcp._tcp".to_string(),
        port: http_port,
        ip: None,
        lease_secs: None,
        txt,
    };
    match mdns.register(payload) {
        Ok(result) => {
            tracing::info!(id = %result.id, port = http_port, "MCP endpoint announced via mDNS (_mcp._tcp)");
            Some(result.id)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to announce MCP endpoint via mDNS");
            None
        }
    }
}

/// Advertise the certmesh CA on the LAN with its fingerprint in TXT (ADR-017 F12).
///
/// Publishes EXACTLY ONE `_certmesh._tcp` mDNS record (on the HTTP port, where the
/// CA serves `/status` and `/trust-bundle`) with `fp=<ca_fingerprint>` in TXT. A
/// joiner discovers this and cross-checks the fingerprint against the one carried
/// in its invite (F3) — a **convenience hint** to disambiguate / fail fast, never
/// a trust source (the authoritative check is the joiner's pinned-fingerprint
/// preflight). No-op when certmesh is absent or no CA is initialized. The record is
/// withdrawn by the mDNS goodbye on shutdown. Shared by the foreground daemon and
/// the Windows service so the two never diverge.
pub(crate) async fn announce_certmesh_endpoint(
    cores: &crate::DaemonCores,
    http_port: u16,
) -> Option<String> {
    let certmesh = cores.certmesh.as_ref()?;
    let mdns = cores.mdns.as_ref()?;
    // Only advertise once a CA exists — the fingerprint is the whole point of the
    // record. An uninitialized node has nothing to advertise.
    let fingerprint = certmesh.ca_fingerprint().await?;

    let hostname = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let mut txt = std::collections::HashMap::new();
    txt.insert("fp".to_string(), fingerprint.clone());
    txt.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    txt.insert("name".to_string(), format!("Koi CA ({hostname})"));
    let payload = koi_mdns::protocol::RegisterPayload {
        name: format!("Koi CA ({hostname})"),
        service_type: koi_certmesh::CERTMESH_SERVICE_TYPE.to_string(),
        port: http_port,
        ip: None,
        lease_secs: None,
        txt,
    };
    match mdns.register(payload) {
        Ok(result) => {
            tracing::info!(id = %result.id, port = http_port, fp = %fingerprint, "Certmesh CA announced via mDNS (_certmesh._tcp)");
            Some(result.id)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to announce certmesh CA via mDNS");
            None
        }
    }
}

/// Resolves the `--http-bind` mode string to a concrete bind address:
/// `loopback` → 127.0.0.1, `0.0.0.0` → all interfaces, `bridge` → the
/// docker/podman bridge IPv4 (errors if none), `<ip>` → parsed literally.
pub(crate) fn resolve_http_bind_ip(mode: &str) -> anyhow::Result<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr};
    match mode {
        "loopback" => Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "0.0.0.0" => Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        "bridge" => resolve_bridge_ip(),
        other => other.parse::<IpAddr>().map_err(|_| {
            anyhow::anyhow!(
                "invalid --http-bind value '{other}': expected loopback, bridge, \
                 an IP address, or 0.0.0.0"
            )
        }),
    }
}

/// Finds the IPv4 address of the local docker/podman bridge interface.
fn resolve_bridge_ip() -> anyhow::Result<std::net::IpAddr> {
    use std::net::IpAddr;
    let ifaces = if_addrs::get_if_addrs()
        .map_err(|e| anyhow::anyhow!("could not enumerate network interfaces: {e}"))?;

    let is_v4 = |iface: &if_addrs::Interface| matches!(iface.addr.ip(), IpAddr::V4(_));

    // Prefer well-known bridge interface names…
    for name in ["docker0", "podman0", "cni-podman0"] {
        if let Some(iface) = ifaces.iter().find(|i| i.name == name && is_v4(i)) {
            return Ok(iface.addr.ip());
        }
    }
    // …then common bridge name prefixes (user-defined docker networks are `br-*`).
    for iface in &ifaces {
        if iface.is_loopback() || !is_v4(iface) {
            continue;
        }
        let n = &iface.name;
        if n.starts_with("docker")
            || n.starts_with("podman")
            || n.starts_with("br-")
            || n.starts_with("cni-")
        {
            return Ok(iface.addr.ip());
        }
    }
    anyhow::bail!(
        "no docker/podman bridge interface found (looked for docker0, podman0, br-*, …). \
         Use --http-bind <ip> with the host IP that containers should reach."
    )
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

#[cfg(test)]
mod http_bind_tests {
    use super::{breadcrumb_endpoint, resolve_http_bind_ip};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn loopback_mode_resolves_to_localhost() {
        assert_eq!(
            resolve_http_bind_ip("loopback").unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn unspecified_mode_resolves_to_all_interfaces() {
        assert_eq!(
            resolve_http_bind_ip("0.0.0.0").unwrap(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn explicit_ipv4_is_parsed() {
        assert_eq!(
            resolve_http_bind_ip("192.168.1.42").unwrap(),
            "192.168.1.42".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn explicit_ipv6_is_parsed() {
        assert_eq!(
            resolve_http_bind_ip("::1").unwrap(),
            "::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(resolve_http_bind_ip("not-an-ip").is_err());
        assert!(resolve_http_bind_ip("999.999.999.999").is_err());
    }

    #[test]
    fn breadcrumb_advertises_loopback_for_unspecified() {
        assert_eq!(
            breadcrumb_endpoint(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 5641),
            "http://127.0.0.1:5641"
        );
    }

    #[test]
    fn breadcrumb_uses_specific_bind_ip() {
        let ip: IpAddr = "172.17.0.1".parse().unwrap();
        assert_eq!(
            breadcrumb_endpoint(Some(ip), 5641),
            "http://172.17.0.1:5641"
        );
    }
}
