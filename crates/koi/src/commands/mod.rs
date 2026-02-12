//! CLI command handlers, organized by domain.
//!
//! - `mdns` — mDNS commands (discover, announce, unregister, resolve, subscribe).
//! - `certmesh` — Certificate mesh commands (create, join, status, log, compliance, unlock, set-hook).
//! - `dns` — DNS commands (serve, lookup, add/remove/list).
//! - `health` — Health commands (status, watch, add/remove, log).
//! - `proxy` — Proxy commands (add/remove/list/status).
//!
//! Shared infrastructure (mode detection, payload builders, formatting) lives here.

pub mod certmesh;
pub mod dns;
pub mod health;
pub mod mdns;
pub mod proxy;
pub mod status;

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use crate::cli::Cli;
use crate::client::KoiClient;

/// Default timeout for browse/subscribe commands (seconds).
pub(crate) const DEFAULT_TIMEOUT: u64 = 5;

// ── Mode detection ───────────────────────────────────────────────────

/// Execution mode for commands that support both local and daemon backends.
pub(crate) enum Mode {
    /// Operate directly on a local MdnsCore instance.
    Standalone,
    /// Talk to a running daemon via HTTP.
    Client { endpoint: String },
}

/// Determine whether to run standalone (local mDNS core) or as a client
/// talking to an already-running daemon.
pub(crate) fn detect_mode(cli: &Cli) -> Mode {
    if cli.standalone {
        return Mode::Standalone;
    }
    if let Some(endpoint) = &cli.endpoint {
        return Mode::Client {
            endpoint: endpoint.clone(),
        };
    }
    // Check breadcrumb — if a daemon is advertising its endpoint, use client mode
    if let Some(endpoint) = koi_config::breadcrumb::read_breadcrumb() {
        let c = KoiClient::new(&endpoint);
        if c.health().is_ok() {
            return Mode::Client { endpoint };
        }
    }
    Mode::Standalone
}

/// Resolve an endpoint for admin commands (which always need a daemon).
pub(crate) fn resolve_endpoint(cli: &Cli) -> anyhow::Result<String> {
    if let Some(endpoint) = &cli.endpoint {
        return Ok(endpoint.clone());
    }
    if let Some(endpoint) = koi_config::breadcrumb::read_breadcrumb() {
        return Ok(endpoint);
    }
    anyhow::bail!("No daemon endpoint found. Is the daemon running? Use --endpoint to specify.")
}

pub(crate) async fn with_mode<T, LFut, CFut, L, C>(
    mode: Mode,
    local: L,
    client_fn: C,
) -> anyhow::Result<T>
where
    L: FnOnce() -> LFut,
    C: FnOnce(KoiClient) -> CFut,
    LFut: Future<Output = anyhow::Result<T>>,
    CFut: Future<Output = anyhow::Result<T>>,
{
    match mode {
        Mode::Standalone => local().await,
        Mode::Client { endpoint } => {
            let client = KoiClient::new(&endpoint);
            client_fn(client).await
        }
    }
}

pub(crate) fn with_mode_sync<T, L, C>(mode: Mode, local: L, client_fn: C) -> anyhow::Result<T>
where
    L: FnOnce() -> anyhow::Result<T>,
    C: FnOnce(KoiClient) -> anyhow::Result<T>,
{
    match mode {
        Mode::Standalone => local(),
        Mode::Client { endpoint } => {
            let client = KoiClient::new(&endpoint);
            client_fn(client)
        }
    }
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Parse `KEY=VALUE` entries into a HashMap.
pub(crate) fn parse_txt(entries: &[String]) -> HashMap<String, String> {
    entries
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Resolve the effective timeout duration.
///
/// - `Some(0)` → infinite (run forever)
/// - `Some(n)` → n seconds
/// - `None` → fall back to the provided default (`None` default = infinite)
pub(crate) fn effective_timeout(
    explicit: Option<u64>,
    default_secs: Option<u64>,
) -> Option<Duration> {
    match explicit {
        Some(0) => None,
        Some(secs) => Some(Duration::from_secs(secs)),
        None => default_secs.map(Duration::from_secs),
    }
}

/// Print a serializable value as JSON, handling serialization errors
/// gracefully instead of panicking.
pub(crate) fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("Error: failed to serialize response: {e}"),
    }
}

/// Build a `RegisterPayload` from CLI arguments.
pub(crate) fn build_register_payload(
    name: &str,
    service_type: &str,
    port: u16,
    ip: Option<&str>,
    txt: &[String],
) -> koi_mdns::protocol::RegisterPayload {
    koi_mdns::protocol::RegisterPayload {
        name: name.to_string(),
        service_type: service_type.to_string(),
        port,
        ip: ip.map(String::from),
        lease_secs: None,
        txt: parse_txt(txt),
    }
}

/// Print the human-readable registration success message.
pub(crate) fn print_register_success(result: &koi_mdns::protocol::RegistrationResult) {
    println!(
        "Registered \"{}\" ({}) on port {} [id: {}]",
        result.name, result.service_type, result.port, result.id
    );
    eprintln!("Service is being advertised. Press Ctrl+C to unregister and exit.");
}

/// Wait for Ctrl+C or an optional timeout, whichever comes first.
pub(crate) async fn wait_for_signal_or_timeout(timeout: Option<Duration>) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match timeout {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }
}

/// Run a streaming operation with Ctrl+C and optional timeout cancellation.
///
/// Extracts the `tokio::select! { stream, ctrl_c, timeout }` skeleton
/// that is shared across discover, subscribe, and similar streaming commands.
pub(crate) async fn run_streaming<F, Fut>(
    timeout: Option<u64>,
    default_timeout: Option<u64>,
    stream_fn: F,
) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let dur = effective_timeout(timeout, default_timeout);
    tokio::select! {
        result = stream_fn() => { result?; }
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match dur {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_txt tests ──────────────────────────────────────────────

    #[test]
    fn parse_txt_basic_key_value() {
        let entries = vec!["version=1.0".to_string(), "env=prod".to_string()];
        let txt = parse_txt(&entries);
        assert_eq!(txt.get("version").unwrap(), "1.0");
        assert_eq!(txt.get("env").unwrap(), "prod");
        assert_eq!(txt.len(), 2);
    }

    #[test]
    fn parse_txt_empty_input() {
        let entries: Vec<String> = vec![];
        let txt = parse_txt(&entries);
        assert!(txt.is_empty());
    }

    #[test]
    fn parse_txt_skips_entries_without_equals() {
        let entries = vec!["noequals".to_string(), "valid=yes".to_string()];
        let txt = parse_txt(&entries);
        assert_eq!(txt.len(), 1);
        assert_eq!(txt.get("valid").unwrap(), "yes");
    }

    #[test]
    fn parse_txt_value_with_equals() {
        // Only splits on first '='
        let entries = vec!["path=/api/v1=test".to_string()];
        let txt = parse_txt(&entries);
        assert_eq!(txt.get("path").unwrap(), "/api/v1=test");
    }

    #[test]
    fn parse_txt_empty_value() {
        let entries = vec!["key=".to_string()];
        let txt = parse_txt(&entries);
        assert_eq!(txt.get("key").unwrap(), "");
    }

    // ── effective_timeout tests ──────────────────────────────────────

    #[test]
    fn effective_timeout_explicit_zero_means_infinite() {
        assert_eq!(effective_timeout(Some(0), Some(5)), None);
    }

    #[test]
    fn effective_timeout_explicit_value_overrides_default() {
        assert_eq!(
            effective_timeout(Some(15), Some(5)),
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn effective_timeout_none_uses_default() {
        assert_eq!(
            effective_timeout(None, Some(5)),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn effective_timeout_none_with_no_default_means_infinite() {
        assert_eq!(effective_timeout(None, None), None);
    }

    #[test]
    fn effective_timeout_explicit_zero_overrides_any_default() {
        assert_eq!(effective_timeout(Some(0), Some(999)), None);
        assert_eq!(effective_timeout(Some(0), None), None);
    }

    // ── build_register_payload tests ─────────────────────────────────

    #[test]
    fn build_register_payload_basic() {
        let payload = build_register_payload("My App", "_http._tcp", 8080, None, &[]);
        assert_eq!(payload.name, "My App");
        assert_eq!(payload.service_type, "_http._tcp");
        assert_eq!(payload.port, 8080);
        assert!(payload.ip.is_none());
        assert!(payload.lease_secs.is_none());
        assert!(payload.txt.is_empty());
    }

    #[test]
    fn build_register_payload_with_ip_and_txt() {
        let txt = vec!["version=2.1".to_string(), "env=staging".to_string()];
        let payload =
            build_register_payload("My App", "_http._tcp", 9090, Some("192.168.1.42"), &txt);
        assert_eq!(payload.ip.as_deref(), Some("192.168.1.42"));
        assert_eq!(payload.txt.get("version").unwrap(), "2.1");
        assert_eq!(payload.txt.get("env").unwrap(), "staging");
    }

    #[test]
    fn build_register_payload_always_has_no_lease() {
        let payload = build_register_payload("X", "_tcp", 80, None, &[]);
        assert!(payload.lease_secs.is_none());
    }
}
