//! CLI command handlers, split by execution mode.
//!
//! - `standalone` — creates a local `MdnsCore`, operates directly on the mDNS engine.
//! - `client` — talks to a running Koi daemon via HTTP using `KoiClient`.

pub mod client;
pub mod standalone;

use std::collections::HashMap;
use std::time::Duration;

/// Default timeout for browse/subscribe commands (seconds).
pub(crate) const DEFAULT_TIMEOUT: u64 = 5;

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
pub(crate) fn print_register_success(
    result: &koi_mdns::protocol::RegistrationResult,
) {
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
