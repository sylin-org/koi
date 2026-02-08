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
