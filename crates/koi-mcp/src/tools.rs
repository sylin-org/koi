//! Tool request types and the pure helpers behind the handlers.
//!
//! Request structs derive `Deserialize + JsonSchema` (schemars re-exported by
//! rmcp). Helpers here are blocking (they call `KoiClient`) or pure, and are kept
//! out of `server.rs` so the handler bodies stay thin.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use koi_client::{KoiClient, Result as ClientResult};
use koi_common::mdns_protocol::RegisterPayload;
use koi_common::types::{ServiceRecord, META_QUERY};
use rmcp::schemars;
use serde::Serialize;

// ── Request types (the tool input schemas) ────────────────────────────

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DiscoverReq {
    #[schemars(
        description = "mDNS service type to browse, e.g. `_http._tcp`. Omit to discover all types."
    )]
    pub service_type: Option<String>,
    #[schemars(description = "How long to collect results, in seconds (default 5, capped at 10).")]
    pub timeout_secs: Option<u64>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct ResolveReq {
    #[schemars(description = "Full mDNS instance name, e.g. `My App._http._tcp.local.`.")]
    pub instance: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct AnnounceReq {
    #[schemars(description = "Human-readable instance name, e.g. `My Agent`.")]
    pub name: String,
    #[schemars(description = "mDNS service type, e.g. `_http._tcp` or `_mcp._tcp`.")]
    #[serde(rename = "type")]
    pub service_type: String,
    #[schemars(description = "TCP/UDP port the service listens on.")]
    pub port: u16,
    #[schemars(description = "Optional TXT record key/value pairs.")]
    pub txt: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct UnregisterReq {
    #[schemars(description = "Registration id returned by `lan_announce`.")]
    pub id: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DnsLookupReq {
    #[schemars(description = "Name to resolve, e.g. `grafana.lan`.")]
    pub name: String,
    #[schemars(description = "Record type: `A` (default), `AAAA`, or `ANY`.")]
    pub record_type: Option<String>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DnsAddReq {
    #[schemars(description = "Name to map, e.g. `app.lan`.")]
    pub name: String,
    #[schemars(
        description = "IP address to map the name to. Omit to use the current host's address."
    )]
    pub ip: Option<String>,
    #[schemars(description = "Optional TTL override, in seconds.")]
    pub ttl: Option<u32>,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct DnsRemoveReq {
    #[schemars(description = "Name to remove from the resolver.")]
    pub name: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
pub struct InventoryReq {
    #[schemars(
        description = "Reserved for future source filtering; currently joins status, health, \
                       and DNS."
    )]
    pub include: Option<Vec<String>>,
}

// ── Browse collection (blocking) ──────────────────────────────────────

/// Browse mDNS for `service_type` (or the meta-query for all types) and collect
/// deduplicated service records until `window` elapses or the stream ends.
///
/// Runs the blocking `SseStream` inside the caller's `spawn_blocking` context.
/// Dedup key is `name` so repeated Found/Resolved events for the same instance
/// collapse to the latest record seen.
pub fn collect_browse(
    client: &KoiClient,
    service_type: Option<&str>,
    window: Duration,
) -> ClientResult<Vec<ServiceRecord>> {
    let browse_type = service_type.unwrap_or(META_QUERY);
    let stream = client.browse_stream(browse_type)?;
    let deadline = Instant::now() + window;
    let mut seen: HashMap<String, ServiceRecord> = HashMap::new();

    for event in stream {
        if Instant::now() >= deadline {
            break;
        }
        let value = match event {
            Ok(value) => value,
            Err(_) => break,
        };
        if let Some(record) = record_from_event(&value) {
            seen.insert(record.name.clone(), record);
        }
    }
    Ok(seen.into_values().collect())
}

/// Extract a `ServiceRecord` from a browse SSE envelope.
///
/// The wire shape is externally tagged: `{"found": {...}}` or
/// `{"resolved": {...}}` (with an optional `status` sibling). `removed` events
/// carry no full record and are ignored for collection.
fn record_from_event(value: &serde_json::Value) -> Option<ServiceRecord> {
    for key in ["resolved", "found"] {
        if let Some(inner) = value.get(key) {
            if let Ok(record) = serde_json::from_value::<ServiceRecord>(inner.clone()) {
                return Some(record);
            }
        }
    }
    None
}

// ── MCP endpoint projection ───────────────────────────────────────────

#[derive(Serialize)]
pub struct McpEndpoint {
    pub name: String,
    pub host: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    /// Transport hint from TXT (`transport=`), defaulting to the convention.
    pub transport: String,
    /// Optional path hint from TXT (`path=`).
    pub path: Option<String>,
}

/// Project `_mcp._tcp` service records into connectable endpoint descriptors,
/// reading the TXT vocabulary aligned to the MCP discovery drafts
/// (`transport=`, `path=`, `name=`).
pub fn to_mcp_endpoints(records: &[ServiceRecord]) -> Vec<McpEndpoint> {
    records
        .iter()
        .map(|r| McpEndpoint {
            name: r.txt.get("name").cloned().unwrap_or_else(|| r.name.clone()),
            host: r.host.clone(),
            ip: r.ip.clone(),
            port: r.port,
            transport: r
                .txt
                .get("transport")
                .cloned()
                .unwrap_or_else(|| "streamable-http".to_string()),
            path: r.txt.get("path").cloned(),
        })
        .collect()
}

// ── Payload + arg helpers ─────────────────────────────────────────────

/// Build a heartbeat-leased `RegisterPayload` from an announce request.
/// `lease_secs = None` lets the daemon apply its default heartbeat lease.
pub fn announce_payload(req: &AnnounceReq) -> RegisterPayload {
    RegisterPayload {
        name: req.name.clone(),
        service_type: req.service_type.clone(),
        port: req.port,
        ip: None,
        lease_secs: None,
        txt: req.txt.clone().unwrap_or_default(),
    }
}

/// Whether `source` should be included in an inventory given the optional
/// `include` filter. `None` (absent) means include everything; an explicit list
/// includes only the named sources (case-insensitive).
pub fn inventory_includes(include: Option<&[String]>, source: &str) -> bool {
    match include {
        None => true,
        Some(list) => list.iter().any(|s| s.eq_ignore_ascii_case(source)),
    }
}

/// Parse an optional record-type string into a `RecordType`, defaulting to A.
pub fn parse_record_type(input: Option<&str>) -> RecordType {
    match input.map(|s| s.trim().to_ascii_uppercase()).as_deref() {
        Some("AAAA") => RecordType::AAAA,
        Some("ANY") => RecordType::ANY,
        _ => RecordType::A,
    }
}

/// Resolve the IP for a `dns_add`: validate an explicit IP, or fall back to the
/// current host's primary address. Returns a user-facing error message on failure.
pub fn resolve_add_ip(ip: Option<&str>) -> std::result::Result<String, String> {
    match ip {
        Some(ip) => match ip.parse::<IpAddr>() {
            Ok(_) => Ok(ip.to_string()),
            Err(_) => Err(format!("invalid IP address: {ip}")),
        },
        None => local_ip().map(|ip| ip.to_string()).ok_or_else(|| {
            "could not determine the local host IP; pass `ip` explicitly".to_string()
        }),
    }
}

/// Best-effort primary non-loopback IPv4 of the host.
fn local_ip() -> Option<IpAddr> {
    let addrs = if_addrs::get_if_addrs().ok()?;
    addrs
        .into_iter()
        .map(|a| a.ip())
        .find(|ip| ip.is_ipv4() && !ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "type": "_http._tcp",
            "host": "host.local",
            "ip": "10.0.0.5",
            "port": 8080,
            "txt": {"transport": "streamable-http", "path": "/mcp"}
        })
    }

    #[test]
    fn record_from_found_envelope() {
        let env = serde_json::json!({ "found": record("A"), "status": "ongoing" });
        let r = record_from_event(&env).expect("should parse found");
        assert_eq!(r.name, "A");
        assert_eq!(r.port, Some(8080));
    }

    #[test]
    fn record_from_resolved_envelope() {
        let env = serde_json::json!({ "resolved": record("B") });
        assert_eq!(record_from_event(&env).unwrap().name, "B");
    }

    #[test]
    fn record_from_removed_is_none() {
        let env = serde_json::json!({ "removed": { "name": "X" } });
        assert!(record_from_event(&env).is_none());
    }

    #[test]
    fn parse_record_type_defaults_to_a() {
        assert_eq!(parse_record_type(None), RecordType::A);
        assert_eq!(parse_record_type(Some("a")), RecordType::A);
        assert_eq!(parse_record_type(Some("aaaa")), RecordType::AAAA);
        assert_eq!(parse_record_type(Some("ANY")), RecordType::ANY);
        assert_eq!(parse_record_type(Some("garbage")), RecordType::A);
    }

    #[test]
    fn resolve_add_ip_validates_explicit() {
        assert_eq!(resolve_add_ip(Some("10.0.0.1")).unwrap(), "10.0.0.1");
        assert!(resolve_add_ip(Some("not-an-ip")).is_err());
    }

    #[test]
    fn announce_payload_uses_default_lease() {
        let req = AnnounceReq {
            name: "Agent".into(),
            service_type: "_mcp._tcp".into(),
            port: 9000,
            txt: None,
        };
        let payload = announce_payload(&req);
        assert_eq!(payload.name, "Agent");
        assert_eq!(payload.service_type, "_mcp._tcp");
        assert_eq!(payload.port, 9000);
        assert!(payload.lease_secs.is_none());
        assert!(payload.ip.is_none());
        assert!(payload.txt.is_empty());
    }

    #[test]
    fn inventory_includes_defaults_to_all() {
        assert!(inventory_includes(None, "status"));
        assert!(inventory_includes(None, "dns"));
    }

    #[test]
    fn inventory_includes_filters_explicit_list() {
        let list = vec!["status".to_string(), "DNS".to_string()];
        assert!(inventory_includes(Some(&list), "status"));
        assert!(inventory_includes(Some(&list), "dns")); // case-insensitive
        assert!(!inventory_includes(Some(&list), "health"));
    }

    #[test]
    fn to_mcp_endpoints_reads_txt() {
        let rec: ServiceRecord = serde_json::from_value(record("svc")).unwrap();
        let eps = to_mcp_endpoints(&[rec]);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].transport, "streamable-http");
        assert_eq!(eps[0].path.as_deref(), Some("/mcp"));
        assert_eq!(eps[0].port, Some(8080));
    }
}
