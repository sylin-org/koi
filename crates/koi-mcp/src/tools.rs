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
use koi_common::integration::MdnsDiscoverySnapshot;
use koi_common::mdns_protocol::RegisterPayload;
use koi_common::types::{EventKind, ServiceRecord, META_QUERY};
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
        description = "Optional subset of `status`, `health`, and `dns`; omit to return all \
                       three from the same captured product revision."
    )]
    pub include: Option<Vec<String>>,
}

// ── Browse collection (blocking) ──────────────────────────────────────

/// Browse mDNS for `service_type` (or the meta-query for all types) and collect
/// deduplicated service records until `window` elapses or the stream ends.
///
/// Runs the blocking `SseStream` inside the caller's `spawn_blocking` context.
/// Dedup key is `name` so repeated Found/Resolved events for the same instance
/// collapse to the latest record seen. Transport and protocol failures abort
/// the operation; a partial collection is never reported as success.
pub fn collect_browse(
    client: &KoiClient,
    service_type: Option<&str>,
    window: Duration,
) -> ClientResult<Vec<ServiceRecord>> {
    let browse_type = service_type.unwrap_or(META_QUERY);
    let deadline = Instant::now().checked_add(window).ok_or_else(|| {
        koi_client::ClientError::Decode("mDNS browse window exceeds monotonic clock range".into())
    })?;
    let stream = client.browse_stream(browse_type)?.with_deadline(deadline);
    let mut seen: HashMap<String, ServiceRecord> = HashMap::new();

    for event in stream {
        let value = event?;
        match browse_frame(&value)? {
            BrowseFrame::Upsert(record) => {
                seen.insert(record.name.clone(), record);
            }
            BrowseFrame::Remove(name) => {
                seen.remove(&name);
            }
            BrowseFrame::Snapshot(snapshot) => {
                seen.clear();
                seen.extend(
                    snapshot
                        .records
                        .into_iter()
                        .filter(|record| snapshot_matches(record, service_type))
                        .map(|record| (record.name.clone(), record)),
                );
            }
        }
    }
    Ok(seen.into_values().collect())
}

/// Decode one exact browse boundary frame. Found/resolved records upsert,
/// removals delete, and lag-recovery snapshots replace the collected view;
/// error or malformed frames terminate the finite browse visibly.
enum BrowseFrame {
    Upsert(ServiceRecord),
    Remove(String),
    Snapshot(MdnsDiscoverySnapshot),
}

fn browse_frame(value: &serde_json::Value) -> ClientResult<BrowseFrame> {
    if let Some(error) = value.get("error") {
        let error = error.as_str().ok_or_else(|| {
            koi_client::ClientError::Decode(
                "mDNS browse error frame has a non-string `error` field".into(),
            )
        })?;
        let message = value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                koi_client::ClientError::Decode(
                    "mDNS browse error frame is missing string field `message`".into(),
                )
            })?;
        return Err(koi_client::ClientError::Api {
            error: error.to_string(),
            message: message.to_string(),
        });
    }
    for key in ["resolved", "found"] {
        if let Some(inner) = value.get(key) {
            let record =
                serde_json::from_value::<ServiceRecord>(inner.clone()).map_err(|error| {
                    koi_client::ClientError::Decode(format!(
                        "invalid mDNS browse `{key}` frame: {error}"
                    ))
                })?;
            return Ok(BrowseFrame::Upsert(record));
        }
    }
    if let Some(snapshot) = value.get("snapshot") {
        let snapshot = serde_json::from_value(snapshot.clone()).map_err(|error| {
            koi_client::ClientError::Decode(format!("invalid mDNS browse snapshot frame: {error}"))
        })?;
        return Ok(BrowseFrame::Snapshot(snapshot));
    }
    if let Some(event) = value.get("event") {
        let event: EventKind = serde_json::from_value(event.clone()).map_err(|error| {
            koi_client::ClientError::Decode(format!("invalid mDNS browse event kind: {error}"))
        })?;
        if event != EventKind::Removed {
            return Err(koi_client::ClientError::Decode(format!(
                "unexpected `{event:?}` event in mDNS browse stream"
            )));
        }
        let service = value.get("service").ok_or_else(|| {
            koi_client::ClientError::Decode(
                "mDNS browse removal frame is missing field `service`".into(),
            )
        })?;
        let service: ServiceRecord = serde_json::from_value(service.clone()).map_err(|error| {
            koi_client::ClientError::Decode(format!("invalid mDNS browse removal service: {error}"))
        })?;
        return Ok(BrowseFrame::Remove(service.name));
    }
    Err(koi_client::ClientError::Decode(
        "unrecognized mDNS browse frame".into(),
    ))
}

fn snapshot_matches(record: &ServiceRecord, requested_type: Option<&str>) -> bool {
    requested_type.is_none_or(|requested| {
        record
            .service_type
            .trim_end_matches(".local.")
            .eq_ignore_ascii_case(requested.trim_end_matches(".local."))
    })
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
    use std::io::{Read, Write};

    fn sse_server_once(body: &'static str) -> (KoiClient, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind SSE server");
        let address = listener.local_addr().expect("SSE address");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept SSE request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = socket.read(&mut buffer).expect("read SSE request");
                assert!(read > 0, "request closed before headers completed");
                request.extend_from_slice(&buffer[..read]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .expect("write SSE response");
        });
        (KoiClient::new(&format!("http://{address}")), server)
    }

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
        let BrowseFrame::Upsert(r) = browse_frame(&env).expect("should parse found") else {
            panic!("found frame must upsert")
        };
        assert_eq!(r.name, "A");
        assert_eq!(r.port, Some(8080));
    }

    #[test]
    fn record_from_resolved_envelope() {
        let env = serde_json::json!({ "resolved": record("B") });
        let BrowseFrame::Upsert(record) = browse_frame(&env).unwrap() else {
            panic!("resolved frame must upsert")
        };
        assert_eq!(record.name, "B");
    }

    #[test]
    fn record_from_removed_names_the_record_to_delete() {
        let env = serde_json::json!({ "event": "removed", "service": record("X") });
        let BrowseFrame::Remove(name) = browse_frame(&env).unwrap() else {
            panic!("removed frame must delete")
        };
        assert_eq!(name, "X");
    }

    #[test]
    fn malformed_or_error_browse_frames_are_not_partial_success() {
        assert!(matches!(
            browse_frame(&serde_json::json!({
                "error": "provider_unavailable",
                "message": "native provider stopped"
            })),
            Err(koi_client::ClientError::Api { error, message })
                if error == "provider_unavailable" && message == "native provider stopped"
        ));
        assert!(matches!(
            browse_frame(&serde_json::json!({ "found": { "name": 7 } })),
            Err(koi_client::ClientError::Decode(_))
        ));
        assert!(matches!(
            browse_frame(&serde_json::json!({ "unexpected": true })),
            Err(koi_client::ClientError::Decode(_))
        ));
    }

    #[test]
    fn finite_browse_propagates_late_protocol_failure_instead_of_partial_results() {
        let body = concat!(
            "data: {\"found\":{\"name\":\"valid\",\"type\":\"_http._tcp\",",
            "\"host\":\"host.local\",\"ip\":\"10.0.0.5\",\"port\":8080,\"txt\":{}}}\n\n",
            "data: {\"unexpected\":true}\n\n"
        );
        let (client, server) = sse_server_once(body);

        assert!(matches!(
            collect_browse(&client, Some("_http._tcp"), Duration::from_secs(1)),
            Err(koi_client::ClientError::Decode(_))
        ));
        server.join().expect("SSE server joins");
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
