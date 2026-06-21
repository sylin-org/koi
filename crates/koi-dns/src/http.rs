use std::sync::Arc;

use axum::extract::{Extension, Path, Query};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use koi_common::error::ErrorCode;
use koi_common::http::error_response;
use koi_config::state::DnsEntry;

use crate::runtime::DnsRuntime;
use crate::zone::DnsZone;

#[derive(Debug, Deserialize, IntoParams)]
struct LookupParams {
    name: String,
    #[serde(rename = "type")]
    record_type: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
struct EntryRequest {
    name: String,
    ip: String,
    ttl: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
struct LookupResponse {
    name: String,
    ips: Vec<String>,
    source: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct StatusResponse {
    running: bool,
    zone: String,
    port: u16,
    records: RecordSummary,
}

#[derive(Debug, Serialize, ToSchema)]
struct RecordSummary {
    static_entries: usize,
    certmesh_entries: usize,
    mdns_entries: usize,
}

#[derive(Debug, Serialize, ToSchema)]
struct EntriesResponse {
    entries: Vec<DnsEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
struct NamesResponse {
    names: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
struct StartedResponse {
    started: bool,
}

#[derive(Debug, Serialize, ToSchema)]
struct StoppedResponse {
    stopped: bool,
}

/// Route path constants - single source of truth for axum routing AND the command manifest.
pub mod paths {
    pub const PREFIX: &str = "/v1/dns";

    pub const STATUS: &str = "/v1/dns/status";
    pub const LOOKUP: &str = "/v1/dns/lookup";
    pub const LIST: &str = "/v1/dns/list";
    pub const ENTRIES: &str = "/v1/dns/entries";
    pub const ZONE: &str = "/v1/dns/zone";
    pub const ADD: &str = "/v1/dns/add";
    pub const REMOVE: &str = "/v1/dns/remove/{name}";
    pub const SERVE: &str = "/v1/dns/serve";
    pub const STOP: &str = "/v1/dns/stop";

    /// Strip the crate nest prefix to get the relative path for axum routing.
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

/// Build DNS domain routes. The binary crate mounts these at `/v1/dns/`.
pub fn routes(runtime: Arc<DnsRuntime>) -> Router {
    use paths::rel;
    Router::new()
        .route(rel(paths::STATUS), get(status_handler))
        .route(rel(paths::LOOKUP), get(lookup_handler))
        .route(rel(paths::LIST), get(list_handler))
        .route(rel(paths::ENTRIES), get(entries_handler))
        .route(rel(paths::ZONE), get(zone_handler))
        .route(rel(paths::ADD), post(add_entry_handler))
        .route(rel(paths::REMOVE), delete(remove_entry_handler))
        .route(rel(paths::SERVE), post(start_handler))
        .route(rel(paths::STOP), post(stop_handler))
        .layer(Extension(runtime))
}

#[utoipa::path(get, path = "/status", tag = "dns",
    summary = "DNS resolver status",
    responses((status = 200, body = StatusResponse)))]
async fn status_handler(Extension(runtime): Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    let runtime_status = runtime.status().await;
    let core = runtime.core();
    let snapshot = core.snapshot();
    Json(StatusResponse {
        running: runtime_status.running,
        zone: core.config().zone.clone(),
        port: core.config().port,
        records: RecordSummary {
            static_entries: snapshot.static_entries.len(),
            certmesh_entries: snapshot.certmesh_entries.len(),
            mdns_entries: snapshot.mdns_entries.len(),
        },
    })
}

#[utoipa::path(get, path = "/lookup", tag = "dns",
    summary = "Resolve a local name",
    params(LookupParams),
    responses((status = 200, body = LookupResponse)))]
async fn lookup_handler(
    Extension(runtime): Extension<Arc<DnsRuntime>>,
    Query(params): Query<LookupParams>,
) -> impl IntoResponse {
    let record_type = match parse_record_type(params.record_type.as_deref()) {
        Ok(rt) => rt,
        Err(code) => return error_response(code, "invalid_record_type").into_response(),
    };

    let core = runtime.core();
    let Some(result) = core.lookup(&params.name, record_type).await else {
        return error_response(ErrorCode::NotFound, "record_not_found").into_response();
    };

    let ips = result.ips.into_iter().map(|ip| ip.to_string()).collect();
    Json(LookupResponse {
        name: result.name,
        ips,
        source: result.source,
    })
    .into_response()
}

#[utoipa::path(get, path = "/list", tag = "dns",
    summary = "List all resolvable names",
    responses((status = 200, body = NamesResponse)))]
async fn list_handler(Extension(runtime): Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    let core = runtime.core();
    let names = core.list_names();
    Json(NamesResponse { names })
}

#[utoipa::path(get, path = "/entries", tag = "dns",
    summary = "List static entries with details",
    responses((status = 200, body = EntriesResponse)))]
async fn entries_handler(Extension(runtime): Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    Json(EntriesResponse {
        entries: runtime.core().list_entries(),
    })
}

#[derive(Debug, Deserialize, IntoParams)]
struct ZoneParams {
    /// Output format: `hosts`, `dnsmasq`, or `json` (default).
    format: Option<String>,
}

/// Structured zone export (the `json` format): each source is a map of
/// FQDN (trailing dot) → list of IP strings.
#[derive(Debug, Serialize, ToSchema)]
struct ZoneJson {
    static_entries: std::collections::BTreeMap<String, Vec<String>>,
    certmesh_entries: std::collections::BTreeMap<String, Vec<String>>,
    mdns_entries: std::collections::BTreeMap<String, Vec<String>>,
}

#[utoipa::path(get, path = "/zone", tag = "dns",
    summary = "Export the resolvable zone (hosts / dnsmasq / json)",
    params(ZoneParams),
    responses((status = 200, description = "Zone export in the requested format")))]
async fn zone_handler(
    Extension(runtime): Extension<Arc<DnsRuntime>>,
    Query(params): Query<ZoneParams>,
) -> impl IntoResponse {
    use axum::http::header;

    let snapshot = runtime.core().snapshot();
    match params.format.as_deref().unwrap_or("json") {
        "hosts" => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format_hosts(&snapshot),
        )
            .into_response(),
        "dnsmasq" => (
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format_dnsmasq(&snapshot),
        )
            .into_response(),
        "json" => Json(format_json(&snapshot)).into_response(),
        other => error_response(
            ErrorCode::InvalidPayload,
            format!("unknown format '{other}' (expected hosts, dnsmasq, or json)"),
        )
        .into_response(),
    }
}

/// Collect every (name, ip) pair from all three sources, with the trailing dot
/// stripped from names (hosts/dnsmasq want a bare FQDN), sorted for stable output.
fn flat_records(snapshot: &crate::records::RecordsSnapshot) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = Vec::new();
    for map in [
        &snapshot.static_entries,
        &snapshot.certmesh_entries,
        &snapshot.mdns_entries,
    ] {
        for (name, ips) in map {
            let bare = name.trim_end_matches('.');
            for ip in ips {
                rows.push((bare.to_string(), ip.to_string()));
            }
        }
    }
    rows.sort();
    rows.dedup();
    rows
}

/// `hosts(5)` format: `<ip> <name>`, one per line.
fn format_hosts(snapshot: &crate::records::RecordsSnapshot) -> String {
    let mut out = String::new();
    for (name, ip) in flat_records(snapshot) {
        out.push_str(&format!("{ip} {name}\n"));
    }
    out
}

/// dnsmasq `address=/<name>/<ip>` format, one per line.
fn format_dnsmasq(snapshot: &crate::records::RecordsSnapshot) -> String {
    let mut out = String::new();
    for (name, ip) in flat_records(snapshot) {
        out.push_str(&format!("address=/{name}/{ip}\n"));
    }
    out
}

/// Structured JSON: the three sources, names kept as stored (trailing dot),
/// IPs stringified, sorted via BTreeMap for stable output.
fn format_json(snapshot: &crate::records::RecordsSnapshot) -> ZoneJson {
    let to_sorted = |map: &std::collections::HashMap<String, Vec<std::net::IpAddr>>| {
        map.iter()
            .map(|(name, ips)| (name.clone(), ips.iter().map(|ip| ip.to_string()).collect()))
            .collect::<std::collections::BTreeMap<String, Vec<String>>>()
    };
    ZoneJson {
        static_entries: to_sorted(&snapshot.static_entries),
        certmesh_entries: to_sorted(&snapshot.certmesh_entries),
        mdns_entries: to_sorted(&snapshot.mdns_entries),
    }
}

#[utoipa::path(post, path = "/add", tag = "dns",
    summary = "Add static DNS entry",
    request_body = EntryRequest,
    responses((status = 200, body = EntriesResponse)))]
async fn add_entry_handler(
    Extension(runtime): Extension<Arc<DnsRuntime>>,
    Json(payload): Json<EntryRequest>,
) -> impl IntoResponse {
    let zone = match DnsZone::new(&runtime.core().config().zone) {
        Ok(zone) => zone,
        Err(e) => {
            return error_response(ErrorCode::InvalidName, e.to_string()).into_response();
        }
    };

    let name = match zone.normalize_name(&payload.name) {
        Some(name) => name,
        None => {
            return error_response(ErrorCode::InvalidName, "name_outside_zone").into_response();
        }
    };

    if payload.ip.parse::<std::net::IpAddr>().is_err() {
        return error_response(ErrorCode::InvalidPayload, "invalid_ip").into_response();
    }

    let entry = DnsEntry {
        name,
        ip: payload.ip,
        ttl: payload.ttl,
    };

    match runtime.core().add_entry(entry) {
        Ok(entries) => Json(EntriesResponse { entries }).into_response(),
        Err(e) => error_response(ErrorCode::IoError, e.to_string()).into_response(),
    }
}

#[utoipa::path(delete, path = "/remove/{name}", tag = "dns",
    summary = "Remove static DNS entry",
    params(("name" = String, Path, description = "DNS entry name")),
    responses((status = 200, body = EntriesResponse)))]
async fn remove_entry_handler(
    Extension(runtime): Extension<Arc<DnsRuntime>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let zone = match DnsZone::new(&runtime.core().config().zone) {
        Ok(zone) => zone,
        Err(e) => {
            return error_response(ErrorCode::InvalidName, e.to_string()).into_response();
        }
    };

    let name = match zone.normalize_name(&name) {
        Some(name) => name,
        None => {
            return error_response(ErrorCode::InvalidName, "name_outside_zone").into_response();
        }
    };

    match runtime.core().remove_entry(&name) {
        Ok(Some(entries)) => Json(EntriesResponse { entries }).into_response(),
        Ok(None) => error_response(ErrorCode::NotFound, "entry_not_found").into_response(),
        Err(e) => error_response(ErrorCode::IoError, e.to_string()).into_response(),
    }
}

#[utoipa::path(post, path = "/serve", tag = "dns",
    summary = "Start the DNS resolver",
    responses((status = 200, body = StartedResponse)))]
async fn start_handler(Extension(runtime): Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    match runtime.start().await {
        Ok(started) => Json(serde_json::json!({ "started": started })).into_response(),
        Err(e) => error_response(ErrorCode::Internal, e.to_string()).into_response(),
    }
}

#[utoipa::path(post, path = "/stop", tag = "dns",
    summary = "Stop the DNS resolver",
    responses((status = 200, body = StoppedResponse)))]
async fn stop_handler(Extension(runtime): Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    let stopped = runtime.stop().await;
    Json(serde_json::json!({ "stopped": stopped }))
}

/// Parse the `type` query param. On an unrecognized value, returns the
/// `ErrorCode` so the caller can build the shared error response (keeping the
/// `Err` variant small — see clippy `result_large_err`).
fn parse_record_type(input: Option<&str>) -> Result<RecordType, ErrorCode> {
    match input.unwrap_or("A").to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "ANY" => Ok(RecordType::ANY),
        _ => Err(ErrorCode::InvalidPayload),
    }
}

/// OpenAPI documentation for the DNS domain.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        status_handler,
        lookup_handler,
        list_handler,
        entries_handler,
        zone_handler,
        add_entry_handler,
        remove_entry_handler,
        start_handler,
        stop_handler,
    ),
    components(schemas(
        StatusResponse,
        LookupResponse,
        NamesResponse,
        EntriesResponse,
        ZoneJson,
        EntryRequest,
        RecordSummary,
        StartedResponse,
        StoppedResponse,
        koi_config::state::DnsEntry,
    ))
)]
pub struct DnsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::RecordsSnapshot;
    use std::collections::HashMap;
    use std::net::IpAddr;

    /// Build a snapshot with sample records. Names are stored as FQDN with a
    /// trailing dot (as the resolver normalizes them).
    fn sample_snapshot() -> RecordsSnapshot {
        let mut static_entries: HashMap<String, Vec<IpAddr>> = HashMap::new();
        static_entries.insert(
            "grafana.lan.".to_string(),
            vec!["10.0.0.5".parse().unwrap()],
        );
        let mut certmesh_entries: HashMap<String, Vec<IpAddr>> = HashMap::new();
        certmesh_entries.insert("ca.lan.".to_string(), vec!["10.0.0.1".parse().unwrap()]);
        let mut mdns_entries: HashMap<String, Vec<IpAddr>> = HashMap::new();
        mdns_entries.insert(
            "printer.lan.".to_string(),
            vec!["10.0.0.50".parse().unwrap()],
        );
        RecordsSnapshot {
            static_entries,
            certmesh_entries,
            mdns_entries,
            alias_feedback: Vec::new(),
        }
    }

    fn empty_snapshot() -> RecordsSnapshot {
        RecordsSnapshot {
            static_entries: HashMap::new(),
            certmesh_entries: HashMap::new(),
            mdns_entries: HashMap::new(),
            alias_feedback: Vec::new(),
        }
    }

    #[test]
    fn hosts_format_strips_trailing_dot() {
        let out = format_hosts(&sample_snapshot());
        // <ip> <name>, trailing dot stripped, sorted across all sources.
        assert!(out.contains("10.0.0.5 grafana.lan\n"), "out: {out}");
        assert!(out.contains("10.0.0.1 ca.lan\n"), "out: {out}");
        assert!(out.contains("10.0.0.50 printer.lan\n"), "out: {out}");
        assert!(
            !out.contains("lan.\n"),
            "trailing dot should be stripped: {out}"
        );
    }

    #[test]
    fn dnsmasq_format_strips_trailing_dot() {
        let out = format_dnsmasq(&sample_snapshot());
        assert!(
            out.contains("address=/grafana.lan/10.0.0.5\n"),
            "out: {out}"
        );
        assert!(out.contains("address=/ca.lan/10.0.0.1\n"), "out: {out}");
        assert!(
            out.contains("address=/printer.lan/10.0.0.50\n"),
            "out: {out}"
        );
    }

    #[test]
    fn json_format_keeps_sources_separate() {
        let json = format_json(&sample_snapshot());
        assert_eq!(
            json.static_entries.get("grafana.lan."),
            Some(&vec!["10.0.0.5".to_string()])
        );
        assert_eq!(
            json.certmesh_entries.get("ca.lan."),
            Some(&vec!["10.0.0.1".to_string()])
        );
        assert_eq!(
            json.mdns_entries.get("printer.lan."),
            Some(&vec!["10.0.0.50".to_string()])
        );
    }

    #[test]
    fn empty_zone_hosts_is_empty() {
        assert_eq!(format_hosts(&empty_snapshot()), "");
    }

    #[test]
    fn empty_zone_dnsmasq_is_empty() {
        assert_eq!(format_dnsmasq(&empty_snapshot()), "");
    }

    #[test]
    fn empty_zone_json_is_empty_maps() {
        let json = format_json(&empty_snapshot());
        assert!(json.static_entries.is_empty());
        assert!(json.certmesh_entries.is_empty());
        assert!(json.mdns_entries.is_empty());
        // Serializes to the expected empty-but-present shape.
        let v = serde_json::to_value(&json).unwrap();
        assert_eq!(v["static_entries"], serde_json::json!({}));
    }

    #[test]
    fn hosts_output_is_sorted_and_deduped() {
        // Two sources with the same (name, ip) → one line.
        let mut a: HashMap<String, Vec<IpAddr>> = HashMap::new();
        a.insert("dup.lan.".to_string(), vec!["10.0.0.9".parse().unwrap()]);
        let mut b: HashMap<String, Vec<IpAddr>> = HashMap::new();
        b.insert("dup.lan.".to_string(), vec!["10.0.0.9".parse().unwrap()]);
        let snap = RecordsSnapshot {
            static_entries: a,
            certmesh_entries: b,
            mdns_entries: HashMap::new(),
            alias_feedback: Vec::new(),
        };
        let out = format_hosts(&snap);
        assert_eq!(
            out, "10.0.0.9 dup.lan\n",
            "duplicates should collapse: {out}"
        );
    }
}
