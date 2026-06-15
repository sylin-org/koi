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
        EntryRequest,
        RecordSummary,
        StartedResponse,
        StoppedResponse,
        koi_config::state::DnsEntry,
    ))
)]
pub struct DnsApiDoc;
