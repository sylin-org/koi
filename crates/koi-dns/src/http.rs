use std::sync::Arc;

use axum::extract::{Extension, Path, Query};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use koi_common::error::ErrorCode;
use koi_config::state::{load_dns_state, save_dns_state, DnsEntry, DnsState};

use crate::resolver::DnsEvent;
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

/// Route path constants — single source of truth for axum routing AND the command manifest.
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

/// DNS server status overview.
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

/// Look up a DNS record.
async fn lookup_handler(
    Extension(runtime): Extension<Arc<DnsRuntime>>,
    Query(params): Query<LookupParams>,
) -> impl IntoResponse {
    let record_type = match parse_record_type(params.record_type.as_deref()) {
        Ok(rt) => rt,
        Err(resp) => return resp.into_response(),
    };

    let core = runtime.core();
    let Some(result) = core.lookup(&params.name, record_type).await else {
        return error_response(
            axum::http::StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "record_not_found",
        )
        .into_response();
    };

    let ips = result.ips.into_iter().map(|ip| ip.to_string()).collect();
    Json(LookupResponse {
        name: result.name,
        ips,
        source: result.source,
    })
    .into_response()
}

/// List all known DNS names.
async fn list_handler(Extension(runtime): Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    let core = runtime.core();
    let names = core.list_names();
    Json(NamesResponse { names })
}

/// List static DNS entries.
async fn entries_handler(_runtime: Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    match load_dns_state() {
        Ok(state) => Json(EntriesResponse {
            entries: state.entries,
        })
        .into_response(),
        Err(e) => error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::IoError,
            &e.to_string(),
        )
        .into_response(),
    }
}

/// Add or update a static DNS entry.
async fn add_entry_handler(
    Extension(runtime): Extension<Arc<DnsRuntime>>,
    Json(payload): Json<EntryRequest>,
) -> impl IntoResponse {
    let zone = match DnsZone::new(&runtime.core().config().zone) {
        Ok(zone) => zone,
        Err(e) => {
            return error_response(
                axum::http::StatusCode::BAD_REQUEST,
                ErrorCode::InvalidName,
                &e.to_string(),
            )
            .into_response();
        }
    };

    let name = match zone.normalize_name(&payload.name) {
        Some(name) => name,
        None => {
            return error_response(
                axum::http::StatusCode::BAD_REQUEST,
                ErrorCode::InvalidName,
                "name_outside_zone",
            )
            .into_response();
        }
    };

    if payload.ip.parse::<std::net::IpAddr>().is_err() {
        return error_response(
            axum::http::StatusCode::BAD_REQUEST,
            ErrorCode::InvalidPayload,
            "invalid_ip",
        )
        .into_response();
    }

    let mut state = load_dns_state().unwrap_or_default();
    upsert_entry(
        &mut state,
        DnsEntry {
            name: name.clone(),
            ip: payload.ip.clone(),
            ttl: payload.ttl,
        },
    );

    if let Err(e) = save_dns_state(&state) {
        return error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::IoError,
            &e.to_string(),
        )
        .into_response();
    }

    runtime.core().emit(DnsEvent::EntryUpdated {
        name,
        ip: payload.ip,
    });

    Json(EntriesResponse {
        entries: state.entries,
    })
    .into_response()
}

/// Remove a static DNS entry by name.
async fn remove_entry_handler(
    Extension(runtime): Extension<Arc<DnsRuntime>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let zone = match DnsZone::new(&runtime.core().config().zone) {
        Ok(zone) => zone,
        Err(e) => {
            return error_response(
                axum::http::StatusCode::BAD_REQUEST,
                ErrorCode::InvalidName,
                &e.to_string(),
            )
            .into_response();
        }
    };

    let name = match zone.normalize_name(&name) {
        Some(name) => name,
        None => {
            return error_response(
                axum::http::StatusCode::BAD_REQUEST,
                ErrorCode::InvalidName,
                "name_outside_zone",
            )
            .into_response();
        }
    };

    let mut state = match load_dns_state() {
        Ok(state) => state,
        Err(e) => {
            return error_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::IoError,
                &e.to_string(),
            )
            .into_response();
        }
    };

    let before = state.entries.len();
    state.entries.retain(|entry| entry.name != name);
    if state.entries.len() == before {
        return error_response(
            axum::http::StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "entry_not_found",
        )
        .into_response();
    }

    if let Err(e) = save_dns_state(&state) {
        return error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::IoError,
            &e.to_string(),
        )
        .into_response();
    }

    runtime.core().emit(DnsEvent::EntryRemoved { name });

    Json(EntriesResponse {
        entries: state.entries,
    })
    .into_response()
}

/// Start the DNS server.
async fn start_handler(Extension(runtime): Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    match runtime.start().await {
        Ok(started) => Json(serde_json::json!({ "started": started })).into_response(),
        Err(e) => error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            &e.to_string(),
        )
        .into_response(),
    }
}

/// Stop the DNS server.
async fn stop_handler(Extension(runtime): Extension<Arc<DnsRuntime>>) -> impl IntoResponse {
    let stopped = runtime.stop().await;
    Json(serde_json::json!({ "stopped": stopped }))
}

fn parse_record_type(input: Option<&str>) -> Result<RecordType, impl IntoResponse> {
    let record_type = match input.unwrap_or("A").to_ascii_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "ANY" => RecordType::ANY,
        _ => {
            return Err(error_response(
                axum::http::StatusCode::BAD_REQUEST,
                ErrorCode::InvalidPayload,
                "invalid_record_type",
            ))
        }
    };
    Ok(record_type)
}

fn upsert_entry(state: &mut DnsState, entry: DnsEntry) {
    if let Some(existing) = state.entries.iter_mut().find(|e| e.name == entry.name) {
        *existing = entry;
    } else {
        state.entries.push(entry);
    }
}

fn error_response(
    status: axum::http::StatusCode,
    code: ErrorCode,
    message: &str,
) -> impl IntoResponse {
    let body = serde_json::json!({
        "error": code,
        "message": message,
    });
    (status, Json(body))
}

/// OpenAPI documentation for the DNS domain.
#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(
    StatusResponse,
    LookupResponse,
    NamesResponse,
    EntriesResponse,
    EntryRequest,
    RecordSummary,
    StartedResponse,
    StoppedResponse,
    koi_config::state::DnsEntry,
)))]
pub struct DnsApiDoc;
