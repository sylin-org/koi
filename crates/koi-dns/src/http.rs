use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};

use koi_common::error::ErrorCode;
use koi_config::state::{load_dns_state, save_dns_state, DnsEntry, DnsState};

use crate::runtime::DnsRuntime;
use crate::zone::DnsZone;

#[derive(Clone)]
struct DnsHttpState {
    runtime: Arc<DnsRuntime>,
}

#[derive(Debug, Deserialize)]
struct LookupParams {
    name: String,
    #[serde(rename = "type")]
    record_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EntryRequest {
    name: String,
    ip: String,
    ttl: Option<u32>,
}

#[derive(Debug, Serialize)]
struct LookupResponse {
    name: String,
    ips: Vec<String>,
    source: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    running: bool,
    zone: String,
    port: u16,
    records: RecordSummary,
}

#[derive(Debug, Serialize)]
struct RecordSummary {
    static_entries: usize,
    certmesh_entries: usize,
    mdns_entries: usize,
}

#[derive(Debug, Serialize)]
struct EntriesResponse {
    entries: Vec<DnsEntry>,
}

#[derive(Debug, Serialize)]
struct NamesResponse {
    names: Vec<String>,
}

/// Build DNS domain routes. The binary crate mounts these at `/v1/dns/`.
pub fn routes(runtime: Arc<DnsRuntime>) -> Router {
    Router::new()
        .route("/status", get(status_handler))
        .route("/lookup", get(lookup_handler))
        .route("/list", get(list_handler))
        .route("/entries", get(entries_handler).post(add_entry_handler))
        .route("/entries/{name}", delete(remove_entry_handler))
        .route("/admin/start", post(start_handler))
        .route("/admin/stop", post(stop_handler))
        .with_state(DnsHttpState { runtime })
}

async fn status_handler(State(state): State<DnsHttpState>) -> impl IntoResponse {
    let runtime_status = state.runtime.status().await;
    let core = state.runtime.core();
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

async fn lookup_handler(
    State(state): State<DnsHttpState>,
    Query(params): Query<LookupParams>,
) -> impl IntoResponse {
    let record_type = match parse_record_type(params.record_type.as_deref()) {
        Ok(rt) => rt,
        Err(resp) => return resp.into_response(),
    };

    let core = state.runtime.core();
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

async fn list_handler(State(state): State<DnsHttpState>) -> impl IntoResponse {
    let core = state.runtime.core();
    let names = core.list_names();
    Json(NamesResponse { names })
}

async fn entries_handler(_state: State<DnsHttpState>) -> impl IntoResponse {
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

async fn add_entry_handler(
    State(state): State<DnsHttpState>,
    Json(payload): Json<EntryRequest>,
) -> impl IntoResponse {
    let zone = match DnsZone::new(&state.runtime.core().config().zone) {
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
    upsert_entry(&mut state, DnsEntry {
        name,
        ip: payload.ip,
        ttl: payload.ttl,
    });

    if let Err(e) = save_dns_state(&state) {
        return error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::IoError,
            &e.to_string(),
        )
        .into_response();
    }

    Json(EntriesResponse {
        entries: state.entries,
    })
    .into_response()
}

async fn remove_entry_handler(
    State(state): State<DnsHttpState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let zone = match DnsZone::new(&state.runtime.core().config().zone) {
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

    Json(EntriesResponse {
        entries: state.entries,
    })
    .into_response()
}

async fn start_handler(State(state): State<DnsHttpState>) -> impl IntoResponse {
    match state.runtime.start().await {
        Ok(started) => Json(serde_json::json!({ "started": started })).into_response(),
        Err(e) => error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            &e.to_string(),
        )
        .into_response(),
    }
}

async fn stop_handler(State(state): State<DnsHttpState>) -> impl IntoResponse {
    let stopped = state.runtime.stop().await;
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
