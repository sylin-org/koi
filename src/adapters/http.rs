use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post, put};
use axum::Router;
use tokio_stream::Stream;
use tower_http::cors::CorsLayer;

use tokio_util::sync::CancellationToken;

use crate::core::{LeasePolicy, MdnsCore};
use crate::protocol::error::ErrorCode;
use crate::protocol::response::{PipelineResponse, Response};
use crate::protocol::RegisterPayload;

/// Default heartbeat lease duration for HTTP-registered services.
const DEFAULT_HEARTBEAT_LEASE: Duration = Duration::from_secs(90);

/// Default grace period after a heartbeat lease expires before removal.
const DEFAULT_HEARTBEAT_GRACE: Duration = Duration::from_secs(30);

/// Default idle timeout for SSE streams (seconds).
/// Stream closes after this duration with no new events.
const DEFAULT_SSE_IDLE: Duration = Duration::from_secs(5);

#[derive(Debug, serde::Deserialize)]
pub struct BrowseParams {
    #[serde(rename = "type")]
    pub service_type: String,
    pub idle_for: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ResolveParams {
    pub name: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct EventsParams {
    #[serde(rename = "type")]
    pub service_type: String,
    pub idle_for: Option<u64>,
}

/// Parse the `idle_for` query parameter into an optional duration.
/// - `None` (absent) → `Some(DEFAULT_SSE_IDLE)` (5s default)
/// - `Some(0)` → `None` (infinite, no timeout)
/// - `Some(n)` → `Some(Duration::from_secs(n))`
fn idle_duration(idle_for: Option<u64>) -> Option<Duration> {
    match idle_for {
        None => Some(DEFAULT_SSE_IDLE),
        Some(0) => None,
        Some(n) => Some(Duration::from_secs(n)),
    }
}

/// Start the HTTP adapter on the given port with graceful shutdown support.
pub async fn start(
    core: Arc<MdnsCore>,
    port: u16,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let app = router(core);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "HTTP adapter listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await?;
    tracing::debug!("HTTP adapter stopped");
    Ok(())
}

/// Build the router (public for testing).
pub fn router(core: Arc<MdnsCore>) -> Router {
    Router::new()
        .route("/v1/browse", get(browse_handler))
        .route("/v1/services", post(register_handler))
        .route("/v1/services/{id}", delete(unregister_handler))
        .route("/v1/services/{id}/heartbeat", put(heartbeat_handler))
        .route("/v1/resolve", get(resolve_handler))
        .route("/v1/events", get(events_handler))
        .route("/v1/admin/status", get(admin_status_handler))
        .route("/v1/admin/registrations", get(admin_registrations_handler))
        .route(
            "/v1/admin/registrations/{id}",
            get(admin_inspect_handler).delete(admin_unregister_handler),
        )
        .route(
            "/v1/admin/registrations/{id}/drain",
            post(admin_drain_handler),
        )
        .route(
            "/v1/admin/registrations/{id}/revive",
            post(admin_revive_handler),
        )
        .route("/healthz", get(health_handler))
        .layer(CorsLayer::permissive())
        .with_state(core)
}

async fn browse_handler(
    State(core): State<Arc<MdnsCore>>,
    Query(params): Query<BrowseParams>,
) -> impl IntoResponse {
    let handle = match core.browse(&params.service_type).await {
        Ok(h) => h,
        Err(e) => return Sse::new(error_event_stream(e)).into_response(),
    };

    let idle = idle_duration(params.idle_for);
    let handle = Arc::new(handle);
    let stream = async_stream::stream! {
        loop {
            let next = match idle {
                Some(dur) => match tokio::time::timeout(dur, handle.recv()).await {
                    Ok(result) => result,
                    Err(_) => break, // idle timeout — close stream
                },
                None => handle.recv().await,
            };
            match next {
                Some(event) => {
                    let resp = PipelineResponse::from_browse_event(event);
                    let data = serde_json::to_string(&resp).unwrap();
                    yield Ok::<_, std::convert::Infallible>(Event::default().data(data));
                }
                None => break,
            }
        }
    };

    Sse::new(stream).into_response()
}

async fn register_handler(
    State(core): State<Arc<MdnsCore>>,
    Json(payload): Json<RegisterPayload>,
) -> impl IntoResponse {
    let policy = policy_from_lease_secs(payload.lease_secs);
    match core.register_with_policy(payload, policy, None) {
        Ok(result) => {
            let resp = PipelineResponse::clean(Response::Registered(result));
            (axum::http::StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => error_json(e).into_response(),
    }
}

async fn unregister_handler(
    State(core): State<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.unregister(&id) {
        Ok(()) => {
            let resp = PipelineResponse::clean(Response::Unregistered(id));
            Json(resp).into_response()
        }
        Err(e) => error_json(e).into_response(),
    }
}

async fn resolve_handler(
    State(core): State<Arc<MdnsCore>>,
    Query(params): Query<ResolveParams>,
) -> impl IntoResponse {
    match core.resolve(&params.name).await {
        Ok(record) => {
            let resp = PipelineResponse::clean(Response::Resolved(record));
            Json(resp).into_response()
        }
        Err(e) => error_json(e).into_response(),
    }
}

async fn events_handler(
    State(core): State<Arc<MdnsCore>>,
    Query(params): Query<EventsParams>,
) -> impl IntoResponse {
    let handle = match core.browse(&params.service_type).await {
        Ok(h) => h,
        Err(e) => return Sse::new(error_event_stream(e)).into_response(),
    };

    let idle = idle_duration(params.idle_for);
    let handle = Arc::new(handle);
    let stream = async_stream::stream! {
        loop {
            let next = match idle {
                Some(dur) => match tokio::time::timeout(dur, handle.recv()).await {
                    Ok(result) => result,
                    Err(_) => break, // idle timeout — close stream
                },
                None => handle.recv().await,
            };
            match next {
                Some(event) => {
                    let resp = PipelineResponse::from_subscribe_event(event);
                    let data = serde_json::to_string(&resp).unwrap();
                    yield Ok::<_, std::convert::Infallible>(Event::default().data(data));
                }
                None => break,
            }
        }
    };

    Sse::new(stream).into_response()
}

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true}))
}

fn error_json(e: crate::core::KoiError) -> impl IntoResponse {
    let code = ErrorCode::from(&e);
    let status_code = axum::http::StatusCode::from_u16(code.http_status())
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    (status_code, Json(PipelineResponse::from_error(&e)))
}

fn error_event_stream(
    e: crate::core::KoiError,
) -> impl Stream<Item = std::result::Result<Event, std::convert::Infallible>> {
    let data = serde_json::to_string(&PipelineResponse::from_error(&e)).unwrap();
    async_stream::stream! {
        yield Ok(Event::default().data(data));
    }
}

// ── Heartbeat ─────────────────────────────────────────────────────────

async fn heartbeat_handler(
    State(core): State<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.heartbeat(&id) {
        Ok(lease_secs) => {
            let resp = PipelineResponse::clean(Response::Renewed(crate::protocol::RenewalResult {
                id,
                lease_secs,
            }));
            Json(resp).into_response()
        }
        Err(e) => error_json(e).into_response(),
    }
}

// ── Admin ─────────────────────────────────────────────────────────────

async fn admin_status_handler(State(core): State<Arc<MdnsCore>>) -> impl IntoResponse {
    Json(core.admin_status())
}

async fn admin_registrations_handler(State(core): State<Arc<MdnsCore>>) -> impl IntoResponse {
    let entries: Vec<_> = core
        .admin_registrations()
        .into_iter()
        .map(|(_, admin)| admin)
        .collect();
    Json(entries)
}

async fn admin_inspect_handler(
    State(core): State<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.admin_inspect(&id) {
        Ok(admin) => Json(serde_json::to_value(admin).unwrap()).into_response(),
        Err(e) => error_json(e).into_response(),
    }
}

async fn admin_unregister_handler(
    State(core): State<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.admin_force_unregister(&id) {
        Ok(()) => {
            let resp = PipelineResponse::clean(Response::Unregistered(id));
            Json(resp).into_response()
        }
        Err(e) => error_json(e).into_response(),
    }
}

async fn admin_drain_handler(
    State(core): State<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.admin_drain(&id) {
        Ok(()) => Json(serde_json::json!({"drained": id})).into_response(),
        Err(e) => error_json(e).into_response(),
    }
}

async fn admin_revive_handler(
    State(core): State<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.admin_revive(&id) {
        Ok(()) => Json(serde_json::json!({"revived": id})).into_response(),
        Err(e) => error_json(e).into_response(),
    }
}

// ── Policy helper ─────────────────────────────────────────────────────

/// Determine lease policy from the optional `lease_secs` field in the register payload.
/// HTTP default: heartbeat with 90s lease, 30s grace.
fn policy_from_lease_secs(lease_secs: Option<u64>) -> LeasePolicy {
    match lease_secs {
        Some(0) => LeasePolicy::Permanent,
        Some(secs) => LeasePolicy::Heartbeat {
            lease: Duration::from_secs(secs),
            grace: DEFAULT_HEARTBEAT_GRACE,
        },
        None => LeasePolicy::Heartbeat {
            lease: DEFAULT_HEARTBEAT_LEASE,
            grace: DEFAULT_HEARTBEAT_GRACE,
        },
    }
}
