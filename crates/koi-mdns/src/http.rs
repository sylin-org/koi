use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Path, Query};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post, put};
use axum::Router;
use tokio_stream::Stream;

use koi_common::error::ErrorCode;
use koi_common::pipeline::PipelineResponse;
use utoipa::IntoParams;

use crate::error::MdnsError;
use crate::protocol::{
    AdminRegistration, DaemonStatus, RegisterPayload, RegistrationCounts, RegistrationResult,
    RenewalResult, Response,
};
use crate::{LeasePolicy, MdnsCore};

/// Default heartbeat lease duration for HTTP-registered services.
const DEFAULT_HEARTBEAT_LEASE: Duration = Duration::from_secs(90);

/// Default grace period after a heartbeat lease expires before removal.
const DEFAULT_HEARTBEAT_GRACE: Duration = Duration::from_secs(30);

/// Default idle timeout for SSE streams (seconds).
/// Stream closes after this duration with no new events.
const DEFAULT_SSE_IDLE: Duration = Duration::from_secs(5);

#[derive(Debug, serde::Deserialize, IntoParams)]
pub struct BrowseParams {
    #[serde(rename = "type", default)]
    pub service_type: Option<String>,
    pub idle_for: Option<u64>,
}

#[derive(Debug, serde::Deserialize, IntoParams)]
pub struct ResolveParams {
    pub name: String,
}

#[derive(Debug, serde::Deserialize, IntoParams)]
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

/// Route path constants - single source of truth for axum routing AND the command manifest.
pub mod paths {
    pub const PREFIX: &str = "/v1/mdns";

    pub const DISCOVER: &str = "/v1/mdns/discover";
    pub const ANNOUNCE: &str = "/v1/mdns/announce";
    pub const UNREGISTER: &str = "/v1/mdns/unregister/{id}";
    pub const RESOLVE: &str = "/v1/mdns/resolve";
    pub const SUBSCRIBE: &str = "/v1/mdns/subscribe";
    pub const HEARTBEAT: &str = "/v1/mdns/heartbeat/{id}";
    pub const ADMIN_STATUS: &str = "/v1/mdns/admin/status";
    pub const ADMIN_LS: &str = "/v1/mdns/admin/ls";
    pub const ADMIN_INSPECT: &str = "/v1/mdns/admin/inspect/{id}";
    pub const ADMIN_UNREGISTER: &str = "/v1/mdns/admin/unregister/{id}";
    pub const ADMIN_DRAIN: &str = "/v1/mdns/admin/drain/{id}";
    pub const ADMIN_REVIVE: &str = "/v1/mdns/admin/revive/{id}";

    /// Strip the crate nest prefix to get the relative path for axum routing.
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

pub fn routes(core: Arc<MdnsCore>) -> Router {
    use paths::rel;
    Router::new()
        .route(rel(paths::DISCOVER), get(browse_handler))
        .route(rel(paths::ANNOUNCE), post(register_handler))
        .route(rel(paths::UNREGISTER), delete(unregister_handler))
        .route(rel(paths::HEARTBEAT), put(heartbeat_handler))
        .route(rel(paths::RESOLVE), get(resolve_handler))
        .route(rel(paths::SUBSCRIBE), get(events_handler))
        .route(rel(paths::ADMIN_STATUS), get(admin_status_handler))
        .route(rel(paths::ADMIN_LS), get(admin_registrations_handler))
        .route(rel(paths::ADMIN_INSPECT), get(admin_inspect_handler))
        .route(
            rel(paths::ADMIN_UNREGISTER),
            delete(admin_unregister_handler),
        )
        .route(rel(paths::ADMIN_DRAIN), post(admin_drain_handler))
        .route(rel(paths::ADMIN_REVIVE), post(admin_revive_handler))
        .layer(Extension(core))
}

/// Browse for mDNS services (SSE stream).
async fn browse_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
    Query(params): Query<BrowseParams>,
) -> impl IntoResponse {
    let browse_type = params
        .service_type
        .as_deref()
        .unwrap_or(koi_common::types::META_QUERY);
    let handle = match core.browse(browse_type).await {
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
                    Err(_) => break, // idle timeout - close stream
                },
                None => handle.recv().await,
            };
            match next {
                Some(event) => {
                    let resp = crate::protocol::browse_event_to_pipeline(event);
                    let data = serde_json::to_string(&resp).unwrap();
                    let id = uuid::Uuid::now_v7().to_string();
                    yield Ok::<_, std::convert::Infallible>(Event::default().id(id).data(data));
                }
                None => break,
            }
        }
    };

    Sse::new(stream).into_response()
}

/// Register a new mDNS service.
async fn register_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
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

/// Unregister an mDNS service.
async fn unregister_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
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

/// Resolve an mDNS service by name.
async fn resolve_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
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

/// Subscribe to mDNS events (SSE stream).
async fn events_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
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
                    Err(_) => break, // idle timeout - close stream
                },
                None => handle.recv().await,
            };
            match next {
                Some(event) => {
                    let resp = crate::protocol::subscribe_event_to_pipeline(event);
                    let data = serde_json::to_string(&resp).unwrap();
                    let id = uuid::Uuid::now_v7().to_string();
                    yield Ok::<_, std::convert::Infallible>(Event::default().id(id).data(data));
                }
                None => break,
            }
        }
    };

    Sse::new(stream).into_response()
}

/// Renew a service lease (heartbeat).
async fn heartbeat_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.heartbeat(&id) {
        Ok(lease_secs) => {
            let resp = PipelineResponse::clean(Response::Renewed(RenewalResult { id, lease_secs }));
            Json(resp).into_response()
        }
        Err(e) => error_json(e).into_response(),
    }
}

// ── Admin ─────────────────────────────────────────────────────────────
/// Daemon status overview.
async fn admin_status_handler(Extension(core): Extension<Arc<MdnsCore>>) -> impl IntoResponse {
    Json(core.admin_status())
}

/// List all registrations.
async fn admin_registrations_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
) -> impl IntoResponse {
    let entries: Vec<_> = core
        .admin_registrations()
        .into_iter()
        .map(|(_, admin)| admin)
        .collect();
    Json(entries)
}

/// Inspect a single registration.
async fn admin_inspect_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.admin_inspect(&id) {
        Ok(admin) => Json(serde_json::to_value(admin).unwrap()).into_response(),
        Err(e) => error_json(e).into_response(),
    }
}

/// Force-unregister a service.
async fn admin_unregister_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
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

/// Drain a registration (mark for removal).
async fn admin_drain_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.admin_drain(&id) {
        Ok(()) => Json(serde_json::json!({"drained": id})).into_response(),
        Err(e) => error_json(e).into_response(),
    }
}

/// Revive a draining registration.
async fn admin_revive_handler(
    Extension(core): Extension<Arc<MdnsCore>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match core.admin_revive(&id) {
        Ok(()) => Json(serde_json::json!({"revived": id})).into_response(),
        Err(e) => error_json(e).into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

fn error_json(e: MdnsError) -> impl IntoResponse {
    let code = ErrorCode::from(&e);
    let status_code = axum::http::StatusCode::from_u16(code.http_status())
        .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    (status_code, Json(crate::protocol::error_to_pipeline(&e)))
}

fn error_event_stream(
    e: MdnsError,
) -> impl Stream<Item = std::result::Result<Event, std::convert::Infallible>> {
    let data = serde_json::to_string(&crate::protocol::error_to_pipeline(&e)).unwrap();
    async_stream::stream! {
        let id = uuid::Uuid::now_v7().to_string();
        yield Ok(Event::default().id(id).data(data));
    }
}

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

/// OpenAPI documentation for the mDNS domain.
#[derive(utoipa::OpenApi)]
#[openapi(components(schemas(
    RegisterPayload,
    RegistrationResult,
    RenewalResult,
    AdminRegistration,
    DaemonStatus,
    RegistrationCounts,
    crate::protocol::LeaseMode,
    crate::protocol::LeaseState,
)))]
pub struct MdnsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // ── idle_duration tests ──────────────────────────────────────────

    #[test]
    fn idle_duration_absent_returns_default_5s() {
        let d = idle_duration(None);
        assert_eq!(d, Some(Duration::from_secs(5)));
    }

    #[test]
    fn idle_duration_zero_returns_none_infinite() {
        let d = idle_duration(Some(0));
        assert_eq!(d, None);
    }

    #[test]
    fn idle_duration_explicit_value() {
        let d = idle_duration(Some(15));
        assert_eq!(d, Some(Duration::from_secs(15)));
    }

    #[test]
    fn idle_duration_one_second() {
        let d = idle_duration(Some(1));
        assert_eq!(d, Some(Duration::from_secs(1)));
    }

    // ── policy_from_lease_secs tests ─────────────────────────────────

    #[test]
    fn policy_from_none_returns_default_heartbeat() {
        let policy = policy_from_lease_secs(None);
        assert!(matches!(
            policy,
            LeasePolicy::Heartbeat { lease, grace }
            if lease == Duration::from_secs(90) && grace == Duration::from_secs(30)
        ));
    }

    #[test]
    fn policy_from_zero_returns_permanent() {
        let policy = policy_from_lease_secs(Some(0));
        assert!(matches!(policy, LeasePolicy::Permanent));
    }

    #[test]
    fn policy_from_custom_returns_heartbeat_with_custom_lease() {
        let policy = policy_from_lease_secs(Some(300));
        assert!(matches!(
            policy,
            LeasePolicy::Heartbeat { lease, grace }
            if lease == Duration::from_secs(300) && grace == Duration::from_secs(30)
        ));
    }

    // ── BrowseParams deserialization ─────────────────────────────────

    #[test]
    fn browse_params_deserializes_type_field() {
        let json = r#"{"type": "_http._tcp"}"#;
        let params: BrowseParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.service_type.as_deref(), Some("_http._tcp"));
        assert!(params.idle_for.is_none());
    }

    #[test]
    fn browse_params_type_is_optional() {
        let json = r#"{}"#;
        let params: BrowseParams = serde_json::from_str(json).unwrap();
        assert!(params.service_type.is_none());
    }

    #[test]
    fn browse_params_deserializes_idle_for() {
        let json = r#"{"type": "_http._tcp", "idle_for": 10}"#;
        let params: BrowseParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.idle_for, Some(10));
    }

    #[test]
    fn resolve_params_deserializes_name() {
        let json = r#"{"name": "My NAS._http._tcp.local."}"#;
        let params: ResolveParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.name, "My NAS._http._tcp.local.");
    }

    // ── error_json helper ───────────────────────────────────────────

    #[tokio::test]
    async fn error_json_not_found_maps_to_404() {
        let resp = error_json(MdnsError::RegistrationNotFound("abc".into())).into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn error_json_invalid_type_maps_to_400() {
        let resp = error_json(MdnsError::InvalidServiceType("bad".into())).into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn error_json_body_is_json_with_error_field() {
        let resp = error_json(MdnsError::RegistrationNotFound("xyz".into())).into_response();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("error").is_some());
        assert!(json.get("message").is_some());
    }

    // ── EventsParams deserialization ─────────────────────────────────

    #[test]
    fn events_params_deserializes() {
        let json = r#"{"type": "_http._tcp", "idle_for": 0}"#;
        let params: EventsParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.service_type, "_http._tcp");
        assert_eq!(params.idle_for, Some(0));
    }

    #[test]
    fn events_params_without_idle_for() {
        let json = r#"{"type": "_ssh._tcp"}"#;
        let params: EventsParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.service_type, "_ssh._tcp");
        assert!(params.idle_for.is_none());
    }

    // ── Constants ───────────────────────────────────────────────────

    #[test]
    fn default_heartbeat_lease_is_90s() {
        assert_eq!(DEFAULT_HEARTBEAT_LEASE, Duration::from_secs(90));
    }

    #[test]
    fn default_heartbeat_grace_is_30s() {
        assert_eq!(DEFAULT_HEARTBEAT_GRACE, Duration::from_secs(30));
    }

    #[test]
    fn default_sse_idle_is_5s() {
        assert_eq!(DEFAULT_SSE_IDLE, Duration::from_secs(5));
    }

    // ── policy_from_lease_secs edge cases ───────────────────────────

    #[test]
    fn policy_from_one_second_returns_heartbeat() {
        let policy = policy_from_lease_secs(Some(1));
        assert!(matches!(
            policy,
            LeasePolicy::Heartbeat { lease, .. }
            if lease == Duration::from_secs(1)
        ));
    }

    #[test]
    fn policy_from_u64_max_returns_heartbeat() {
        let policy = policy_from_lease_secs(Some(u64::MAX));
        assert!(matches!(policy, LeasePolicy::Heartbeat { .. }));
    }

    // ── UUIDv7 SSE event ID tests ───────────────────────────────────

    #[test]
    fn uuid_v7_is_valid_sse_id() {
        let id = uuid::Uuid::now_v7().to_string();
        assert_eq!(id.len(), 36, "UUIDv7 string should be 36 chars: {id}");
        assert!(!id.contains('\n'), "must not contain newlines");
        assert!(!id.contains('\r'), "must not contain carriage returns");
    }

    #[test]
    fn uuid_v7_is_monotonic() {
        let a = uuid::Uuid::now_v7().to_string();
        let b = uuid::Uuid::now_v7().to_string();
        assert!(a <= b, "UUIDv7 should be monotonic: {a} <= {b}");
    }

    #[test]
    fn uuid_v7_is_unique() {
        let ids: std::collections::HashSet<String> =
            (0..100).map(|_| uuid::Uuid::now_v7().to_string()).collect();
        assert_eq!(ids.len(), 100, "100 UUIDv7 IDs should all be unique");
    }
}
