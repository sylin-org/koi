//! Authenticated machine-local HTTP adapter for personal preferences.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, put};
use axum::Router;
use koi_common::error::ErrorCode;
use koi_common::service::{
    PreferenceErrorBody, PreferredServiceContext, ServiceId, SetCandidatePreferenceRequest,
    SetServicePreferenceRequest, PREFERENCES_SCHEMA,
};
use koi_compose::catalog::ServiceCatalogRuntime;
use koi_preferences::{PreferencesCore, PreferencesError};

#[derive(Clone)]
pub(crate) struct PreferencesState {
    preferences: Arc<PreferencesCore>,
    catalog: Arc<ServiceCatalogRuntime>,
}

pub fn routes(preferences: Arc<PreferencesCore>, catalog: Arc<ServiceCatalogRuntime>) -> Router {
    Router::new()
        .route(crate::http::paths::PREFERENCES, get(status))
        .route("/v1/preferences/services/{service_id}", put(set_service))
        .route(
            "/v1/preferences/candidates/{candidate_id}",
            put(set_candidate),
        )
        .layer(middleware::from_fn(local_operator_middleware))
        .with_state(PreferencesState {
            preferences,
            catalog,
        })
}

pub(crate) async fn local_operator_middleware(req: Request, next: Next) -> Response {
    if req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }
    let local = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|peer| peer.0.ip().is_loopback());
    if local {
        next.run(req).await
    } else {
        preference_error_response(
            StatusCode::FORBIDDEN,
            PreferenceErrorBody {
                error: ErrorCode::LocalOperatorRequired,
                message: "Personal preferences are available only to this machine's operator."
                    .into(),
                current_revision: None,
                found_schema: None,
                minimum_schema: None,
                maximum_schema: None,
            },
        )
    }
}

#[utoipa::path(get, path = "/v1/preferences", tag = "preferences",
    responses((status = 200, body = koi_common::service::PreferencesStatus)))]
pub(crate) async fn status(
    State(state): State<PreferencesState>,
) -> Json<Arc<koi_common::service::PreferencesStatus>> {
    Json(state.preferences.status())
}

#[utoipa::path(put, path = "/v1/preferences/services/{service_id}", tag = "preferences",
    request_body = SetServicePreferenceRequest,
    responses((status = 200, body = koi_common::service::PreferencesStatus)))]
pub(crate) async fn set_service(
    State(state): State<PreferencesState>,
    Path(service_id): Path<String>,
    Json(request): Json<SetServicePreferenceRequest>,
) -> Response {
    let service_id = match ServiceId::new(service_id) {
        Ok(service_id) => service_id,
        Err(_) => return invalid("service id is invalid"),
    };
    if request.service_key.service_id() != &service_id {
        return invalid("request service key does not match the route service id");
    }
    let snapshot = state.catalog.status();
    let context = snapshot
        .services
        .iter()
        .find(|service| service.id == service_id)
        .map(|service| {
            let device_name = snapshot
                .devices
                .iter()
                .find(|device| device.id == service.device_id)
                .and_then(|device| device.names.first())
                .map(|name| name.value.clone());
            let last_seen = service
                .observations
                .iter()
                .map(|observation| observation.observed_at)
                .max()
                .unwrap_or(snapshot.generated_at);
            PreferredServiceContext {
                device_id: service.device_id.clone(),
                display_name: service.display_name.clone(),
                device_name,
                kind: service.kind.clone(),
                last_condition: service.condition,
                last_seen,
            }
        });
    let known_preference = state
        .preferences
        .status()
        .services
        .iter()
        .any(|record| record.service_key.service_id() == &service_id);
    if context.is_none() && !known_preference {
        return preference_error_response(
            StatusCode::NOT_FOUND,
            PreferenceErrorBody {
                error: ErrorCode::NotFound,
                message: "service is not present and has no retained preference".into(),
                current_revision: None,
                found_schema: None,
                minimum_schema: None,
                maximum_schema: None,
            },
        );
    }
    command_result(state.preferences.set_service(request, context))
}

#[utoipa::path(put, path = "/v1/preferences/candidates/{candidate_id}", tag = "preferences",
    request_body = SetCandidatePreferenceRequest,
    responses((status = 200, body = koi_common::service::PreferencesStatus)))]
pub(crate) async fn set_candidate(
    State(state): State<PreferencesState>,
    Path(candidate_id): Path<String>,
    Json(request): Json<SetCandidatePreferenceRequest>,
) -> Response {
    let candidate_id = match ServiceId::new(candidate_id) {
        Ok(candidate_id) => candidate_id,
        Err(_) => return invalid("candidate id is invalid"),
    };
    let snapshot = state.catalog.status();
    let known_candidate = snapshot
        .local_candidates
        .iter()
        .any(|candidate| candidate.id == candidate_id && candidate.key == request.candidate_key);
    let known_preference = state.preferences.status().candidates.iter().any(|record| {
        record.candidate_id == candidate_id && record.candidate_key == request.candidate_key
    });
    if !known_candidate && !known_preference {
        return preference_error_response(
            StatusCode::NOT_FOUND,
            PreferenceErrorBody {
                error: ErrorCode::NotFound,
                message: "candidate is not present and has no retained dismissal".into(),
                current_revision: None,
                found_schema: None,
                minimum_schema: None,
                maximum_schema: None,
            },
        );
    }
    command_result(state.preferences.set_candidate(candidate_id, request))
}

fn command_result(
    value: Result<Arc<koi_common::service::PreferencesStatus>, PreferencesError>,
) -> Response {
    match value {
        Ok(status) => Json(status).into_response(),
        Err(error) => preference_error_response(
            StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.error_body(),
        ),
    }
}

fn invalid(message: &str) -> Response {
    preference_error_response(
        StatusCode::BAD_REQUEST,
        PreferenceErrorBody {
            error: ErrorCode::InvalidPayload,
            message: message.into(),
            current_revision: None,
            found_schema: None,
            minimum_schema: Some(PREFERENCES_SCHEMA),
            maximum_schema: Some(PREFERENCES_SCHEMA),
        },
    )
}

fn preference_error_response(status: StatusCode, body: PreferenceErrorBody) -> Response {
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn with_peer(mut request: Request<Body>, peer: &str) -> Request<Body> {
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        request
    }

    #[tokio::test]
    async fn preference_surface_requires_a_loopback_peer() {
        let app = Router::new()
            .route("/v1/preferences", get(|| async { "ok" }))
            .layer(middleware::from_fn(local_operator_middleware));
        let remote = with_peer(
            Request::get("/v1/preferences").body(Body::empty()).unwrap(),
            "192.168.1.50:40000",
        );
        let response = app.clone().oneshot(remote).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let local = with_peer(
            Request::get("/v1/preferences").body(Body::empty()).unwrap(),
            "127.0.0.1:40000",
        );
        assert_eq!(app.oneshot(local).await.unwrap().status(), StatusCode::OK);
    }

    fn authenticated_preference_test_router() -> Router {
        let expected = Arc::new("secret-token".to_string());
        Router::new()
            .route("/v1/preferences", get(|| async { "ok" }))
            .route("/v1/preferences/services/svc_one", put(|| async { "ok" }))
            .layer(middleware::from_fn(local_operator_middleware))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                crate::http::dat_auth_middleware(req, next, expected)
            }))
    }

    #[tokio::test]
    async fn preference_auth_requires_dat_then_enforces_local_operator_boundary() {
        let local = with_peer(
            Request::get("/v1/preferences").body(Body::empty()).unwrap(),
            "127.0.0.1:40000",
        );
        assert_eq!(
            authenticated_preference_test_router()
                .oneshot(local)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        let local = with_peer(
            Request::get("/v1/preferences")
                .header("x-koi-token", "secret-token")
                .body(Body::empty())
                .unwrap(),
            "127.0.0.1:40000",
        );
        assert_eq!(
            authenticated_preference_test_router()
                .oneshot(local)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        let remote = with_peer(
            Request::put("/v1/preferences/services/svc_one")
                .header("x-koi-token", "secret-token")
                .body(Body::empty())
                .unwrap(),
            "192.168.1.50:40000",
        );
        let response = authenticated_preference_test_router()
            .oneshot(remote)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: PreferenceErrorBody = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.error, ErrorCode::LocalOperatorRequired);

        let remote = with_peer(
            Request::put("/v1/preferences/services/svc_one")
                .header("x-koi-token", "wrong-token")
                .body(Body::empty())
                .unwrap(),
            "192.168.1.50:40000",
        );
        assert_eq!(
            authenticated_preference_test_router()
                .oneshot(remote)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
