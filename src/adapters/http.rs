use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Json};
use axum::routing::{delete, get, post};
use axum::Router;
use tokio_stream::Stream;
use tower_http::cors::CorsLayer;

use crate::core::MdnsCore;
use crate::protocol::response::{PipelineResponse, Response};
use crate::protocol::RegisterPayload;

#[derive(Debug, serde::Deserialize)]
pub struct BrowseParams {
    #[serde(rename = "type")]
    pub service_type: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct ResolveParams {
    pub name: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct EventsParams {
    #[serde(rename = "type")]
    pub service_type: String,
}

/// Start the HTTP adapter on the given port.
pub async fn start(core: Arc<MdnsCore>, port: u16) -> anyhow::Result<()> {
    let app = router(core);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "HTTP adapter listening");

    axum::serve(listener, app).await?;
    Ok(())
}

/// Build the router (public for testing).
pub fn router(core: Arc<MdnsCore>) -> Router {
    Router::new()
        .route("/v1/browse", get(browse_handler))
        .route("/v1/services", post(register_handler))
        .route("/v1/services/{id}", delete(unregister_handler))
        .route("/v1/resolve", get(resolve_handler))
        .route("/v1/events", get(events_handler))
        .route("/healthz", get(health_handler))
        .layer(CorsLayer::permissive())
        .with_state(core)
}

async fn browse_handler(
    State(core): State<Arc<MdnsCore>>,
    Query(params): Query<BrowseParams>,
) -> impl IntoResponse {
    let handle = match core.browse(&params.service_type) {
        Ok(h) => h,
        Err(e) => return Sse::new(error_event_stream(e)).into_response(),
    };

    let handle = Arc::new(handle);
    let stream = async_stream::stream! {
        loop {
            match handle.recv().await {
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
    match core.register(payload) {
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
    let handle = match core.browse(&params.service_type) {
        Ok(h) => h,
        Err(e) => return Sse::new(error_event_stream(e)).into_response(),
    };

    let handle = Arc::new(handle);
    let stream = async_stream::stream! {
        loop {
            match handle.recv().await {
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
    let status_code = match &e {
        crate::core::KoiError::InvalidServiceType(_) => axum::http::StatusCode::BAD_REQUEST,
        crate::core::KoiError::RegistrationNotFound(_) => axum::http::StatusCode::NOT_FOUND,
        crate::core::KoiError::ResolveTimeout(_) => axum::http::StatusCode::GATEWAY_TIMEOUT,
        _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
    };
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
