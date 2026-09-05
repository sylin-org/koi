//! Typed operator catalog snapshot and coalescing subscription.

use std::convert::Infallible;
use std::sync::Arc;

use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use koi_compose::catalog::ServiceCatalogRuntime;

pub fn routes(catalog: Arc<ServiceCatalogRuntime>) -> Router {
    Router::new()
        .route(crate::http::paths::CATALOG, get(snapshot))
        .route(crate::http::paths::CATALOG_EVENTS, get(events))
        .with_state(catalog)
}

#[utoipa::path(get, path = "/v1/catalog", tag = "catalog",
    responses((status = 200, body = koi_common::service::CatalogSnapshot)))]
pub(crate) async fn snapshot(
    axum::extract::State(catalog): axum::extract::State<Arc<ServiceCatalogRuntime>>,
) -> Json<Arc<koi_common::service::CatalogSnapshot>> {
    Json(catalog.status())
}

#[utoipa::path(get, path = "/v1/catalog/events", tag = "catalog",
    responses((status = 200, description = "Catalog snapshot SSE stream")))]
pub(crate) async fn events(
    axum::extract::State(catalog): axum::extract::State<Arc<ServiceCatalogRuntime>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let mut snapshots = catalog.watch_status();
    let stream = async_stream::stream! {
        loop {
            let snapshot = snapshots.borrow_and_update().clone();
            let id = format!("{}:{}", snapshot.epoch, snapshot.revision);
            match Event::default().event("catalog").id(id).json_data(snapshot.as_ref()) {
                Ok(event) => yield Ok(event),
                Err(error) => {
                    tracing::error!(%error, "catalog SSE serialization failed");
                    break;
                }
            }
            if snapshots.changed().await.is_err() {
                break;
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn snapshot_is_the_catalogs_typed_current_value() {
        let catalog = Arc::new(ServiceCatalogRuntime::default());
        let expected = catalog.status();
        let response = routes(catalog)
            .oneshot(Request::get("/v1/catalog").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let actual: koi_common::service::CatalogSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(actual, *expected);
    }
}
