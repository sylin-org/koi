//! Typed HTTP adapter for the Trust domain.
//!
//! The router is mounted by `koi-serve`; every handler delegates to the one
//! composition-owned [`TrustCore`] supplied as an extension. Authentication is
//! a serving concern, while request/response truth stays owned by this domain.

use std::sync::Arc;

use axum::extract::Extension;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use koi_common::error::ErrorCode;

use crate::{
    InstallRoot, TrustCore, TrustError, TrustMutation, TrustPresence, TrustRecovery, TrustStatus,
};

/// Route paths shared by the domain router, serving composition, and clients.
pub mod paths {
    pub const PREFIX: &str = "/v1/trust";
    pub const STATUS: &str = "/v1/trust/status";
    pub const INSTALL: &str = "/v1/trust/install";
    pub const ENSURE: &str = "/v1/trust/ensure";
    pub const REMOVE: &str = "/v1/trust/remove";
    pub const INSPECT: &str = "/v1/trust/inspect";
    pub const RECONCILE: &str = "/v1/trust/reconcile";

    /// Strip the mount prefix for an axum router nested at [`PREFIX`].
    pub fn rel(full: &str) -> &str {
        full.strip_prefix(PREFIX).unwrap_or(full)
    }
}

/// Remove one Koi-managed root by its domain name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RemoveRootRequest {
    pub name: String,
}

/// Inspect one concrete CA certificate through the selected owner's platform
/// adapter without modifying desired state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InspectCertificateRequest {
    pub certificate_pem: String,
}

/// Build the Trust router around one already-open aggregate owner.
pub fn routes(core: Arc<TrustCore>) -> Router {
    use paths::rel;

    Router::new()
        .route(rel(paths::STATUS), get(status_handler))
        .route(rel(paths::INSTALL), post(install_handler))
        .route(rel(paths::ENSURE), post(ensure_handler))
        .route(rel(paths::REMOVE), delete(remove_handler))
        .route(rel(paths::INSPECT), post(inspect_handler))
        .route(rel(paths::RECONCILE), post(reconcile_handler))
        .layer(Extension(core))
}

#[utoipa::path(get, path = "/status", tag = "trust",
    summary = "Read the authoritative Trust status projection",
    responses((status = 200, body = TrustStatus)))]
async fn status_handler(Extension(core): Extension<Arc<TrustCore>>) -> Json<TrustStatus> {
    Json(core.status().as_ref().clone())
}

#[utoipa::path(post, path = "/install", tag = "trust",
    summary = "Install one operator-managed CA root",
    request_body = InstallRoot,
    responses((status = 200, body = TrustMutation)))]
async fn install_handler(
    Extension(core): Extension<Arc<TrustCore>>,
    Json(request): Json<InstallRoot>,
) -> Response {
    mutation_response(core.install(request).await)
}

#[utoipa::path(post, path = "/ensure", tag = "trust",
    summary = "Ensure one source-owned CA root is installed",
    request_body = InstallRoot,
    responses((status = 200, body = TrustMutation)))]
async fn ensure_handler(
    Extension(core): Extension<Arc<TrustCore>>,
    Json(request): Json<InstallRoot>,
) -> Response {
    mutation_response(core.ensure_installed(request).await)
}

#[utoipa::path(delete, path = "/remove", tag = "trust",
    summary = "Remove one Koi-managed CA root",
    request_body = RemoveRootRequest,
    responses((status = 200, body = TrustMutation)))]
async fn remove_handler(
    Extension(core): Extension<Arc<TrustCore>>,
    Json(request): Json<RemoveRootRequest>,
) -> Response {
    mutation_response(core.remove(&request.name).await)
}

#[utoipa::path(post, path = "/inspect", tag = "trust",
    summary = "Inspect a certificate in the selected owner's platform trust store",
    request_body = InspectCertificateRequest,
    responses((status = 200, body = TrustPresence)))]
async fn inspect_handler(
    Extension(core): Extension<Arc<TrustCore>>,
    Json(request): Json<InspectCertificateRequest>,
) -> Response {
    match core.inspect(&request.certificate_pem).await {
        Ok(presence) => Json(presence).into_response(),
        Err(error) => error_response(error),
    }
}

#[utoipa::path(post, path = "/reconcile", tag = "trust",
    summary = "Recover pending Trust intent and refresh platform truth",
    responses((status = 200, body = TrustRecovery)))]
async fn reconcile_handler(Extension(core): Extension<Arc<TrustCore>>) -> Response {
    match core.reconcile().await {
        Ok(recovery) => Json(recovery).into_response(),
        Err(error) => error_response(error),
    }
}

fn mutation_response(result: Result<TrustMutation, TrustError>) -> Response {
    match result {
        Ok(mutation) => Json(mutation).into_response(),
        Err(error) => error_response(error),
    }
}

fn error_response(error: TrustError) -> Response {
    let code = match &error {
        TrustError::InvalidCertificate(_) => ErrorCode::InvalidPayload,
        TrustError::Conflict(_) => ErrorCode::Conflict,
        TrustError::NotFound(_) => ErrorCode::NotFound,
        TrustError::Io(_) => ErrorCode::IoError,
        TrustError::Platform(_) => ErrorCode::ProviderUnavailable,
        TrustError::ShutDown => ErrorCode::ShuttingDown,
        TrustError::DurabilityUncertain(_) | TrustError::Worker(_) => ErrorCode::Internal,
    };
    koi_common::http::error_response(code, error.to_string()).into_response()
}

/// OpenAPI description of the Trust-owned operator surface.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        status_handler,
        install_handler,
        ensure_handler,
        remove_handler,
        inspect_handler,
        reconcile_handler
    ),
    components(schemas(
        InstallRoot,
        RemoveRootRequest,
        InspectCertificateRequest,
        TrustMutation,
        TrustPresence,
        TrustRecovery,
        TrustStatus,
        crate::TrustRootStatus,
        crate::TrustPendingStatus,
        crate::TrustOperation,
    ))
)]
pub struct TrustApiDoc;

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use utoipa::OpenApi;

    use super::*;

    fn certificate(name: &str) -> String {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    async fn response_json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn typed_routes_drive_one_owner_and_return_authoritative_truth() {
        let data_dir = koi_common::test::ensure_data_dir("koi-trust-http-tests")
            .join(koi_common::id::generate_short_id());
        let (core, _) = TrustCore::open_memory(data_dir).await.unwrap();
        let core = Arc::new(core);
        let app = routes(Arc::clone(&core));
        let pem = certificate("http-root");
        let request = InstallRoot {
            name: "http-root".into(),
            source: "operator".into(),
            certificate_pem: pem.clone(),
        };

        let response = app
            .clone()
            .oneshot(
                Request::post(paths::rel(paths::INSTALL))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let installed: TrustMutation = response_json(response).await;
        assert!(installed.changed);
        assert!(installed.fingerprint.is_some());

        let response = app
            .clone()
            .oneshot(
                Request::post(paths::rel(paths::ENSURE))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let ensured: TrustMutation = response_json(response).await;
        assert!(
            !ensured.changed,
            "the same desired root is a semantic no-op"
        );

        let response = app
            .clone()
            .oneshot(
                Request::get(paths::rel(paths::STATUS))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status: TrustStatus = response_json(response).await;
        assert_eq!(status.roots.len(), 1);
        assert_eq!(status.roots[0].presence, TrustPresence::Present);

        let response = app
            .clone()
            .oneshot(
                Request::post(paths::rel(paths::INSPECT))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&InspectCertificateRequest {
                            certificate_pem: pem,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let presence: TrustPresence = response_json(response).await;
        assert_eq!(presence, TrustPresence::Present);

        let response = app
            .clone()
            .oneshot(
                Request::post(paths::rel(paths::RECONCILE))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let recovery: TrustRecovery = response_json(response).await;
        assert_eq!(recovery, TrustRecovery::Clean);

        let response = app
            .clone()
            .oneshot(
                Request::delete(paths::rel(paths::REMOVE))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&RemoveRootRequest {
                            name: "http-root".into(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let removed: TrustMutation = response_json(response).await;
        assert!(removed.changed);
        assert!(core.status().roots.is_empty());

        drop(app);
        core.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn invalid_certificate_is_a_typed_client_error() {
        let data_dir = koi_common::test::ensure_data_dir("koi-trust-http-error-tests")
            .join(koi_common::id::generate_short_id());
        let (core, _) = TrustCore::open_memory(data_dir).await.unwrap();
        let core = Arc::new(core);
        let response = routes(Arc::clone(&core))
            .oneshot(
                Request::post(paths::rel(paths::INSPECT))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&InspectCertificateRequest {
                            certificate_pem: "not a certificate".into(),
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: koi_common::api::ErrorBody = response_json(response).await;
        assert_eq!(error.error, ErrorCode::InvalidPayload);
        core.shutdown().await.unwrap();
    }

    #[test]
    fn openapi_contains_every_real_trust_route() {
        let document = TrustApiDoc::openapi();
        for path in [
            "/status",
            "/install",
            "/ensure",
            "/remove",
            "/inspect",
            "/reconcile",
        ] {
            assert!(document.paths.paths.contains_key(path), "missing {path}");
        }
    }
}
