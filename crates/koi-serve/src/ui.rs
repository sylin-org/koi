//! Authenticated operator HTML on the existing HTTP adapter, never Pond.
use std::sync::Arc;

use axum::{
    extract::{RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use koi_compose::catalog::ServiceCatalogRuntime;
use koi_ui::{Links, View};

pub const SHELL: &str = "/v1/ui/shell";
/// The authenticated rendering API is used by operator integrations. Browser
/// onboarding is parked; no login page or browser transport is mounted.
pub(crate) fn routes(catalog: Arc<ServiceCatalogRuntime>) -> Router {
    Router::new()
        .route(SHELL, get(snapshot))
        .with_state(catalog)
}

async fn snapshot(
    State(catalog): State<Arc<ServiceCatalogRuntime>>,
    RawQuery(query): RawQuery,
) -> Response {
    let Ok(intent) = koi_ui::home::HomeRequest::parse(query.as_deref().unwrap_or("")) else {
        return (StatusCode::BAD_REQUEST, "Invalid Home query").into_response();
    };
    // Capture once, no join of domain reads, no presentation-owned live state.
    let snapshot = catalog.status();
    response(
        "text/html; charset=utf-8",
        koi_ui::render_home(
            View::Snapshot(&snapshot),
            Links {
                refresh: None,
                advanced: "/",
            },
            &intent.query(),
        ),
        koi_ui::DOCUMENT_CSP,
    )
}

fn response(content_type: &'static str, body: String, csp: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            ("content-type", content_type),
            ("cache-control", "no-store"),
            ("content-security-policy", csp),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("x-frame-options", "DENY"),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        extract::ConnectInfo,
        http::Request,
        middleware,
    };
    use tower::ServiceExt;

    fn app() -> Router {
        app_with(Arc::new(ServiceCatalogRuntime::default()))
    }

    fn app_with(catalog: Arc<ServiceCatalogRuntime>) -> Router {
        routes(catalog).layer(middleware::from_fn(|request, next| {
            crate::http::dat_auth_middleware(request, next, Arc::new("secret-token".into()))
        }))
    }

    #[tokio::test]
    async fn catalog_html_requires_token_for_every_peer_and_method() {
        for peer in ["127.0.0.1:1000", "192.0.2.1:1000", "[::1]:1000"] {
            for method in ["GET", "HEAD"] {
                for token in [None, Some("wrong"), Some("secret-token")] {
                    let mut request = Request::builder().uri(SHELL).method(method);
                    if let Some(token) = token {
                        request = request.header("x-koi-token", token);
                    }
                    let mut request = request.body(Body::empty()).unwrap();
                    request
                        .extensions_mut()
                        .insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
                    let reply = app().oneshot(request).await.unwrap();
                    assert_eq!(
                        reply.status(),
                        if token == Some("secret-token") {
                            StatusCode::OK
                        } else {
                            StatusCode::UNAUTHORIZED
                        }
                    );
                    let body = String::from_utf8(
                        to_bytes(reply.into_body(), usize::MAX)
                            .await
                            .unwrap()
                            .to_vec(),
                    )
                    .unwrap();
                    if token != Some("secret-token") {
                        assert!(!body.contains("Snapshot revision"));
                    }
                }
            }
        }
        let reply = app()
            .oneshot(Request::builder().uri(SHELL).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authorized_html_matches_shared_renderer_and_is_never_cached() {
        let catalog = Arc::new(ServiceCatalogRuntime::default());
        let expected = koi_ui::render(
            View::Snapshot(&catalog.status()),
            Links {
                refresh: None,
                advanced: "/",
            },
        );
        let reply = app_with(catalog)
            .oneshot(
                Request::builder()
                    .uri(SHELL)
                    .header("x-koi-token", "secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.headers()["cache-control"], "no-store");
        assert_eq!(
            reply.headers()["content-security-policy"],
            koi_ui::DOCUMENT_CSP
        );
        let body = String::from_utf8(
            to_bytes(reply.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body == expected,
            "adapter must render the captured authoritative snapshot"
        );
        assert!(!body.contains("secret-token"));
    }

    #[tokio::test]
    async fn parked_browser_routes_are_absent_even_with_operator_authorization() {
        for path in [
            "/ui",
            "/ui/transport.js",
            "/ui/refresh.js",
            "/ui/browser-access.js",
            "/ui/connect",
            "/ui/challenge",
            "/ui/session/shell",
            "/ui/disconnect",
            "/v1/browser-access",
            "/v1/browser-access/invitations",
            "/v1/browser-access/sessions/old-session",
        ] {
            for method in ["GET", "POST", "PUT", "DELETE"] {
                let response = app()
                    .oneshot(
                        Request::builder()
                            .uri(path)
                            .method(method)
                            .header("x-koi-token", "secret-token")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
            }
        }
    }

    #[tokio::test]
    async fn home_intent_is_rendered_only_after_authentication_and_rejects_unknown_fields() {
        for (query, expected) in [
            (
                "search=Office+web&selected=notes&favorites=1",
                StatusCode::OK,
            ),
            ("search=a&search=b", StatusCode::BAD_REQUEST),
            ("token=secret-token", StatusCode::BAD_REQUEST),
        ] {
            for authenticated in [false, true] {
                let mut request = Request::builder().uri(format!("{SHELL}?{query}"));
                if authenticated {
                    request = request.header("x-koi-token", "secret-token");
                }
                let reply = app()
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    reply.status(),
                    if authenticated {
                        expected
                    } else {
                        StatusCode::UNAUTHORIZED
                    }
                );
                if authenticated && expected == StatusCode::OK {
                    let body = String::from_utf8(
                        to_bytes(reply.into_body(), usize::MAX)
                            .await
                            .unwrap()
                            .to_vec(),
                    )
                    .unwrap();
                    assert!(body.contains("value=\"Office web\""));
                    assert!(body.contains("The selected service is no longer"));
                    assert!(!body.contains("secret-token"));
                }
            }
        }
    }

    #[tokio::test]
    async fn encoded_and_noncanonical_paths_cannot_bypass_authentication() {
        for path in [
            "/v1/ui/%73hell",
            "/v1/ui/shell/",
            "/v1/ui//shell",
            "/v1/ui/shell?token=secret-token",
        ] {
            let reply = app()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(reply.status(), StatusCode::OK, "unauthenticated {path}");
        }
    }
}
