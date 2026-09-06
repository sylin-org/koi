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
pub const LOGIN: &str = "/ui";
const TRANSPORT: &str = "/ui/transport.js";
const BROWSER_CSP: &str = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Mount only when the host configured DAT authentication. An unauthenticated
/// embedded host does not implicitly expose an operator catalog as HTML.
pub(crate) fn routes(catalog: Arc<ServiceCatalogRuntime>) -> Router {
    Router::new()
        .route(LOGIN, get(login))
        .route(TRANSPORT, get(transport))
        .route(SHELL, get(snapshot))
        .with_state(catalog)
}

async fn login() -> Response {
    let document =
        include_str!("../assets/ui-login.html").replace("{{style}}", &koi_ui::stylesheet());
    response("text/html; charset=utf-8", document, BROWSER_CSP)
}

async fn transport() -> Response {
    response(
        "text/javascript; charset=utf-8",
        include_str!("../assets/ui-transport.js").into(),
        BROWSER_CSP,
    )
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
    async fn bootstrap_is_public_but_contains_no_catalog_or_credentials() {
        let reply = app()
            .oneshot(Request::builder().uri(LOGIN).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        let body = String::from_utf8(
            to_bytes(reply.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("type=\"password\""));
        assert!(!body.contains("Snapshot revision"));
        assert!(!body.contains("secret-token"));
        for route in ["/v1/ui", "/ui/unknown", "/v1/ui/shell/unknown"] {
            assert_eq!(
                app()
                    .oneshot(
                        Request::builder()
                            .uri(route)
                            .header("x-koi-token", "secret-token")
                            .body(Body::empty())
                            .unwrap()
                    )
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
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
