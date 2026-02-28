//! Embedded HTTP adapter - lightweight axum server for koi-embedded.
//!
//! When `http_enabled` is set on the builder, this module spins up a
//! HTTP server that mounts domain routes, with optional dashboard and
//! mDNS browser.  OpenAPI docs and admin shutdown are not included.

use std::sync::Arc;

use axum::extract::Extension;
use axum::routing::get;
use axum::Router;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

use koi_common::browser::BrowserState;
use koi_common::dashboard::DashboardState;

/// Start the embedded HTTP server.
///
/// Mounts `/healthz` plus each enabled domain's routes at their standard
/// prefix (e.g., `/v1/mdns`, `/v1/dns`, `/v1/health`, `/v1/proxy`,
/// `/v1/certmesh`).  Disabled capabilities get a 503 fallback router.
///
/// When `dashboard_state` is `Some`, the dashboard SPA and its
/// snapshot/events endpoints are mounted at `/` and `/v1/dashboard/`.
///
/// When `browser_state` is `Some`, the mDNS browser SPA and its
/// snapshot/events endpoints are mounted at `/mdns-browser` and
/// `/v1/mdns/browser/`.
///
/// The server shuts down when `cancel` is cancelled.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    port: u16,
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
    dashboard_state: Option<DashboardState>,
    browser_state: Option<BrowserState>,
    cancel: CancellationToken,
) {
    let mut app = Router::new().route("/healthz", get(healthz));

    // ── Dashboard (opt-in) ───────────────────────────────────────

    if let Some(ref ds) = dashboard_state {
        app = app
            .route("/", get(koi_common::dashboard::get_dashboard))
            .route("/v1/dashboard/snapshot", get(koi_common::dashboard::get_snapshot))
            .route("/v1/dashboard/events", get(koi_common::dashboard::get_events))
            .layer(Extension(ds.clone()));
    }

    // ── mDNS browser (opt-in) ────────────────────────────────────

    if let Some(bs) = browser_state {
        app = app
            .route("/mdns-browser", get(koi_common::browser::get_page))
            .nest("/v1/mdns/browser", koi_common::browser::routes(bs));
    }

    // ── Domain routes ────────────────────────────────────────────

    if let Some(ref core) = mdns {
        app = app.nest(
            koi_mdns::http::paths::PREFIX,
            koi_mdns::http::routes(core.clone()),
        );
    } else {
        app = app.nest(koi_mdns::http::paths::PREFIX, disabled_fallback("mdns"));
    }

    if let Some(ref core) = certmesh {
        app = app.nest(koi_certmesh::http::paths::PREFIX, core.routes());
    } else {
        app = app.nest(
            koi_certmesh::http::paths::PREFIX,
            disabled_fallback("certmesh"),
        );
    }

    if let Some(ref runtime) = dns {
        app = app.nest(
            koi_dns::http::paths::PREFIX,
            koi_dns::http::routes(runtime.clone()),
        );
    } else {
        app = app.nest(koi_dns::http::paths::PREFIX, disabled_fallback("dns"));
    }

    if let Some(ref runtime) = health {
        app = app.nest(
            koi_health::http::paths::PREFIX,
            koi_health::http::routes(runtime.core()),
        );
    } else {
        app = app.nest(koi_health::http::paths::PREFIX, disabled_fallback("health"));
    }

    if let Some(ref runtime) = proxy {
        app = app.nest(
            koi_proxy::http::paths::PREFIX,
            koi_proxy::http::routes(runtime.clone()),
        );
    } else {
        app = app.nest(koi_proxy::http::paths::PREFIX, disabled_fallback("proxy"));
    }

    if let Some(ref runtime) = udp {
        app = app.nest(
            koi_udp::http::paths::PREFIX,
            koi_udp::http::routes(runtime.clone()),
        );
    } else {
        app = app.nest(koi_udp::http::paths::PREFIX, disabled_fallback("udp"));
    }

    app = app.layer(CorsLayer::permissive());

    // ── Bind & serve ─────────────────────────────────────────────

    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(port, error = %e, "Failed to bind embedded HTTP server");
            return;
        }
    };

    tracing::info!(port, "Embedded HTTP adapter listening");

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel.cancelled().await;
        })
        .await
    {
        tracing::error!(error = %e, "Embedded HTTP adapter error");
    }

    tracing::debug!("Embedded HTTP adapter stopped");
}

/// Liveness probe - matches standalone `/healthz`.
async fn healthz() -> &'static str {
    "OK"
}

/// 503 fallback for disabled capabilities.
fn disabled_fallback(capability: &'static str) -> Router {
    Router::new().fallback(move || async move {
        let body = serde_json::json!({
            "error": "capability_disabled",
            "message": format!(
                "The '{}' capability is disabled on this instance.",
                capability
            ),
        });
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(body),
        )
    })
}
