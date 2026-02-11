//! HTTP adapter — builds and serves the axum router.
//!
//! Mounts domain routes, health check, unified status, and CORS.
//! Called by `daemon_mode()` in `main.rs` and `run_service()` in `platform/windows.rs`.

use std::sync::Arc;

use axum::extract::State as AxumState;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use koi_common::capability::Capability;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;

use crate::DaemonCores;

// ── App state ───────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    started_at: std::time::Instant,
}

// ── Entrypoint ──────────────────────────────────────────────────────

pub async fn start(
    cores: DaemonCores,
    port: u16,
    cancel: CancellationToken,
    started_at: std::time::Instant,
) -> anyhow::Result<()> {
    let app_state = AppState {
        mdns: cores.mdns.clone(),
        certmesh: cores.certmesh.clone(),
        started_at,
    };

    let mut app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/status", get(unified_status_handler))
        .with_state(app_state);

    // Mount domain routes or fallback routers
    if let Some(ref mdns_core) = cores.mdns {
        app = app.nest("/v1/mdns", koi_mdns::http::routes(mdns_core.clone()));
    } else {
        app = app.nest("/v1/mdns", disabled_fallback_router("mdns"));
    }

    if let Some(ref certmesh_core) = cores.certmesh {
        app = app.nest("/v1/certmesh", certmesh_core.routes());
    } else {
        app = app.nest("/v1/certmesh", disabled_fallback_router("certmesh"));
    }

    app = app.layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("HTTP adapter listening on port {}", port);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            cancel.cancelled().await;
        })
        .await?;

    tracing::debug!("HTTP adapter stopped");
    Ok(())
}

// ── Handlers ────────────────────────────────────────────────────────

async fn health() -> &'static str {
    "OK"
}

async fn unified_status_handler(
    AxumState(state): AxumState<AppState>,
) -> Json<serde_json::Value> {
    use koi_common::capability::CapabilityStatus;

    let mut capabilities = Vec::new();

    if let Some(ref core) = state.mdns {
        capabilities.push(core.status());
    } else {
        capabilities.push(CapabilityStatus {
            name: "mdns".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    }

    if let Some(ref core) = state.certmesh {
        capabilities.push(core.status());
    } else {
        capabilities.push(CapabilityStatus {
            name: "certmesh".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    }

    let uptime_secs = state.started_at.elapsed().as_secs();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "uptime_secs": uptime_secs,
        "daemon": true,
        "capabilities": capabilities,
    }))
}

/// Returns a router that responds 503 for any request to a disabled capability.
fn disabled_fallback_router(capability_name: &'static str) -> Router {
    Router::new().fallback(move || async move {
        let body = serde_json::json!({
            "error": "capability_disabled",
            "message": format!(
                "The '{}' capability is disabled on this daemon.",
                capability_name
            ),
        });
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(body),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn disabled_fallback_returns_503() {
        let app = disabled_fallback_router("mdns");
        let req = Request::get("/browse").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn disabled_fallback_body_has_error_field() {
        let app = disabled_fallback_router("certmesh");
        let req = Request::get("/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("error").unwrap(), "capability_disabled");
    }

    #[tokio::test]
    async fn disabled_fallback_message_includes_capability_name() {
        let app = disabled_fallback_router("mdns");
        let req = Request::get("/any").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let msg = json.get("message").unwrap().as_str().unwrap();
        assert!(msg.contains("mdns"), "message should contain capability name: {msg}");
    }

    #[tokio::test]
    async fn disabled_fallback_works_for_post() {
        let app = disabled_fallback_router("certmesh");
        let req = Request::post("/join").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
}
