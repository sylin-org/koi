//! HTTP adapter — builds and serves the axum router.
//!
//! Mounts domain routes, health check, unified status, and CORS.
//! Called by `daemon_mode()` in `main.rs` and `run_service()` in `platform/windows.rs`.

use std::sync::Arc;

use axum::extract::Extension;
use axum::response::Json;
use axum::routing::{get, post};
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
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    started_at: std::time::Instant,
    cancel: CancellationToken,
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
        dns: cores.dns.clone(),
        health: cores.health.clone(),
        proxy: cores.proxy.clone(),
        started_at,
        cancel: cancel.clone(),
    };

    let mut app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/status", get(unified_status_handler))
        .route("/v1/admin/shutdown", post(shutdown_handler));

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

    if let Some(ref dns_runtime) = cores.dns {
        app = app.nest("/v1/dns", koi_dns::http::routes(dns_runtime.clone()));
    } else {
        app = app.nest("/v1/dns", disabled_fallback_router("dns"));
    }

    if let Some(ref health_runtime) = cores.health {
        app = app.nest("/v1/health", koi_health::http::routes(health_runtime.core()));
    } else {
        app = app.nest("/v1/health", disabled_fallback_router("health"));
    }

    if let Some(ref proxy_runtime) = cores.proxy {
        app = app.nest("/v1/proxy", koi_proxy::http::routes(proxy_runtime.clone()));
    } else {
        app = app.nest("/v1/proxy", disabled_fallback_router("proxy"));
    }

    app = app.layer(Extension(app_state));
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

async fn unified_status_handler(Extension(state): Extension<AppState>) -> Json<serde_json::Value> {
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

    if let Some(ref runtime) = state.dns {
        let running = runtime.status().await.running;
        if running {
            capabilities.push(runtime.core().status());
        } else {
            capabilities.push(CapabilityStatus {
                name: "dns".to_string(),
                summary: "stopped".to_string(),
                healthy: false,
            });
        }
    } else {
        capabilities.push(CapabilityStatus {
            name: "dns".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    }

    if let Some(ref runtime) = state.health {
        let running = runtime.status().await.running;
        if running {
            capabilities.push(runtime.core().status());
        } else {
            capabilities.push(CapabilityStatus {
                name: "health".to_string(),
                summary: "stopped".to_string(),
                healthy: false,
            });
        }
    } else {
        capabilities.push(CapabilityStatus {
            name: "health".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    }

    if let Some(ref runtime) = state.proxy {
        let status = runtime.status().await;
        if status.is_empty() {
            capabilities.push(CapabilityStatus {
                name: "proxy".to_string(),
                summary: "no listeners".to_string(),
                healthy: true,
            });
        } else {
            capabilities.push(CapabilityStatus {
                name: "proxy".to_string(),
                summary: format!("{} listeners", status.len()),
                healthy: true,
            });
        }
    } else {
        capabilities.push(CapabilityStatus {
            name: "proxy".to_string(),
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

async fn shutdown_handler(Extension(state): Extension<AppState>) -> Json<serde_json::Value> {
    tracing::info!("Shutdown requested via admin endpoint");
    state.cancel.cancel();
    Json(serde_json::json!({ "status": "shutting_down" }))
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
