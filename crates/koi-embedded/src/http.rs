//! Embedded HTTP adapter - lightweight axum server for koi-embedded.
//!
//! When `http_enabled` is set on the builder, this module spins up a
//! HTTP server that mounts domain routes, system-level endpoints
//! (`/v1/status`, `/v1/host`), and optional dashboard, mDNS browser,
//! and OpenAPI docs.  Admin shutdown is not included.

use std::sync::Arc;

use axum::extract::Extension;
use axum::http::{header, HeaderValue, Method};
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use utoipa::{OpenApi, ToSchema};
use utoipa_scalar::{Scalar, Servable};

use koi_common::browser::BrowserState;
use koi_common::dashboard::DashboardState;

// ── Embedded app state for system-level handlers ────────────────────

#[derive(Clone)]
struct EmbeddedState {
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
    started_at: std::time::Instant,
}

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
    api_docs_enabled: bool,
    cancel: CancellationToken,
) {
    let embedded_state = EmbeddedState {
        mdns: mdns.clone(),
        certmesh: certmesh.clone(),
        dns: dns.clone(),
        health: health.clone(),
        proxy: proxy.clone(),
        udp: udp.clone(),
        started_at: std::time::Instant::now(),
    };

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status_handler))
        .route("/v1/host", get(host_handler));

    // ── Dashboard (opt-in) ───────────────────────────────────────

    if let Some(ref ds) = dashboard_state {
        app = app
            .route("/", get(koi_common::dashboard::get_dashboard))
            .route(
                "/v1/dashboard/snapshot",
                get(koi_common::dashboard::get_snapshot),
            )
            .route(
                "/v1/dashboard/events",
                get(koi_common::dashboard::get_events),
            )
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

    // ── OpenAPI docs (opt-in) ────────────────────────────────────

    if api_docs_enabled {
        let openapi = build_embedded_openapi(&mdns, &dns, &health, &certmesh, &proxy, &udp);
        app = app.merge(Scalar::with_url("/docs", openapi.clone()));
        let spec_json = match openapi.to_pretty_json() {
            Ok(json) => json,
            Err(e) => {
                tracing::error!(error = %e, "OpenAPI JSON serialization failed");
                String::from(r#"{"error":"OpenAPI serialization failed"}"#)
            }
        };
        app = app.route(
            "/openapi.json",
            get(move || {
                let json = spec_json.clone();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        json,
                    )
                }
            }),
        );
    }

    app = app.layer(Extension(embedded_state));
    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_static("http://localhost"),
            HeaderValue::from_static("http://127.0.0.1"),
        ])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE]);
    app = app.layer(cors);

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

// ── System-level response types ─────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
struct StatusResponse {
    version: String,
    platform: String,
    uptime_secs: u64,
    daemon: bool,
    capabilities: Vec<koi_common::capability::CapabilityStatus>,
}

#[derive(Debug, Serialize, ToSchema)]
struct HostInfoResponse {
    hostname: String,
    hostname_fqdn: String,
    os: String,
    arch: String,
    interfaces: HostInterfaces,
}

#[derive(Debug, Serialize, ToSchema)]
struct HostInterfaces {
    lan: Vec<NetworkInterface>,
}

#[derive(Debug, Serialize, ToSchema)]
struct NetworkInterface {
    name: String,
    ip: String,
}

// ── System-level handlers ───────────────────────────────────────────

async fn status_handler(Extension(state): Extension<EmbeddedState>) -> Json<StatusResponse> {
    use koi_common::capability::{Capability, CapabilityStatus};

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
        capabilities.push(CapabilityStatus {
            name: "proxy".to_string(),
            summary: if status.is_empty() {
                "no listeners".to_string()
            } else {
                format!("{} listeners", status.len())
            },
            healthy: true,
        });
    } else {
        capabilities.push(CapabilityStatus {
            name: "proxy".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    }

    if let Some(ref runtime) = state.udp {
        capabilities.push(Capability::status(runtime.as_ref()));
    } else {
        capabilities.push(CapabilityStatus {
            name: "udp".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    }

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        daemon: false,
        capabilities,
    })
}

async fn host_handler() -> Json<HostInfoResponse> {
    let raw = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let fqdn = format!("{raw}.local");

    let lan: Vec<NetworkInterface> = match netdev::get_default_interface() {
        Ok(default_iface) => default_iface
            .ipv4
            .iter()
            .map(|addr| NetworkInterface {
                name: default_iface.name.clone(),
                ip: addr.addr().to_string(),
            })
            .collect(),
        Err(_) => if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter(|iface| {
                if iface.is_loopback() {
                    return false;
                }
                match iface.addr.ip() {
                    std::net::IpAddr::V4(v4) => !v4.is_link_local(),
                    std::net::IpAddr::V6(_) => false,
                }
            })
            .map(|iface| NetworkInterface {
                name: iface.name,
                ip: iface.addr.ip().to_string(),
            })
            .collect(),
    };

    Json(HostInfoResponse {
        hostname: raw,
        hostname_fqdn: fqdn,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        interfaces: HostInterfaces { lan },
    })
}

/// Build an OpenAPI spec reflecting only the enabled domains.
fn build_embedded_openapi(
    mdns: &Option<Arc<koi_mdns::MdnsCore>>,
    dns: &Option<Arc<koi_dns::DnsRuntime>>,
    health: &Option<Arc<koi_health::HealthRuntime>>,
    certmesh: &Option<Arc<koi_certmesh::CertmeshCore>>,
    proxy: &Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: &Option<Arc<koi_udp::UdpRuntime>>,
) -> utoipa::openapi::OpenApi {
    use utoipa::openapi::{InfoBuilder, LicenseBuilder, PathsBuilder};

    let info = InfoBuilder::new()
        .title("Koi Embedded API")
        .version(env!("CARGO_PKG_VERSION"))
        .description(Some(
            "Embedded Koi network toolkit: service discovery, DNS, \
             health monitoring, TLS proxy, and certificate mesh.",
        ))
        .license(Some(
            LicenseBuilder::new().name("Apache-2.0 OR MIT").build(),
        ))
        .build();

    let mut openapi = utoipa::openapi::OpenApi::new(info, PathsBuilder::new());

    if mdns.is_some() {
        openapi = openapi.nest(
            koi_mdns::http::paths::PREFIX,
            koi_mdns::http::MdnsApiDoc::openapi(),
        );
    }
    if certmesh.is_some() {
        openapi = openapi.nest(
            koi_certmesh::http::paths::PREFIX,
            koi_certmesh::http::CertmeshApiDoc::openapi(),
        );
    }
    if dns.is_some() {
        openapi = openapi.nest(
            koi_dns::http::paths::PREFIX,
            koi_dns::http::DnsApiDoc::openapi(),
        );
    }
    if health.is_some() {
        openapi = openapi.nest(
            koi_health::http::paths::PREFIX,
            koi_health::http::HealthApiDoc::openapi(),
        );
    }
    if proxy.is_some() {
        openapi = openapi.nest(
            koi_proxy::http::paths::PREFIX,
            koi_proxy::http::ProxyApiDoc::openapi(),
        );
    }
    if udp.is_some() {
        openapi = openapi.nest(
            koi_udp::http::paths::PREFIX,
            koi_udp::http::UdpApiDoc::openapi(),
        );
    }

    openapi
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
