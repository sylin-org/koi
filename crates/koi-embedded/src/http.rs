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

use koi_dashboard::browser::BrowserState;
use koi_dashboard::dashboard::DashboardState;

// ── Embedded app state for system-level handlers ────────────────────

#[derive(Clone)]
struct EmbeddedState {
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
    runtime: Option<Arc<koi_runtime::RuntimeCore>>,
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
    runtime: Option<Arc<koi_runtime::RuntimeCore>>,
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
        runtime: runtime.clone(),
        started_at: std::time::Instant::now(),
    };

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/status", get(status_handler))
        .route("/v1/host", get(host_handler));

    // ── Dashboard (opt-in) ───────────────────────────────────────

    if let Some(ref ds) = dashboard_state {
        app = app
            .route("/", get(koi_dashboard::dashboard::get_dashboard))
            .route(
                "/v1/dashboard/snapshot",
                get(koi_dashboard::dashboard::get_snapshot),
            )
            .route(
                "/v1/dashboard/events",
                get(koi_dashboard::dashboard::get_events),
            )
            .layer(Extension(ds.clone()));
    }

    // ── mDNS browser (opt-in) ────────────────────────────────────

    if let Some(bs) = browser_state {
        app = app
            .route("/mdns-browser", get(koi_dashboard::browser::get_page))
            .nest("/v1/mdns/browser", koi_dashboard::browser::routes(bs));
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

    if let Some(ref udp_runtime) = udp {
        app = app.nest(
            koi_udp::http::paths::PREFIX,
            koi_udp::http::routes(udp_runtime.clone()),
        );
    } else {
        app = app.nest(koi_udp::http::paths::PREFIX, disabled_fallback("udp"));
    }

    if let Some(ref rt) = runtime {
        app = app.nest(koi_runtime::http::paths::PREFIX, rt.routes());
    } else {
        app = app.nest(
            koi_runtime::http::paths::PREFIX,
            disabled_fallback("runtime"),
        );
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
    // Refit onto the shared koi-compose capability ladder (P10, finishing P07's unification):
    // build a `Cores` from the embedded cores and project the report into `/v1/status`'s
    // shape — just the `CapabilityStatus`, dropping `enabled` — identical to the daemon.
    let cores = koi_compose::cores::Cores {
        mdns: state.mdns.clone(),
        certmesh: state.certmesh.clone(),
        dns: state.dns.clone(),
        health: state.health.clone(),
        proxy: state.proxy.clone(),
        udp: state.udp.clone(),
        runtime: state.runtime.clone(),
        mdns_snapshot: None,
    };
    let capabilities = koi_compose::status::assemble_capabilities(&cores)
        .await
        .into_iter()
        .map(|c| c.status)
        .collect();

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        daemon: false,
        capabilities,
    })
}

/// LAN interfaces for the `/v1/host` response: the interface that owns the
/// default route (matched by its source IP), or — failing that — every
/// non-loopback, non-link-local IPv4 interface.
fn default_lan_interfaces() -> Vec<NetworkInterface> {
    let all = if_addrs::get_if_addrs().unwrap_or_default();

    if let Some(ip) = default_route_ipv4() {
        if let Some(iface) = all.iter().find(|i| i.addr.ip() == std::net::IpAddr::V4(ip)) {
            return vec![NetworkInterface {
                name: iface.name.clone(),
                ip: ip.to_string(),
            }];
        }
    }

    all.into_iter()
        .filter(|iface| !iface.is_loopback())
        .filter_map(|iface| match iface.addr.ip() {
            std::net::IpAddr::V4(v4) if !v4.is_link_local() => Some(NetworkInterface {
                name: iface.name,
                ip: v4.to_string(),
            }),
            _ => None,
        })
        .collect()
}

/// The IPv4 source address the OS would use to reach the public internet — i.e.
/// the address of the default-route interface. A UDP socket "connected" to a
/// public IP sends no traffic; it only makes the kernel resolve its
/// source-address choice, which `local_addr()` then reports. Returns `None`
/// when there is no usable default route.
fn default_route_ipv4() -> Option<std::net::Ipv4Addr> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect(("8.8.8.8", 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

async fn host_handler() -> Json<HostInfoResponse> {
    let raw = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let fqdn = format!("{raw}.local");

    let lan = default_lan_interfaces();

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
