//! HTTP adapter - builds and serves the axum router.
//!
//! Mounts domain routes, health check, unified status, CORS, and OpenAPI docs.
//! Called by `daemon_mode()` in `main.rs` and `run_service()` in `platform/windows.rs`.

use std::sync::Arc;

use axum::extract::{Extension, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use koi_common::capability::Capability;
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa::ToSchema;
use utoipa_scalar::{Scalar, Servable};

use crate::DaemonCores;
use koi_common::browser::BrowserState;
use koi_common::dashboard::DashboardState;

/// Header name for Daemon Access Token authentication.
const DAT_HEADER: &str = "x-koi-token";

// ── System-level route path constants ───────────────────────────────

/// Route path constants for system endpoints not owned by any domain crate.
pub mod paths {
    pub const HEALTHZ: &str = "/healthz";
    pub const UNIFIED_STATUS: &str = "/v1/status";
    pub const SHUTDOWN: &str = "/v1/admin/shutdown";
    pub const HOST: &str = "/v1/host";
}

// ── App state ───────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    mdns: Option<Arc<koi_mdns::MdnsCore>>,
    certmesh: Option<Arc<koi_certmesh::CertmeshCore>>,
    dns: Option<Arc<koi_dns::DnsRuntime>>,
    health: Option<Arc<koi_health::HealthRuntime>>,
    proxy: Option<Arc<koi_proxy::ProxyRuntime>>,
    udp: Option<Arc<koi_udp::UdpRuntime>>,
    started_at: std::time::Instant,
    cancel: CancellationToken,
}

// ── Entrypoint ──────────────────────────────────────────────────────

pub async fn start(
    cores: DaemonCores,
    port: u16,
    cancel: CancellationToken,
    started_at: std::time::Instant,
    dashboard_state: DashboardState,
    browser_state: Option<BrowserState>,
    dat_token: String,
) -> anyhow::Result<()> {
    let app_state = AppState {
        mdns: cores.mdns.clone(),
        certmesh: cores.certmesh.clone(),
        dns: cores.dns.clone(),
        health: cores.health.clone(),
        proxy: cores.proxy.clone(),
        udp: cores.udp.clone(),
        started_at,
        cancel: cancel.clone(),
    };

    // ── Dashboard (always mounted) ──
    let mut app = Router::new()
        .route(paths::HEALTHZ, get(health))
        .route(paths::UNIFIED_STATUS, get(unified_status_handler))
        .route(paths::SHUTDOWN, post(shutdown_handler))
        .route(paths::HOST, get(host_handler))
        .route("/", get(koi_common::dashboard::get_dashboard))
        .route(
            "/v1/dashboard/snapshot",
            get(koi_common::dashboard::get_snapshot),
        )
        .route(
            "/v1/dashboard/events",
            get(koi_common::dashboard::get_events),
        );

    // ── mDNS browser (conditional on mDNS being enabled) ──
    if let Some(bs) = browser_state {
        app = app
            .route("/mdns-browser", get(koi_common::browser::get_page))
            .nest("/v1/mdns/browser", koi_common::browser::routes(bs));
    } else {
        app = app.nest("/v1/mdns/browser", disabled_fallback_router("mdns-browser"));
    }

    // Mount domain routes or fallback routers
    if let Some(ref mdns_core) = cores.mdns {
        app = app.nest(
            koi_mdns::http::paths::PREFIX,
            koi_mdns::http::routes(mdns_core.clone()),
        );
    } else {
        app = app.nest(
            koi_mdns::http::paths::PREFIX,
            disabled_fallback_router("mdns"),
        );
    }

    if let Some(ref certmesh_core) = cores.certmesh {
        app = app.nest(koi_certmesh::http::paths::PREFIX, certmesh_core.routes());
    } else {
        app = app.nest(
            koi_certmesh::http::paths::PREFIX,
            disabled_fallback_router("certmesh"),
        );
    }

    if let Some(ref dns_runtime) = cores.dns {
        app = app.nest(
            koi_dns::http::paths::PREFIX,
            koi_dns::http::routes(dns_runtime.clone()),
        );
    } else {
        app = app.nest(
            koi_dns::http::paths::PREFIX,
            disabled_fallback_router("dns"),
        );
    }

    if let Some(ref health_runtime) = cores.health {
        app = app.nest(
            koi_health::http::paths::PREFIX,
            koi_health::http::routes(health_runtime.core()),
        );
    } else {
        app = app.nest(
            koi_health::http::paths::PREFIX,
            disabled_fallback_router("health"),
        );
    }

    if let Some(ref proxy_runtime) = cores.proxy {
        app = app.nest(
            koi_proxy::http::paths::PREFIX,
            koi_proxy::http::routes(proxy_runtime.clone()),
        );
    } else {
        app = app.nest(
            koi_proxy::http::paths::PREFIX,
            disabled_fallback_router("proxy"),
        );
    }

    if let Some(ref udp_runtime) = cores.udp {
        app = app.nest(
            koi_udp::http::paths::PREFIX,
            koi_udp::http::routes(udp_runtime.clone()),
        );
    } else {
        app = app.nest(
            koi_udp::http::paths::PREFIX,
            disabled_fallback_router("udp"),
        );
    }

    // OpenAPI spec - composed from domain-owned specs via nest()
    let openapi = build_openapi();

    // Serve interactive API docs at /docs and raw spec at /openapi.json
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

    app = app.layer(Extension(app_state));
    app = app.layer(Extension(dashboard_state));
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost".parse::<HeaderValue>().unwrap(),
            "http://127.0.0.1".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE]);
    app = app.layer(cors);

    // DAT auth middleware: mutation requests (non-GET) require X-Koi-Token header
    let token_state = Arc::new(dat_token);
    app = app.layer(middleware::from_fn_with_state(
        token_state,
        dat_auth_middleware,
    ));

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

// ── Response types for top-level endpoints ──────────────────────────

#[derive(Debug, Serialize, ToSchema)]
struct UnifiedStatusResponse {
    version: String,
    platform: String,
    uptime_secs: u64,
    daemon: bool,
    capabilities: Vec<koi_common::capability::CapabilityStatus>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ShutdownResponse {
    status: String,
}

/// Host identity and network interfaces.
#[derive(Debug, Serialize, ToSchema)]
struct HostInfoResponse {
    /// Raw hostname (e.g. "stone-azure-pool").
    hostname: String,
    /// Fully-qualified mDNS name (e.g. "stone-azure-pool.local").
    hostname_fqdn: String,
    /// Operating system (e.g. "linux", "windows").
    os: String,
    /// CPU architecture (e.g. "x86_64", "aarch64").
    arch: String,
    /// Network interfaces grouped by category.
    interfaces: HostInterfaces,
}

/// Grouped network interfaces. Extensible — future categories (e.g. vpn)
/// can be added without breaking the schema.
#[derive(Debug, Serialize, ToSchema)]
struct HostInterfaces {
    /// LAN-routable interfaces (loopback and link-local excluded).
    lan: Vec<NetworkInterface>,
}

/// A single network interface.
#[derive(Debug, Serialize, ToSchema)]
struct NetworkInterface {
    /// Platform-specific interface name (e.g. "eth0", "Ethernet", "en0").
    name: String,
    /// IPv4 or IPv6 address.
    ip: String,
}

// ── System-level OpenAPI doc ─────────────────────────────────────────

/// System-level OpenAPI doc with paths for top-level endpoints and schemas.
#[derive(OpenApi)]
#[openapi(
    paths(health, unified_status_handler, shutdown_handler, host_handler),
    components(schemas(
        UnifiedStatusResponse,
        ShutdownResponse,
        HostInfoResponse,
        HostInterfaces,
        NetworkInterface,
        koi_common::capability::CapabilityStatus,
        koi_common::error::ErrorCode,
        koi_common::api::ErrorBody,
    ))
)]
struct KoiSchemas;

/// Build the full OpenAPI spec by composing domain-owned specs via `nest()`.
///
/// System-level paths (healthz, status, shutdown, host) come from `KoiSchemas`.
/// Each domain crate self-describes its API surface via `#[utoipa::path]` on
/// handlers and `paths(...)` in its `ApiDoc`. The `nest()` call prepends the
/// domain prefix to all paths.
pub fn build_openapi() -> utoipa::openapi::OpenApi {
    use utoipa::openapi::external_docs::ExternalDocs;
    use utoipa::openapi::tag::TagBuilder;
    use utoipa::openapi::{InfoBuilder, LicenseBuilder};

    let openapi = KoiSchemas::openapi()
        .nest(
            koi_mdns::http::paths::PREFIX,
            koi_mdns::http::MdnsApiDoc::openapi(),
        )
        .nest(
            koi_certmesh::http::paths::PREFIX,
            koi_certmesh::http::CertmeshApiDoc::openapi(),
        )
        .nest(
            koi_dns::http::paths::PREFIX,
            koi_dns::http::DnsApiDoc::openapi(),
        )
        .nest(
            koi_health::http::paths::PREFIX,
            koi_health::http::HealthApiDoc::openapi(),
        )
        .nest(
            koi_proxy::http::paths::PREFIX,
            koi_proxy::http::ProxyApiDoc::openapi(),
        )
        .nest(
            koi_udp::http::paths::PREFIX,
            koi_udp::http::UdpApiDoc::openapi(),
        );

    let info = InfoBuilder::new()
        .title("Koi Network Toolkit API")
        .version(env!("CARGO_PKG_VERSION"))
        .description(Some(
            "Local network toolkit: service discovery, DNS, health monitoring, \
             TLS proxy, and certificate mesh.",
        ))
        .license(Some(
            LicenseBuilder::new().name("Apache-2.0 OR MIT").build(),
        ))
        .build();

    let base = "https://github.com/sylin-org/koi/blob/main/docs";
    let tags = vec![
        TagBuilder::new()
            .name("system")
            .description(Some(
                "Core daemon lifecycle - status, version, health probes, \
                 and graceful shutdown.",
            ))
            .external_docs(Some(ExternalDocs::new(format!("{base}/guide-system.md"))))
            .build(),
        TagBuilder::new()
            .name("mdns")
            .description(Some(
                "Multicast DNS service discovery - announce, discover, \
                 and manage services on the local network. Includes \
                 admin operations for inspecting and controlling \
                 individual registrations.",
            ))
            .external_docs(Some(ExternalDocs::new(format!("{base}/guide-mdns.md"))))
            .build(),
        TagBuilder::new()
            .name("certmesh")
            .description(Some(
                "Zero-config TLS certificate mesh - automatic CA \
                 bootstrapping, certificate enrollment, renewal, \
                 revocation, and cluster-wide trust distribution.",
            ))
            .external_docs(Some(ExternalDocs::new(format!("{base}/guide-certmesh.md"))))
            .build(),
        TagBuilder::new()
            .name("dns")
            .description(Some(
                "Local DNS server - custom record management, \
                 upstream forwarding, and split-horizon resolution \
                 for development environments.",
            ))
            .external_docs(Some(ExternalDocs::new(format!("{base}/guide-dns.md"))))
            .build(),
        TagBuilder::new()
            .name("health")
            .description(Some(
                "Endpoint health monitoring - configure checks, \
                 view live status, and receive real-time health \
                 change events via SSE.",
            ))
            .external_docs(Some(ExternalDocs::new(format!("{base}/guide-health.md"))))
            .build(),
        TagBuilder::new()
            .name("proxy")
            .description(Some(
                "TLS-terminating reverse proxy - route traffic \
                 to local services with automatic certificate \
                 provisioning from the certmesh CA.",
            ))
            .external_docs(Some(ExternalDocs::new(format!("{base}/guide-proxy.md"))))
            .build(),
        TagBuilder::new()
            .name("udp")
            .description(Some(
                "UDP datagram bridging - bind host sockets, send \
                 and receive datagrams over HTTP/SSE.",
            ))
            .external_docs(Some(ExternalDocs::new(format!("{base}/guide-udp.md"))))
            .build(),
    ];

    let mut openapi = openapi;
    openapi.info = info;
    openapi.tags = Some(tags);
    openapi
}

// ── DAT auth middleware ──────────────────────────────────────────────

/// Daemon Access Token authentication middleware.
///
/// GET requests pass through unconditionally (read-only).
/// All other methods require a valid `X-Koi-Token` header or `?token=` query
/// parameter matching the daemon's generated token.
async fn dat_auth_middleware(
    State(expected_token): State<Arc<String>>,
    request: Request,
    next: Next,
) -> Response {
    // Allow all GET requests (read-only endpoints are public)
    if request.method() == Method::GET {
        return next.run(request).await;
    }

    // Check X-Koi-Token header (case-insensitive header lookup by axum)
    if let Some(val) = request.headers().get(DAT_HEADER) {
        if val.as_bytes() == expected_token.as_bytes() {
            return next.run(request).await;
        }
    }

    // Fallback: check ?token= query parameter (for browser/SSE clients)
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            if let Some(val) = pair.strip_prefix("token=") {
                if val == expected_token.as_str() {
                    return next.run(request).await;
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "unauthorized",
            "message": "Missing or invalid X-Koi-Token header"
        })),
    )
        .into_response()
}

// ── Handlers ────────────────────────────────────────────────────────

#[utoipa::path(get, path = "/healthz", tag = "system",
    summary = "Basic liveness probe",
    responses((status = 200, description = "Daemon is alive")))]
async fn health() -> &'static str {
    "OK"
}

#[utoipa::path(get, path = "/v1/status", tag = "system",
    summary = "Unified capability status",
    responses((status = 200, body = UnifiedStatusResponse)))]
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

    if let Some(ref runtime) = state.udp {
        capabilities.push(koi_common::capability::Capability::status(runtime.as_ref()));
    } else {
        capabilities.push(CapabilityStatus {
            name: "udp".to_string(),
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

#[utoipa::path(get, path = "/v1/host", tag = "system",
    summary = "Host identity and network interfaces",
    responses((status = 200, body = HostInfoResponse)))]
async fn host_handler() -> Json<HostInfoResponse> {
    let raw = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let fqdn = format!("{}.local", raw);

    // Use netdev to find the interface with the default route.
    // This is the only deterministic way to identify the real LAN adapter
    // on Windows where virtual switches (vEthernet) report the same
    // IfType as physical Ethernet.
    let lan: Vec<NetworkInterface> = match netdev::get_default_interface() {
        Ok(default_iface) => {
            let mut interfaces = Vec::new();
            for addr in &default_iface.ipv4 {
                interfaces.push(NetworkInterface {
                    name: default_iface.name.clone(),
                    ip: addr.addr().to_string(),
                });
            }
            interfaces
        }
        Err(e) => {
            tracing::warn!(error = %e, "netdev default interface detection failed, falling back to if_addrs");
            // Fallback: enumerate all non-loopback, non-link-local IPv4 interfaces
            if_addrs::get_if_addrs()
                .unwrap_or_default()
                .into_iter()
                .filter(|iface| {
                    if iface.is_loopback() {
                        return false;
                    }
                    match iface.addr.ip() {
                        std::net::IpAddr::V4(v4) => !v4.is_link_local(),
                        std::net::IpAddr::V6(_) => false, // IPv4 only in fallback
                    }
                })
                .map(|iface| NetworkInterface {
                    name: iface.name,
                    ip: iface.addr.ip().to_string(),
                })
                .collect()
        }
    };

    Json(HostInfoResponse {
        hostname: raw,
        hostname_fqdn: fqdn,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        interfaces: HostInterfaces { lan },
    })
}

#[utoipa::path(post, path = "/v1/admin/shutdown", tag = "system",
    summary = "Request graceful daemon shutdown",
    responses((status = 200, body = ShutdownResponse)))]
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
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.get("error").unwrap(), "capability_disabled");
    }

    #[tokio::test]
    async fn disabled_fallback_message_includes_capability_name() {
        let app = disabled_fallback_router("mdns");
        let req = Request::get("/any").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let msg = json.get("message").unwrap().as_str().unwrap();
        assert!(
            msg.contains("mdns"),
            "message should contain capability name: {msg}"
        );
    }

    #[tokio::test]
    async fn disabled_fallback_works_for_post() {
        let app = disabled_fallback_router("certmesh");
        let req = Request::post("/join").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn openapi_spec_contains_system_paths() {
        let spec = build_openapi();
        let paths: Vec<&str> = spec.paths.paths.keys().map(|k| k.as_str()).collect();
        assert!(paths.contains(&"/healthz"), "missing /healthz: {paths:?}");
        assert!(
            paths.contains(&"/v1/status"),
            "missing /v1/status: {paths:?}"
        );
        assert!(paths.contains(&"/v1/host"), "missing /v1/host: {paths:?}");
        assert!(
            paths.contains(&"/v1/admin/shutdown"),
            "missing /v1/admin/shutdown: {paths:?}"
        );
    }

    #[test]
    fn openapi_spec_contains_domain_paths() {
        let spec = build_openapi();
        let paths: Vec<&str> = spec.paths.paths.keys().map(|k| k.as_str()).collect();
        // Spot-check one path per domain to verify nest() prefixing works
        assert!(
            paths.contains(&"/v1/mdns/discover"),
            "missing /v1/mdns/discover: {paths:?}"
        );
        assert!(
            paths.contains(&"/v1/dns/status"),
            "missing /v1/dns/status: {paths:?}"
        );
        assert!(
            paths.contains(&"/v1/health/status"),
            "missing /v1/health/status: {paths:?}"
        );
        assert!(
            paths.contains(&"/v1/proxy/status"),
            "missing /v1/proxy/status: {paths:?}"
        );
        assert!(
            paths.contains(&"/v1/certmesh/status"),
            "missing /v1/certmesh/status: {paths:?}"
        );
        assert!(
            paths.contains(&"/v1/udp/status"),
            "missing /v1/udp/status: {paths:?}"
        );
    }

    #[tokio::test]
    async fn host_handler_returns_default_interface_only() {
        let Json(resp) = host_handler().await;
        assert!(!resp.hostname.is_empty(), "hostname should not be empty");
        assert!(
            resp.hostname_fqdn.ends_with(".local"),
            "FQDN should end with .local: {}",
            resp.hostname_fqdn
        );
        // The LAN list should contain exactly the default-route interface
        // (not virtual switches, Docker bridges, etc.)
        assert!(
            !resp.interfaces.lan.is_empty(),
            "lan interfaces should not be empty on a machine with network"
        );
        for iface in &resp.interfaces.lan {
            let ip: std::net::IpAddr = iface.ip.parse().expect("should be a valid IP");
            assert!(!ip.is_loopback(), "LAN should not contain loopback");
        }
        // On a machine with a single physical NIC, expect exactly 1 entry
        println!(
            "host_handler returned {} LAN interface(s):",
            resp.interfaces.lan.len()
        );
        for iface in &resp.interfaces.lan {
            println!("  {} -> {}", iface.name, iface.ip);
        }
    }
}
