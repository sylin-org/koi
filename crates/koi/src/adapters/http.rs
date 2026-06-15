//! HTTP adapter - builds and serves the axum router.
//!
//! Mounts domain routes, health check, unified status, CORS, and OpenAPI docs.
//! Called by `daemon_mode()` in `main.rs` and `run_service()` in `platform/windows.rs`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{header, HeaderName, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa::ToSchema;
use utoipa_scalar::{Scalar, Servable};

use crate::DaemonCores;
use koi_dashboard::browser::BrowserState;
use koi_dashboard::dashboard::DashboardState;
use koi_dashboard::meta_browse::LazyMetaBrowse;

/// Header name for Daemon Access Token authentication.
const DAT_HEADER: &str = "x-koi-token";

// ── System-level route path constants ───────────────────────────────

/// Route path constants for system endpoints not owned by any domain crate.
pub mod paths {
    pub const HEALTHZ: &str = "/healthz";
    pub const UNIFIED_STATUS: &str = "/v1/status";
    pub const SHUTDOWN: &str = "/v1/admin/shutdown";
    pub const HOST: &str = "/v1/host";
    /// Prometheus HTTP service discovery (their format — see Door 1 / integrations.md).
    pub const PROMETHEUS_SD: &str = "/v1/sd/prometheus";
    /// In-process MCP server (Streamable HTTP / JSON-RPC). Token-authenticated for
    /// all methods (carved out of the GET exemption); not in `/openapi.json`.
    pub const MCP: &str = "/v1/mcp";
    /// Public MCP discovery descriptor (the "Door"): an unauthenticated GET
    /// describing the MCP endpoint, transport, and auth. No secrets.
    pub const MCP_SERVER_CARD: &str = "/.well-known/mcp/server-card.json";
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
    runtime: Option<Arc<koi_runtime::RuntimeCore>>,
    started_at: std::time::Instant,
    cancel: CancellationToken,
    http_bind: String,
    /// Lazy mDNS meta-browse controller (when mDNS is enabled), so `/v1/status` can
    /// report whether LAN-wide browsing is currently active.
    mdns_browse: Option<Arc<LazyMetaBrowse>>,
    /// Cached-mDNS snapshot used only by the Prometheus `?include=discovered` slice.
    /// `None` when mDNS is disabled — the managed slice never touches it.
    mdns_snapshot: Option<Arc<dyn koi_common::integration::MdnsSnapshot>>,
    /// Whether the in-process MCP HTTP transport (`/v1/mcp`) is mounted. Reported
    /// on `/v1/status` as a field (MCP-HTTP is a transport, not a domain rung).
    mcp_http_enabled: bool,
}

// ── Entrypoint ──────────────────────────────────────────────────────

// Wiring entrypoint: it threads every daemon component through to the HTTP
// adapter. Pre-existing signature (P03); clippy 0.1.95 (> repo MSRV 1.92) newly
// flags the arg count. Behaviour-neutral allow to keep the gate green.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    cores: DaemonCores,
    bind_ip: std::net::IpAddr,
    port: u16,
    cancel: CancellationToken,
    started_at: std::time::Instant,
    dashboard_state: DashboardState,
    browser_state: Option<BrowserState>,
    dat_token: String,
    mdns_snapshot: Option<Arc<dyn koi_common::integration::MdnsSnapshot>>,
    mcp_http_enabled: bool,
) -> anyhow::Result<()> {
    let app_state = AppState {
        mdns: cores.mdns.clone(),
        certmesh: cores.certmesh.clone(),
        dns: cores.dns.clone(),
        health: cores.health.clone(),
        proxy: cores.proxy.clone(),
        udp: cores.udp.clone(),
        runtime: cores.runtime.clone(),
        started_at,
        cancel: cancel.clone(),
        http_bind: bind_ip.to_string(),
        mdns_browse: browser_state.as_ref().map(|b| b.meta.clone()),
        mdns_snapshot,
        mcp_http_enabled,
    };

    // ── Dashboard (always mounted) ──
    let mut app = Router::new()
        .route(paths::HEALTHZ, get(health))
        .route(paths::UNIFIED_STATUS, get(unified_status_handler))
        .route(paths::SHUTDOWN, post(shutdown_handler))
        .route(paths::HOST, get(host_handler))
        .route(paths::PROMETHEUS_SD, get(prometheus_sd_handler))
        .route(paths::MCP_SERVER_CARD, get(mcp_server_card_handler))
        .route("/", get(koi_dashboard::dashboard::get_dashboard))
        .route(
            "/v1/dashboard/snapshot",
            get(koi_dashboard::dashboard::get_snapshot),
        )
        .route(
            "/v1/dashboard/events",
            get(koi_dashboard::dashboard::get_events),
        );

    // ── mDNS browser (conditional on mDNS being enabled) ──
    if let Some(bs) = browser_state {
        app = app
            .route("/mdns-browser", get(koi_dashboard::browser::get_page))
            .nest("/v1/mdns/browser", koi_dashboard::browser::routes(bs));
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

    if let Some(ref runtime_core) = cores.runtime {
        app = app.nest(koi_runtime::http::paths::PREFIX, runtime_core.routes());
    } else {
        app = app.nest(
            koi_runtime::http::paths::PREFIX,
            disabled_fallback_router("runtime"),
        );
    }

    // ── MCP over Streamable HTTP (in-process, mounted on this adapter) ──
    // A tower Service (rmcp), so use nest_service. Token-authenticated for all
    // methods via the dat_auth_middleware carve-out below. Not in /openapi.json.
    if mcp_http_enabled {
        let source = Arc::new(crate::adapters::mcp_http::CoreSource::new(
            cores.clone(),
            started_at,
            bind_ip.to_string(),
            cancel.clone(),
        ));
        // A loopback bind keeps rmcp's default Host allowlist; a deliberately
        // exposed bind disables it (the DAT token + TLS are the boundary). MCP
        // requests are token-authenticated regardless.
        let allowed_hosts = if bind_ip.is_loopback() {
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ]
        } else {
            Vec::new()
        };
        app = app.nest_service(
            paths::MCP,
            koi_mcp::streamable_http_service(source, allowed_hosts),
        );
    } else {
        app = app.nest(paths::MCP, disabled_fallback_router("mcp-http"));
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

    // DAT auth middleware: mutation requests (non-GET/OPTIONS) require X-Koi-Token header.
    // Applied BEFORE CORS so it only sees real requests (CORS handles OPTIONS preflight).
    let shared_token = Arc::new(dat_token);
    app = app.layer(middleware::from_fn(move |req, next| {
        let token = Arc::clone(&shared_token);
        dat_auth_middleware(req, next, token)
    }));

    // CORS must be the LAST .layer() call (outermost) so OPTIONS preflight
    // is handled before auth middleware strips unauthenticated requests.
    let cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, HeaderName::from_static("x-koi-token")])
        .allow_origin(tower_http::cors::AllowOrigin::predicate(|origin, _| {
            let s = origin.to_str().unwrap_or("");
            s.starts_with("http://localhost") || s.starts_with("http://127.0.0.1")
        }));
    app = app.layer(cors);

    // Bind to the resolved address (loopback by default; see --http-bind).
    // Exposure does not relax auth — mutations still require the DAT token.
    let listener = tokio::net::TcpListener::bind((bind_ip, port)).await?;
    tracing::info!("HTTP adapter listening on {}:{}", bind_ip, port);

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
    /// The HTTP adapter's bind address (e.g. "127.0.0.1" or "0.0.0.0").
    http_bind: String,
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
    paths(
        health,
        unified_status_handler,
        shutdown_handler,
        host_handler,
        prometheus_sd_handler
    ),
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
        )
        .nest(
            koi_runtime::http::paths::PREFIX,
            koi_runtime::http::RuntimeApiDoc::openapi(),
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
        TagBuilder::new()
            .name("runtime")
            .description(Some(
                "Runtime adapter - container lifecycle integration (Docker, Podman).",
            ))
            .external_docs(Some(ExternalDocs::new(format!("{base}/guide-runtime.md"))))
            .build(),
    ];

    let mut openapi = openapi;
    openapi.info = info;
    openapi.tags = Some(tags);
    openapi
}

// ── DAT auth middleware ──────────────────────────────────────────────

/// Daemon Access Token (DAT) authentication middleware.
///
/// GET and OPTIONS requests are exempt (read-only, CORS preflight).
/// All other methods require a valid `x-koi-token` header.
/// Uses constant-time comparison to prevent timing attacks.
pub(crate) async fn dat_auth_middleware(
    req: Request<Body>,
    next: Next,
    expected_token: Arc<String>,
) -> Response {
    // GET, HEAD, and OPTIONS are exempt from auth — EXCEPT under /v1/mcp. MCP
    // Streamable HTTP uses GET for its server→client SSE stream (a live channel,
    // not a read), so every method on /v1/mcp must carry the token. The public
    // discovery descriptors (e.g. the server card) live outside /v1/mcp and stay
    // GET-exempt. OPTIONS preflight is still let through so CORS works.
    let method = req.method().clone();
    let is_mcp = req.uri().path().starts_with(paths::MCP);
    let exempt_method = method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS;
    if method == axum::http::Method::OPTIONS || (exempt_method && !is_mcp) {
        return next.run(req).await;
    }

    // Check x-koi-token header with constant-time comparison.
    // The subtle crate guarantees constant-time execution regardless of length
    // difference, so no separate length check is needed.
    let authenticated = req
        .headers()
        .get(DAT_HEADER)
        .and_then(|val| val.to_str().ok())
        .map(|val| bool::from(val.as_bytes().ct_eq(expected_token.as_bytes())))
        .unwrap_or(false);

    if !authenticated {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "error": "unauthorized",
                "message": "Missing or invalid x-koi-token header"
            })),
        )
            .into_response();
    }

    next.run(req).await
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
    // The capability ladder is assembled once in koi-compose, shared with the dashboard and
    // embedded snapshots. `/v1/status` emits just the status (no `enabled` field).
    let cores = crate::DaemonCores {
        mdns: state.mdns.clone(),
        certmesh: state.certmesh.clone(),
        dns: state.dns.clone(),
        health: state.health.clone(),
        proxy: state.proxy.clone(),
        udp: state.udp.clone(),
        runtime: state.runtime.clone(),
        // Capability assembly does not read the snapshot bridge.
        mdns_snapshot: None,
    };
    let capabilities: Vec<koi_common::capability::CapabilityStatus> =
        koi_compose::status::assemble_capabilities(&cores)
            .await
            .into_iter()
            .map(|c| c.status)
            .collect();

    let uptime_secs = state.started_at.elapsed().as_secs();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "uptime_secs": uptime_secs,
        "daemon": true,
        "http_bind": state.http_bind,
        "mdns_browse_active": state.mdns_browse.as_ref().map(|m| m.is_active()),
        "mcp_http": state.mcp_http_enabled,
        "capabilities": capabilities,
    }))
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

#[utoipa::path(get, path = "/v1/host", tag = "system",
    summary = "Host identity and network interfaces",
    responses((status = 200, body = HostInfoResponse)))]
async fn host_handler() -> Json<HostInfoResponse> {
    let raw = hostname::get()
        .ok()
        .and_then(|os| os.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string());
    let fqdn = format!("{}.local", raw);

    // Identify the interface that owns the default route — the real LAN adapter
    // even on Windows, where virtual switches (vEthernet) share the physical
    // Ethernet IfType. We use the kernel's own route selection rather than a
    // network-enumeration crate (see `default_lan_interfaces`).
    let lan = default_lan_interfaces();

    Json(HostInfoResponse {
        hostname: raw,
        hostname_fqdn: fqdn,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        interfaces: HostInterfaces { lan },
    })
}

/// Query parameters for the Prometheus SD endpoint.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
struct PrometheusSdParams {
    /// `discovered` to also include LAN-discovered mDNS `_http._tcp` services.
    /// Absent/anything else returns only Koi-managed targets.
    include: Option<String>,
}

#[utoipa::path(get, path = "/v1/sd/prometheus", tag = "system",
    summary = "Prometheus HTTP service discovery",
    params(PrometheusSdParams),
    responses((status = 200, description = "Array of Prometheus target groups",
        content_type = "application/json")))]
async fn prometheus_sd_handler(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PrometheusSdParams>,
) -> Response {
    use crate::adapters::prometheus_sd::{build_target_groups, Slice};

    let slice = Slice::from_query(params.include.as_deref());

    // Snapshot each source (no locks held across await beyond the core's own).
    let health = match &state.health {
        Some(rt) => rt.core().snapshot().await.services,
        None => Vec::new(),
    };
    let instances = match &state.runtime {
        Some(rt) => rt.list_instances().await.unwrap_or_default(),
        None => Vec::new(),
    };
    // The certmesh roster is read from disk via the bridge — cheap and lock-free.
    let members = match &state.certmesh {
        Some(core) => {
            use koi_common::integration::CertmeshSnapshot;
            koi_compose::bridges::CertmeshBridge::new(core.clone()).active_members()
        }
        None => Vec::new(),
    };
    let discovered = match (slice, &state.mdns_snapshot) {
        (Slice::WithDiscovered, Some(snap)) => snap.cached_records(),
        _ => Vec::new(),
    };

    let groups = build_target_groups(
        &health,
        &instances,
        &members,
        &discovered,
        slice,
        chrono::Utc::now(),
    );

    // Prometheus http_sd requires a 200 with Content-Type: application/json and a
    // JSON array body. Build it explicitly so the content type is exact even on the
    // empty `[]` case.
    match serde_json::to_string(&groups) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Prometheus SD serialization failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json")],
                String::from("[]"),
            )
                .into_response()
        }
    }
}

#[utoipa::path(post, path = "/v1/admin/shutdown", tag = "system",
    summary = "Request graceful daemon shutdown",
    responses((status = 200, body = ShutdownResponse)))]
async fn shutdown_handler(Extension(state): Extension<AppState>) -> Json<serde_json::Value> {
    tracing::info!("Shutdown requested via admin endpoint");
    state.cancel.cancel();
    Json(serde_json::json!({ "status": "shutting_down" }))
}

// ── MCP discovery descriptor (the public "Door") ─────────────────────

/// Build the MCP server-card document — a public discovery descriptor (no secrets)
/// describing the in-process MCP endpoint, its transport, and how to authenticate.
/// Path-relative so it stays correct behind a proxy / under any host:port.
fn build_server_card(version: &str, mcp_enabled: bool) -> serde_json::Value {
    serde_json::json!({
        "name": "koi",
        "version": version,
        "mcp": {
            "enabled": mcp_enabled,
            "transport": "streamable-http",
            "path": paths::MCP,
            "auth": { "scheme": "bearer", "header": DAT_HEADER },
        }
    })
}

/// `GET /.well-known/mcp/server-card.json` — unauthenticated discovery (the Door).
async fn mcp_server_card_handler(Extension(state): Extension<AppState>) -> Response {
    let card = build_server_card(env!("CARGO_PKG_VERSION"), state.mcp_http_enabled);
    let body = serde_json::to_string(&card).unwrap_or_else(|_| "{}".to_string());
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
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

    // ── DAT auth: --http-bind exposure must never relax authentication ──
    // The token requirement is independent of the bind address, so these
    // wrap the exact production middleware and assert the policy directly.

    /// Minimal router applying the production `dat_auth_middleware`.
    fn dat_test_router(token: &str) -> Router {
        let expected = Arc::new(token.to_string());
        Router::new()
            .route("/probe", get(|| async { "ok" }).post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                dat_auth_middleware(req, next, expected)
            }))
    }

    #[tokio::test]
    async fn get_is_exempt_from_dat_auth() {
        let app = dat_test_router("secret-token");
        let req = Request::get("/probe").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn post_without_token_is_rejected() {
        let app = dat_test_router("secret-token");
        let req = Request::post("/probe").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_with_valid_token_is_accepted() {
        let app = dat_test_router("secret-token");
        let req = Request::post("/probe")
            .header(DAT_HEADER, "secret-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn post_with_wrong_token_is_rejected() {
        let app = dat_test_router("secret-token");
        let req = Request::post("/probe")
            .header(DAT_HEADER, "wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    // ── MCP auth carve-out: /v1/mcp is authenticated for ALL methods ──
    // MCP Streamable HTTP uses GET for its server→client SSE stream, so unlike
    // the rest of the API a GET under /v1/mcp must still carry the token.

    /// Router with a non-MCP GET and an MCP route, behind the production middleware.
    fn mcp_auth_test_router(token: &str) -> Router {
        let expected = Arc::new(token.to_string());
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route(paths::MCP, get(|| async { "ok" }).post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                dat_auth_middleware(req, next, expected)
            }))
    }

    #[tokio::test]
    async fn mcp_get_without_token_is_rejected() {
        let app = mcp_auth_test_router("secret-token");
        let req = Request::get(paths::MCP).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mcp_get_with_token_is_accepted() {
        let app = mcp_auth_test_router("secret-token");
        let req = Request::get(paths::MCP)
            .header(DAT_HEADER, "secret-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn mcp_post_without_token_is_rejected() {
        let app = mcp_auth_test_router("secret-token");
        let req = Request::post(paths::MCP).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_mcp_get_stays_exempt() {
        // The carve-out must not change the rest of the API: /healthz GET is still free.
        let app = mcp_auth_test_router("secret-token");
        let req = Request::get("/healthz").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn mcp_options_preflight_is_not_blocked() {
        // OPTIONS is always let through so CORS preflight works (the handler has no
        // OPTIONS method → 405, but crucially NOT 401).
        let app = mcp_auth_test_router("secret-token");
        let req = Request::builder()
            .method("OPTIONS")
            .uri(paths::MCP)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mcp_http_disabled_fallback_is_503() {
        let app = disabled_fallback_router("mcp-http");
        let req = Request::post("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn server_card_describes_streamable_http() {
        let card = build_server_card("9.9.9", true);
        assert_eq!(card["mcp"]["transport"], "streamable-http");
        assert_eq!(card["mcp"]["path"], "/v1/mcp");
        assert_eq!(card["mcp"]["auth"]["header"], "x-koi-token");
        assert_eq!(card["mcp"]["enabled"], true);
        assert_eq!(card["version"], "9.9.9");
    }

    #[tokio::test]
    async fn server_card_get_is_unauthenticated() {
        // The Door is a public GET (NOT under /v1/mcp), so the auth carve-out must
        // not catch it — discovery metadata carries no secrets.
        let expected = Arc::new("secret-token".to_string());
        let app = Router::new()
            .route(paths::MCP_SERVER_CARD, get(mcp_server_card_handler))
            .layer(Extension(empty_app_state()))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                dat_auth_middleware(req, next, expected)
            }));
        let req = Request::get(paths::MCP_SERVER_CARD)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
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
        // MCP is JSON-RPC over Streamable HTTP, not a utoipa surface — like ACME it
        // is deliberately excluded from /openapi.json.
        assert!(
            !paths.contains(&"/v1/mcp"),
            "/v1/mcp must NOT be in OpenAPI: {paths:?}"
        );
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

    // ── Prometheus HTTP SD endpoint ──
    //
    // An AppState with all-None cores models a fresh daemon: the endpoint must
    // still return 200 + application/json + an empty array (Prometheus treats a
    // missing array as an error, so `[]` is the contract for "nothing yet").

    /// AppState with every capability absent — the empty-daemon fixture.
    fn empty_app_state() -> AppState {
        AppState {
            mdns: None,
            certmesh: None,
            dns: None,
            health: None,
            proxy: None,
            udp: None,
            runtime: None,
            started_at: std::time::Instant::now(),
            cancel: CancellationToken::new(),
            http_bind: "127.0.0.1".to_string(),
            mdns_browse: None,
            mdns_snapshot: None,
            mcp_http_enabled: false,
        }
    }

    fn prometheus_test_router(state: AppState) -> Router {
        Router::new()
            .route(paths::PROMETHEUS_SD, get(prometheus_sd_handler))
            .layer(Extension(state))
    }

    #[tokio::test]
    async fn prometheus_sd_is_json_content_type() {
        let app = prometheus_test_router(empty_app_state());
        let req = Request::get(paths::PROMETHEUS_SD)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("application/json"),
            "content-type should be application/json, got: {ct}"
        );
    }

    #[tokio::test]
    async fn prometheus_sd_empty_daemon_returns_empty_array() {
        let app = prometheus_test_router(empty_app_state());
        let req = Request::get(paths::PROMETHEUS_SD)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // Must be a valid JSON array, and empty on a fresh daemon.
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array(), "body should be a JSON array: {json}");
        assert_eq!(json.as_array().unwrap().len(), 0, "empty daemon → []");
    }

    #[tokio::test]
    async fn prometheus_sd_get_is_unauthenticated() {
        // The endpoint must be reachable without the DAT token (like /healthz).
        // GET is exempt from the auth middleware; this guards that it stays a GET.
        let app = prometheus_test_router(empty_app_state()).layer(middleware::from_fn(
            move |req, next| {
                let token = Arc::new("never-supplied".to_string());
                dat_auth_middleware(req, next, token)
            },
        ));
        let req = Request::get(paths::PROMETHEUS_SD)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn openapi_spec_contains_prometheus_sd_path() {
        let spec = build_openapi();
        let paths: Vec<&str> = spec.paths.paths.keys().map(|k| k.as_str()).collect();
        assert!(
            paths.contains(&"/v1/sd/prometheus"),
            "missing /v1/sd/prometheus: {paths:?}"
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
