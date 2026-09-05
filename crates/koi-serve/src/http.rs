//! HTTP adapter - builds and serves the axum router.
//!
//! Mounts domain routes, health check, unified status, CORS, and OpenAPI docs.
//! Called by `daemon_mode()` in `main.rs` and `run_service()` in `platform/windows.rs`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Extension};
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

use koi_compose::cores::Cores as DaemonCores;
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
    /// One coherent aggregate revision projected for automation inventory reads.
    pub const INVENTORY: &str = "/v1/inventory";
    pub const SHUTDOWN: &str = "/v1/admin/shutdown";
    pub const HOST: &str = "/v1/host";
    /// Aggregate dashboard snapshot. Loopback-readable; DAT required remotely.
    pub const DASHBOARD_SNAPSHOT: &str = "/v1/dashboard/snapshot";
    /// Dashboard activity SSE. Loopback-readable; DAT required remotely.
    pub const DASHBOARD_EVENTS: &str = "/v1/dashboard/events";
    /// Prometheus HTTP service discovery (their format — see Door 1 / integrations.md).
    pub const PROMETHEUS_SD: &str = "/v1/sd/prometheus";
    /// In-process MCP server (Streamable HTTP / JSON-RPC). Token-authenticated for
    /// all methods (carved out of the GET exemption); not in `/openapi.json`.
    pub const MCP: &str = "/v1/mcp";
    /// Public MCP discovery descriptor (the "Door"): an unauthenticated GET
    /// describing the MCP endpoint, transport, and auth. No secrets.
    pub const MCP_SERVER_CARD: &str = "/.well-known/mcp/server-card.json";
    /// Unified event SSE stream (DAT-gated GET; wishlist 1.1/1.2).
    /// Emits `KoiEventWire` JSON objects one per line / SSE data field.
    pub const EVENTS: &str = "/v1/events";
}

// ── App state ───────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    system_status: Arc<koi_compose::status::KoiStatusRuntime>,
    host: koi_compose::host::HostIdentity,
    started_at: std::time::Instant,
    cancel: CancellationToken,
    http_bind: String,
    /// Lazy mDNS meta-browse controller (when mDNS is enabled), so `/v1/status` can
    /// report whether LAN-wide browsing is currently active.
    mdns_browse: Option<Arc<LazyMetaBrowse>>,
    /// Whether the in-process MCP HTTP transport (`/v1/mcp`) is mounted. Reported
    /// on `/v1/status` as a field (MCP-HTTP is a transport, not a domain rung).
    mcp_http_enabled: bool,
    /// Enabled outbound webhook sink count (ADR-028). Zero = fan-out off.
    webhook_sinks: usize,
    /// `/v1/status` `daemon` field - a full daemon (`true`) vs an embedded instance.
    daemon: bool,
}

// ── Entrypoint ──────────────────────────────────────────────────────

/// Declarative description of the HTTP surface to serve. One router builder backs both
/// the daemon (full surface: DAT auth, MCP, admin-shutdown, OpenAPI) via [`crate::serve()`]
/// and an embedded host (loopback bind, optional auth, no MCP) — one implementation, so
/// their `/v1/status` shapes and route sets cannot drift.
pub struct HttpConfig {
    pub started_at: std::time::Instant,
    pub host: koi_compose::host::HostIdentity,
    /// Dashboard state — `Some` mounts the dashboard SPA + snapshot/events routes.
    pub dashboard: Option<DashboardState>,
    /// Browser state — `Some` mounts the mDNS browser page + routes (else a 503 fallback).
    pub browser: Option<BrowserState>,
    /// DAT for mutation auth — `Some` enforces the `x-koi-token` middleware; `None` leaves
    /// mutations unauthenticated (only safe behind a loopback bind).
    pub auth: Option<String>,
    /// Mount the in-process MCP HTTP transport at `/v1/mcp`.
    pub mcp_http: bool,
    /// Outbound webhook sinks (ADR-028). Reported on `/v1/status`; the fan-out
    /// itself is spawned by [`crate::serve()`], not this adapter.
    pub webhooks: Vec<koi_compose::webhook::WebhookSink>,
    /// Mount `POST /v1/admin/shutdown` (cancels the serving token).
    pub admin_shutdown: bool,
    /// Mount `/docs` (Scalar) + `/openapi.json`.
    pub api_docs: bool,
    /// `/v1/status` `daemon` field — a full daemon (`true`) vs an embedded instance.
    pub daemon: bool,
    /// In-process Pond desired-state adapter. `Some` mounts only its authenticated
    /// publish/control routes here; its read-only LAN router owns a separate socket.
    pub pond: Option<crate::pond::PondRuntime>,
}

/// Serve a previously bound HTTP listener until `cancel` fires.
///
/// Socket acquisition is deliberately separate from task admission: callers can prove the
/// real address (including an OS-assigned port), construct dependent adapters such as Pond and
/// local control from that fact, and fail startup before publishing readiness or discovery.
pub async fn serve(
    listener: tokio::net::TcpListener,
    cores: DaemonCores,
    cfg: HttpConfig,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let local_addr = listener.local_addr()?;
    let bind_ip = local_addr.ip();
    let HttpConfig {
        started_at,
        host,
        dashboard: dashboard_state,
        browser: browser_state,
        auth,
        mcp_http: mcp_http_enabled,
        webhooks,
        admin_shutdown,
        api_docs,
        daemon,
        pond,
    } = cfg;
    let webhook_sinks = webhooks.len();

    let app_state = AppState {
        system_status: Arc::clone(&cores.system_status),
        host,
        started_at,
        cancel: cancel.clone(),
        http_bind: local_addr.ip().to_string(),
        mdns_browse: browser_state.as_ref().map(|b| b.meta.clone()),
        mcp_http_enabled,
        webhook_sinks,
        daemon,
    };

    // ── System endpoints (always mounted) ──
    let mut app = Router::new()
        .route(paths::HEALTHZ, get(health))
        .route(paths::UNIFIED_STATUS, get(unified_status_handler))
        .route(paths::INVENTORY, get(inventory_handler))
        .route(paths::HOST, get(host_handler))
        .route(paths::PROMETHEUS_SD, get(prometheus_sd_handler))
        .route(paths::MCP_SERVER_CARD, get(mcp_server_card_handler));

    // ── Admin shutdown (daemon / Windows service only; an embedded host owns its own
    // lifecycle via its handle, so it does not expose a remote shutdown endpoint) ──
    if admin_shutdown {
        app = app.route(paths::SHUTDOWN, post(shutdown_handler));
    }

    // ── Operator surface + dashboard. Pond's public read model never merges here;
    // only its DAT-gated intent and fixed-bundle publish doors do. ──
    let pond_enabled = pond.is_some();
    if let Some(runtime) = pond {
        app = app.merge(crate::pond::operator_routes(runtime));
    }
    if dashboard_state.is_some() {
        app = app
            .route("/", get(koi_dashboard::dashboard::get_dashboard))
            .route(
                paths::DASHBOARD_SNAPSHOT,
                get(koi_dashboard::dashboard::get_snapshot),
            )
            .route(
                paths::DASHBOARD_EVENTS,
                get(koi_dashboard::dashboard::get_events),
            );
    }

    // ── Unified event stream (wishlist 1.1/1.2 — always mounted, 503 when no dashboard) ──
    app = app.route(paths::EVENTS, get(events_handler));

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

    if let Some(ref trust_core) = cores.trust {
        app = app.nest(koi_trust::http::paths::PREFIX, trust_core.routes());
    } else {
        app = app.nest(
            koi_trust::http::paths::PREFIX,
            disabled_fallback_router("trust"),
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
            koi_health::http::routes(health_runtime.clone()),
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
    let mut mcp_source = None;
    if mcp_http_enabled {
        let source = Arc::new(crate::mcp_http::CoreSource::new(
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
            koi_mcp::streamable_http_service(source.clone(), allowed_hosts),
        );
        mcp_source = Some(source);
    } else {
        app = app.nest(paths::MCP, disabled_fallback_router("mcp-http"));
    }

    // ── OpenAPI spec + Scalar docs (conditional) ──
    if api_docs {
        // Composed from domain-owned specs via nest().
        let openapi = build_openapi_for(pond_enabled);
        // Serve interactive API docs at /docs and the raw spec at /openapi.json.
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

    app = app.layer(Extension(app_state));
    if let Some(ds) = dashboard_state {
        app = app.layer(Extension(ds));
    }

    // DAT auth middleware: mutation requests (non-GET/OPTIONS) require the x-koi-token
    // header when a token is configured. Applied BEFORE CORS so it only sees real requests
    // (CORS handles OPTIONS preflight). `None` — an embedded host on a loopback bind —
    // leaves mutations open to the loopback boundary.
    if let Some(token) = auth {
        let shared_token = Arc::new(token);
        app = app.layer(middleware::from_fn(move |req, next| {
            let token = Arc::clone(&shared_token);
            dat_auth_middleware(req, next, token)
        }));
    }

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
            is_loopback_origin(origin.to_str().unwrap_or(""))
        }));
    app = app.layer(cors);

    tracing::info!("HTTP adapter listening on {local_addr}");

    // ConnectInfo carries the peer address so the auth middleware can keep the
    // trust/zone reads token-free for loopback callers but gated for remote peers.
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        cancel.cancelled().await;
    })
    .await;

    if let Some(source) = mcp_source {
        source.shutdown().await;
    }
    result?;

    tracing::debug!("HTTP adapter stopped");
    Ok(())
}

// ── Response types for top-level endpoints ──────────────────────────

#[derive(Debug, Serialize, ToSchema)]
struct UnifiedStatusResponse {
    version: String,
    platform: String,
    uptime_secs: u64,
    revision: u64,
    daemon: bool,
    /// The HTTP adapter's bind address (e.g. "127.0.0.1" or "0.0.0.0").
    http_bind: String,
    /// The confidentiality `seal()` produces — `passthrough` | `groupkey` (ADR-020
    /// §4). Absent when certmesh is disabled. `null`-able.
    #[serde(skip_serializing_if = "Option::is_none")]
    seal: Option<String>,
    capabilities: Vec<koi_common::capability::CapabilityStatus>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ShutdownResponse {
    status: String,
}

/// Host identity and network interfaces.
#[derive(Debug, Serialize, ToSchema)]
struct HostInfoResponse {
    /// Raw hostname (e.g. "node-azure-pool").
    hostname: String,
    /// Fully-qualified mDNS name (e.g. "node-azure-pool.local").
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
        inventory_handler,
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
    build_openapi_for(true)
}

fn build_openapi_for(include_pond: bool) -> utoipa::openapi::OpenApi {
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
            koi_trust::http::paths::PREFIX,
            koi_trust::http::TrustApiDoc::openapi(),
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
        TagBuilder::new()
            .name("pond")
            .description(Some(
                "Operator control for Koi's read-only LAN presentation adapter.",
            ))
            .build(),
    ];

    let mut openapi = openapi;
    if include_pond {
        openapi.merge(crate::pond::PondApiDoc::openapi());
    }
    openapi.info = info;
    openapi.tags = Some(tags);
    openapi
}

/// Exact loopback-origin check for CORS. Accepts only `http://` origins whose host
/// authority is exactly `localhost`, `127.0.0.1`, or `::1` (optional port). A prefix
/// match would let an attacker-registrable name like `http://localhost.evil.com`
/// through and have it reflected into `Access-Control-Allow-Origin`, exposing the
/// GET-readable surface cross-origin.
fn is_loopback_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = if let Some(v6) = authority.strip_prefix('[') {
        // IPv6 literal: "[::1]:port" → "::1"
        match v6.split_once(']') {
            Some((h, _)) => h,
            None => return false,
        }
    } else {
        // "host" or "host:port"
        authority.split(':').next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

// ── DAT auth middleware ──────────────────────────────────────────────

/// Daemon Access Token (DAT) authentication middleware.
///
/// GET, HEAD, and OPTIONS requests are exempt (read-only, CORS preflight) —
/// except for `/v1/mcp` and `/v1/certmesh/log` (token required even on GET), the
/// `/v1/udp/` surface, and the protected zone/posture reads
/// (`/v1/certmesh/{status,diagnose}`, `/v1/dns/{list,zone}`, and the dashboard's
/// aggregate snapshot/activity stream) which stay exempt only for a loopback peer and
/// require the token from a remote one. Pond control is also
/// token-gated on every method. All other methods require a valid
/// `x-koi-token` header. Uses constant-time comparison to
/// prevent timing attacks.
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
    let path = req.uri().path();
    let is_mcp = path.starts_with(paths::MCP);
    // The CA audit log is the one GET that is NOT read-safe to expose: it
    // narrates the full trust history (member joins/revocations, auth rotations,
    // failed unlock attempts, backup/restore). Carve it out of the GET exemption
    // so reading it requires the daemon token — exactly like /v1/mcp, on every
    // peer. The trust bundle remains public for its self-verifying protocol role;
    // full status and diagnosis are loopback-gated below, while `/bootstrap` is
    // the intentionally small public preflight.
    // The `koi certmesh log` CLI already sends the token (require_daemon → auth_get).
    let is_audit_log = path == koi_certmesh::http::paths::LOG;
    // `/v1/certmesh/posture` is the live trust-posture endpoint (ADR-020 reactive
    // plane / wishlist 1.2). Like the audit log it is a GET whose content is not
    // safe to leave open to an unauthenticated remote peer (it confirms whether a
    // node is signed/authenticated). Gate it on the daemon token.
    let is_posture = path == koi_certmesh::http::paths::POSTURE;
    // `/v1/events` is the unified SSE event stream (wishlist 1.1/1.2). Like
    // `/v1/mcp` it is a GET that opens a persistent live channel rather than
    // returning a static document, so it must carry the token on every request.
    let is_events_stream = path == paths::EVENTS;
    // Pond desire is operator state. Even its GET is intentionally absent from
    // the broad read exemption; the public projection lives on Pond's own router.
    let is_pond_control = path == "/v1/pond";
    // The UDP surface is carved out of the GET exemption too: `/v1/udp/status`
    // enumerates every binding's id and `/v1/udp/recv/{id}` streams a binding's
    // inbound datagrams — both expose other token-holders' bindings, so reading
    // them requires the daemon token (the mutations already do). Gating the whole
    // `/v1/udp/` prefix keeps the surface coherent.
    let is_udp = path.starts_with("/v1/udp/");
    // Certmesh enrollment is the one mutation that is NOT DAT-gated: a fresh node
    // joining a remote CA has no way to know that host's local token, so it
    // authorizes with a TOTP enrollment code in the request body instead. The
    // join handler enforces that auth + the enrollment policy itself, so the DAT
    // middleware must let the request reach it.
    let is_enrollment = path == koi_certmesh::http::paths::JOIN;
    // These reads expose the DNS zone, full trust posture, or an aggregate/SSE
    // carrying that same detail. Fine on loopback — local tooling and dashboard
    // UX — but not safe to leave world-readable when the adapter is routable. They
    // stay GET-exempt only for a loopback peer; a non-loopback peer must present
    // the token. When the peer address is unknown we fail closed.
    //
    // NOT gated, deliberately: `/v1/certmesh/bootstrap` and
    // `/v1/certmesh/trust-bundle` are load-bearing in the unauthenticated
    // cross-host protocol. Bootstrap exposes only the CA pin/enrollment preflight;
    // the bundle is self-verifying. Full status contains roster and diagnosis.
    let is_protected_read = path == koi_certmesh::http::paths::DIAGNOSE
        || path == koi_certmesh::http::paths::STATUS
        || path == koi_trust::http::paths::STATUS
        || path == "/v1/dns/list"
        || path == "/v1/dns/zone"
        || path == "/v1/dns/entries"
        || path == paths::INVENTORY
        || path == paths::DASHBOARD_SNAPSHOT
        || path == paths::DASHBOARD_EVENTS;
    let peer_is_loopback = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false);
    let exempt_method = method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS;
    // A protected read is exempt only from a loopback peer.
    let protected_ok = peer_is_loopback || !is_protected_read;
    let read_exempt = exempt_method
        && !is_mcp
        && !is_audit_log
        && !is_posture
        && !is_events_stream
        && !is_pond_control
        && !is_udp
        && protected_ok;
    // OPTIONS is always let through, even on a gated path: a CORS preflight carries no
    // credentials by web standard, and a preflight against a GET-only/gated route returns
    // only CORS headers or 405 — never the resource body — so it cannot leak gated content.
    // Gating it would instead break legitimate preflights for /v1/mcp and the protected reads.
    if is_enrollment || method == axum::http::Method::OPTIONS || read_exempt {
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

/// `GET /v1/events` — DAT-gated unified event SSE stream (wishlist 1.1/1.2).
///
/// Delegates to koi-dashboard which owns the event channel and the stream
/// types (`tokio_stream`, `async_stream`) — koi-serve avoids importing them.
async fn events_handler(
    dashboard: Option<Extension<koi_dashboard::dashboard::DashboardState>>,
) -> axum::response::Response {
    koi_dashboard::dashboard::get_wire_events(dashboard).await
}

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
    let status = state.system_status.status();
    let capabilities: Vec<koi_common::capability::CapabilityStatus> = status
        .capabilities
        .iter()
        .map(|capability| capability.status.clone())
        .collect();

    let uptime_secs = state.started_at.elapsed().as_secs();
    // The confidentiality `seal()` currently produces (ADR-020 §4) — `passthrough`
    // until the group-key rung lands. Reported only when certmesh is present (sealing
    // needs the identity infra); makes the un-encrypted state observable, not silent.
    let seal = seal_projection(status.as_ref());
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "uptime_secs": uptime_secs,
        "revision": status.revision,
        "daemon": state.daemon,
        "http_bind": state.http_bind,
        "mdns_browse_active": state.mdns_browse.as_ref().map(|m| m.is_active()),
        "mcp_http": state.mcp_http_enabled,
        "webhooks": {
            "enabled": state.webhook_sinks > 0,
            "sinks": state.webhook_sinks,
        },
        "seal": seal,
        "capabilities": capabilities,
    }))
}

fn seal_projection(status: &koi_compose::status::KoiStatus) -> Option<&'static str> {
    status
        .domains
        .certmesh
        .as_ref()
        .map(|_| koi_common::sealed::CURRENT_CONFIDENTIALITY.as_wire())
}

/// `GET /v1/inventory` — one coherent product revision for transport-backed MCP.
///
/// The handler captures the aggregate exactly once. Bounded mDNS/DNS runtime,
/// Health, and DNS catalog details are projected from that same immutable value;
/// the client must never join separate domain endpoint reads into a second model.
#[utoipa::path(get, path = "/v1/inventory", tag = "system",
    summary = "Coherent aggregate inventory snapshot",
    responses((status = 200, description = "Capability and domain inventory from one product revision")))]
async fn inventory_handler(Extension(state): Extension<AppState>) -> Response {
    let status = state.system_status.status();
    match crate::inventory::project(
        status.as_ref(),
        None,
        state.started_at.elapsed().as_secs(),
        &state.http_bind,
        state.daemon,
    ) {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            tracing::error!(error = %error, "aggregate inventory serialization failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "serialization_failed",
                    "message": "Could not serialize the aggregate inventory",
                })),
            )
                .into_response()
        }
    }
}

/// LAN interfaces for the `/v1/host` response: the interface that owns the
/// default route (matched by its source IP), or — failing that — every
/// non-loopback, non-link-local IPv4 interface.
fn default_lan_interfaces() -> std::io::Result<Vec<NetworkInterface>> {
    Ok(crate::network::lan_ipv4_interfaces()?
        .into_iter()
        .map(|interface| NetworkInterface {
            name: interface.name,
            ip: interface.address.to_string(),
        })
        .collect())
}

#[utoipa::path(get, path = "/v1/host", tag = "system",
    summary = "Host identity and network interfaces",
    responses(
        (status = 200, body = HostInfoResponse),
        (status = 500, description = "Host observation failed")
    ))]
async fn host_handler(Extension(state): Extension<AppState>) -> Response {
    match observe_host(&state.host) {
        Ok(host) => Json(host).into_response(),
        Err(error) => {
            tracing::error!(%error, "host observation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "host_observation_failed",
                    "message": error.to_string(),
                })),
            )
                .into_response()
        }
    }
}

fn observe_host(host: &koi_compose::host::HostIdentity) -> anyhow::Result<HostInfoResponse> {
    // Identify the interface that owns the default route — the real LAN adapter
    // even on Windows, where virtual switches (vEthernet) share the physical
    // Ethernet IfType. We use the kernel's own route selection rather than a
    // network-enumeration crate (see `default_lan_interfaces`).
    let lan = default_lan_interfaces()?;

    Ok(HostInfoResponse {
        hostname: host.hostname().to_string(),
        hostname_fqdn: host.local_fqdn().to_string(),
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
    use crate::prometheus_sd::{build_target_groups, Slice};

    let slice = Slice::from_query(params.include.as_deref());

    // One immutable product revision is the complete input. Presentation never
    // rereads individual domains, performs I/O, or assembles a torn view.
    let status = state.system_status.status();
    let groups = build_target_groups(status.as_ref(), slice, chrono::Utc::now());

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
    Json(card).into_response()
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
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::Request;
    use koi_runtime::{RuntimeBackend, RuntimeError, RuntimeObservation};
    use tower::ServiceExt;

    struct FixedRuntimeBackend {
        initial: Vec<koi_runtime::Instance>,
    }

    #[async_trait]
    impl RuntimeBackend for FixedRuntimeBackend {
        fn name(&self) -> &'static str {
            "fixed-test-provider"
        }

        async fn connect(&mut self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn list_instances(&self) -> Result<Vec<koi_runtime::Instance>, RuntimeError> {
            Ok(self.initial.clone())
        }

        async fn begin_observation(
            self: Arc<Self>,
            _tx: tokio::sync::mpsc::Sender<koi_runtime::RuntimeEvent>,
            cancel: CancellationToken,
        ) -> Result<RuntimeObservation, RuntimeError> {
            Ok(RuntimeObservation::new(self.initial.clone(), async move {
                cancel.cancelled().await;
                Ok(())
            }))
        }
    }

    /// Agent-Door conformance vector (V1-11): the served card must match the
    /// pinned shape in docs/reference/vectors/agent-door-card.json exactly
    /// (module version substituted for the `<semver>` placeholder).
    #[test]
    fn agent_door_vector_matches_the_impl() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/reference/vectors/agent-door-card.json"
        ))
        .expect("agent-door vector parses");
        let card = build_server_card("9.9.9", true);
        let mut expected = vector["card"].clone();
        expected["version"] = serde_json::json!("9.9.9");
        assert_eq!(
            card, expected,
            "served Agent-Door card drifted from the pinned vector"
        );

        let disabled = build_server_card("9.9.9", false);
        assert_eq!(
            disabled["mcp"]["enabled"],
            vector["disabled_variant"]["mcp"]["enabled"]
        );
    }

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

    // ── Audit-log carve-out: /v1/certmesh/log is authenticated on GET ──
    // The CA audit log narrates the full trust history (joins, revocations, auth
    // rotations, failed unlocks), so unlike the other certmesh read GETs it must
    // carry the token even though it is a GET.

    /// Router with the audit-log route and a sibling exempt GET, behind the
    /// production middleware.
    fn audit_log_test_router(token: &str) -> Router {
        let expected = Arc::new(token.to_string());
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route(koi_certmesh::http::paths::LOG, get(|| async { "ok" }))
            .route("/v1/certmesh/status", get(|| async { "ok" }))
            .route("/v1/certmesh/bootstrap", get(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                dat_auth_middleware(req, next, expected)
            }))
    }

    #[tokio::test]
    async fn audit_log_get_without_token_is_rejected() {
        let app = audit_log_test_router("secret-token");
        let req = Request::get(koi_certmesh::http::paths::LOG)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn audit_log_get_with_token_is_accepted() {
        let app = audit_log_test_router("secret-token");
        let req = Request::get(koi_certmesh::http::paths::LOG)
            .header(DAT_HEADER, "secret-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn certmesh_bootstrap_read_stays_exempt() {
        // Bootstrap is the deliberately small public enrollment preflight.
        let app = audit_log_test_router("secret-token");
        let req = Request::get("/v1/certmesh/bootstrap")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    // ── UDP GET surface is token-gated (binding enumeration / datagram read) ──

    fn udp_carveout_test_router(token: &str) -> Router {
        let expected = Arc::new(token.to_string());
        Router::new()
            .route("/v1/udp/status", get(|| async { "ok" }))
            .route("/v1/udp/recv/abc", get(|| async { "ok" }))
            .route("/v1/mdns/discover", get(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                dat_auth_middleware(req, next, expected)
            }))
    }

    #[tokio::test]
    async fn udp_get_surface_requires_token() {
        for path in ["/v1/udp/status", "/v1/udp/recv/abc"] {
            let app = udp_carveout_test_router("secret-token");
            let req = Request::get(path).body(Body::empty()).unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "{path} must require the token even on GET"
            );
        }
        // With the token the request reaches the handler.
        let app = udp_carveout_test_router("secret-token");
        let req = Request::get("/v1/udp/status")
            .header(DAT_HEADER, "secret-token")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            axum::http::StatusCode::OK
        );
    }

    #[tokio::test]
    async fn non_udp_sibling_get_stays_exempt() {
        // The carve-out is surgical: an unprotected sibling read GET stays token-free.
        let app = udp_carveout_test_router("secret-token");
        let req = Request::get("/v1/mdns/discover")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            axum::http::StatusCode::OK
        );
    }

    #[tokio::test]
    async fn pond_control_get_requires_the_daemon_token() {
        let expected = Arc::new("secret-token".to_string());
        let app = Router::new()
            .route("/v1/pond", get(|| async { "ok" }))
            .route("/healthz", get(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                dat_auth_middleware(req, next, expected)
            }));

        let response = app
            .clone()
            .oneshot(Request::get("/v1/pond").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::get("/v1/pond")
                    .header(DAT_HEADER, "secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // ── Protected zone/posture reads: loopback-exempt, remote-gated ──
    // Full trust/DNS reads and dashboard projections carrying the same data are
    // token-free for a loopback peer (local tooling), token-required from a remote
    // peer, and fail-closed when the peer is unknown. Bootstrap and the signed
    // trust bundle remain part of the unauthenticated protocol.

    const PROTECTED_READS: [&str; 9] = [
        "/v1/dns/list",
        "/v1/dns/zone",
        "/v1/dns/entries",
        koi_certmesh::http::paths::STATUS,
        koi_certmesh::http::paths::DIAGNOSE,
        koi_trust::http::paths::STATUS,
        paths::INVENTORY,
        paths::DASHBOARD_SNAPSHOT,
        paths::DASHBOARD_EVENTS,
    ];

    fn protected_read_test_router(token: &str) -> Router {
        let expected = Arc::new(token.to_string());
        let mut router = Router::new();
        for path in PROTECTED_READS {
            router = router.route(path, get(|| async { "ok" }));
        }
        router.layer(middleware::from_fn(move |req, next| {
            let expected = expected.clone();
            dat_auth_middleware(req, next, expected)
        }))
    }

    fn get_with_peer(path: &str, peer: SocketAddr) -> Request<Body> {
        let mut req = Request::get(path).body(Body::empty()).unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        req
    }

    #[tokio::test]
    async fn protected_read_exempt_for_loopback_peer() {
        for path in PROTECTED_READS {
            let app = protected_read_test_router("secret-token");
            let req = get_with_peer(path, "127.0.0.1:54321".parse().unwrap());
            assert_eq!(
                app.oneshot(req).await.unwrap().status(),
                axum::http::StatusCode::OK,
                "{path} must stay token-free for a loopback peer"
            );
        }
    }

    #[tokio::test]
    async fn protected_read_requires_token_for_remote_peer() {
        for path in PROTECTED_READS {
            // Remote peer, no token → 401.
            let app = protected_read_test_router("secret-token");
            let req = get_with_peer(path, "192.168.1.50:40000".parse().unwrap());
            assert_eq!(
                app.oneshot(req).await.unwrap().status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "{path} must require the token for a remote peer"
            );
            // Remote peer with the token → reaches the handler.
            let app = protected_read_test_router("secret-token");
            let mut req = Request::get(path)
                .header(DAT_HEADER, "secret-token")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(
                "192.168.1.50:40000".parse::<SocketAddr>().unwrap(),
            ));
            assert_eq!(
                app.oneshot(req).await.unwrap().status(),
                axum::http::StatusCode::OK,
                "{path} must accept the token from a remote peer"
            );
        }
    }

    #[tokio::test]
    async fn protected_read_fails_closed_without_peer_info() {
        // No ConnectInfo extension (peer unknown) → require the token.
        for path in PROTECTED_READS {
            let app = protected_read_test_router("secret-token");
            let req = Request::get(path).body(Body::empty()).unwrap();
            assert_eq!(
                app.oneshot(req).await.unwrap().status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "{path} must fail closed without peer identity"
            );
        }
    }

    fn trust_auth_test_router(token: &str) -> Router {
        let expected = Arc::new(token.to_string());
        Router::new()
            .route(koi_trust::http::paths::INSTALL, post(|| async { "ok" }))
            .route(koi_trust::http::paths::ENSURE, post(|| async { "ok" }))
            .route(
                koi_trust::http::paths::REMOVE,
                axum::routing::delete(|| async { "ok" }),
            )
            .route(koi_trust::http::paths::INSPECT, post(|| async { "ok" }))
            .route(koi_trust::http::paths::RECONCILE, post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                dat_auth_middleware(req, next, expected)
            }))
    }

    #[tokio::test]
    async fn every_trust_command_and_platform_query_requires_the_daemon_token() {
        let routes = [
            (axum::http::Method::POST, koi_trust::http::paths::INSTALL),
            (axum::http::Method::POST, koi_trust::http::paths::ENSURE),
            (axum::http::Method::DELETE, koi_trust::http::paths::REMOVE),
            (axum::http::Method::POST, koi_trust::http::paths::INSPECT),
            (axum::http::Method::POST, koi_trust::http::paths::RECONCILE),
        ];
        for (method, path) in routes {
            let response = trust_auth_test_router("secret-token")
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");

            let response = trust_auth_test_router("secret-token")
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header(DAT_HEADER, "secret-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
    }

    // ── CORS loopback-origin check is an exact host-authority match ──

    #[test]
    fn cors_origin_accepts_only_exact_loopback_hosts() {
        assert!(is_loopback_origin("http://localhost:5641"));
        assert!(is_loopback_origin("http://127.0.0.1:5641"));
        assert!(is_loopback_origin("http://localhost"));
        assert!(is_loopback_origin("http://[::1]:5641"));
        // Attacker-registrable look-alikes must be rejected (the prefix-match bug).
        assert!(!is_loopback_origin("http://localhost.evil.com"));
        assert!(!is_loopback_origin("http://127.0.0.1.evil.com"));
        assert!(!is_loopback_origin("http://localhostfoo:9999"));
        assert!(!is_loopback_origin("https://localhost:5641"));
        assert!(!is_loopback_origin("http://evil.com/http://localhost"));
    }

    // ── Certmesh enrollment is DAT-exempt (TOTP-authorized bootstrap) ──
    // A fresh node joining a remote CA can't know that host's token, so
    // /v1/certmesh/join must reach its handler (which enforces TOTP) without one.

    fn certmesh_auth_test_router(token: &str) -> Router {
        let expected = Arc::new(token.to_string());
        Router::new()
            .route(koi_certmesh::http::paths::JOIN, post(|| async { "ok" }))
            .route("/v1/certmesh/revoke", post(|| async { "ok" }))
            .layer(middleware::from_fn(move |req, next| {
                let expected = expected.clone();
                dat_auth_middleware(req, next, expected)
            }))
    }

    #[tokio::test]
    async fn certmesh_join_is_exempt_from_dat_auth() {
        let app = certmesh_auth_test_router("secret-token");
        let req = Request::post(koi_certmesh::http::paths::JOIN)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "tokenless enrollment must pass the auth layer (TOTP is the gate)"
        );
    }

    #[tokio::test]
    async fn other_certmesh_mutations_still_require_token() {
        let app = certmesh_auth_test_router("secret-token");
        let req = Request::post("/v1/certmesh/revoke")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "non-enrollment certmesh writes still require the token"
        );
    }

    /// Pin the documented operator-route matrix to the production middleware.
    /// Handlers return `200`; any other status therefore comes from the real DAT
    /// boundary, including the intentional enrollment exception and remote-read
    /// distinction.
    #[tokio::test]
    async fn documented_route_auth_matrix_matches_production_middleware() {
        struct Case {
            name: &'static str,
            method: &'static str,
            path: &'static str,
            peer: &'static str,
            token: bool,
            expected: StatusCode,
        }

        let cases = [
            Case {
                name: "public bootstrap",
                method: "GET",
                path: koi_certmesh::http::paths::BOOTSTRAP,
                peer: "192.168.1.50:40000",
                token: false,
                expected: StatusCode::OK,
            },
            Case {
                name: "public signed trust bundle",
                method: "GET",
                path: koi_certmesh::http::paths::TRUST_BUNDLE,
                peer: "192.168.1.50:40000",
                token: false,
                expected: StatusCode::OK,
            },
            Case {
                name: "local full status",
                method: "GET",
                path: koi_certmesh::http::paths::STATUS,
                peer: "127.0.0.1:40000",
                token: false,
                expected: StatusCode::OK,
            },
            Case {
                name: "remote full status without DAT",
                method: "GET",
                path: koi_certmesh::http::paths::STATUS,
                peer: "192.168.1.50:40000",
                token: false,
                expected: StatusCode::UNAUTHORIZED,
            },
            Case {
                name: "remote full status with DAT",
                method: "GET",
                path: koi_certmesh::http::paths::STATUS,
                peer: "192.168.1.50:40000",
                token: true,
                expected: StatusCode::OK,
            },
            Case {
                name: "enrollment uses invite or TOTP instead of DAT",
                method: "POST",
                path: koi_certmesh::http::paths::JOIN,
                peer: "192.168.1.50:40000",
                token: false,
                expected: StatusCode::OK,
            },
            Case {
                name: "operator mutation without DAT",
                method: "POST",
                path: koi_certmesh::http::paths::REVOKE,
                peer: "127.0.0.1:40000",
                token: false,
                expected: StatusCode::UNAUTHORIZED,
            },
            Case {
                name: "operator mutation with DAT",
                method: "POST",
                path: koi_certmesh::http::paths::REVOKE,
                peer: "127.0.0.1:40000",
                token: true,
                expected: StatusCode::OK,
            },
            Case {
                name: "remote HTTP MCP without DAT",
                method: "GET",
                path: paths::MCP,
                peer: "192.168.1.50:40000",
                token: false,
                expected: StatusCode::UNAUTHORIZED,
            },
            Case {
                name: "remote HTTP MCP with DAT",
                method: "GET",
                path: paths::MCP,
                peer: "192.168.1.50:40000",
                token: true,
                expected: StatusCode::OK,
            },
            Case {
                name: "Pond operator control",
                method: "GET",
                path: "/v1/pond",
                peer: "127.0.0.1:40000",
                token: false,
                expected: StatusCode::UNAUTHORIZED,
            },
        ];

        let expected = Arc::new("secret-token".to_string());
        let mut router = Router::new();
        for path in [
            koi_certmesh::http::paths::BOOTSTRAP,
            koi_certmesh::http::paths::TRUST_BUNDLE,
            koi_certmesh::http::paths::STATUS,
            koi_certmesh::http::paths::JOIN,
            koi_certmesh::http::paths::REVOKE,
            paths::MCP,
            "/v1/pond",
        ] {
            router = router.route(path, axum::routing::any(|| async { "ok" }));
        }
        let app = router.layer(middleware::from_fn(move |req, next| {
            let expected = expected.clone();
            dat_auth_middleware(req, next, expected)
        }));

        for case in cases {
            let mut builder = Request::builder().method(case.method).uri(case.path);
            if case.token {
                builder = builder.header(DAT_HEADER, "secret-token");
            }
            let mut req = builder.body(Body::empty()).unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(case.peer.parse::<SocketAddr>().unwrap()));
            assert_eq!(
                app.clone().oneshot(req).await.unwrap().status(),
                case.expected,
                "{}",
                case.name
            );
        }
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
        assert!(paths.contains(&"/v1/pond"), "missing /v1/pond: {paths:?}");
        assert!(paths.contains(&"/v1/ui"), "missing /v1/ui: {paths:?}");
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
    fn embedded_openapi_does_not_claim_unmounted_pond_routes() {
        let spec = build_openapi_for(false);
        assert!(!spec.paths.paths.contains_key("/v1/pond"));
        assert!(!spec.paths.paths.contains_key("/v1/ui"));
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
            paths.contains(&"/v1/health/log"),
            "missing /v1/health/log: {paths:?}"
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
            paths.contains(&"/v1/trust/status"),
            "missing /v1/trust/status: {paths:?}"
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
            system_status: Arc::new(koi_compose::status::KoiStatusRuntime::default()),
            host: koi_compose::host::HostIdentity::from_hostname("test-host").unwrap(),
            started_at: std::time::Instant::now(),
            cancel: CancellationToken::new(),
            http_bind: "127.0.0.1".to_string(),
            mdns_browse: None,
            mcp_http_enabled: false,
            webhook_sinks: 0,
            daemon: true,
        }
    }

    #[test]
    fn seal_presence_follows_the_captured_product_snapshot() {
        let status = koi_compose::status::KoiStatusRuntime::default().status();
        assert_eq!(seal_projection(status.as_ref()), None);

        let mut with_certmesh = status.as_ref().clone();
        with_certmesh.domains.certmesh = Some(Arc::new(koi_certmesh::CertmeshStatus {
            revision: 0,
            role: koi_certmesh::CertmeshRole::Open,
            posture: koi_common::posture::Posture::OPEN,
            identity: koi_certmesh::CertmeshIdentityStatus {
                condition: koi_certmesh::IdentityCondition::Absent,
                info: None,
                reason: None,
            },
            diagnosis: koi_common::diagnosis::TrustDiagnosis::from_checks(
                koi_common::posture::Posture::OPEN,
                Vec::new(),
            ),
            authority: None,
            reload: None,
            renewal: koi_certmesh::CertmeshRenewalStatus::default(),
        }));
        assert_eq!(
            seal_projection(&with_certmesh),
            Some(koi_common::sealed::CURRENT_CONFIDENTIALITY.as_wire())
        );
    }

    fn prometheus_test_router(state: AppState) -> Router {
        Router::new()
            .route(paths::PROMETHEUS_SD, get(prometheus_sd_handler))
            .layer(Extension(state))
    }

    #[tokio::test]
    async fn inventory_endpoint_projects_one_cached_product_revision() {
        let state = empty_app_state();
        let expected = state.system_status.status();
        let system_status = Arc::clone(&state.system_status);
        let app = Router::new()
            .route(paths::INVENTORY, get(inventory_handler))
            .layer(Extension(state));

        let response = app
            .oneshot(Request::get(paths::INVENTORY).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let inventory: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(inventory["status"]["revision"], expected.revision);
        assert_eq!(inventory["status"]["mdns"], serde_json::Value::Null);
        assert_eq!(inventory["status"]["dns"], serde_json::Value::Null);
        assert_eq!(inventory["health"], serde_json::Value::Null);
        assert_eq!(inventory["dns"], serde_json::Value::Null);
        assert!(Arc::ptr_eq(&expected, &system_status.status()));
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
    async fn prometheus_sd_projects_the_captured_product_snapshot() {
        let runtime = Arc::new(koi_runtime::RuntimeCore::new(
            koi_runtime::RuntimeConfig::default(),
        ));
        let cancel = CancellationToken::new();
        let instance = koi_runtime::Instance {
            id: "aggregate-instance".to_string(),
            name: "aggregate-service".to_string(),
            ports: vec![koi_runtime::PortMapping {
                host_port: 9464,
                container_port: 9464,
                protocol: koi_runtime::instance::PortProtocol::Tcp,
                host_ip: "127.0.0.1".to_string(),
            }],
            ips: Vec::new(),
            metadata: koi_runtime::KoiMetadata::default(),
            backend: "test".to_string(),
            state: koi_runtime::InstanceState::Running,
            discovered_at: chrono::Utc::now(),
            image: None,
        };
        runtime
            .start_with_backend(
                cancel.clone(),
                Box::new(FixedRuntimeBackend {
                    initial: vec![instance],
                }),
            )
            .await
            .expect("runtime provider startup");
        let cores = DaemonCores {
            runtime: Some(Arc::clone(&runtime)),
            ..DaemonCores::default()
        };
        cores.system_status.reconcile(&cores);
        let expected_revision = cores.system_status.status().revision;

        let mut state = empty_app_state();
        state.system_status = Arc::clone(&cores.system_status);
        let app = prometheus_test_router(state);
        let response = app
            .oneshot(
                Request::get(paths::PROMETHEUS_SD)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        cancel.cancel();
        runtime.shutdown().await.expect("Runtime shutdown");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let groups: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(groups[0]["targets"][0], "127.0.0.1:9464");
        assert_eq!(groups[0]["labels"]["__meta_koi_name"], "aggregate-service");
        assert_eq!(
            cores.system_status.status().revision,
            expected_revision,
            "a presentation read must not reconcile or mutate product status"
        );
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
        let host = koi_compose::host::HostIdentity::from_hostname("accepted-host").unwrap();
        let resp = observe_host(&host).expect("observe local host");
        assert_eq!(resp.hostname, "accepted-host");
        assert_eq!(resp.hostname_fqdn, "accepted-host.local");
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
