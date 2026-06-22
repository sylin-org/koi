//! # koi-serve — the serving layer
//!
//! koi-serve exposes the composed domain cores ([`koi_compose::cores::Cores`]) over the
//! network. It owns every **transport adapter** and the **trust-plane presence**
//! supervisor; it sits one layer above [`koi_compose`] (which *builds* the cores) and is
//! consumed by the two top-level hosts — the `koi` binary and `koi-embedded`.
//!
//! The split keeps two responsibilities crisp:
//! - **koi-compose** — construct cores, wire cross-domain bridges, run the orchestrator and
//!   certmesh role loops, project capability status, and own ordered shutdown.
//! - **koi-serve** — serve those cores: the HTTP/OpenAPI router, IPC and piped-stdio NDJSON,
//!   the in-process MCP HTTP transport, the inter-node mTLS + ACME listeners, Prometheus
//!   service discovery, the dashboard/browser wiring, and the posture-reactive trust plane.
//!
//! Nothing depends on koi-serve except the top-level consumers, so the kernel and domain
//! closures stay clean (no cycle: koi-serve → koi-compose → domains).
//!
//! ## Modules
//! - [`http`] — the axum router (domain routes, system endpoints, dashboard, MCP, OpenAPI,
//!   DAT auth, CORS) + `build_openapi`.
//! - [`pipe`] — IPC adapter (Windows Named Pipe / Unix domain socket), NDJSON.
//! - [`stdio`] — piped stdin/stdout NDJSON adapter (standalone piped mode).
//! - [`dispatch`] — shared NDJSON request dispatch for [`pipe`] and [`stdio`].
//! - [`mcp_http`] — `CoreSource`, the live-cores backing for the in-process MCP transport.
//! - [`mtls`] — inter-node certmesh mTLS listener.
//! - [`acme`] — RFC 8555 server-auth TLS listener.
//! - [`prometheus_sd`] — Prometheus HTTP service-discovery target builder.
//! - [`dashboard`] — dashboard `DashboardState` wiring (snapshot closure).
//! - [`trust_plane`] — the posture-reactive supervisor owning mTLS + ACME + the
//!   `_certmesh._tcp` discovery announce.

pub mod acme;
pub mod dashboard;
pub mod dispatch;
pub mod http;
pub mod mcp_http;
pub mod mtls;
pub mod pipe;
pub mod prometheus_sd;
pub mod stdio;
pub mod trust_plane;
