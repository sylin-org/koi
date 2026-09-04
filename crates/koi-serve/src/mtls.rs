//! mTLS adapter — wires koi's certmesh inter-node router onto the certmesh-mTLS
//! server primitive ([`koi_certmesh::mtls`]).
//!
//! The TLS termination, client-cert verification against the CA, and CN extraction
//! all live in `koi-certmesh` (the crate that owns the CA) so consumers share them;
//! this adapter only supplies koi's binary-specific pieces — the inter-node router
//! and the listen port.
//!
//! When enabled, the same listener also serves the **management plane**
//! (ADR-026 §5): `/v1/mcp` mounted under per-request principal authorization
//! (`CN → roster`; unknown/expired/revoked are refused with named reasons).
//! Loopback + DAT remains unchanged; this is additive remote surface that is
//! mutually authenticated by construction.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json, Router};
use koi_compose::cores::Cores;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Default mTLS port for inter-node certmesh traffic.
pub const DEFAULT_MTLS_PORT: u16 = 5642;

/// What the management plane needs to mount `/v1/mcp` on the mTLS listener.
pub struct MgmtMcp {
    /// Live domain cores backing the MCP tools (same source the loopback
    /// transport uses — one tool surface, two authenticated transports).
    pub cores: Cores,
    pub started_at: std::time::Instant,
}

/// Start the mTLS adapter on an already-bound listener.
///
/// Builds a certmesh-verifying TLS config whose server leaf is resolved from the
/// shared hot-swappable `resolver`, binds `0.0.0.0:port`, and serves the certmesh
/// inter-node router over mTLS via [`koi_certmesh::mtls::serve`] until `cancel` fires.
/// Connections without a valid CA-signed client cert are rejected; the authenticated
/// CN is injected as `Extension(ClientCn)` for per-caller authorization in the
/// inter-node handlers. The trust plane reloads `resolver` when the self leaf is
/// renewed, so this listener presents the fresh cert without a restart.
///
/// With `mgmt_mcp`, the listener additionally serves `/v1/mcp` behind
/// the internal `principal_guard` (ADR-026 §5): every request must present an active,
/// unexpired, unrevoked roster CN.
pub async fn start(
    listener: TcpListener,
    certmesh_core: Arc<koi_certmesh::CertmeshCore>,
    resolver: Arc<koi_certmesh::mtls::ReloadableServerCert>,
    ca_cert_pem: &str,
    cancel: CancellationToken,
    mgmt_mcp: Option<MgmtMcp>,
    ready: oneshot::Sender<()>,
) -> anyhow::Result<()> {
    let address = listener.local_addr()?;
    let port = address.port();
    let config = koi_certmesh::mtls::build_server_config_with_resolver(resolver, ca_cert_pem)?;
    let mut app = Router::new().nest("/v1/certmesh", certmesh_core.inter_node_routes());
    let mut mcp_source = None;

    if let Some(mgmt) = mgmt_mcp {
        // Non-loopback bind disables rmcp's default Host allowlist; mutual TLS +
        // CN→roster authorization is the boundary here (mirrors the exposed
        // HTTP transport's reasoning in http.rs).
        let source = Arc::new(crate::mcp_http::CoreSource::new(
            mgmt.cores,
            mgmt.started_at,
            format!("0.0.0.0:{port}"),
            cancel.clone(),
        ));
        let service = koi_mcp::streamable_http_service(source.clone(), Vec::new());
        let guarded = Router::new().nest_service("/v1/mcp", service).layer(
            axum::middleware::from_fn_with_state(certmesh_core.clone(), principal_guard),
        );
        app = app.merge(guarded);
        tracing::info!(
            port,
            "mTLS management plane: /v1/mcp mounted (CN-authorized)"
        );
        mcp_source = Some(source);
    }

    // Configuration and the native socket both exist before the trust-plane owner may
    // publish discovery. A dropped observer does not invalidate this real listener.
    let _ = ready.send(());
    tracing::info!(%address, "mTLS adapter listening");
    let result = koi_certmesh::mtls::serve(app, listener, config, cancel).await;
    if let Some(source) = mcp_source {
        source.shutdown().await;
    }
    result?;
    Ok(())
}

/// Per-request management-plane authorization (ADR-026 §5): the connection-level
/// `ClientCn` extension (injected by [`koi_certmesh::mtls::serve`] after the
/// handshake) must name an active, unexpired, unrevoked roster member. Named
/// rejections carry the ADR-020 vocabulary in the message; failures are audited
/// inside [`CertmeshCore::authorize_principal`] before this returns.
async fn principal_guard(
    State(core): State<Arc<koi_certmesh::CertmeshCore>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(koi_certmesh::http::ClientCn(cn)) = req
        .extensions()
        .get::<koi_certmesh::http::ClientCn>()
        .cloned()
    else {
        // Unreachable over this listener (a handshake without a usable CN is
        // dropped at the connection layer) — but fail closed regardless.
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "scope_violation",
                "message": "unknown_signer: no client certificate CN on this connection"
            })),
        )
            .into_response();
    };

    match core.authorize_principal(&cn).await {
        Ok(()) => next.run(req).await,
        Err(rej) => {
            tracing::warn!(%cn, reason = rej.reason(), "management-plane request refused");
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "scope_violation",
                    "message": format!("{}: {rej}", rej.reason())
                })),
            )
                .into_response()
        }
    }
}
