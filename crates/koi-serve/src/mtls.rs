//! mTLS adapter — wires koi's certmesh inter-node router onto the certmesh-mTLS
//! server primitive ([`koi_certmesh::mtls`]).
//!
//! The TLS termination, client-cert verification against the CA, and CN extraction
//! all live in `koi-certmesh` (the crate that owns the CA) so consumers share them;
//! this adapter only supplies koi's binary-specific pieces — the inter-node router
//! and the listen port.

use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Default mTLS port for inter-node certmesh traffic.
pub const DEFAULT_MTLS_PORT: u16 = 5642;

/// Start the mTLS adapter on the given port.
///
/// Builds a certmesh-verifying TLS config whose server leaf is resolved from the
/// shared hot-swappable `resolver`, binds `0.0.0.0:port`, and serves the certmesh
/// inter-node router over mTLS via [`koi_certmesh::mtls::serve`] until `cancel` fires.
/// Connections without a valid CA-signed client cert are rejected; the authenticated
/// CN is injected as `Extension(ClientCn)` for per-caller authorization in the
/// inter-node handlers. The trust plane reloads `resolver` when the self leaf is
/// renewed, so this listener presents the fresh cert without a restart.
pub async fn start(
    port: u16,
    certmesh_core: Arc<koi_certmesh::CertmeshCore>,
    resolver: Arc<koi_certmesh::mtls::ReloadableServerCert>,
    ca_cert_pem: &str,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let config = koi_certmesh::mtls::build_server_config_with_resolver(resolver, ca_cert_pem)?;
    let app = Router::new().nest("/v1/certmesh", certmesh_core.inter_node_routes());
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "mTLS adapter listening");
    koi_certmesh::mtls::serve(app, listener, config, cancel).await?;
    Ok(())
}
