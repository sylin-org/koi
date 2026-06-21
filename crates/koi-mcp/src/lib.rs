//! koi-mcp — a Model Context Protocol (MCP) server over stdio.
//!
//! Exposes Koi's LAN substrate (mDNS discovery/announce, local DNS, health,
//! runtime inventory) to AI agents as MCP tools. The server talks to a running
//! Koi daemon through the blocking `KoiClient`; every client call is bridged onto
//! a blocking thread so the async MCP runtime is never blocked.
//!
//! ## Boundaries
//! - CA-admin operations (create/promote/destroy/unlock) are intentionally NOT
//!   exposed (charter Do-NOT).
//! - The daemon access token is never included in any tool output.
//! - `lan_announce` registrations are auto-heartbeated and unregistered on
//!   shutdown (leases over liveness guesses).

mod client;
mod heartbeat;
mod server;
mod source;
mod tools;

use std::sync::Arc;

use koi_client::KoiClient;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager,
    tower::{StreamableHttpServerConfig, StreamableHttpService},
};
use rmcp::{transport::stdio, ServiceExt};

pub use client::build_client;
pub use server::Server;
pub use source::{ClientSource, KoiSource, ResourceChange, SourceError};

/// The stdio server type: a [`Server`] backed by the blocking [`ClientSource`].
pub type StdioServer = Server<ClientSource>;

/// The in-process HTTP transport: a stateful Streamable-HTTP service whose handler
/// is a fresh [`Server`] per session (so each session's announcements drain when it
/// ends), all sharing the one `Arc<S>` source.
pub type McpHttpService<S> = StreamableHttpService<Server<S>, LocalSessionManager>;

/// Build the Streamable-HTTP MCP service to mount at `/v1/mcp` on the daemon's
/// existing axum adapter (via `.nest_service`).
///
/// Stateful mode keeps a per-session SSE stream alive (required for
/// `resources/updated` deltas). `allowed_hosts` is the rmcp `Host`-header
/// allowlist (DNS-rebinding defense): pass the loopback set for a loopback bind,
/// or an **empty** vec to disable the check when the operator has deliberately
/// exposed the daemon (the DAT token + TLS are then the boundary).
pub fn streamable_http_service<S: KoiSource>(
    source: Arc<S>,
    allowed_hosts: Vec<String>,
) -> McpHttpService<S> {
    // `StreamableHttpServerConfig` is #[non_exhaustive]; build via Default (which
    // already sets stateful_mode = true) + the host-allowlist builder.
    let config = StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts);
    StreamableHttpService::new(
        move || Ok(Server::new(Arc::clone(&source))),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}

/// Run the MCP server over stdio against the given Koi daemon client.
///
/// Blocks until the stdio transport closes (the MCP host disconnects or EOF on
/// stdin). On completion, every service announced during the session is
/// unregistered so nothing is left to go stale.
pub async fn serve(client: KoiClient) -> anyhow::Result<()> {
    let source = Arc::new(ClientSource::new(Arc::new(client)));
    let server = Server::new(source);

    tracing::info!("koi-mcp serving over stdio");
    let service = server.clone().serve(stdio()).await?;
    let result = service.waiting().await;

    // Always retract announced services, whether the session ended cleanly or not.
    server.shutdown().await;

    result?;
    Ok(())
}
