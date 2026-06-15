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
mod tools;

use std::sync::Arc;

use koi_client::KoiClient;
use rmcp::{transport::stdio, ServiceExt};

pub use client::build_client;
pub use server::Server;

/// Run the MCP server over stdio against the given Koi daemon client.
///
/// Blocks until the stdio transport closes (the MCP host disconnects or EOF on
/// stdin). On completion, every service announced during the session is
/// unregistered so nothing is left to go stale.
pub async fn serve(client: KoiClient) -> anyhow::Result<()> {
    let client = Arc::new(client);
    let server = Server::new(client);

    tracing::info!("koi-mcp serving over stdio");
    let service = server.clone().serve(stdio()).await?;
    let result = service.waiting().await;

    // Always retract announced services, whether the session ended cleanly or not.
    server.shutdown().await;

    result?;
    Ok(())
}
