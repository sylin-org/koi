//! MCP command handler — serves the Model Context Protocol over stdio.

use crate::cli::Cli;
use crate::client::KoiClient;

use super::cli_token;

/// Serve MCP over stdio.
///
/// Resolves the daemon endpoint the same way client-mode commands do:
/// 1. An explicit `--endpoint` (with `--token`/`KOI_TOKEN`, never the breadcrumb
///    token — it would leak to a remote host).
/// 2. The breadcrumb file the local daemon writes (endpoint + its token).
///
/// The MCP server probes the daemon per-tool and returns an actionable error if
/// it is unreachable, so we still serve even when no daemon is up yet (the host
/// may start one, or the agent may just call read tools that report the outage).
pub async fn serve(cli: &Cli) -> anyhow::Result<()> {
    let client = build_client(cli);
    koi_mcp::serve(client).await
}

/// Build the `KoiClient` for the MCP server from CLI flags / breadcrumb / env.
fn build_client(cli: &Cli) -> KoiClient {
    if let Some(endpoint) = &cli.endpoint {
        // Explicit endpoint: explicit token or tokenless. Never the breadcrumb.
        let token = cli_token(cli).unwrap_or("");
        return KoiClient::with_token(endpoint, token);
    }
    // Fall back to the breadcrumb (local daemon) or KOI_ENDPOINT/KOI_TOKEN env.
    // Default to the conventional loopback endpoint if neither exists, so the
    // server still starts and reports "no daemon reachable" per tool.
    koi_mcp::build_client().unwrap_or_else(|| {
        KoiClient::new(&format!(
            "http://localhost:{}",
            crate::cli::DEFAULT_HTTP_PORT
        ))
    })
}
