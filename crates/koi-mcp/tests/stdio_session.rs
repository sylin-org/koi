//! Scripted stdio MCP session against the real `koi-mcp` `Server`.
//!
//! Drives the server over an in-process duplex pipe (no spawned binary, no
//! network) and speaks raw JSON-RPC. The assertions that matter for the tool
//! contract — `initialize` and `tools/list` with the v1 tool names and the
//! read-only annotations — need NO Koi daemon, because the tool schema is static.
//!
//! A tool *call* would need a daemon (or a mock), so that part is intentionally
//! out of scope here; `tools/list` is the contract this test guards.

use std::sync::Arc;
use std::time::Duration;

use koi_client::KoiClient;
use koi_mcp::{ClientSource, StdioServer};
use rmcp::ServiceExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Build a `Server` with a client pointed at an unused loopback port. `tools/list`
/// never touches the daemon, so the port need not be live.
fn test_server() -> StdioServer {
    let client = Arc::new(KoiClient::new("http://127.0.0.1:1"));
    StdioServer::new(Arc::new(ClientSource::new(client)))
}

/// Write one JSON-RPC line and flush.
async fn send(w: &mut (impl AsyncWriteExt + Unpin), line: &str) {
    w.write_all(line.as_bytes()).await.unwrap();
    w.write_all(b"\n").await.unwrap();
    w.flush().await.unwrap();
}

/// Read one non-empty JSON line, parsed.
async fn recv(r: &mut (impl AsyncBufReadExt + Unpin)) -> serde_json::Value {
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line).await.unwrap();
        assert!(n > 0, "stream closed before a response arrived");
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return serde_json::from_str(trimmed).expect("server emitted non-JSON line");
    }
}

#[tokio::test]
async fn initialize_then_tools_list() {
    // Duplex pipe: server reads `srv_in`, writes `srv_out`. The test writes to
    // `srv_in`'s peer and reads from `srv_out`'s peer.
    let (client_to_server, server_reads) = tokio::io::duplex(64 * 1024);
    let (server_writes, server_to_client) = tokio::io::duplex(64 * 1024);

    let server = test_server();
    let serve_task = tokio::spawn(async move {
        let service = server
            .serve((server_reads, server_writes))
            .await
            .expect("server failed to start");
        let _ = service.waiting().await;
    });

    let (read_half, _w) = tokio::io::split(server_to_client);
    let (_r, mut write_half) = tokio::io::split(client_to_server);
    let mut reader = BufReader::new(read_half);

    // ── initialize ──────────────────────────────────────────────────
    send(
        &mut write_half,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"itest","version":"0.0.0"}}}"#,
    )
    .await;

    let init = tokio::time::timeout(Duration::from_secs(5), recv(&mut reader))
        .await
        .expect("timed out waiting for initialize response");
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "koi-mcp");
    assert!(
        init["result"]["capabilities"]["tools"].is_object(),
        "server must advertise tools capability"
    );

    // The spec requires a `notifications/initialized` after initialize.
    send(
        &mut write_half,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;

    // ── tools/list ──────────────────────────────────────────────────
    send(
        &mut write_half,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    )
    .await;

    let listed = tokio::time::timeout(Duration::from_secs(5), recv(&mut reader))
        .await
        .expect("timed out waiting for tools/list response");
    assert_eq!(listed["id"], 2);

    let tools = listed["result"]["tools"]
        .as_array()
        .expect("tools/list must return an array");

    // Every v1 tool name from the plan must be present.
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    let expected = [
        "lan_discover",
        "lan_resolve",
        "lan_announce",
        "lan_unregister",
        "dns_lookup",
        "dns_add",
        "dns_remove",
        "lan_inventory",
        "health_snapshot",
        "runtime_instances",
        "mcp_servers_on_lan",
    ];
    for name in expected {
        assert!(
            names.contains(&name),
            "tools/list is missing `{name}`; got: {names:?}"
        );
    }

    // Read tools must carry read_only_hint = true.
    let read_tools = [
        "lan_discover",
        "lan_resolve",
        "dns_lookup",
        "lan_inventory",
        "health_snapshot",
        "runtime_instances",
        "mcp_servers_on_lan",
    ];
    for name in read_tools {
        let tool = tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("tool `{name}` not found"));
        assert_eq!(
            tool["annotations"]["readOnlyHint"], true,
            "read tool `{name}` must set readOnlyHint=true; tool was: {tool}"
        );
    }

    // The remover must be flagged destructive.
    let remove = tools
        .iter()
        .find(|t| t["name"] == "lan_unregister")
        .expect("lan_unregister present");
    assert_eq!(
        remove["annotations"]["destructiveHint"], true,
        "lan_unregister must set destructiveHint=true"
    );

    // Each tool must carry an input schema (the static schema this test guards).
    for tool in tools {
        assert!(
            tool["inputSchema"].is_object(),
            "tool `{}` has no inputSchema",
            tool["name"]
        );
    }

    // Closing the writer ends the server's input stream.
    drop(write_half);
    let _ = tokio::time::timeout(Duration::from_secs(5), serve_task).await;
}
