//! UDP command handlers.

use base64::Engine;

use crate::commands::{print_json, with_mode, Mode};

pub async fn bind(
    port: u16,
    addr: &str,
    lease: u64,
    mode: Mode,
    json: bool,
) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            // Standalone mode is not meaningful for UDP - it requires a running socket.
            // Create a short-lived runtime and bind.
            let cancel = tokio_util::sync::CancellationToken::new();
            let runtime = koi_udp::UdpRuntime::new(cancel.clone());
            let info = runtime
                .bind(koi_udp::UdpBindRequest {
                    port,
                    addr: addr.to_string(),
                    lease_secs: lease,
                })
                .await?;
            if json {
                print_json(&serde_json::json!(info));
            } else {
                println!("Bound {} → {}", info.id, info.local_addr);
            }
            // Keep the binding alive until the user terminates.
            // For standalone, this isn't very useful, but matches the pattern.
            cancel.cancel();
            runtime.shutdown().await;
            Ok(())
        },
        |client| async move {
            let resp = client.udp_bind(port, addr, lease)?;
            if json {
                print_json(&resp);
            } else {
                let id = resp.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let addr = resp
                    .get("local_addr")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                println!("Bound {id} → {addr}");
            }
            Ok(())
        },
    )
    .await
}

pub async fn unbind(id: &str, mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            anyhow::bail!("UDP unbind requires a running daemon (no standalone mode)");
        },
        |client| async move {
            let resp = client.udp_unbind(id)?;
            if json {
                print_json(&resp);
            } else {
                println!("Unbound {id}");
            }
            Ok(())
        },
    )
    .await
}

pub async fn send(
    id: &str,
    dest: &str,
    payload: &str,
    mode: Mode,
    json: bool,
) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            anyhow::bail!("UDP send requires a running daemon (no standalone mode)");
        },
        |client| async move {
            let payload_b64 =
                base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            let resp = client.udp_send(id, dest, &payload_b64)?;
            if json {
                print_json(&resp);
            } else {
                let sent = resp.get("sent").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("Sent {sent} bytes → {dest}");
            }
            Ok(())
        },
    )
    .await
}

pub async fn status(mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            anyhow::bail!("UDP status requires a running daemon (no standalone mode)");
        },
        |client| async move {
            let resp = client.udp_status()?;
            if json {
                print_json(&resp);
            } else if let Some(bindings) = resp.get("bindings").and_then(|v| v.as_array()) {
                if bindings.is_empty() {
                    println!("No active UDP bindings.");
                } else {
                    println!("UDP bindings:");
                    for b in bindings {
                        let id = b.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                        let addr = b
                            .get("local_addr")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        let lease = b.get("lease_secs").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("  {id}  {addr}  (lease {lease}s)");
                    }
                }
            }
            Ok(())
        },
    )
    .await
}

pub async fn heartbeat(id: &str, mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            anyhow::bail!("UDP heartbeat requires a running daemon (no standalone mode)");
        },
        |client| async move {
            let resp = client.udp_heartbeat(id)?;
            if json {
                print_json(&resp);
            } else {
                println!("Renewed {id}");
            }
            Ok(())
        },
    )
    .await
}
