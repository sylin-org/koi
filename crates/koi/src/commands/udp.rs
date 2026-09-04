//! UDP command handlers.

use base64::Engine;

use crate::commands::{decode_field, decode_response, print_json, with_mode, Mode};

fn matching_id(
    response: &serde_json::Value,
    field: &str,
    expected: &str,
    surface: &str,
) -> anyhow::Result<String> {
    let actual: String = decode_field(response, field, surface)?;
    if actual == expected {
        Ok(actual)
    } else {
        anyhow::bail!("invalid {surface} response: `{field}` was `{actual}`, expected `{expected}`")
    }
}

pub async fn bind(
    port: u16,
    addr: &str,
    lease: u64,
    allow_remote: bool,
    mode: Mode,
    json: bool,
) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            // Explicit standalone mode owns a real binding for its complete
            // advertised lifetime. The status feed is the cheap authoritative
            // boundary for lease expiry; Ctrl+C requests terminal teardown.
            let cancel = tokio_util::sync::CancellationToken::new();
            let runtime = koi_udp::UdpRuntime::new(cancel.clone());
            let mut status = runtime.watch_status();
            let info = runtime
                .bind(koi_udp::UdpBindRequest {
                    port,
                    addr: addr.to_string(),
                    lease_secs: lease,
                    allow_remote,
                })
                .await?;
            let binding_id = info.id.clone();
            if json {
                print_json(&serde_json::json!(info))?;
            } else {
                println!("Bound {} → {}", info.id, info.local_addr);
                eprintln!("Binding is live until its lease expires. Press Ctrl+C to release it.");
            }

            let signal = tokio::select! {
                result = tokio::signal::ctrl_c() => Some(result),
                _ = async {
                    while status
                        .borrow()
                        .bindings
                        .iter()
                        .any(|binding| binding.id == binding_id)
                    {
                        if status.changed().await.is_err() {
                            break;
                        }
                    }
                } => None,
            };
            cancel.cancel();
            runtime.shutdown().await;
            if let Some(result) = signal {
                result?;
            }
            Ok(())
        },
        |client| async move {
            let info: koi_udp::BindingInfo = decode_response(
                client.udp_bind(port, addr, lease, allow_remote)?,
                "UDP bind",
            )?;
            if json {
                print_json(&info)?;
            } else {
                println!("Bound {} → {}", info.id, info.local_addr);
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
            client.udp_unbind(id)?;
            if json {
                print_json(&serde_json::json!({ "unbound": id }))?;
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
            let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
            let resp = client.udp_send(id, dest, &payload_b64)?;
            let sent: usize = decode_field(&resp, "sent", "UDP send")?;
            if json {
                print_json(&serde_json::json!({ "sent": sent }))?;
            } else {
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
            let status: koi_udp::UdpRuntimeStatus =
                decode_response(client.udp_status()?, "UDP status")?;
            if json {
                print_json(&status)?;
            } else if status.bindings.is_empty() {
                println!("No active UDP bindings.");
            } else {
                println!("UDP bindings:");
                for binding in status.bindings {
                    println!(
                        "  {}  {}  (lease {}s)",
                        binding.id, binding.local_addr, binding.lease_secs
                    );
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
            let renewed = matching_id(&resp, "renewed", id, "UDP heartbeat")?;
            if json {
                print_json(&serde_json::json!({ "renewed": renewed }))?;
            } else {
                println!("Renewed {id}");
            }
            Ok(())
        },
    )
    .await
}
