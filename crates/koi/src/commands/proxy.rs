//! Proxy command handlers.

use koi_proxy::config::ProxyEntry;

use crate::commands::{print_json, with_mode, Mode};

fn build_entry(name: &str, listen: u16, backend: &str, allow_remote: bool) -> anyhow::Result<ProxyEntry> {
    let url = url::Url::parse(backend)?;
    koi_proxy::ensure_backend_allowed(&url, allow_remote)?;
    if allow_remote {
        let host = url.host_str().unwrap_or("unknown");
        tracing::warn!("Backend traffic to {} is unencrypted", host);
    }
    Ok(ProxyEntry {
        name: name.to_string(),
        listen_port: listen,
        backend: backend.to_string(),
        allow_remote,
    })
}

pub async fn add(
    name: &str,
    listen: u16,
    backend: &str,
    allow_remote: bool,
    mode: Mode,
    json: bool,
) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let entry = build_entry(name, listen, backend, allow_remote)?;
            let entries = koi_proxy::config::upsert_entry(entry)?;
            if json {
                print_json(&serde_json::json!({ "entries": entries }));
            } else {
                println!("Proxy {name} -> {backend} (listen {listen})");
            }
            Ok(())
        },
        |client| async move {
            let resp = client.proxy_add(name, listen, backend, allow_remote)?;
            if json {
                print_json(&resp);
            } else {
                println!("Proxy {name} -> {backend} (listen {listen})");
            }
            Ok(())
        },
    )
    .await
}

pub async fn remove(name: &str, mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let entries = koi_proxy::config::remove_entry(name)?;
            if json {
                print_json(&serde_json::json!({ "entries": entries }));
            } else {
                println!("Removed proxy {name}");
            }
            Ok(())
        },
        |client| async move {
            let resp = client.proxy_remove(name)?;
            if json {
                print_json(&resp);
            } else {
                println!("Removed proxy {name}");
            }
            Ok(())
        },
    )
    .await
}

pub async fn list(mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let entries = koi_proxy::config::load_entries()?;
            if json {
                print_json(&serde_json::json!({ "entries": entries }));
            } else if entries.is_empty() {
                println!("No proxy entries configured.");
            } else {
                for entry in entries {
                    println!("{} -> {} (listen {})", entry.name, entry.backend, entry.listen_port);
                }
            }
            Ok(())
        },
        |client| async move {
            let resp = client.proxy_list()?;
            if json {
                print_json(&resp);
            } else if let Some(entries) = resp.get("entries").and_then(|v| v.as_array()) {
                if entries.is_empty() {
                    println!("No proxy entries configured.");
                } else {
                    for entry in entries {
                        let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let backend = entry.get("backend").and_then(|v| v.as_str()).unwrap_or("?");
                        let listen = entry.get("listen_port").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("{} -> {} (listen {})", name, backend, listen);
                    }
                }
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
            let entries = koi_proxy::config::load_entries()?;
            if json {
                print_json(&serde_json::json!({ "entries": entries }));
            } else if entries.is_empty() {
                println!("Proxy: no entries configured");
            } else {
                println!("Proxy entries:");
                for entry in entries {
                    println!("  {} -> {} (listen {})", entry.name, entry.backend, entry.listen_port);
                }
            }
            Ok(())
        },
        |client| async move {
            let resp = client.proxy_status()?;
            if json {
                print_json(&resp);
            } else if let Some(proxies) = resp.get("proxies").and_then(|v| v.as_array()) {
                if proxies.is_empty() {
                    println!("Proxy: no listeners running");
                } else {
                    println!("Proxy listeners:");
                    for entry in proxies {
                        let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                        let backend = entry.get("backend").and_then(|v| v.as_str()).unwrap_or("?");
                        let listen = entry.get("listen_port").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("  {} -> {} (listen {})", name, backend, listen);
                    }
                }
            }
            Ok(())
        },
    )
    .await
}
