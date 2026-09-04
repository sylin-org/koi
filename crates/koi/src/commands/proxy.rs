//! Proxy command handlers.

use std::sync::Arc;

use koi_proxy::ProxyEntry;

use crate::cli::Config;
use crate::commands::{
    decode_field, decode_response, print_json, require_ok_response, with_mode, Mode,
};

fn standalone_core(config: &Config) -> anyhow::Result<koi_proxy::ProxyCore> {
    let persistence = koi_compose::cores::PersistencePaths::from_data_dir(config.data_dir.clone());
    Ok(koi_proxy::ProxyCore::open(
        persistence.proxy_config().to_path_buf(),
        persistence.proxy_certificates().to_path_buf(),
    )?)
}

fn build_entry(
    name: &str,
    listen: u16,
    backend: &str,
    allow_remote: bool,
) -> anyhow::Result<ProxyEntry> {
    koi_proxy::ensure_backend_allowed(backend, allow_remote)?;
    if allow_remote {
        tracing::warn!("Backend traffic to {} is unencrypted", backend);
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
    config: &Config,
) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let entry = build_entry(name, listen, backend, allow_remote)?;
            let runtime = koi_proxy::ProxyRuntime::new(Arc::new(standalone_core(config)?));
            runtime.configure_for_next_start(entry).await?;
            let entries = runtime.entries().await;
            if json {
                print_json(&serde_json::json!({ "entries": entries }))?;
            } else {
                println!("Proxy {name} -> {backend} (listen {listen})");
            }
            Ok(())
        },
        |client| async move {
            let resp = client.proxy_add(name, listen, backend, allow_remote)?;
            require_ok_response(&resp, "proxy add")?;
            if json {
                print_json(&serde_json::json!({ "status": "ok" }))?;
            } else {
                println!("Proxy {name} -> {backend} (listen {listen})");
            }
            Ok(())
        },
    )
    .await
}

pub async fn remove(name: &str, mode: Mode, json: bool, config: &Config) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let runtime = koi_proxy::ProxyRuntime::new(Arc::new(standalone_core(config)?));
            runtime.remove_for_next_start(name).await?;
            let entries = runtime.entries().await;
            if json {
                print_json(&serde_json::json!({ "entries": entries }))?;
            } else {
                println!("Removed proxy {name}");
            }
            Ok(())
        },
        |client| async move {
            let resp = client.proxy_remove(name)?;
            require_ok_response(&resp, "proxy remove")?;
            if json {
                print_json(&serde_json::json!({ "status": "ok" }))?;
            } else {
                println!("Removed proxy {name}");
            }
            Ok(())
        },
    )
    .await
}

pub async fn list(mode: Mode, json: bool, config: &Config) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let core = standalone_core(config)?;
            let entries = core.entries().await;
            if json {
                print_json(&serde_json::json!({ "entries": entries }))?;
            } else if entries.is_empty() {
                println!("No proxy entries configured.");
            } else {
                for entry in entries {
                    println!(
                        "{} -> {} (listen {})",
                        entry.name, entry.backend, entry.listen_port
                    );
                }
            }
            Ok(())
        },
        |client| async move {
            let resp = client.proxy_list()?;
            let entries: Vec<ProxyEntry> = decode_field(&resp, "entries", "proxy list")?;
            if json {
                print_json(&serde_json::json!({ "entries": entries }))?;
            } else if entries.is_empty() {
                println!("No proxy entries configured.");
            } else {
                for entry in entries {
                    println!(
                        "{} -> {} (listen {})",
                        entry.name, entry.backend, entry.listen_port
                    );
                }
            }
            Ok(())
        },
    )
    .await
}

pub async fn status(mode: Mode, json: bool, config: &Config) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let runtime = koi_proxy::ProxyRuntime::new(Arc::new(standalone_core(config)?));
            let status = runtime.status();
            if json {
                print_json(status.as_ref())?;
            } else if status.proxies.is_empty() {
                println!("Proxy: no listeners configured");
            } else {
                let rows: Vec<crate::format::ProxyStatusRow> = status
                    .proxies
                    .iter()
                    .map(|proxy| crate::format::ProxyStatusRow {
                        name: proxy.name.clone(),
                        listen_port: proxy.listen_port,
                        backend: proxy.backend.clone(),
                        cert_source: proxy.cert_source.clone(),
                        state: proxy.state.clone(),
                        error: proxy.error.clone(),
                    })
                    .collect();
                print!("{}", crate::format::proxy_status_table(&rows));
            }
            Ok(())
        },
        |client| async move {
            let status: koi_proxy::ProxyRuntimeStatus =
                decode_response(client.proxy_status()?, "proxy status")?;
            if json {
                print_json(&status)?;
            } else if status.proxies.is_empty() {
                println!("Proxy: no listeners running");
            } else {
                let rows: Vec<crate::format::ProxyStatusRow> = status
                    .proxies
                    .iter()
                    .map(|proxy| crate::format::ProxyStatusRow {
                        name: proxy.name.clone(),
                        listen_port: proxy.listen_port,
                        backend: proxy.backend.clone(),
                        cert_source: proxy.cert_source.clone(),
                        state: proxy.state.clone(),
                        error: proxy.error.clone(),
                    })
                    .collect();
                print!("{}", crate::format::proxy_status_table(&rows));
            }
            Ok(())
        },
    )
    .await
}
