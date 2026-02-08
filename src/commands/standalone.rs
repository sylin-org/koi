//! Standalone-mode command handlers.
//!
//! These create a local `MdnsCore` and operate directly on the mDNS engine.
//! Used when no daemon is running (or `--standalone` is passed).

use std::sync::Arc;

use crate::core::{self, MdnsCore};
use crate::format;
use crate::protocol::response::{PipelineResponse, Response};
use crate::protocol::{RegisterPayload, ServiceRecord};

// ── Browse ──────────────────────────────────────────────────────────

pub async fn browse(
    core: Arc<MdnsCore>,
    service_type: Option<&str>,
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let is_meta = service_type.is_none();
    let browse_type = service_type.unwrap_or(core::META_QUERY);
    let handle = core.browse(browse_type).await?;
    let dur = super::effective_timeout(timeout, Some(super::DEFAULT_TIMEOUT));

    tokio::select! {
        _ = async {
            while let Some(event) = handle.recv().await {
                if json {
                    let resp = PipelineResponse::from_browse_event(event);
                    println!("{}", serde_json::to_string(&resp).unwrap());
                } else {
                    match event {
                        core::ServiceEvent::Resolved(record)
                        | core::ServiceEvent::Found(record) => {
                            if is_meta {
                                println!("{}", record.name);
                            } else {
                                format::service_line(&record);
                            }
                        }
                        core::ServiceEvent::Removed { name, .. } => {
                            println!("[removed]\t{name}");
                        }
                    }
                }
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match dur {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }

    let _ = core.shutdown().await;
    Ok(())
}

// ── Register ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn register(
    core: Arc<MdnsCore>,
    name: &str,
    service_type: &str,
    port: u16,
    ip: Option<&str>,
    txt: &[String],
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let payload = RegisterPayload {
        name: name.to_string(),
        service_type: service_type.to_string(),
        port,
        ip: ip.map(String::from),
        lease_secs: None,
        txt: super::parse_txt(txt),
    };

    let result = core.register(payload)?;
    if json {
        let resp = PipelineResponse::clean(Response::Registered(result));
        println!("{}", serde_json::to_string(&resp).unwrap());
    } else {
        println!(
            "Registered \"{}\" ({}) on port {} [id: {}]",
            result.name, result.service_type, result.port, result.id
        );
        eprintln!("Service is being advertised. Press Ctrl+C to unregister and exit.");
    }

    // Keep process alive to maintain the mDNS advertisement.
    // Register defaults to infinite (no timeout) unless explicitly set.
    let dur = super::effective_timeout(timeout, None);
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match dur {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }

    let _ = core.shutdown().await;
    Ok(())
}

// ── Unregister ──────────────────────────────────────────────────────

pub async fn unregister(core: Arc<MdnsCore>, id: &str, json: bool) -> anyhow::Result<()> {
    core.unregister(id)?;
    if json {
        let resp = PipelineResponse::clean(Response::Unregistered(id.to_string()));
        println!("{}", serde_json::to_string(&resp).unwrap());
    } else {
        println!("Unregistered {id}");
    }
    let _ = core.shutdown().await;
    Ok(())
}

// ── Resolve ─────────────────────────────────────────────────────────

pub async fn resolve(core: Arc<MdnsCore>, instance: &str, json: bool) -> anyhow::Result<()> {
    let record = core.resolve(instance).await?;
    if json {
        let resp = PipelineResponse::clean(Response::Resolved(record));
        println!("{}", serde_json::to_string(&resp).unwrap());
    } else {
        format::resolved_detail(&record);
    }
    let _ = core.shutdown().await;
    Ok(())
}

// ── Subscribe ───────────────────────────────────────────────────────

pub async fn subscribe(
    core: Arc<MdnsCore>,
    service_type: &str,
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let handle = core.browse(service_type).await?;
    let dur = super::effective_timeout(timeout, Some(super::DEFAULT_TIMEOUT));

    tokio::select! {
        _ = async {
            while let Some(event) = handle.recv().await {
                if json {
                    let resp = PipelineResponse::from_subscribe_event(event);
                    println!("{}", serde_json::to_string(&resp).unwrap());
                } else {
                    match event {
                        core::ServiceEvent::Found(record) => {
                            format::subscribe_event("found", &record);
                        }
                        core::ServiceEvent::Resolved(record) => {
                            format::subscribe_event("resolved", &record);
                        }
                        core::ServiceEvent::Removed { name, service_type } => {
                            format::subscribe_event("removed", &ServiceRecord {
                                name,
                                service_type,
                                host: None,
                                ip: None,
                                port: None,
                                txt: Default::default(),
                            });
                        }
                    }
                }
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match dur {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }

    let _ = core.shutdown().await;
    Ok(())
}
