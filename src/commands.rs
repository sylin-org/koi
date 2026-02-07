//! CLI subcommand handlers — the **application service layer**.
//!
//! Each function orchestrates a single verb: it takes the domain core,
//! user-facing parameters, and produces output (human or JSON).
//! Core creation and CLI parsing live in `main.rs`; formatting lives
//! in `format.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::core::{self, MdnsCore};
use crate::format;
use crate::protocol::response::{PipelineResponse, Response};
use crate::protocol::{RegisterPayload, ServiceRecord};

/// Default timeout for browse/subscribe commands (seconds).
const DEFAULT_TIMEOUT: u64 = 5;

// ── Browse ──────────────────────────────────────────────────────────

pub async fn browse(
    core: Arc<MdnsCore>,
    service_type: Option<&str>,
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let is_meta = service_type.is_none();
    let browse_type = service_type.unwrap_or(core::META_QUERY);
    let handle = core.browse(browse_type)?;
    let dur = effective_timeout(timeout, Some(DEFAULT_TIMEOUT));

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

    let _ = core.shutdown();
    Ok(())
}

// ── Register ────────────────────────────────────────────────────────

pub async fn register(
    core: Arc<MdnsCore>,
    name: &str,
    service_type: &str,
    port: u16,
    txt: &[String],
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let payload = RegisterPayload {
        name: name.to_string(),
        service_type: service_type.to_string(),
        port,
        txt: parse_txt(txt),
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
    let dur = effective_timeout(timeout, None);
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match dur {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }

    let _ = core.shutdown();
    Ok(())
}

// ── Unregister ──────────────────────────────────────────────────────

pub fn unregister(
    core: Arc<MdnsCore>,
    id: &str,
    json: bool,
) -> anyhow::Result<()> {
    core.unregister(id)?;
    if json {
        let resp = PipelineResponse::clean(Response::Unregistered(id.to_string()));
        println!("{}", serde_json::to_string(&resp).unwrap());
    } else {
        println!("Unregistered {id}");
    }
    let _ = core.shutdown();
    Ok(())
}

// ── Resolve ─────────────────────────────────────────────────────────

pub async fn resolve(
    core: Arc<MdnsCore>,
    instance: &str,
    json: bool,
) -> anyhow::Result<()> {
    let record = core.resolve(instance).await?;
    if json {
        let resp = PipelineResponse::clean(Response::Resolved(record));
        println!("{}", serde_json::to_string(&resp).unwrap());
    } else {
        format::resolved_detail(&record);
    }
    let _ = core.shutdown();
    Ok(())
}

// ── Subscribe ───────────────────────────────────────────────────────

pub async fn subscribe(
    core: Arc<MdnsCore>,
    service_type: &str,
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let handle = core.browse(service_type)?;
    let dur = effective_timeout(timeout, Some(DEFAULT_TIMEOUT));

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

    let _ = core.shutdown();
    Ok(())
}

// ── Private helpers ─────────────────────────────────────────────────

fn parse_txt(entries: &[String]) -> HashMap<String, String> {
    entries
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Resolve the effective timeout duration.
///
/// - `Some(0)` → infinite (run forever)
/// - `Some(n)` → n seconds
/// - `None` → fall back to the provided default (`None` default = infinite)
fn effective_timeout(
    explicit: Option<u64>,
    default_secs: Option<u64>,
) -> Option<std::time::Duration> {
    match explicit {
        Some(0) => None,
        Some(secs) => Some(std::time::Duration::from_secs(secs)),
        None => default_secs.map(std::time::Duration::from_secs),
    }
}
