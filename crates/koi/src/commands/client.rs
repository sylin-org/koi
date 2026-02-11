//! Client-mode command handlers.
//!
//! These talk to a running Koi daemon via HTTP using `KoiClient`.
//! All service operations go through the daemon's REST API.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use koi_common::pipeline::PipelineResponse;
use koi_common::types::{ServiceRecord, META_QUERY};
use koi_mdns::protocol::{RegisterPayload, Response};

use crate::client::KoiClient;
use crate::format;

/// Minimum heartbeat interval floor (seconds) to avoid busy-looping
/// on very short leases. Heartbeat fires at max(lease, this) / 2.
const MIN_HEARTBEAT_LEASE_FLOOR: u64 = 4;

// ── Browse ──────────────────────────────────────────────────────────

pub async fn browse(
    endpoint: &str,
    service_type: Option<&str>,
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    let is_meta = service_type.is_none();
    let browse_type = service_type.unwrap_or(META_QUERY);
    let stream = client.browse_stream(browse_type)?;
    let dur = super::effective_timeout(timeout, Some(super::DEFAULT_TIMEOUT));

    tokio::select! {
        _ = tokio::task::spawn_blocking(move || {
            for event in stream {
                match event {
                    Ok(val) => {
                        if json {
                            println!("{val}");
                        } else {
                            format_browse_event(&val, is_meta);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        break;
                    }
                }
            }
        }) => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match dur {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }

    Ok(())
}

// ── Register ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn register(
    endpoint: &str,
    name: &str,
    service_type: &str,
    port: u16,
    ip: Option<&str>,
    txt: &[String],
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    let payload = RegisterPayload {
        name: name.to_string(),
        service_type: service_type.to_string(),
        port,
        ip: ip.map(String::from),
        lease_secs: None,
        txt: super::parse_txt(txt),
    };

    let result = client.register(&payload)?;
    let id = result.id.clone();

    if json {
        let resp = PipelineResponse::clean(Response::Registered(result.clone()));
        println!("{}", serde_json::to_string(&resp).unwrap());
    } else {
        println!(
            "Registered \"{}\" ({}) on port {} [id: {}]",
            result.name, result.service_type, result.port, result.id
        );
        eprintln!("Service is being advertised. Press Ctrl+C to unregister and exit.");
    }

    // Start heartbeat loop if the registration has a lease
    let stop = Arc::new(AtomicBool::new(false));
    if let Some(lease_secs) = result.lease_secs {
        let heartbeat_client = KoiClient::new(endpoint);
        let heartbeat_id = id.clone();
        let stop_clone = stop.clone();
        let interval = Duration::from_secs(lease_secs.max(MIN_HEARTBEAT_LEASE_FLOOR) / 2);

        std::thread::spawn(move || loop {
            std::thread::sleep(interval);
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            match heartbeat_client.heartbeat(&heartbeat_id) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Heartbeat failed: {e}");
                    break;
                }
            }
        });
    }

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

    stop.store(true, Ordering::Relaxed);
    let _ = client.unregister(&id);
    Ok(())
}

// ── Unregister ──────────────────────────────────────────────────────

pub fn unregister(endpoint: &str, id: &str, json: bool) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    client.unregister(id)?;
    if json {
        let resp = PipelineResponse::clean(Response::Unregistered(id.to_string()));
        println!("{}", serde_json::to_string(&resp).unwrap());
    } else {
        println!("Unregistered {id}");
    }
    Ok(())
}

// ── Resolve ─────────────────────────────────────────────────────────

pub fn resolve(endpoint: &str, instance: &str, json: bool) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    let record = client.resolve(instance)?;
    if json {
        let resp = PipelineResponse::clean(Response::Resolved(record));
        println!("{}", serde_json::to_string(&resp).unwrap());
    } else {
        format::resolved_detail(&record);
    }
    Ok(())
}

// ── Subscribe ───────────────────────────────────────────────────────

pub async fn subscribe(
    endpoint: &str,
    service_type: &str,
    json: bool,
    timeout: Option<u64>,
) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    let stream = client.events_stream(service_type)?;
    let dur = super::effective_timeout(timeout, Some(super::DEFAULT_TIMEOUT));

    tokio::select! {
        _ = tokio::task::spawn_blocking(move || {
            for event in stream {
                match event {
                    Ok(val) => {
                        if json {
                            println!("{val}");
                        } else {
                            format_subscribe_event(&val);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        break;
                    }
                }
            }
        }) => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = async {
            match dur {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        } => {}
    }

    Ok(())
}

// ── Formatting helpers ──────────────────────────────────────────────

fn format_browse_event(json: &serde_json::Value, is_meta: bool) {
    if let Some(found) = json.get("found") {
        if let Ok(record) = serde_json::from_value::<ServiceRecord>(found.clone()) {
            if is_meta {
                println!("{}", record.name);
            } else {
                format::service_line(&record);
            }
        }
    } else if json.get("event").and_then(|e| e.as_str()) == Some("removed") {
        if let Some(name) = json
            .get("service")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
        {
            println!("[removed]\t{name}");
        }
    }
}

fn format_subscribe_event(json: &serde_json::Value) {
    if let Some(event_kind) = json.get("event").and_then(|e| e.as_str()) {
        if let Some(service) = json.get("service") {
            if let Ok(record) = serde_json::from_value::<ServiceRecord>(service.clone()) {
                format::subscribe_event(event_kind, &record);
            }
        }
    }
}
