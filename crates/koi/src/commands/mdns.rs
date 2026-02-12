//! mDNS command handlers.
//!
//! Each public function handles both standalone (local MdnsCore) and client
//! (KoiClient → daemon HTTP) modes. Output formatting is shared across modes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use koi_common::pipeline::PipelineResponse;
use koi_common::types::{ServiceRecord, META_QUERY};
use koi_mdns::events::MdnsEvent;
use koi_mdns::protocol::{self as mdns_protocol, Response};
use koi_mdns::MdnsCore;

use crate::cli::AdminSubcommand;
use crate::client::KoiClient;
use crate::format;

use super::Mode;

/// Minimum heartbeat interval floor (seconds) to avoid busy-looping
/// on very short leases. Heartbeat fires at max(lease, this) / 2.
const MIN_HEARTBEAT_LEASE_FLOOR: u64 = 4;

// ── Admin ───────────────────────────────────────────────────────────

/// Route admin subcommands to the appropriate handler.
pub fn admin(subcmd: &AdminSubcommand, cli: &crate::cli::Cli) -> anyhow::Result<()> {
    let endpoint = super::resolve_endpoint(cli)?;
    match subcmd {
        AdminSubcommand::Status => crate::admin::status(&endpoint, cli.json),
        AdminSubcommand::List => crate::admin::list(&endpoint, cli.json),
        AdminSubcommand::Inspect { id } => crate::admin::inspect(&endpoint, id, cli.json),
        AdminSubcommand::Unregister { id } => crate::admin::unregister(&endpoint, id, cli.json),
        AdminSubcommand::Drain { id } => crate::admin::drain(&endpoint, id, cli.json),
        AdminSubcommand::Revive { id } => crate::admin::revive(&endpoint, id, cli.json),
    }
}

// ── Discover ────────────────────────────────────────────────────────

pub async fn discover(
    service_type: Option<&str>,
    json: bool,
    timeout: Option<u64>,
    mode: Mode,
) -> anyhow::Result<()> {
    let is_meta = service_type.is_none();
    let browse_type = service_type.unwrap_or(META_QUERY);

    match mode {
        Mode::Standalone => {
            let core = Arc::new(MdnsCore::new()?);
            let handle = core.browse(browse_type).await?;

            super::run_streaming(timeout, Some(super::DEFAULT_TIMEOUT), || async {
                while let Some(event) = handle.recv().await {
                    if json {
                        super::print_json(&mdns_protocol::browse_event_to_pipeline(event));
                    } else {
                        format_browse_standalone(&event, is_meta);
                    }
                }
                Ok(())
            })
            .await?;

            let _ = core.shutdown().await;
        }
        Mode::Client { endpoint } => {
            let client = KoiClient::new(&endpoint);
            let stream = client.browse_stream(browse_type)?;

            super::run_streaming(timeout, Some(super::DEFAULT_TIMEOUT), || async {
                tokio::task::spawn_blocking(move || {
                    for event in stream {
                        match event {
                            Ok(val) => {
                                if json {
                                    println!("{val}");
                                } else if let Some(line) = format::browse_event_json(&val, is_meta)
                                {
                                    print!("{line}");
                                }
                            }
                            Err(e) => {
                                eprintln!("Error: {e}");
                                break;
                            }
                        }
                    }
                })
                .await?;
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}

/// Format a standalone browse event for human output.
fn format_browse_standalone(event: &MdnsEvent, is_meta: bool) {
    match event {
        MdnsEvent::Resolved(record) | MdnsEvent::Found(record) => {
            if is_meta {
                println!("{}", record.name);
            } else {
                print!("{}", format::service_line(record));
            }
        }
        MdnsEvent::Removed { name, .. } => {
            println!("[removed]\t{name}");
        }
    }
}

// ── Announce ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn announce(
    name: &str,
    service_type: &str,
    port: u16,
    ip: Option<&str>,
    txt: &[String],
    json: bool,
    timeout: Option<u64>,
    mode: Mode,
) -> anyhow::Result<()> {
    let payload = super::build_register_payload(name, service_type, port, ip, txt);

    match mode {
        Mode::Standalone => {
            let core = Arc::new(MdnsCore::new()?);
            let result = core.register(payload)?;
            print_registration(&result, json);

            let dur = super::effective_timeout(timeout, None);
            super::wait_for_signal_or_timeout(dur).await;

            let _ = core.shutdown().await;
        }
        Mode::Client { endpoint } => {
            let client = KoiClient::new(&endpoint);
            let result = client.register(&payload)?;
            let id = result.id.clone();
            print_registration(&result, json);

            // Start heartbeat loop if the registration has a lease
            let stop = Arc::new(AtomicBool::new(false));
            if let Some(lease_secs) = result.lease_secs {
                let heartbeat_client = KoiClient::new(&endpoint);
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
            super::wait_for_signal_or_timeout(dur).await;

            stop.store(true, Ordering::Relaxed);
            let _ = client.unregister(&id);
        }
    }
    Ok(())
}

/// Print registration result (shared across standalone and client modes).
fn print_registration(result: &koi_mdns::protocol::RegistrationResult, json: bool) {
    if json {
        super::print_json(&PipelineResponse::clean(Response::Registered(
            result.clone(),
        )));
    } else {
        super::print_register_success(result);
    }
}

// ── Unregister ──────────────────────────────────────────────────────

pub async fn unregister(id: &str, json: bool, mode: Mode) -> anyhow::Result<()> {
    match mode {
        Mode::Standalone => {
            let core = Arc::new(MdnsCore::new()?);
            core.unregister(id)?;
            let _ = core.shutdown().await;
        }
        Mode::Client { endpoint } => {
            KoiClient::new(&endpoint).unregister(id)?;
        }
    }

    if json {
        super::print_json(&PipelineResponse::clean(Response::Unregistered(
            id.to_string(),
        )));
    } else {
        println!("Unregistered {id}");
    }
    Ok(())
}

// ── Resolve ─────────────────────────────────────────────────────────

pub async fn resolve(instance: &str, json: bool, mode: Mode) -> anyhow::Result<()> {
    let record = match mode {
        Mode::Standalone => {
            let core = Arc::new(MdnsCore::new()?);
            let r = core.resolve(instance).await?;
            let _ = core.shutdown().await;
            r
        }
        Mode::Client { endpoint } => KoiClient::new(&endpoint).resolve(instance)?,
    };

    if json {
        super::print_json(&PipelineResponse::clean(Response::Resolved(record)));
    } else {
        print!("{}", format::resolved_detail(&record));
    }
    Ok(())
}

// ── Subscribe ───────────────────────────────────────────────────────

pub async fn subscribe(
    service_type: &str,
    json: bool,
    timeout: Option<u64>,
    mode: Mode,
) -> anyhow::Result<()> {
    match mode {
        Mode::Standalone => {
            let core = Arc::new(MdnsCore::new()?);
            let handle = core.browse(service_type).await?;

            super::run_streaming(timeout, Some(super::DEFAULT_TIMEOUT), || async {
                while let Some(event) = handle.recv().await {
                    if json {
                        super::print_json(&mdns_protocol::subscribe_event_to_pipeline(event));
                    } else {
                        format_subscribe_standalone(&event);
                    }
                }
                Ok(())
            })
            .await?;

            let _ = core.shutdown().await;
        }
        Mode::Client { endpoint } => {
            let client = KoiClient::new(&endpoint);
            let stream = client.events_stream(service_type)?;

            super::run_streaming(timeout, Some(super::DEFAULT_TIMEOUT), || async {
                tokio::task::spawn_blocking(move || {
                    for event in stream {
                        match event {
                            Ok(val) => {
                                if json {
                                    println!("{val}");
                                } else if let Some(line) = format::subscribe_event_json(&val) {
                                    print!("{line}");
                                }
                            }
                            Err(e) => {
                                eprintln!("Error: {e}");
                                break;
                            }
                        }
                    }
                })
                .await?;
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}

/// Format a standalone subscribe event for human output.
fn format_subscribe_standalone(event: &MdnsEvent) {
    match event {
        MdnsEvent::Found(record) => print!("{}", format::subscribe_event("found", record)),
        MdnsEvent::Resolved(record) => print!("{}", format::subscribe_event("resolved", record)),
        MdnsEvent::Removed { name, service_type } => {
            print!(
                "{}",
                format::subscribe_event(
                    "removed",
                    &ServiceRecord {
                        name: name.clone(),
                        service_type: service_type.clone(),
                        host: None,
                        ip: None,
                        port: None,
                        txt: Default::default(),
                    },
                )
            );
        }
    }
}
