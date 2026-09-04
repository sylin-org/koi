//! mDNS command handlers.
//!
//! Each public function handles both standalone (local MdnsCore) and client
//! (KoiClient → daemon HTTP) modes. Output formatting is shared across modes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use koi_common::pipeline::PipelineResponse;
use koi_common::types::{ServiceRecord, ServiceType, META_QUERY};
use koi_mdns::events::MdnsEvent;
use koi_mdns::protocol::{self as mdns_protocol, Response};
use koi_mdns::MdnsCore;
use tokio_util::sync::CancellationToken;

use crate::cli::AdminSubcommand;
use crate::client::KoiClient;
use crate::format;

use super::Mode;

/// Minimum heartbeat interval floor (seconds) to avoid busy-looping
/// on very short leases. Heartbeat fires at max(lease, this) / 2.
const MIN_HEARTBEAT_LEASE_FLOOR: u64 = 4;

async fn standalone_core() -> anyhow::Result<Arc<MdnsCore>> {
    Ok(Arc::new(
        koi_compose::mdns::build_core(CancellationToken::new()).await?,
    ))
}

// ── Admin ───────────────────────────────────────────────────────────

/// Route admin subcommands to the appropriate handler.
pub fn admin(subcmd: &AdminSubcommand, cli: &crate::cli::Cli) -> anyhow::Result<()> {
    let client = super::require_client(cli.endpoint.as_deref(), super::cli_token(cli))?;
    match subcmd {
        AdminSubcommand::Status => crate::admin::status(&client, cli.json),
        AdminSubcommand::List => crate::admin::list(&client, cli.json),
        AdminSubcommand::Inspect { id } => crate::admin::inspect(&client, id, cli.json),
        AdminSubcommand::Unregister { id } => crate::admin::unregister(&client, id, cli.json),
        AdminSubcommand::Drain { id } => crate::admin::drain(&client, id, cli.json),
        AdminSubcommand::Revive { id } => crate::admin::revive(&client, id, cli.json),
    }
}

// ── Discover ────────────────────────────────────────────────────────

/// `koi mdns ping` — force a fresh mDNS query burst on the daemon ("ping the
/// pond"): the meta-browse worker restarts, re-querying `_services._dns-sd._udp`
/// and every known type so all mDNS clients answer immediately.
pub async fn ping(cli: &crate::cli::Cli, json: bool) -> anyhow::Result<()> {
    let client = super::require_client(cli.endpoint.as_deref(), super::cli_token(cli))?;
    let result = client.post_json("/v1/mdns/browser/query", &serde_json::json!({}))?;
    let types: u64 = super::decode_field(&result, "types_known", "mDNS ping")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Pinged the pond — fresh query burst running across {types} known service type(s)."
        );
        println!("Watch `koi mdns discover` or the workbench Discover pane for replies.");
    }
    Ok(())
}

pub async fn discover(
    service_type: Option<&str>,
    json: bool,
    timeout: Option<u64>,
    mode: Mode,
) -> anyhow::Result<()> {
    let is_meta = service_type.is_none();
    let browse_type = service_type.unwrap_or(META_QUERY);
    let canonical_type = if is_meta {
        META_QUERY.to_string()
    } else {
        ServiceType::parse(browse_type)?.as_str().to_string()
    };

    match mode {
        Mode::Standalone => {
            let core = standalone_core().await?;
            let handle = core.subscribe_type(browse_type).await?;

            super::run_streaming(timeout, Some(super::DEFAULT_TIMEOUT), || async {
                loop {
                    match handle.recv().await {
                        Ok(event) => {
                            if json {
                                super::print_json(&mdns_protocol::browse_event_to_pipeline(event))?;
                            } else {
                                format_browse_standalone(&event, is_meta);
                            }
                        }
                        Err(koi_mdns::BrowseRecvError::Lagged { dropped }) => {
                            eprintln!(
                                "mDNS browse missed {dropped} events; resyncing current state"
                            );
                            output_discovery_resync(&core, browse_type, json, false)?;
                        }
                        Err(koi_mdns::BrowseRecvError::Closed) => break,
                    }
                }
                Ok(())
            })
            .await?;

            let _ = core.shutdown().await;
        }
        Mode::Client { endpoint, token } => {
            let client = KoiClient::with_token(&endpoint, &token);
            let stream = client.browse_stream(browse_type)?;

            run_client_stream(
                stream,
                timeout,
                Some(super::DEFAULT_TIMEOUT),
                move |value| {
                    let line = format::browse_stream_item_json(&value, is_meta, &canonical_type)?;
                    if json {
                        println!("{value}");
                    } else {
                        print!("{line}");
                    }
                    Ok(())
                },
            )
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
            let core = standalone_core().await?;
            let result = core.register(payload).await?;
            print_registration(&result, json)?;

            let dur = super::effective_timeout(timeout, None);
            super::wait_for_signal_or_timeout(dur).await;

            let _ = core.shutdown().await;
        }
        Mode::Client { endpoint, token } => {
            let client = KoiClient::with_token(&endpoint, &token);
            let result = client.register(&payload)?;
            let id = result.id.clone();
            print_registration(&result, json)?;

            // Start heartbeat loop if the registration has a lease
            let stop = Arc::new(AtomicBool::new(false));
            let heartbeat_handle = if let Some(lease_secs) = result.lease_secs {
                let heartbeat_client = KoiClient::with_token(&endpoint, &token);
                let heartbeat_id = id.clone();
                let stop_clone = stop.clone();
                let interval = Duration::from_secs(lease_secs.max(MIN_HEARTBEAT_LEASE_FLOOR) / 2);

                Some(std::thread::spawn(move || {
                    let mut elapsed = Duration::ZERO;
                    loop {
                        std::thread::sleep(Duration::from_millis(100));
                        if stop_clone.load(Ordering::Acquire) {
                            break;
                        }
                        elapsed += Duration::from_millis(100);
                        if elapsed >= interval {
                            elapsed = Duration::ZERO;
                            match heartbeat_client.heartbeat(&heartbeat_id) {
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("Heartbeat failed: {e}");
                                    break;
                                }
                            }
                        }
                    }
                }))
            } else {
                None
            };

            let dur = super::effective_timeout(timeout, None);
            super::wait_for_signal_or_timeout(dur).await;

            stop.store(true, Ordering::Release);
            if let Some(handle) = heartbeat_handle {
                let _ = handle.join();
            }
            let _ = client.unregister(&id);
        }
    }
    Ok(())
}

/// Print registration result (shared across standalone and client modes).
fn print_registration(
    result: &koi_mdns::protocol::RegistrationResult,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        super::print_json(&PipelineResponse::clean(Response::Registered(
            result.clone(),
        )))?;
    } else {
        super::print_register_success(result);
    }
    Ok(())
}

// ── Unregister ──────────────────────────────────────────────────────

pub async fn unregister(id: &str, json: bool, mode: Mode) -> anyhow::Result<()> {
    match mode {
        Mode::Standalone => {
            let core = standalone_core().await?;
            core.unregister(id).await?;
            let _ = core.shutdown().await;
        }
        Mode::Client { endpoint, token } => {
            KoiClient::with_token(&endpoint, &token).unregister(id)?;
        }
    }

    if json {
        super::print_json(&PipelineResponse::clean(Response::Unregistered(
            id.to_string(),
        )))?;
    } else {
        println!("Unregistered {id}");
    }
    Ok(())
}

// ── Resolve ─────────────────────────────────────────────────────────

pub async fn resolve(instance: &str, json: bool, mode: Mode) -> anyhow::Result<()> {
    let record = match mode {
        Mode::Standalone => {
            let core = standalone_core().await?;
            let r = core.resolve(instance).await?;
            let _ = core.shutdown().await;
            r
        }
        Mode::Client { endpoint, token } => {
            KoiClient::with_token(&endpoint, &token).resolve(instance)?
        }
    };

    if json {
        super::print_json(&PipelineResponse::clean(Response::Resolved(record)))?;
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
    let canonical_type = ServiceType::parse(service_type)?.as_str().to_string();
    match mode {
        Mode::Standalone => {
            let core = standalone_core().await?;
            let handle = core.subscribe_type(service_type).await?;

            super::run_streaming(timeout, Some(super::DEFAULT_TIMEOUT), || async {
                loop {
                    match handle.recv().await {
                        Ok(event) => {
                            if json {
                                super::print_json(&mdns_protocol::subscribe_event_to_pipeline(event))?;
                            } else {
                                format_subscribe_standalone(&event);
                            }
                        }
                        Err(koi_mdns::BrowseRecvError::Lagged { dropped }) => {
                            eprintln!("mDNS subscription missed {dropped} events; resyncing current state");
                            output_discovery_resync(&core, service_type, json, true)?;
                        }
                        Err(koi_mdns::BrowseRecvError::Closed) => break,
                    }
                }
                Ok(())
            })
            .await?;

            let _ = core.shutdown().await;
        }
        Mode::Client { endpoint, token } => {
            let client = KoiClient::with_token(&endpoint, &token);
            let stream = client.events_stream(service_type)?;

            run_client_stream(
                stream,
                timeout,
                Some(super::DEFAULT_TIMEOUT),
                move |value| {
                    let line = format::subscribe_stream_item_json(&value, &canonical_type)?;
                    if json {
                        println!("{value}");
                    } else {
                        print!("{line}");
                    }
                    Ok(())
                },
            )
            .await?;
        }
    }
    Ok(())
}

/// Own one blocking HTTP stream across its complete lifecycle. The cancellation
/// handle remains on the async side of the boundary, so a CLI deadline or
/// Ctrl+C both stop and reap the worker instead of merely dropping its join
/// handle while ureq remains blocked.
async fn run_client_stream<F>(
    stream: koi_client::SseStream,
    timeout: Option<u64>,
    default_timeout: Option<u64>,
    mut consume: F,
) -> anyhow::Result<()>
where
    F: FnMut(serde_json::Value) -> anyhow::Result<()> + Send + 'static,
{
    let cancellation = stream.cancellation();
    let mut worker = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        for event in stream {
            consume(event?)?;
        }
        Ok(())
    });
    let duration = super::effective_timeout(timeout, default_timeout);
    let completed = tokio::select! {
        result = &mut worker => Some(result),
        _ = tokio::signal::ctrl_c() => None,
        _ = async {
            match duration {
                Some(duration) => tokio::time::sleep(duration).await,
                None => std::future::pending().await,
            }
        } => None,
    };

    cancellation.cancel();
    if let Some(result) = completed {
        return result?;
    }

    let reap_bound = koi_client::SSE_CANCELLATION_BOUND + Duration::from_millis(250);
    match tokio::time::timeout(reap_bound, &mut worker).await {
        Ok(result) => {
            result??;
        }
        Err(_) => {
            worker.abort();
            anyhow::bail!(
                "mDNS stream worker did not stop within its {:?} cancellation bound",
                koi_client::SSE_CANCELLATION_BOUND
            );
        }
    }
    Ok(())
}

fn output_discovery_resync(
    core: &MdnsCore,
    service_type: &str,
    json: bool,
    subscription: bool,
) -> anyhow::Result<()> {
    let snapshot = core.discovery_snapshot();
    if json {
        super::print_json(&PipelineResponse::clean(Response::Snapshot(
            snapshot.as_ref().clone(),
        )))?;
        return Ok(());
    }

    if service_type == META_QUERY {
        for discovered in &snapshot.service_types {
            println!("{discovered}");
        }
        return Ok(());
    }

    let canonical = ServiceType::parse(service_type)?.as_str().to_string();
    for record in snapshot
        .records
        .iter()
        .filter(|record| record.service_type == canonical)
    {
        let event = MdnsEvent::Resolved(record.clone());
        if subscription {
            format_subscribe_standalone(&event);
        } else {
            format_browse_standalone(&event, false);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[tokio::test]
    async fn client_stream_timeout_cancels_reaps_and_disconnects() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind SSE server");
        let address = listener.local_addr().expect("SSE address");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept SSE request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = socket.read(&mut buffer).expect("read SSE request");
                assert!(read > 0, "request closed before headers completed");
                request.extend_from_slice(&buffer[..read]);
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n",
                )
                .expect("write SSE headers");
            for _ in 0..60 {
                if socket.write_all(b": keepalive\n\n").is_err() {
                    return;
                }
                socket.flush().expect("flush keepalive");
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("CLI returned without reclaiming its stream socket");
        });

        let stream = KoiClient::new(&format!("http://{address}"))
            .browse_stream("_http._tcp")
            .expect("establish SSE stream");
        let started = std::time::Instant::now();
        run_client_stream(stream, Some(1), None, |_| {
            anyhow::bail!("keepalive comments must not reach the consumer")
        })
        .await
        .expect("timeout is a clean local stop");

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "CLI stream owner did not reap promptly"
        );
        server.join().expect("SSE server observes disconnect");
    }
}
