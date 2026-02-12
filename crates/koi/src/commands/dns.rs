//! DNS command handlers.

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::rr::RecordType;
use koi_config::state::{load_dns_state, save_dns_state, DnsEntry, DnsState};
use tokio_util::sync::CancellationToken;

use crate::cli::Config;

use super::{print_json, with_mode, with_mode_sync, Mode};

fn dns_config(config: &Config) -> koi_dns::DnsConfig {
    koi_dns::DnsConfig {
        port: config.dns_port,
        zone: config.dns_zone.clone(),
        allow_public_clients: config.dns_public,
        ..Default::default()
    }
}

async fn build_core(config: &Config) -> anyhow::Result<(koi_dns::DnsCore, Option<Arc<koi_mdns::MdnsCore>>)> {
    let mdns = if !config.no_mdns {
        Some(Arc::new(koi_mdns::MdnsCore::new()?))
    } else {
        None
    };
    let core = koi_dns::DnsCore::new(dns_config(config), mdns.clone(), None).await?;
    Ok((core, mdns))
}

fn parse_record_type(input: &str) -> anyhow::Result<RecordType> {
    let record_type = match input.trim().to_ascii_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "ANY" => RecordType::ANY,
        other => anyhow::bail!("Unsupported record type: {other}"),
    };
    Ok(record_type)
}

// ── Serve ──────────────────────────────────────────────────────────

pub async fn serve(config: &Config, mode: Mode) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let (core, mdns) = build_core(config).await?;
            let cancel = CancellationToken::new();

            tracing::info!(
                port = config.dns_port,
                zone = %config.dns_zone,
                "DNS resolver listening"
            );

            let server_task = tokio::spawn({
                let token = cancel.clone();
                async move { core.serve(token).await }
            });

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    cancel.cancel();
                }
                result = server_task => {
                    if let Ok(Err(e)) = result {
                        return Err(anyhow::anyhow!(e.to_string()));
                    }
                }
            }

            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }

            Ok(())
        },
        |client| async move {
            let resp = client.dns_start()?;
            if let Some(started) = resp.get("started") {
                println!("DNS started: {started}");
            } else {
                println!("DNS start requested");
            }
            Ok(())
        },
    )
    .await
}

pub async fn stop(mode: Mode) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async { anyhow::bail!("dns stop is only supported in daemon mode") },
        |client| async move {
            let resp = client.dns_stop()?;
            if let Some(stopped) = resp.get("stopped") {
                println!("DNS stopped: {stopped}");
            } else {
                println!("DNS stop requested");
            }
            Ok(())
        },
    )
    .await
}

// ── Status ─────────────────────────────────────────────────────────

pub async fn status(config: &Config, mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let (core, mdns) = build_core(config).await?;
            let snapshot = core.snapshot();
            let status = serde_json::json!({
                "running": false,
                "zone": core.config().zone.clone(),
                "port": core.config().port,
                "records": {
                    "static_entries": snapshot.static_entries.len(),
                    "certmesh_entries": snapshot.certmesh_entries.len(),
                    "mdns_entries": snapshot.mdns_entries.len(),
                }
            });
            if json {
                print_json(&status);
            } else {
                println!("DNS: standalone (not serving)");
                println!("  Zone:   {}", status["zone"]);
                println!("  Port:   {}", status["port"]);
                println!("  Static: {}", status["records"]["static_entries"]);
                println!("  Certmesh: {}", status["records"]["certmesh_entries"]);
                println!("  mDNS:   {}", status["records"]["mdns_entries"]);
            }
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
            Ok(())
        },
        |client| async move {
            let status = client.dns_status()?;
            if json {
                print_json(&status);
            } else {
                let running = status.get("running").and_then(|v| v.as_bool()).unwrap_or(false);
                let zone = status.get("zone").and_then(|v| v.as_str()).unwrap_or("?");
                let port = status.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("DNS: {}", if running { "running" } else { "stopped" });
                println!("  Zone:   {zone}");
                println!("  Port:   {port}");
                if let Some(records) = status.get("records") {
                    let static_entries = records.get("static_entries").and_then(|v| v.as_u64()).unwrap_or(0);
                    let certmesh_entries = records.get("certmesh_entries").and_then(|v| v.as_u64()).unwrap_or(0);
                    let mdns_entries = records.get("mdns_entries").and_then(|v| v.as_u64()).unwrap_or(0);
                    println!("  Static: {static_entries}");
                    println!("  Certmesh: {certmesh_entries}");
                    println!("  mDNS:   {mdns_entries}");
                }
            }
            Ok(())
        },
    )
    .await
}

// ── Lookup ─────────────────────────────────────────────────────────

pub async fn lookup(
    name: &str,
    record_type: &str,
    mode: Mode,
    json: bool,
    config: &Config,
) -> anyhow::Result<()> {
    let record_type = parse_record_type(record_type)?;
    with_mode(
        mode,
        || async {
            let (core, mdns) = build_core(config).await?;
            let result = core.lookup(name, record_type).await;
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
            output_lookup(result, json)
        },
        |client| async move {
            let resp = client.dns_lookup(name, record_type)?;
            if json {
                print_json(&resp);
            } else {
                let ips = resp.get("ips").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let ips = ips.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>();
                if ips.is_empty() {
                    println!("No records for {name}");
                } else {
                    println!("{name} -> {}", ips.join(", "));
                }
            }
            Ok(())
        },
    )
    .await
}

fn output_lookup(result: Option<koi_dns::DnsLookupResult>, json: bool) -> anyhow::Result<()> {
    match result {
        Some(result) => {
            if json {
                print_json(&serde_json::json!({
                    "name": result.name,
                    "ips": result.ips,
                    "source": result.source,
                }));
            } else {
                let ips = result.ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>();
                println!("{} -> {}", result.name, ips.join(", "));
            }
            Ok(())
        }
        None => anyhow::bail!("No records found"),
    }
}

// ── Add / Remove / List ───────────────────────────────────────────

pub fn add(name: &str, ip: &str, ttl: Option<u32>, mode: Mode, json: bool, zone: &str) -> anyhow::Result<()> {
    with_mode_sync(
        mode,
        || {
            let entry = build_entry(name, ip, ttl, zone)?;
            let mut state = load_dns_state().unwrap_or_default();
            upsert_entry(&mut state, entry);
            save_dns_state(&state)?;
            if json {
                print_json(&state);
            } else {
                println!("Added {name} -> {ip}");
            }
            Ok(())
        },
        |client| {
            let resp = client.dns_add(name, ip, ttl)?;
            if json {
                print_json(&resp);
            } else {
                println!("Added {name} -> {ip}");
            }
            Ok(())
        },
    )
}

pub fn remove(name: &str, mode: Mode, json: bool, zone: &str) -> anyhow::Result<()> {
    with_mode_sync(
        mode,
        || {
            let name = normalize_name(name, zone)?;
            let mut state = load_dns_state().unwrap_or_default();
            let before = state.entries.len();
            state.entries.retain(|entry| entry.name != name);
            if state.entries.len() == before {
                anyhow::bail!("Entry not found: {name}");
            }
            save_dns_state(&state)?;
            if json {
                print_json(&state);
            } else {
                println!("Removed {name}");
            }
            Ok(())
        },
        |client| {
            let resp = client.dns_remove(name)?;
            if json {
                print_json(&resp);
            } else {
                println!("Removed {name}");
            }
            Ok(())
        },
    )
}

pub async fn list(mode: Mode, json: bool, config: &Config) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let (core, mdns) = build_core(config).await?;
            let names = core.list_names();
            if json {
                print_json(&serde_json::json!({ "names": names }));
            } else if names.is_empty() {
                println!("No resolvable names.");
            } else {
                for name in names {
                    println!("{name}");
                }
            }
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
            Ok(())
        },
        |client| async move {
            let resp = client.dns_list()?;
            if json {
                print_json(&resp);
            } else if let Some(names) = resp.get("names").and_then(|v| v.as_array()) {
                if names.is_empty() {
                    println!("No resolvable names.");
                } else {
                    for name in names {
                        if let Some(name) = name.as_str() {
                            println!("{name}");
                        }
                    }
                }
            }
            Ok(())
        },
    )
    .await
}

fn normalize_name(name: &str, zone: &str) -> anyhow::Result<String> {
    let zone_cfg = koi_dns::DnsZone::new(zone)?;
    zone_cfg
        .normalize_name(name)
        .ok_or_else(|| anyhow::anyhow!("Name is outside the {zone} zone"))
}

fn build_entry(name: &str, ip: &str, ttl: Option<u32>, zone: &str) -> anyhow::Result<DnsEntry> {
    let name = normalize_name(name, zone)?;
    ip.parse::<IpAddr>()?;
    Ok(DnsEntry {
        name,
        ip: ip.to_string(),
        ttl,
    })
}

fn upsert_entry(state: &mut DnsState, entry: DnsEntry) {
    if let Some(existing) = state.entries.iter_mut().find(|e| e.name == entry.name) {
        *existing = entry;
    } else {
        state.entries.push(entry);
    }
}
