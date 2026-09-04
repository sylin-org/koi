//! DNS command handlers.

use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::rr::RecordType;
use koi_dns::DnsEntry;
use tokio_util::sync::CancellationToken;

use crate::cli::Config;

use super::{decode_field, decode_response, print_json, with_mode, with_mode_sync, Mode};

fn persistence_paths(config: &Config) -> koi_compose::cores::PersistencePaths {
    koi_compose::cores::PersistencePaths::from_data_dir(config.data_dir.clone())
}

async fn build_core(
    config: &Config,
) -> anyhow::Result<(koi_dns::DnsCore, Option<Arc<koi_mdns::MdnsCore>>)> {
    let mdns = if !config.no_mdns {
        Some(Arc::new(
            koi_compose::mdns::build_core(CancellationToken::new()).await?,
        ))
    } else {
        None
    };
    let mdns_bridge: Option<Arc<dyn koi_common::integration::MdnsSnapshot>> =
        if let Some(ref core) = mdns {
            Some(koi_compose::bridges::MdnsBridge::spawn(core.clone()).await)
        } else {
            None
        };
    let core = koi_dns::DnsCore::open(
        persistence_paths(config).dns_state().to_path_buf(),
        config.dns_config(),
        mdns_bridge,
        None,
        None,
    )
    .await?;
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
            let runtime = koi_dns::DnsRuntime::new(core);

            // Standalone serving uses the same owned desired-state lifecycle as
            // the daemon. The runtime retains the listener generation and all
            // background observers, retries transient bind failures, and gives
            // this command one terminal, acknowledged shutdown boundary.
            runtime.start().await?;
            let status = runtime.status();
            tracing::info!(
                port = config.dns_port,
                zone = %config.dns_zone,
                state = ?status.state,
                endpoints = ?status.endpoints,
                reason = ?status.reason,
                "DNS resolver lifecycle armed"
            );
            tokio::signal::ctrl_c().await?;
            runtime.shutdown().await;

            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }

            Ok(())
        },
        |client| async move {
            let started = client.dns_start()?;
            if started {
                println!("DNS started");
            } else {
                println!("DNS was already running");
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
            let stopped = client.dns_stop()?;
            if stopped {
                println!("DNS stopped");
            } else {
                println!("DNS was already stopped");
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
            let status = core.status();
            if json {
                print_json(status.as_ref())?;
            } else {
                println!(
                    "DNS: {}",
                    if status.running { "running" } else { "stopped" }
                );
                println!("  Zone:   {}", status.zone);
                println!("  Port:   {}", status.port);
                println!("  Static: {}", status.records.static_entries);
                println!("  Certmesh: {}", status.records.certmesh_entries);
                println!("  mDNS:   {}", status.records.mdns_entries);
            }
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
            Ok(())
        },
        |client| async move {
            let status: koi_dns::DnsRuntimeStatus =
                decode_response(client.dns_status()?, "DNS status")?;
            if json {
                print_json(&status)?;
            } else {
                println!(
                    "DNS: {}",
                    if status.running { "running" } else { "stopped" }
                );
                println!("  Zone:   {}", status.zone);
                println!("  Port:   {}", status.port);
                println!("  Static: {}", status.records.static_entries);
                println!("  Certmesh: {}", status.records.certmesh_entries);
                println!("  mDNS:   {}", status.records.mdns_entries);
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
            let result = core.lookup(name, record_type).await?;
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
            output_lookup(result, json)
        },
        |client| async move {
            let result = client.dns_lookup(name, record_type)?;
            output_lookup(result, json)
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
                }))?;
            } else {
                let ips = result
                    .ips
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>();
                println!("{} -> {}", result.name, ips.join(", "));
            }
            Ok(())
        }
        None => anyhow::bail!("No records found"),
    }
}

// ── Add / Remove / List ───────────────────────────────────────────

pub async fn add(
    name: &str,
    ip: &str,
    ttl: Option<u32>,
    mode: Mode,
    json: bool,
    config: &Config,
) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let core = koi_dns::DnsCore::open(
                persistence_paths(config).dns_state().to_path_buf(),
                config.dns_config(),
                None,
                None,
                None,
            )
            .await?;
            let entry = build_entry(name, ip, ttl, &core.config().zone)?;
            let entries = core.add_entry(entry)?;
            if json {
                print_json(&serde_json::json!({ "entries": entries }))?;
            } else {
                println!("Added {name} -> {ip}");
            }
            Ok(())
        },
        |client| async move {
            let resp = client.dns_add(name, ip, ttl)?;
            let entries: Vec<DnsEntry> = decode_field(&resp, "entries", "DNS add")?;
            if json {
                print_json(&serde_json::json!({ "entries": entries }))?;
            } else {
                println!("Added {name} -> {ip}");
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
            let core = koi_dns::DnsCore::open(
                persistence_paths(config).dns_state().to_path_buf(),
                config.dns_config(),
                None,
                None,
                None,
            )
            .await?;
            let name = normalize_name(name, &core.config().zone)?;
            let Some(entries) = core.remove_entry(&name)? else {
                anyhow::bail!("Entry not found: {name}");
            };
            if json {
                print_json(&serde_json::json!({ "entries": entries }))?;
            } else {
                println!("Removed {name}");
            }
            Ok(())
        },
        |client| async move {
            let resp = client.dns_remove(name)?;
            let entries: Vec<DnsEntry> = decode_field(&resp, "entries", "DNS remove")?;
            if json {
                print_json(&serde_json::json!({ "entries": entries }))?;
            } else {
                println!("Removed {name}");
            }
            Ok(())
        },
    )
    .await
}

pub fn txt_set(name: &str, value: &str, mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode_sync(
        mode,
        || anyhow::bail!("ephemeral TXT values require a running Koi daemon"),
        |client| {
            let response = client.dns_txt_set(name, value)?;
            let response_name: String = decode_field(&response, "name", "DNS TXT set")?;
            let values: Vec<String> = decode_field(&response, "values", "DNS TXT set")?;
            if json {
                print_json(&serde_json::json!({ "name": response_name, "values": values }))?;
            } else {
                println!("Published TXT {response_name}");
            }
            Ok(())
        },
    )
}

pub fn txt_clear(name: &str, value: &str, mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode_sync(
        mode,
        || anyhow::bail!("ephemeral TXT values require a running Koi daemon"),
        |client| {
            let response = client.dns_txt_clear(name, value)?;
            let response_name: String = decode_field(&response, "name", "DNS TXT clear")?;
            let values: Vec<String> = decode_field(&response, "values", "DNS TXT clear")?;
            if json {
                print_json(&serde_json::json!({ "name": response_name, "values": values }))?;
            } else {
                println!("Removed TXT {response_name}");
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
                print_json(&serde_json::json!({ "names": names }))?;
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
            let names: Vec<String> = decode_field(&resp, "names", "DNS list")?;
            if json {
                print_json(&serde_json::json!({ "names": names }))?;
            } else if names.is_empty() {
                println!("No resolvable names.");
            } else {
                for name in names {
                    println!("{name}");
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
