//! Health command handlers.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    cursor::MoveTo,
    execute,
    terminal::{Clear, ClearType},
};

use crate::cli::Config;
use crate::client::KoiClient;
use crate::commands::{print_json, with_mode, Mode};

use koi_health::{HealthCheck, HealthSnapshot, HealthStatus, ServiceCheckKind};

async fn build_core(
    config: &Config,
) -> anyhow::Result<(Arc<koi_health::HealthCore>, Option<Arc<koi_mdns::MdnsCore>>)> {
    let mdns = if !config.no_mdns {
        Some(Arc::new(koi_mdns::MdnsCore::new()?))
    } else {
        None
    };

    let dns_runtime = if !config.no_dns {
        let core = koi_dns::DnsCore::new(config.dns_config(), mdns.clone(), None).await?;
        Some(Arc::new(koi_dns::DnsRuntime::new(core)))
    } else {
        None
    };

    let core = koi_health::HealthCore::new(mdns.clone(), dns_runtime).await;
    Ok((Arc::new(core), mdns))
}

pub async fn status(config: &Config, mode: Mode, json: bool) -> anyhow::Result<()> {
    with_mode(
        mode,
        || async {
            let (core, mdns) = build_core(config).await?;
            core.run_checks_once().await;
            let snapshot = core.snapshot().await;
            if json {
                print_json(&snapshot);
            } else {
                println!("{}", render_snapshot(&snapshot));
            }
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
            Ok(())
        },
        |client| async move {
            let snapshot = client.health_status()?;
            if json {
                print_json(&snapshot);
            } else {
                let snapshot: HealthSnapshot = serde_json::from_value(snapshot)?;
                println!("{}", render_snapshot(&snapshot));
            }
            Ok(())
        },
    )
    .await
}

pub async fn watch(config: &Config, mode: Mode, interval: u64) -> anyhow::Result<()> {
    let interval = Duration::from_secs(interval.max(1));

    match mode {
        Mode::Standalone => {
            let (core, mdns) = build_core(config).await?;
            let runtime = Arc::new(koi_health::HealthRuntime::new(core.clone()));
            let _ = runtime.start().await?;
            let mut ticker = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        break;
                    }
                    _ = ticker.tick() => {
                        let snapshot = core.snapshot().await;
                        render_watch(&snapshot)?;
                    }
                }
            }

            let _ = runtime.stop().await;
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
        }
        Mode::Client { endpoint } => {
            let client = KoiClient::new(&endpoint);
            let mut ticker = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        break;
                    }
                    _ = ticker.tick() => {
                        let snapshot = client.health_status()?;
                        let snapshot: HealthSnapshot = serde_json::from_value(snapshot)?;
                        render_watch(&snapshot)?;
                    }
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn add(
    name: &str,
    http: Option<&str>,
    tcp: Option<&str>,
    interval: u64,
    timeout: u64,
    mode: Mode,
    json: bool,
    config: &Config,
) -> anyhow::Result<()> {
    let (kind, target) = match (http, tcp) {
        (Some(url), None) => (ServiceCheckKind::Http, url.to_string()),
        (None, Some(target)) => (ServiceCheckKind::Tcp, target.to_string()),
        _ => anyhow::bail!("Specify exactly one of --http or --tcp"),
    };
    let target_local = target.clone();
    let target_client = target.clone();

    with_mode(
        mode,
        || async {
            let (core, mdns) = build_core(config).await?;
            let check = HealthCheck {
                name: name.to_string(),
                kind,
                target: target_local,
                interval_secs: interval,
                timeout_secs: timeout,
            };
            core.add_check(check).await?;
            if json {
                print_json(&serde_json::json!({ "status": "ok" }));
            } else {
                println!("Added health check {name}");
            }
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
            Ok(())
        },
        |client| async move {
            let resp = client.health_add_check(name, kind, &target_client, interval, timeout)?;
            if json {
                print_json(&resp);
            } else {
                println!("Added health check {name}");
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
            let (core, mdns) = build_core(config).await?;
            core.remove_check(name).await?;
            if json {
                print_json(&serde_json::json!({ "status": "ok" }));
            } else {
                println!("Removed health check {name}");
            }
            if let Some(mdns) = mdns {
                let _ = mdns.shutdown().await;
            }
            Ok(())
        },
        |client| async move {
            let resp = client.health_remove_check(name)?;
            if json {
                print_json(&resp);
            } else {
                println!("Removed health check {name}");
            }
            Ok(())
        },
    )
    .await
}

pub fn log() -> anyhow::Result<()> {
    let contents = koi_health::log::read_log()?;
    if contents.trim().is_empty() {
        println!("No health transitions recorded.");
    } else {
        print!("{contents}");
    }
    Ok(())
}

fn render_snapshot(snapshot: &HealthSnapshot) -> String {
    let mut out = String::new();

    out.push_str("Machines:\n");
    if snapshot.machines.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for machine in &snapshot.machines {
            let status = status_label(machine.status);
            let last_seen = machine
                .last_seen_secs
                .map(|s| format!("{s}s"))
                .unwrap_or_else(|| "unknown".to_string());
            out.push_str(&format!(
                "  [{status}] {} (last seen {last_seen})\n",
                machine.hostname
            ));
        }
    }

    out.push_str("\nServices:\n");
    if snapshot.services.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for service in &snapshot.services {
            let status = status_label(service.status);
            let target = &service.target;
            out.push_str(&format!("  [{status}] {} -> {}\n", service.name, target));
        }
    }

    out
}

fn render_watch(snapshot: &HealthSnapshot) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout();
    execute!(stdout, Clear(ClearType::All), MoveTo(0, 0))?;
    stdout.write_all(render_snapshot(snapshot).as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn status_label(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Up => "+",
        HealthStatus::Down => "-",
        HealthStatus::Unknown => "?",
    }
}
