//! Headless Pond control through authenticated local daemon discovery.

use crate::cli::Cli;

use super::{cli_token, print_json, require_client};

pub fn status(cli: &Cli) -> anyhow::Result<()> {
    let client = require_client(cli.endpoint.as_deref(), cli_token(cli))?;
    let status = client.pond_status()?;
    output_status(&status, cli.json);
    Ok(())
}

pub fn start(cli: &Cli) -> anyhow::Result<()> {
    let client = require_client(cli.endpoint.as_deref(), cli_token(cli))?;
    let status = client.pond_enable()?;
    if cli.json {
        print_json(&status);
        return Ok(());
    }
    output_status(&status, false);
    if status.get("running").and_then(|value| value.as_bool()) != Some(true) {
        anyhow::bail!(actionable_reason(&status));
    }
    Ok(())
}

pub fn stop(cli: &Cli) -> anyhow::Result<()> {
    let client = require_client(cli.endpoint.as_deref(), cli_token(cli))?;
    let status = client.pond_disable()?;
    output_status(&status, cli.json);
    Ok(())
}

fn output_status(status: &serde_json::Value, json: bool) {
    if json {
        print_json(status);
        return;
    }
    let state = status
        .get("state")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let desired = status
        .get("desired")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let running = status
        .get("running")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    println!("Pond: {state} (desired={desired}, running={running})");
    if let Some(url) = status.get("url").and_then(|value| value.as_str()) {
        println!("  URL:      {url}");
    } else if let Some(port) = status.get("port").and_then(|value| value.as_u64()) {
        println!("  Port:     {port}");
    }
    if let Some(firewall) = status.get("firewall") {
        let state = firewall
            .get("state")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let detail = firewall
            .get("detail")
            .and_then(|value| value.as_str())
            .unwrap_or("no assessment returned");
        println!("  Firewall: {state} — {detail}");
    }
    if let Some(reason) = status.get("reason").and_then(|value| value.as_str()) {
        println!("  Action:   {reason}");
    }
}

fn actionable_reason(status: &serde_json::Value) -> String {
    status
        .get("reason")
        .and_then(|value| value.as_str())
        .map(|reason| format!("Pond is not reachable: {reason}"))
        .unwrap_or_else(|| {
            "Pond is not reachable; run `koi pond status` for listener and firewall details"
                .to_owned()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_status_keeps_the_daemon_reason_actionable() {
        let status = serde_json::json!({
            "running": false,
            "reason": "No private LAN address is available"
        });
        assert_eq!(
            actionable_reason(&status),
            "Pond is not reachable: No private LAN address is available"
        );
    }
}
