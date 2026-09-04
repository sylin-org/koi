//! Headless Pond control through the authenticated daemon boundary.

use koi_client::PondCommandOutcome;
use koi_common::pond::{PondFirewallState, PondState, PondStatus};

use crate::cli::Cli;

use super::{cli_token, print_json, require_client};

pub fn status(cli: &Cli) -> anyhow::Result<()> {
    reject_standalone(cli)?;
    let client = require_client(cli.endpoint.as_deref(), cli_token(cli))?;
    output_status(&client.pond_status()?, cli.json)
}

pub fn start(cli: &Cli) -> anyhow::Result<()> {
    reject_standalone(cli)?;
    let client = require_client(cli.endpoint.as_deref(), cli_token(cli))?;
    let outcome = client.pond_enable()?;
    output_status(outcome_status(&outcome), cli.json)?;
    match outcome {
        PondCommandOutcome::Succeeded(status) => validate_started(&status),
        PondCommandOutcome::Unavailable(status) => Err(terminal_error(&status)),
    }
}

pub fn stop(cli: &Cli) -> anyhow::Result<()> {
    reject_standalone(cli)?;
    let client = require_client(cli.endpoint.as_deref(), cli_token(cli))?;
    let outcome = client.pond_disable()?;
    output_status(outcome_status(&outcome), cli.json)?;
    match outcome {
        PondCommandOutcome::Succeeded(status) => validate_stopped(&status),
        PondCommandOutcome::Unavailable(status) => Err(terminal_error(&status)),
    }
}

fn reject_standalone(cli: &Cli) -> anyhow::Result<()> {
    if cli.standalone {
        anyhow::bail!(
            "Pond lifecycle is owned by the installed Koi service; --standalone is not supported"
        );
    }
    Ok(())
}

fn validate_started(status: &PondStatus) -> anyhow::Result<()> {
    let selected_url = status.url.as_deref().filter(|url| !url.is_empty());
    if status.desired
        && status.running
        && status.state == PondState::Running
        && selected_url.is_some()
    {
        return Ok(());
    }
    anyhow::bail!(actionable_reason(status))
}

fn validate_stopped(status: &PondStatus) -> anyhow::Result<()> {
    if !status.desired && !status.running && status.state == PondState::Disabled {
        return Ok(());
    }
    anyhow::bail!(
        "Pond stop was acknowledged without reaching disabled state (desired={}, running={}, state={})",
        status.desired,
        status.running,
        state_name(status.state)
    )
}

fn output_status(status: &PondStatus, json: bool) -> anyhow::Result<()> {
    if json {
        return print_json(status);
    }
    println!(
        "Pond: {} (desired={}, running={}, accepting_commands={})",
        state_name(status.state),
        status.desired,
        status.running,
        status.accepting_commands
    );
    if let Some(url) = &status.url {
        println!("  URL:      {url}");
    } else {
        println!("  Port:     {}", status.port);
    }
    println!(
        "  Firewall: {} — {}",
        firewall_name(status.firewall.state),
        status.firewall.detail
    );
    if let Some(reason) = &status.reason {
        println!("  Action:   {reason}");
    }
    Ok(())
}

fn actionable_reason(status: &PondStatus) -> String {
    status
        .reason
        .as_deref()
        .map(|reason| format!("Pond is not reachable: {reason}"))
        .unwrap_or_else(|| {
            format!(
                "Pond is not reachable (state={}, desired={}, running={}); run `koi pond status` for listener and firewall details",
                state_name(status.state),
                status.desired,
                status.running
            )
        })
}

fn terminal_error(status: &PondStatus) -> anyhow::Error {
    if let Some(reason) = &status.reason {
        anyhow::anyhow!("Pond command was not admitted: {reason}")
    } else if !status.accepting_commands {
        anyhow::anyhow!("Pond is shutting down and no longer accepts lifecycle commands")
    } else {
        anyhow::anyhow!("Pond command was not admitted by the selected daemon")
    }
}

const fn state_name(state: PondState) -> &'static str {
    match state {
        PondState::Disabled => "disabled",
        PondState::Reconciling => "reconciling",
        PondState::Running => "running",
        PondState::Waiting => "waiting",
        PondState::Error => "error",
    }
}

const fn firewall_name(state: PondFirewallState) -> &'static str {
    match state {
        PondFirewallState::Open => "open",
        PondFirewallState::Inactive => "inactive",
        PondFirewallState::Blocked => "blocked",
        PondFirewallState::Unknown => "unknown",
    }
}

fn outcome_status(outcome: &PondCommandOutcome) -> &PondStatus {
    match outcome {
        PondCommandOutcome::Succeeded(status) | PondCommandOutcome::Unavailable(status) => status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::pond::{PondFirewallStatus, PondUiStatus};

    fn sample(state: PondState) -> PondStatus {
        PondStatus {
            revision: 1,
            generation: 1,
            accepting_commands: true,
            desired: state != PondState::Disabled,
            running: state == PondState::Running,
            state,
            port: 5644,
            urls: Vec::new(),
            url: None,
            firewall: PondFirewallStatus {
                state: PondFirewallState::Inactive,
                detail: "no active firewall".into(),
            },
            ui: PondUiStatus::default(),
            reason: None,
        }
    }

    #[test]
    fn start_requires_running_state_and_selected_url() {
        let mut status = sample(PondState::Running);
        assert!(validate_started(&status).is_err());
        status.url = Some("http://192.0.2.10:5644".into());
        assert!(validate_started(&status).is_ok());
        status.state = PondState::Waiting;
        assert!(validate_started(&status).is_err());
    }

    #[test]
    fn stop_requires_observed_disabled_state() {
        assert!(validate_stopped(&sample(PondState::Disabled)).is_ok());
        assert!(validate_stopped(&sample(PondState::Waiting)).is_err());
    }

    #[test]
    fn unavailable_status_keeps_the_daemon_reason_actionable() {
        let mut status = sample(PondState::Waiting);
        status.reason = Some("No private LAN address is available".into());
        assert_eq!(
            actionable_reason(&status),
            "Pond is not reachable: No private LAN address is available"
        );
    }
}
