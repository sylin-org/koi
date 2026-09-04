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
        PondCommandOutcome::Unavailable(status) => Err(unavailable_error(&status)),
    }
}

pub fn stop(cli: &Cli) -> anyhow::Result<()> {
    reject_standalone(cli)?;
    let client = require_client(cli.endpoint.as_deref(), cli_token(cli))?;
    let outcome = client.pond_disable()?;
    output_status(outcome_status(&outcome), cli.json)?;
    match outcome {
        PondCommandOutcome::Succeeded(status) => validate_stopped(&status),
        PondCommandOutcome::Unavailable(status) => Err(unavailable_error(&status)),
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
    if status.desired
        && status.running
        && status.state == PondState::Running
        && selected_http_url(status).is_some()
    {
        return Ok(());
    }
    anyhow::bail!(actionable_reason(status))
}

fn selected_http_url(status: &PondStatus) -> Option<&str> {
    let selected = status.url.as_deref()?;
    if !status.urls.iter().any(|candidate| candidate == selected) {
        return None;
    }
    let parsed = url::Url::parse(selected).ok()?;
    if parsed.scheme() != "http" || parsed.host().is_none() || parsed.port() != Some(status.port) {
        return None;
    }
    Some(selected)
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

fn unavailable_error(status: &PondStatus) -> anyhow::Error {
    if status.accepting_commands {
        return anyhow::anyhow!(actionable_reason(status));
    }
    if let Some(reason) = &status.reason {
        anyhow::anyhow!("Pond command was not admitted: {reason}")
    } else {
        anyhow::anyhow!("Pond is shutting down and no longer accepts lifecycle commands")
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
    use clap::Parser;
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
        status.urls = vec!["http://192.0.2.10:5644".into()];
        assert!(validate_started(&status).is_ok());

        status.desired = false;
        assert!(validate_started(&status).is_err());
        status.desired = true;
        status.running = false;
        assert!(validate_started(&status).is_err());
        status.running = true;
        status.state = PondState::Waiting;
        assert!(validate_started(&status).is_err());
    }

    #[test]
    fn start_rejects_a_non_http_or_inconsistent_selected_url() {
        let mut status = sample(PondState::Running);
        for selected in [
            "",
            "not a URL",
            "https://192.0.2.10:5644/",
            "http://192.0.2.10:9999/",
        ] {
            status.url = Some(selected.into());
            status.urls = vec![selected.into()];
            assert!(
                validate_started(&status).is_err(),
                "accepted invalid selected URL {selected:?}"
            );
        }

        status.url = Some("http://192.0.2.10:5644/".into());
        status.urls = vec!["http://192.0.2.11:5644/".into()];
        assert!(validate_started(&status).is_err());
    }

    #[test]
    fn stop_requires_observed_disabled_state() {
        assert!(validate_stopped(&sample(PondState::Disabled)).is_ok());
        let mut status = sample(PondState::Disabled);
        status.desired = true;
        assert!(validate_stopped(&status).is_err());
        status.desired = false;
        status.running = true;
        assert!(validate_stopped(&status).is_err());
        status.running = false;
        status.state = PondState::Waiting;
        assert!(validate_stopped(&status).is_err());
    }

    #[test]
    fn unavailable_status_keeps_the_daemon_reason_actionable() {
        let mut status = sample(PondState::Waiting);
        status.reason = Some("No private LAN address is available".into());
        assert_eq!(
            unavailable_error(&status).to_string(),
            "Pond is not reachable: No private LAN address is available"
        );
    }

    #[test]
    fn closed_admission_is_not_confused_with_pending_reachability() {
        let mut status = sample(PondState::Waiting);
        status.accepting_commands = false;
        status.reason = Some("daemon is shutting down".into());
        assert_eq!(
            unavailable_error(&status).to_string(),
            "Pond command was not admitted: daemon is shutting down"
        );
    }

    #[test]
    fn pond_rejects_standalone_before_selecting_an_owner() {
        let cli = Cli::try_parse_from(["koi", "--standalone", "pond", "status"]).unwrap();
        let error = reject_standalone(&cli).expect_err("Pond has one installed owner");
        assert!(error.to_string().contains("--standalone is not supported"));
    }
}
