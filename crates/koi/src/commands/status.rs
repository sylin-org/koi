//! Unified status command handler.
//!
//! Shows the status of all capabilities from a running daemon. When no daemon
//! can be observed, it preserves the product ladder but does not infer domain
//! state from configuration or files.

use koi_common::capability::CapabilityStatus;

use crate::cli::Cli;
use crate::client::KoiClient;
use crate::format;

pub fn status(cli: &Cli) -> anyhow::Result<()> {
    if let Some(status_json) = try_daemon_status(cli)? {
        let human = format::unified_status(&status_json)?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&status_json)?);
        } else {
            print!("{human}");
        }
        return Ok(());
    }

    // No daemon means there is no authoritative domain status to project. Keep
    // the stable product shape, but mark every rung as unobserved rather than
    // guessing from launch configuration or private persistence.
    let observation = offline_observation(cli);
    let capabilities = offline_capabilities(observation);

    let status = LocalStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        daemon: false,
        capabilities,
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Koi v{}", status.version);
        println!("  Platform:  {}", status.platform);
        println!(
            "  Daemon:    {}",
            if cli.standalone {
                "not queried (--standalone)"
            } else {
                "not observed"
            }
        );
        for cap in &status.capabilities {
            let marker = if cap.healthy { "+" } else { "-" };
            println!("  [{}] {}:  {}", marker, cap.name, cap.summary);
        }
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct LocalStatus {
    version: String,
    platform: String,
    daemon: bool,
    capabilities: Vec<CapabilityStatus>,
}

/// Probe for a running daemon and return unified status JSON if reachable.
///
/// Failure to discover a local service is ordinary absence. Once a service is
/// explicitly selected—or a discovered service answers its liveness probe—its
/// transport and protocol failures remain real errors rather than being
/// rewritten as an offline status.
pub fn try_daemon_status(cli: &Cli) -> anyhow::Result<Option<serde_json::Value>> {
    if cli.standalone {
        return Ok(None);
    }

    if let Some(endpoint) = &cli.endpoint {
        let client = KoiClient::with_token(endpoint, super::cli_token(cli).unwrap_or(""));
        client.health()?;
        return Ok(Some(client.unified_status()?));
    }

    let access = match koi_client::observe_local_daemon_access() {
        koi_client::LocalDaemonObservation::Present(access) => access,
        koi_client::LocalDaemonObservation::Absent => return Ok(None),
        koi_client::LocalDaemonObservation::Uncertain(error) => {
            anyhow::bail!("the local Koi service owner could not be verified: {error}")
        }
    };
    let client = KoiClient::with_token(&access.endpoint, &access.token);
    if let Err(error) = client.health() {
        anyhow::bail!(
            "the local Koi owner is published at {}, but its health boundary is unavailable: {error}",
            access.endpoint
        );
    }
    Ok(Some(client.unified_status()?))
}

fn offline_observation(cli: &Cli) -> &'static str {
    if cli.standalone {
        "standalone mode"
    } else {
        "daemon status unavailable"
    }
}

fn offline_capabilities(observation: &str) -> Vec<CapabilityStatus> {
    koi_compose::status::CAPABILITY_LADDER
        .into_iter()
        .map(|name| CapabilityStatus {
            name: name.to_string(),
            summary: format!("not observed: {observation}"),
            healthy: false,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn status_has_no_local_domain_or_configuration_input() {
        // The status entry point accepts only connection intent. It cannot be
        // handed a data root or a domain core, so its offline branch is
        // structurally unable to replay durable state or mutate a platform.
        let entry_point: fn(&Cli) -> anyhow::Result<()> = status;
        let _ = entry_point;
    }

    #[test]
    fn offline_status_preserves_the_canonical_product_ladder_without_inference() {
        let caps = offline_capabilities("daemon status unavailable");
        let names: Vec<&str> = caps
            .iter()
            .map(|capability| capability.name.as_str())
            .collect();

        assert_eq!(names, koi_compose::status::CAPABILITY_LADDER);
        assert!(caps.iter().all(|capability| !capability.healthy));
        assert!(caps
            .iter()
            .all(|capability| capability.summary == "not observed: daemon status unavailable"));
    }

    #[test]
    fn standalone_status_says_the_daemon_was_not_queried() {
        let cli = Cli::try_parse_from(["koi", "--standalone", "status"]).unwrap();
        let observation = offline_observation(&cli);
        let caps = offline_capabilities(observation);

        assert_eq!(observation, "standalone mode");
        assert!(caps
            .iter()
            .all(|capability| capability.summary == "not observed: standalone mode"));
    }
}
