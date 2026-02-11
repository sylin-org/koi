//! Unified status command handler.
//!
//! Shows the status of all capabilities — connecting to a running daemon
//! if available, otherwise reporting offline status.

use koi_common::capability::CapabilityStatus;

use crate::cli::{Cli, Config};
use crate::client::KoiClient;
use crate::format;

pub fn status(cli: &Cli, config: &Config) -> anyhow::Result<()> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct UnifiedStatus {
        version: String,
        platform: String,
        daemon: bool,
        capabilities: Vec<CapabilityStatus>,
    }

    // Try to connect to daemon first
    if !cli.standalone {
        if let Some(endpoint) = cli
            .endpoint
            .clone()
            .or_else(koi_config::breadcrumb::read_breadcrumb)
        {
            let c = KoiClient::new(&endpoint);
            if c.health().is_ok() {
                match c.unified_status() {
                    Ok(status_json) => {
                        if cli.json {
                            println!("{}", serde_json::to_string_pretty(&status_json)?);
                        } else {
                            format::unified_status(&status_json);
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "Could not fetch unified status");
                    }
                }
            }
        }
    }

    // No daemon — report offline status
    let capabilities = offline_capabilities(config);

    let status = UnifiedStatus {
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
        println!("  Daemon:    not running");
        for cap in &status.capabilities {
            let marker = if cap.healthy { "+" } else { "-" };
            println!("  [{}] {}:  {}", marker, cap.name, cap.summary);
        }
    }

    Ok(())
}

fn offline_capabilities(config: &Config) -> Vec<CapabilityStatus> {
    let mut caps = Vec::new();

    if config.no_mdns {
        caps.push(CapabilityStatus {
            name: "mdns".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    } else {
        caps.push(CapabilityStatus {
            name: "mdns".to_string(),
            summary: "not running".to_string(),
            healthy: false,
        });
    }

    if config.no_certmesh {
        caps.push(CapabilityStatus {
            name: "certmesh".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    } else {
        let certmesh_summary = if koi_certmesh::ca::is_ca_initialized() {
            "CA initialized (daemon not running)".to_string()
        } else {
            "CA not initialized".to_string()
        };
        caps.push(CapabilityStatus {
            name: "certmesh".to_string(),
            summary: certmesh_summary,
            healthy: false,
        });
    }

    caps
}
