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
                            print!("{}", format::unified_status(&status_json));
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

    if config.no_dns {
        caps.push(CapabilityStatus {
            name: "dns".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    } else {
        caps.push(CapabilityStatus {
            name: "dns".to_string(),
            summary: "not running".to_string(),
            healthy: false,
        });
    }

    if config.no_health {
        caps.push(CapabilityStatus {
            name: "health".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    } else {
        caps.push(CapabilityStatus {
            name: "health".to_string(),
            summary: "not running".to_string(),
            healthy: false,
        });
    }

    if config.no_proxy {
        caps.push(CapabilityStatus {
            name: "proxy".to_string(),
            summary: "disabled".to_string(),
            healthy: false,
        });
    } else {
        caps.push(CapabilityStatus {
            name: "proxy".to_string(),
            summary: "not running".to_string(),
            healthy: false,
        });
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_all_enabled_shows_not_running() {
        let config = Config::default();
        let caps = offline_capabilities(&config);
        assert_eq!(caps[0].name, "mdns");
        assert!(!caps[0].healthy);
        assert!(
            caps[0].summary.contains("not running"),
            "mdns summary: {}",
            caps[0].summary
        );
        assert_eq!(caps[1].name, "certmesh");
        assert!(!caps[1].healthy);
        assert_eq!(caps[2].name, "dns");
        assert!(!caps[2].healthy);
        assert_eq!(caps[3].name, "health");
        assert!(!caps[3].healthy);
        assert_eq!(caps[4].name, "proxy");
        assert!(!caps[4].healthy);
    }

    #[test]
    fn offline_mdns_disabled() {
        let config = Config {
            no_mdns: true,
            ..Config::default()
        };
        let caps = offline_capabilities(&config);
        assert_eq!(caps[0].name, "mdns");
        assert_eq!(caps[0].summary, "disabled");
    }

    #[test]
    fn offline_certmesh_disabled() {
        let config = Config {
            no_certmesh: true,
            ..Config::default()
        };
        let caps = offline_capabilities(&config);
        assert_eq!(caps[1].name, "certmesh");
        assert_eq!(caps[1].summary, "disabled");
    }

    #[test]
    fn offline_dns_disabled() {
        let config = Config {
            no_dns: true,
            ..Config::default()
        };
        let caps = offline_capabilities(&config);
        assert_eq!(caps[2].name, "dns");
        assert_eq!(caps[2].summary, "disabled");
    }

    #[test]
    fn offline_health_disabled() {
        let config = Config {
            no_health: true,
            ..Config::default()
        };
        let caps = offline_capabilities(&config);
        assert_eq!(caps[3].name, "health");
        assert_eq!(caps[3].summary, "disabled");
    }

    #[test]
    fn offline_proxy_disabled() {
        let config = Config {
            no_proxy: true,
            ..Config::default()
        };
        let caps = offline_capabilities(&config);
        assert_eq!(caps[4].name, "proxy");
        assert_eq!(caps[4].summary, "disabled");
    }

    #[test]
    fn offline_both_disabled() {
        let config = Config {
            no_mdns: true,
            no_certmesh: true,
            ..Config::default()
        };
        let caps = offline_capabilities(&config);
        assert_eq!(caps[0].summary, "disabled");
        assert_eq!(caps[1].summary, "disabled");
    }

    #[test]
    fn offline_returns_five_capabilities() {
        let config = Config::default();
        let caps = offline_capabilities(&config);
        assert_eq!(caps.len(), 5);
    }
}
