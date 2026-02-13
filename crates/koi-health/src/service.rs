use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::state::HealthCheckConfig;

/// Health status for machines and services.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Up,
    Down,
    Unknown,
}

/// Supported service check kinds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ServiceCheckKind {
    Http,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct ServiceCheckOutcome {
    pub status: ServiceStatus,
    pub message: Option<String>,
}

pub fn validate_check(check: &HealthCheckConfig) -> Result<(), String> {
    if check.name.trim().is_empty() {
        return Err("name is required".to_string());
    }
    if check.interval_secs == 0 {
        return Err("interval must be > 0".to_string());
    }
    if check.timeout_secs == 0 {
        return Err("timeout must be > 0".to_string());
    }

    match check.kind {
        ServiceCheckKind::Http => {
            let url =
                reqwest::Url::parse(&check.target).map_err(|e| format!("invalid URL: {e}"))?;
            match url.scheme() {
                "http" | "https" => Ok(()),
                _ => Err("URL must be http or https".to_string()),
            }
        }
        ServiceCheckKind::Tcp => {
            let (host, port) = check
                .target
                .split_once(':')
                .ok_or_else(|| "TCP target must be host:port".to_string())?;
            if host.trim().is_empty() {
                return Err("TCP target host is empty".to_string());
            }
            port.parse::<u16>()
                .map_err(|_| "TCP target port must be a number".to_string())?;
            Ok(())
        }
    }
}

pub async fn run_check(check: &HealthCheckConfig) -> ServiceCheckOutcome {
    match check.kind {
        ServiceCheckKind::Http => run_http_check(check).await,
        ServiceCheckKind::Tcp => run_tcp_check(check).await,
    }
}

async fn run_http_check(check: &HealthCheckConfig) -> ServiceCheckOutcome {
    let timeout = Duration::from_secs(check.timeout_secs);
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(e) => {
            return ServiceCheckOutcome {
                status: ServiceStatus::Down,
                message: Some(format!("client_error: {e}")),
            };
        }
    };

    match client.get(&check.target).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                ServiceCheckOutcome {
                    status: ServiceStatus::Up,
                    message: None,
                }
            } else {
                ServiceCheckOutcome {
                    status: ServiceStatus::Down,
                    message: Some(format!("http_status: {}", resp.status())),
                }
            }
        }
        Err(e) => ServiceCheckOutcome {
            status: ServiceStatus::Down,
            message: Some(format!("http_error: {e}")),
        },
    }
}

async fn run_tcp_check(check: &HealthCheckConfig) -> ServiceCheckOutcome {
    let timeout = Duration::from_secs(check.timeout_secs);
    let connect = tokio::net::TcpStream::connect(check.target.as_str());
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(_)) => ServiceCheckOutcome {
            status: ServiceStatus::Up,
            message: None,
        },
        Ok(Err(e)) => ServiceCheckOutcome {
            status: ServiceStatus::Down,
            message: Some(format!("tcp_error: {e}")),
        },
        Err(_) => ServiceCheckOutcome {
            status: ServiceStatus::Down,
            message: Some("tcp_timeout".to_string()),
        },
    }
}
