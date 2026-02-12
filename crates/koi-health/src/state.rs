use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use koi_common::paths;

/// Default interval for health checks (seconds).
pub const DEFAULT_INTERVAL_SECS: u64 = 30;
/// Default timeout for health checks (seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Persisted health checks configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub name: String,
    pub kind: crate::service::ServiceCheckKind,
    pub target: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthChecksState {
    #[serde(default)]
    pub checks: Vec<HealthCheckConfig>,
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECS
}

fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

/// Path to the health checks state file.
pub fn health_state_path() -> PathBuf {
    paths::koi_state_dir().join("health.json")
}

/// Load health checks from disk. Returns default state if missing.
pub fn load_health_state() -> Result<HealthChecksState, std::io::Error> {
    let path = health_state_path();
    if !path.exists() {
        return Ok(HealthChecksState::default());
    }
    let json = std::fs::read_to_string(&path)?;
    serde_json::from_str(&json)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Save health checks to disk, creating the state directory if needed.
pub fn save_health_state(state: &HealthChecksState) -> Result<(), std::io::Error> {
    let path = health_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        assert_eq!(DEFAULT_INTERVAL_SECS, 30);
        assert_eq!(DEFAULT_TIMEOUT_SECS, 5);
    }
}
