use std::path::Path;

use serde::{Deserialize, Serialize};

use koi_common::persist;

/// Default interval for health checks (seconds).
pub const DEFAULT_INTERVAL_SECS: u64 = 30;
/// Default timeout for health checks (seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Persisted health checks configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HealthCheckConfig {
    pub name: String,
    pub kind: crate::service::ServiceCheckKind,
    pub target: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
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

/// Load health checks from disk. Returns default state if missing.
pub fn load_health_state(path: &Path) -> Result<HealthChecksState, std::io::Error> {
    persist::read_json_or_default(path)
}

/// Save health checks to disk, creating the state directory if needed.
pub fn save_health_state(path: &Path, state: &HealthChecksState) -> Result<(), std::io::Error> {
    persist::write_json_pretty(path, state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        assert_eq!(DEFAULT_INTERVAL_SECS, 30);
        assert_eq!(DEFAULT_TIMEOUT_SECS, 5);
    }

    #[test]
    fn load_health_state_missing_returns_default() {
        let path = std::env::temp_dir()
            .join(format!(
                "koi-health-state-{}",
                koi_common::id::generate_short_id()
            ))
            .join("health.json");
        let state = load_health_state(&path).unwrap();
        assert!(state.checks.is_empty());
    }

    #[test]
    fn load_health_state_rejects_corrupt_json() {
        let path = std::env::temp_dir()
            .join(format!(
                "koi-health-state-{}",
                koi_common::id::generate_short_id()
            ))
            .join("health.json");
        std::fs::create_dir_all(path.parent().expect("state parent")).unwrap();
        std::fs::write(&path, b"{not-json").unwrap();

        let error = load_health_state(&path).expect_err("corrupt state must not become empty");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
