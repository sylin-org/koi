//! Runtime state file management (Phase 1+).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use koi_common::paths;
use koi_common::persist;

/// DNS static entry stored in the local state file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct DnsEntry {
    pub name: String,
    pub ip: String,
    #[serde(default)]
    pub ttl: Option<u32>,
}

/// DNS state persisted on disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DnsState {
    #[serde(default)]
    pub entries: Vec<DnsEntry>,
}

/// Path to the DNS state file.
pub fn dns_state_path() -> PathBuf {
    paths::koi_state_dir().join("dns.json")
}

/// Load DNS state from disk. Returns default state if missing.
pub fn load_dns_state() -> Result<DnsState, std::io::Error> {
    let path = dns_state_path();
    persist::read_json_or_default(&path)
}

/// Save DNS state to disk, creating the state directory if needed.
pub fn save_dns_state(state: &DnsState) -> Result<(), std::io::Error> {
    let path = dns_state_path();
    persist::write_json_pretty(&path, state)
}

/// A CA root that Koi installed into the OS trust store.
///
/// Koi tracks *only* the roots it installed so `koi trust list` / `remove` manage
/// Koi's own footprint and never enumerate or mutate the OS store wholesale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustEntry {
    /// Name used as the install marker (filename on Linux, store name elsewhere).
    pub name: String,
    /// RFC 3339 timestamp of when Koi installed it.
    pub installed_at: String,
    /// Lowercase hex SHA-256 fingerprint of the certificate (DER).
    pub fingerprint: String,
    /// Where the cert came from (e.g. a file path, or "certmesh-ca").
    pub source: String,
}

/// Trust state persisted on disk (`state/trust.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TrustState {
    #[serde(default)]
    pub roots: Vec<TrustEntry>,
}

/// Path to the trust state file.
pub fn trust_state_path() -> PathBuf {
    paths::koi_state_dir().join("trust.json")
}

/// Load trust state from disk. Returns default (empty) state if missing.
pub fn load_trust_state() -> Result<TrustState, std::io::Error> {
    let path = trust_state_path();
    persist::read_json_or_default(&path)
}

/// Save trust state to disk, creating the state directory if needed.
pub fn save_trust_state(state: &TrustState) -> Result<(), std::io::Error> {
    let path = trust_state_path();
    persist::write_json_pretty(&path, state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_state_round_trip() {
        let state = DnsState {
            entries: vec![DnsEntry {
                name: "grafana.lan".to_string(),
                ip: "192.168.1.50".to_string(),
                ttl: Some(60),
            }],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: DnsState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }

    #[test]
    fn load_dns_state_missing_returns_default() {
        let _ = koi_common::test::ensure_data_dir("koi-config-state-tests");
        let state = load_dns_state().unwrap();
        assert!(state.entries.is_empty());
    }

    #[test]
    fn trust_state_round_trip() {
        let state = TrustState {
            roots: vec![TrustEntry {
                name: "step-ca-root".to_string(),
                installed_at: "2026-06-15T00:00:00Z".to_string(),
                fingerprint: "abcd1234".to_string(),
                source: "./root.pem".to_string(),
            }],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: TrustState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }

    #[test]
    fn trust_state_default_is_empty() {
        assert!(TrustState::default().roots.is_empty());
    }
}
