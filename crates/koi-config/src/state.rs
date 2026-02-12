//! Runtime state file management (Phase 1+).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use koi_common::paths;

/// DNS static entry stored in the local state file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
	if !path.exists() {
		return Ok(DnsState::default());
	}
	let json = std::fs::read_to_string(&path)?;
	serde_json::from_str(&json)
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Save DNS state to disk, creating the state directory if needed.
pub fn save_dns_state(state: &DnsState) -> Result<(), std::io::Error> {
	let path = dns_state_path();
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
}
