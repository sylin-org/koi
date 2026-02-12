//! Runtime state file management (Phase 1+).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use koi_common::paths;
use koi_common::persist;

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
	persist::read_json_or_default(&path)
}

/// Save DNS state to disk, creating the state directory if needed.
pub fn save_dns_state(state: &DnsState) -> Result<(), std::io::Error> {
	let path = dns_state_path();
	persist::write_json_pretty(&path, state)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::{SystemTime, UNIX_EPOCH};

	fn with_temp_data_dir<F, T>(f: F) -> T
	where
		F: FnOnce() -> T,
	{
		let nanos = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_nanos();
		let dir = std::env::temp_dir().join(format!("koi-dns-state-test-{nanos}"));
		let prev = std::env::var("KOI_DATA_DIR").ok();
		std::env::set_var("KOI_DATA_DIR", &dir);
		let result = f();
		match prev {
			Some(v) => std::env::set_var("KOI_DATA_DIR", v),
			None => std::env::remove_var("KOI_DATA_DIR"),
		}
		result
	}

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
		with_temp_data_dir(|| {
			let state = load_dns_state().unwrap();
			assert!(state.entries.is_empty());
		});
	}
}
