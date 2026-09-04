use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use koi_common::persist;

/// A static DNS entry accepted by the DNS domain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct DnsEntry {
    pub name: String,
    pub ip: String,
    #[serde(default)]
    pub ttl: Option<u32>,
}

/// The durable DNS aggregate representation.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct DnsState {
    #[serde(default)]
    pub entries: Vec<DnsEntry>,
}

/// DNS-owned repository. State is loaded once, and accepted commands commit
/// disk before replacing the in-memory aggregate.
pub(crate) struct DnsStateRepository {
    path: PathBuf,
    state: Arc<RwLock<DnsState>>,
}

impl DnsStateRepository {
    pub(crate) fn load(path: PathBuf) -> Result<Self, std::io::Error> {
        let state = persist::read_json_or_default(&path)?;
        Ok(Self {
            path,
            state: Arc::new(RwLock::new(state)),
        })
    }

    pub(crate) fn snapshot(&self) -> DnsState {
        self.state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    pub(crate) fn save(&self, state: &DnsState) -> Result<(), std::io::Error> {
        persist::write_json_pretty(&self.path, state)?;
        *self
            .state
            .write()
            .unwrap_or_else(|error| error.into_inner()) = state.clone();
        Ok(())
    }
}

impl Clone for DnsStateRepository {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_wire_round_trip() {
        let state = DnsState {
            entries: vec![DnsEntry {
                name: "grafana.internal.".to_string(),
                ip: "192.168.1.50".to_string(),
                ttl: Some(60),
            }],
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: DnsState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }
}
