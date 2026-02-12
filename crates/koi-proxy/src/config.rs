use serde::{Deserialize, Serialize};

use koi_certmesh::roster::ProxyConfigEntry;
use koi_common::paths;

use crate::ProxyError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyEntry {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    #[serde(default)]
    pub allow_remote: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProxySection {
    #[serde(default)]
    entries: Vec<ProxyEntry>,
}

pub fn config_path() -> std::path::PathBuf {
    paths::koi_data_dir().join("config.toml")
}

pub fn load_entries() -> Result<Vec<ProxyEntry>, ProxyError> {
    let mut entries = load_entries_from_config()?;

    match load_entries_from_roster() {
        Ok(roster_entries) => {
            merge_entries(&mut entries, roster_entries);
        }
        Err(e) => {
            tracing::debug!(error = %e, "Failed to load proxy entries from roster");
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn load_entries_from_config() -> Result<Vec<ProxyEntry>, ProxyError> {
    let path = config_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| ProxyError::Io(e.to_string()))?;
    let value: toml::Value = raw
        .parse()
        .map_err(|e| ProxyError::Config(format!("Invalid config.toml: {e}")))?;
    let proxy = value
        .get("proxy")
        .cloned()
        .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));
    let proxy: ProxySection = proxy
        .try_into()
        .map_err(|e| ProxyError::Config(format!("Invalid proxy section: {e}")))?;
    Ok(proxy.entries)
}

fn load_entries_from_roster() -> Result<Vec<ProxyEntry>, ProxyError> {
    let roster_path = koi_certmesh::ca::roster_path();
    if !roster_path.exists() {
        return Ok(Vec::new());
    }

    let roster = koi_certmesh::roster::load_roster(&roster_path)
        .map_err(|e| ProxyError::Io(e.to_string()))?;
    let hostname = hostname::get()
        .map_err(|e| ProxyError::Io(e.to_string()))?
        .to_string_lossy()
        .to_string();

    let Some(member) = roster.find_member(&hostname) else {
        return Ok(Vec::new());
    };

    Ok(member
        .proxy_entries
        .iter()
        .map(|entry| ProxyEntry {
            name: entry.name.clone(),
            listen_port: entry.listen_port,
            backend: entry.backend.clone(),
            allow_remote: entry.allow_remote,
        })
        .collect())
}

pub fn save_entries(entries: &[ProxyEntry]) -> Result<(), ProxyError> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ProxyError::Io(e.to_string()))?;
    }

    let mut root = if path.exists() {
        let raw = std::fs::read_to_string(&path).map_err(|e| ProxyError::Io(e.to_string()))?;
        raw.parse::<toml::Value>()
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    let proxy = ProxySection {
        entries: entries.to_vec(),
    };
    let proxy_value = toml::Value::try_from(proxy)
        .map_err(|e| ProxyError::Config(format!("Proxy config serialize error: {e}")))?;

    if let toml::Value::Table(table) = &mut root {
        table.insert("proxy".to_string(), proxy_value);
    }

    let raw = toml::to_string_pretty(&root)
        .map_err(|e| ProxyError::Config(format!("Config serialize error: {e}")))?;
    std::fs::write(&path, raw).map_err(|e| ProxyError::Io(e.to_string()))?;
    Ok(())
}

pub fn upsert_entry(entry: ProxyEntry) -> Result<Vec<ProxyEntry>, ProxyError> {
    let mut entries = load_entries_from_config()?;
    if let Some(existing) = entries.iter_mut().find(|e| e.name == entry.name) {
        *existing = entry;
    } else {
        entries.push(entry);
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    save_entries(&entries)?;
    sync_roster(&entries)?;
    Ok(entries)
}

pub fn remove_entry(name: &str) -> Result<Vec<ProxyEntry>, ProxyError> {
    let mut entries = load_entries_from_config()?;
    let before = entries.len();
    entries.retain(|e| e.name != name);
    if entries.len() == before {
        return Err(ProxyError::NotFound(name.to_string()));
    }
    save_entries(&entries)?;
    sync_roster(&entries)?;
    Ok(entries)
}

fn sync_roster(entries: &[ProxyEntry]) -> Result<(), ProxyError> {
    let roster_path = koi_certmesh::ca::roster_path();
    if !roster_path.exists() {
        return Ok(());
    }

    let mut roster = koi_certmesh::roster::load_roster(&roster_path)
        .map_err(|e| ProxyError::Io(e.to_string()))?;
    let hostname = hostname::get()
        .map_err(|e| ProxyError::Io(e.to_string()))?
        .to_string_lossy()
        .to_string();

    let Some(member) = roster.find_member_mut(&hostname) else {
        return Ok(());
    };

    member.proxy_entries = entries
        .iter()
        .map(|entry| ProxyConfigEntry {
            name: entry.name.clone(),
            listen_port: entry.listen_port,
            backend: entry.backend.clone(),
            allow_remote: entry.allow_remote,
        })
        .collect();

    koi_certmesh::roster::save_roster(&roster, &roster_path)
        .map_err(|e| ProxyError::Io(e.to_string()))?;
    Ok(())
}

fn merge_entries(entries: &mut Vec<ProxyEntry>, roster_entries: Vec<ProxyEntry>) {
    let mut map: std::collections::BTreeMap<String, ProxyEntry> = std::collections::BTreeMap::new();
    for entry in roster_entries {
        map.insert(entry.name.clone(), entry);
    }
    for entry in entries.drain(..) {
        map.insert(entry.name.clone(), entry);
    }
    *entries = map.into_values().collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_path_is_under_data_dir() {
        let path = config_path();
        assert!(path.ends_with("config.toml"));
    }

    #[test]
    fn proxy_entry_round_trip() {
        let entry = ProxyEntry {
            name: "grafana".to_string(),
            listen_port: 443,
            backend: "http://localhost:3000".to_string(),
            allow_remote: false,
        };
        let proxy = ProxySection {
            entries: vec![entry.clone()],
        };
        let value = toml::Value::try_from(proxy).unwrap();
        let decoded: ProxySection = value.try_into().unwrap();
        assert_eq!(decoded.entries[0], entry);
    }
}
