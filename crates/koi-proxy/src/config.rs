use serde::{Deserialize, Serialize};

use koi_common::integration::CertmeshSnapshot;
use koi_common::paths;

use crate::ProxyError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
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

pub fn config_path_with_override(data_dir: Option<&std::path::Path>) -> std::path::PathBuf {
    paths::koi_data_dir_with_override(data_dir).join("config.toml")
}

pub fn load_entries() -> Result<Vec<ProxyEntry>, ProxyError> {
    load_entries_from(&config_path())
}

pub fn load_entries_with_data_dir(
    data_dir: Option<&std::path::Path>,
) -> Result<Vec<ProxyEntry>, ProxyError> {
    load_entries_from(&config_path_with_override(data_dir))
}

/// Load entries from config file and merge with roster entries from certmesh.
pub fn load_entries_with_certmesh(
    certmesh: Option<&dyn CertmeshSnapshot>,
) -> Result<Vec<ProxyEntry>, ProxyError> {
    let mut entries = load_entries_from(&config_path())?;

    if let Some(cm) = certmesh {
        let hostname = hostname::get()
            .map_err(|e| ProxyError::Io(e.to_string()))?
            .to_string_lossy()
            .to_string();

        let members = cm.active_members();
        if let Some(member) = members.iter().find(|m| m.hostname == hostname) {
            let roster_entries: Vec<ProxyEntry> = member
                .proxy_entries
                .iter()
                .map(|entry| ProxyEntry {
                    name: entry.name.clone(),
                    listen_port: entry.listen_port,
                    backend: entry.backend.clone(),
                    allow_remote: entry.allow_remote,
                })
                .collect();
            merge_entries(&mut entries, roster_entries);
        }
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn load_entries_from(path: &std::path::Path) -> Result<Vec<ProxyEntry>, ProxyError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| ProxyError::Io(e.to_string()))?;
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

pub fn save_entries(entries: &[ProxyEntry]) -> Result<(), ProxyError> {
    save_entries_to(entries, &config_path())
}

fn save_entries_to(
    entries: &[ProxyEntry],
    path: &std::path::Path,
) -> Result<(), ProxyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ProxyError::Io(e.to_string()))?;
    }

    let mut root = if path.exists() {
        let raw = std::fs::read_to_string(path).map_err(|e| ProxyError::Io(e.to_string()))?;
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
    std::fs::write(path, raw).map_err(|e| ProxyError::Io(e.to_string()))?;
    Ok(())
}

pub fn upsert_entry(entry: ProxyEntry) -> Result<Vec<ProxyEntry>, ProxyError> {
    upsert_entry_with_data_dir(entry, None)
}

pub fn upsert_entry_with_data_dir(
    entry: ProxyEntry,
    data_dir: Option<&std::path::Path>,
) -> Result<Vec<ProxyEntry>, ProxyError> {
    let path = config_path_with_override(data_dir);
    let mut entries = load_entries_from(&path)?;
    if let Some(existing) = entries.iter_mut().find(|e| e.name == entry.name) {
        *existing = entry;
    } else {
        entries.push(entry);
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    save_entries_to(&entries, &path)?;
    Ok(entries)
}

pub fn remove_entry(name: &str) -> Result<Vec<ProxyEntry>, ProxyError> {
    remove_entry_with_data_dir(name, None)
}

pub fn remove_entry_with_data_dir(
    name: &str,
    data_dir: Option<&std::path::Path>,
) -> Result<Vec<ProxyEntry>, ProxyError> {
    let path = config_path_with_override(data_dir);
    let mut entries = load_entries_from(&path)?;
    let before = entries.len();
    entries.retain(|e| e.name != name);
    if entries.len() == before {
        return Err(ProxyError::NotFound(name.to_string()));
    }
    save_entries_to(&entries, &path)?;
    Ok(entries)
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
