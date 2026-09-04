use serde::{Deserialize, Serialize};

use crate::ProxyError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct ProxyEntry {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    #[serde(default)]
    pub allow_remote: bool,
}

/// The proxy-owned section of Koi's shared `config.toml` substrate.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default)]
    pub entries: Vec<ProxyEntry>,
}

pub(crate) fn load_entries(path: &std::path::Path) -> Result<Vec<ProxyEntry>, ProxyError> {
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
    let proxy: ProxyConfig = proxy
        .try_into()
        .map_err(|e| ProxyError::Config(format!("Invalid proxy section: {e}")))?;
    Ok(proxy.entries)
}

pub(crate) fn save_entries(
    entries: &[ProxyEntry],
    path: &std::path::Path,
) -> Result<(), ProxyError> {
    save_entries_to_with(entries, path, koi_common::persist::write_bytes_atomic)
}

fn save_entries_to_with(
    entries: &[ProxyEntry],
    path: &std::path::Path,
    write: impl FnOnce(&std::path::Path, &[u8]) -> std::io::Result<koi_common::persist::AtomicCommit>,
) -> Result<(), ProxyError> {
    let mut root = if path.exists() {
        let raw = std::fs::read_to_string(path).map_err(|e| ProxyError::Io(e.to_string()))?;
        raw.parse::<toml::Value>()
            .map_err(|e| ProxyError::Config(format!("Invalid config.toml: {e}")))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    let proxy = ProxyConfig {
        entries: entries.to_vec(),
    };
    let proxy_value = toml::Value::try_from(proxy)
        .map_err(|e| ProxyError::Config(format!("Proxy config serialize error: {e}")))?;

    if let toml::Value::Table(table) = &mut root {
        table.insert("proxy".to_string(), proxy_value);
    }

    let raw = toml::to_string_pretty(&root)
        .map_err(|e| ProxyError::Config(format!("Config serialize error: {e}")))?;

    match write(path, raw.as_bytes()).map_err(|error| ProxyError::Io(error.to_string()))? {
        koi_common::persist::AtomicCommit::Durable => {}
        koi_common::persist::AtomicCommit::DurabilityUncertain(error) => {
            // Replacement is already visible. Returning an error would leave
            // Proxy's accepted model/status behind the config this process and
            // an ordinary restart now read, so accept it and make the weaker
            // crash-survival guarantee operationally loud.
            tracing::error!(
                path = %path.display(),
                %error,
                "Proxy config is visible, but its crash durability could not be confirmed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_entry_round_trip() {
        let entry = ProxyEntry {
            name: "grafana".to_string(),
            listen_port: 443,
            backend: "http://localhost:3000".to_string(),
            allow_remote: false,
        };
        let proxy = ProxyConfig {
            entries: vec![entry.clone()],
        };
        let value = toml::Value::try_from(proxy).unwrap();
        let decoded: ProxyConfig = value.try_into().unwrap();
        assert_eq!(decoded.entries[0], entry);
    }

    #[test]
    fn save_refuses_to_replace_a_malformed_shared_config() {
        let dir = std::env::temp_dir().join(format!(
            "koi-proxy-config-corrupt-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let malformed = "[unclosed\nvalue = true";
        std::fs::write(&path, malformed).unwrap();

        let result = save_entries(&[], &path);
        assert!(matches!(result, Err(ProxyError::Config(_))));
        assert_eq!(std::fs::read_to_string(path).unwrap(), malformed);
    }

    #[test]
    fn save_replaces_only_the_proxy_section() {
        let dir = std::env::temp_dir().join(format!(
            "koi-proxy-config-preserve-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let original = r#"
version = 1
dns_port = 5354

[unrelated]
owner = "operator"
enabled = true

[proxy]
entries = [
  { name = "old", listen_port = 7443, backend = "http://127.0.0.1:7000" },
]
"#;
        std::fs::write(&path, original).unwrap();
        let before = original.parse::<toml::Value>().unwrap();
        let replacement = ProxyEntry {
            name: "new".to_string(),
            listen_port: 8443,
            backend: "http://127.0.0.1:8000".to_string(),
            allow_remote: false,
        };

        save_entries(std::slice::from_ref(&replacement), &path).unwrap();

        let after = std::fs::read_to_string(&path)
            .unwrap()
            .parse::<toml::Value>()
            .unwrap();
        assert_eq!(after.get("version"), before.get("version"));
        assert_eq!(after.get("dns_port"), before.get("dns_port"));
        assert_eq!(after.get("unrelated"), before.get("unrelated"));
        assert_eq!(load_entries(&path).unwrap(), [replacement]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pre_replace_write_failure_preserves_the_previous_config() {
        let dir = std::env::temp_dir().join(format!(
            "koi-proxy-config-failure-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let original = "version = 1\n[proxy]\nentries = []\n";
        std::fs::write(&path, original).unwrap();
        let replacement = ProxyEntry {
            name: "rejected".to_string(),
            listen_port: 8443,
            backend: "http://127.0.0.1:8000".to_string(),
            allow_remote: false,
        };

        let result = save_entries_to_with(std::slice::from_ref(&replacement), &path, |_, _| {
            Err(std::io::Error::other("injected pre-replace failure"))
        });

        assert!(matches!(result, Err(ProxyError::Io(message)) if message.contains("injected")));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(load_entries(&path).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn visible_uncertain_commit_is_accepted_and_reload_observes_the_new_entries() {
        let dir = std::env::temp_dir().join(format!(
            "koi-proxy-config-uncertain-{}",
            koi_common::id::generate_short_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "version = 1\n[proxy]\nentries = []\n").unwrap();
        let replacement = ProxyEntry {
            name: "accepted".to_string(),
            listen_port: 8443,
            backend: "http://127.0.0.1:8000".to_string(),
            allow_remote: false,
        };

        save_entries_to_with(
            std::slice::from_ref(&replacement),
            &path,
            |target, bytes| {
                let outcome = koi_common::persist::write_bytes_atomic(target, bytes)?;
                Ok(match outcome {
                    koi_common::persist::AtomicCommit::Durable => {
                        koi_common::persist::AtomicCommit::DurabilityUncertain(
                            std::io::Error::other("injected post-replace sync failure"),
                        )
                    }
                    uncertain @ koi_common::persist::AtomicCommit::DurabilityUncertain(_) => {
                        uncertain
                    }
                })
            },
        )
        .expect("visible uncertain replacement is an accepted commit");

        assert_eq!(load_entries(&path).unwrap(), [replacement]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
