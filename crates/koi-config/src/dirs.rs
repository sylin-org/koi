//! Koi data directory initialization.
//!
//! Ensures the `~/.koi/` directory structure exists and contains a
//! default `config.toml` if not already present. Called once during
//! daemon startup.

use koi_common::paths;

/// Default content for a freshly created config.toml.
const DEFAULT_CONFIG_TOML: &str = "\
# Koi configuration
# See https://github.com/sylin-org/koi for documentation.

# [mdns]
# port = 5641
";

/// Ensure the Koi data directory structure exists.
///
/// Creates:
/// - `~/.koi/` (or platform equivalent)
/// - `~/.koi/config.toml` (if not already present)
/// - `~/.koi/certs/`
/// - `~/.koi/state/`
/// - `~/.koi/logs/`
///
/// Errors are logged but not fatal - the daemon can run without
/// a data directory.
pub fn ensure_data_dir() {
    let data_dir = paths::koi_data_dir();

    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        tracing::warn!(
            path = %data_dir.display(),
            error = %e,
            "Could not create data directory"
        );
        return;
    }

    // Subdirectories
    for subdir in &["certs", "state", "logs"] {
        let path = data_dir.join(subdir);
        if let Err(e) = std::fs::create_dir_all(&path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Could not create subdirectory"
            );
        }
    }

    // Default config.toml (only if absent)
    let config_path = data_dir.join("config.toml");
    if !config_path.exists() {
        match std::fs::write(&config_path, DEFAULT_CONFIG_TOML) {
            Ok(()) => tracing::debug!(path = %config_path.display(), "Created default config"),
            Err(e) => tracing::warn!(
                path = %config_path.display(),
                error = %e,
                "Could not write default config"
            ),
        }
    }

    tracing::debug!(path = %data_dir.display(), "Data directory ready");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_toml() {
        let parsed: Result<toml::Value, _> = DEFAULT_CONFIG_TOML.parse();
        assert!(parsed.is_ok(), "Default config.toml should be valid TOML");
    }
}
