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
    // Phase 2: migrate onto an injected data root like certmesh did.
    #[allow(clippy::disallowed_methods)]
    let data_dir = paths::koi_data_dir();

    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        tracing::warn!(
            path = %data_dir.display(),
            error = %e,
            "Could not create data directory"
        );
        return;
    }

    // Lock the data root down to the owner BEFORE creating children, so secrets
    // that lean on directory protection — the certmesh audit log, roster.json,
    // config.toml — are not readable by other local users (the HTTP layer gates
    // e.g. the audit log behind the token; the filesystem must not undercut it).
    restrict_dir_perms(&data_dir);

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

/// Restrict the data directory to its owner so other local users can't read the
/// secrets that rely on directory protection (audit log, roster, config).
///
/// Unix: `0700` on the root — non-owners can't traverse, so children are
/// protected regardless of their own mode. Windows: an inheriting (`(OI)(CI)`)
/// icacls ACL granting SYSTEM + Administrators + the owner, with inheritance
/// stripped, applied before children are created so they inherit it. Best-effort.
fn restrict_dir_perms(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(
                path = %dir.display(),
                error = %e,
                "Could not restrict data-directory permissions"
            );
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut args = vec![
            dir.display().to_string(),
            "/inheritance:r".to_string(),
            "/grant:r".to_string(),
            "SYSTEM:(OI)(CI)F".to_string(),
            "/grant:r".to_string(),
            "BUILTIN\\Administrators:(OI)(CI)F".to_string(),
        ];
        if let Ok(user) = std::env::var("USERNAME") {
            if !user.eq_ignore_ascii_case("SYSTEM") {
                args.push("/grant:r".to_string());
                args.push(format!("{user}:(OI)(CI)F"));
            }
        }
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let _ = std::process::Command::new("icacls")
            .args(&args_ref)
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    #[cfg(not(any(unix, windows)))]
    let _ = dir;
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
