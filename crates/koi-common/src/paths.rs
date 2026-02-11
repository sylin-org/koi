use std::path::PathBuf;

/// Root data directory for Koi.
///
/// All Koi data is machine-local (CA keys, roster, certs, logs, state).
/// None of it should roam across machines via AD roaming profiles.
///
/// - Linux: `~/.koi/`
/// - macOS: `~/Library/Application Support/koi/`
/// - Windows: `%LOCALAPPDATA%\koi\`
pub fn koi_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("koi");
        }
    }

    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("koi");
        }
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".koi");
        }
    }

    // Fallback
    PathBuf::from(".koi")
}

/// Runtime state directory.
pub fn koi_state_dir() -> PathBuf {
    koi_data_dir().join("state")
}

/// Log directory.
pub fn koi_log_dir() -> PathBuf {
    koi_data_dir().join("logs")
}

/// Certificate directory (used by certmesh).
pub fn koi_certs_dir() -> PathBuf {
    koi_data_dir().join("certs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_ends_with_koi() {
        let dir = koi_data_dir();
        assert!(
            dir.ends_with("koi") || dir.ends_with(".koi"),
            "data dir should end with 'koi' or '.koi': {dir:?}"
        );
    }

    #[test]
    fn data_dir_is_not_empty() {
        let dir = koi_data_dir();
        assert!(dir.components().count() > 0);
    }

    #[test]
    fn state_dir_is_child_of_data_dir() {
        let data = koi_data_dir();
        let state = koi_state_dir();
        assert!(state.starts_with(&data));
        assert!(state.ends_with("state"));
    }

    #[test]
    fn log_dir_is_child_of_data_dir() {
        let data = koi_data_dir();
        let logs = koi_log_dir();
        assert!(logs.starts_with(&data));
        assert!(logs.ends_with("logs"));
    }

    #[test]
    fn certs_dir_is_child_of_data_dir() {
        let data = koi_data_dir();
        let certs = koi_certs_dir();
        assert!(certs.starts_with(&data));
        assert!(certs.ends_with("certs"));
    }

    #[test]
    fn subdirs_are_distinct() {
        let state = koi_state_dir();
        let logs = koi_log_dir();
        let certs = koi_certs_dir();
        assert_ne!(state, logs);
        assert_ne!(state, certs);
        assert_ne!(logs, certs);
    }

    #[cfg(windows)]
    #[test]
    fn windows_uses_localappdata() {
        let dir = koi_data_dir();
        // On Windows, should be under LOCALAPPDATA (not APPDATA/roaming)
        let dir_str = dir.to_string_lossy().to_lowercase();
        assert!(
            dir_str.contains("local"),
            "Windows data dir should use LOCALAPPDATA: {dir:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_library_application_support() {
        let dir = koi_data_dir();
        let dir_str = dir.to_string_lossy();
        assert!(
            dir_str.contains("Library") && dir_str.contains("Application Support"),
            "macOS data dir should be in Library/Application Support: {dir:?}"
        );
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    #[test]
    fn linux_uses_dot_koi() {
        let dir = koi_data_dir();
        assert!(
            dir.ends_with(".koi"),
            "Linux data dir should end with .koi: {dir:?}"
        );
    }
}
