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
