use std::path::PathBuf;

/// Root data directory for Koi.
///
/// - Linux: `~/.koi/`
/// - macOS: `~/Library/Application Support/koi/`
/// - Windows: `%APPDATA%\koi\`
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
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("koi");
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
