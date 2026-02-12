use std::path::PathBuf;

/// Root data directory for Koi.
///
/// All Koi data is machine-scoped (CA keys, roster, certs, logs, state).
/// The user never owns the data — certificates belong to the machine.
///
/// - Linux: `/var/lib/koi/`
/// - macOS: `/Library/Application Support/koi/`
/// - Windows: `%ProgramData%\koi\`
///
/// Override with `KOI_DATA_DIR` env var (for testing).
pub fn koi_data_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("KOI_DATA_DIR") {
        return PathBuf::from(override_dir);
    }

    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/koi")
    }

    #[cfg(windows)]
    {
        let program_data =
            std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(program_data).join("koi")
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    {
        PathBuf::from("/var/lib/koi")
    }
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
    use std::sync::Mutex;

    /// Tests that call `koi_data_dir()` must hold this lock because
    /// `koi_data_dir_env_override` mutates the `KOI_DATA_DIR` env var
    /// and parallel tests would see inconsistent values.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn data_dir_ends_with_koi() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = koi_data_dir();
        assert!(
            dir.ends_with("koi"),
            "data dir should end with 'koi': {dir:?}"
        );
    }

    #[test]
    fn data_dir_is_not_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = koi_data_dir();
        assert!(dir.components().count() > 0);
    }

    #[test]
    fn state_dir_is_child_of_data_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        let data = koi_data_dir();
        let state = koi_state_dir();
        assert!(state.starts_with(&data));
        assert!(state.ends_with("state"));
    }

    #[test]
    fn log_dir_is_child_of_data_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        let data = koi_data_dir();
        let logs = koi_log_dir();
        assert!(logs.starts_with(&data));
        assert!(logs.ends_with("logs"));
    }

    #[test]
    fn certs_dir_is_child_of_data_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        let data = koi_data_dir();
        let certs = koi_certs_dir();
        assert!(certs.starts_with(&data));
        assert!(certs.ends_with("certs"));
    }

    #[test]
    fn subdirs_are_distinct() {
        let _lock = ENV_LOCK.lock().unwrap();
        let state = koi_state_dir();
        let logs = koi_log_dir();
        let certs = koi_certs_dir();
        assert_ne!(state, logs);
        assert_ne!(state, certs);
        assert_ne!(logs, certs);
    }

    #[cfg(windows)]
    #[test]
    fn windows_uses_programdata() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = koi_data_dir();
        let dir_str = dir.to_string_lossy().to_lowercase();
        assert!(
            dir_str.contains("programdata"),
            "Windows data dir should use ProgramData: {dir:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_system_library() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = koi_data_dir();
        let dir_str = dir.to_string_lossy();
        assert!(
            dir_str.starts_with("/Library/Application Support"),
            "macOS data dir should be in /Library/Application Support: {dir:?}"
        );
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    #[test]
    fn linux_uses_var_lib() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = koi_data_dir();
        let dir_str = dir.to_string_lossy();
        assert!(
            dir_str.starts_with("/var/lib/koi"),
            "Linux data dir should be /var/lib/koi: {dir:?}"
        );
    }

    #[test]
    fn koi_data_dir_env_override() {
        let _lock = ENV_LOCK.lock().unwrap();

        // Save and set override
        let prev = std::env::var("KOI_DATA_DIR").ok();
        std::env::set_var("KOI_DATA_DIR", "/tmp/koi-test-override");
        let dir = koi_data_dir();
        assert_eq!(dir, PathBuf::from("/tmp/koi-test-override"));

        // Restore
        match prev {
            Some(v) => std::env::set_var("KOI_DATA_DIR", v),
            None => std::env::remove_var("KOI_DATA_DIR"),
        }
    }
}
