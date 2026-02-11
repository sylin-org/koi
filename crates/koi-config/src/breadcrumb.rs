use std::path::PathBuf;

/// Breadcrumb filename written by the daemon for client discovery.
const BREADCRUMB_FILENAME: &str = "koi.endpoint";

/// Application directory name used for breadcrumb storage.
#[cfg(windows)]
const APP_DIR_NAME: &str = "koi";

/// Unix fallback runtime directory when XDG_RUNTIME_DIR is unset.
#[cfg(unix)]
const UNIX_FALLBACK_RUNTIME_DIR: &str = "/var/run";

/// Path to the breadcrumb file that advertises the daemon's endpoint.
pub fn breadcrumb_path() -> PathBuf {
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(local)
            .join(APP_DIR_NAME)
            .join(BREADCRUMB_FILENAME)
    }
    #[cfg(unix)]
    {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join(BREADCRUMB_FILENAME)
        } else {
            PathBuf::from(UNIX_FALLBACK_RUNTIME_DIR).join(BREADCRUMB_FILENAME)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from(BREADCRUMB_FILENAME)
    }
}

/// Write the daemon endpoint to the breadcrumb file.
pub fn write_breadcrumb(endpoint: &str) {
    let path = breadcrumb_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&path, endpoint) {
        Ok(()) => tracing::debug!(path = %path.display(), "Breadcrumb written"),
        Err(e) => tracing::warn!(error = %e, path = %path.display(), "Failed to write breadcrumb"),
    }
}

/// Delete the breadcrumb file.
pub fn delete_breadcrumb() {
    let path = breadcrumb_path();
    match std::fs::remove_file(&path) {
        Ok(()) => tracing::debug!(path = %path.display(), "Breadcrumb deleted"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, path = %path.display(), "Failed to delete breadcrumb"),
    }
}

/// Read the daemon endpoint from the breadcrumb file.
pub fn read_breadcrumb() -> Option<String> {
    std::fs::read_to_string(breadcrumb_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
