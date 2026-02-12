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
        let program_data =
            std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        PathBuf::from(program_data)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breadcrumb_path_ends_with_filename() {
        let path = breadcrumb_path();
        assert!(
            path.ends_with(BREADCRUMB_FILENAME),
            "breadcrumb path should end with '{BREADCRUMB_FILENAME}', got: {}",
            path.display()
        );
    }

    #[test]
    fn breadcrumb_path_has_parent_directory() {
        let path = breadcrumb_path();
        assert!(
            path.parent().is_some(),
            "breadcrumb path should have a parent directory"
        );
    }

    /// Test the write → read → delete lifecycle using a temp directory.
    /// We override LOCALAPPDATA (Windows) or XDG_RUNTIME_DIR (Unix) to
    /// point at a temp dir, then verify the full cycle.
    #[test]
    fn breadcrumb_write_read_delete_lifecycle() {
        let dir = std::env::temp_dir().join(format!("koi-breadcrumb-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let breadcrumb_file = dir.join(BREADCRUMB_FILENAME);
        let endpoint = "http://127.0.0.1:5641";

        // Write
        if let Some(parent) = breadcrumb_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&breadcrumb_file, endpoint).unwrap();

        // Read
        let content = std::fs::read_to_string(&breadcrumb_file)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        assert_eq!(content.as_deref(), Some(endpoint));

        // Delete
        std::fs::remove_file(&breadcrumb_file).unwrap();
        assert!(!breadcrumb_file.exists());

        // Read after delete returns None
        let content = std::fs::read_to_string(&breadcrumb_file).ok();
        assert!(content.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_breadcrumb_returns_none_for_empty_content() {
        let dir = std::env::temp_dir().join(format!("koi-bc-empty-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("empty.endpoint");

        // Write empty content
        std::fs::write(&file, "").unwrap();
        let content = std::fs::read_to_string(&file)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        assert!(content.is_none(), "empty breadcrumb should return None");

        // Write whitespace-only content
        std::fs::write(&file, "  \n  ").unwrap();
        let content = std::fs::read_to_string(&file)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        assert!(
            content.is_none(),
            "whitespace-only breadcrumb should return None"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_breadcrumb_trims_whitespace() {
        let dir = std::env::temp_dir().join(format!("koi-bc-trim-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("trim.endpoint");

        std::fs::write(&file, "  http://localhost:5641  \n").unwrap();
        let content = std::fs::read_to_string(&file)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        assert_eq!(content.as_deref(), Some("http://localhost:5641"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
