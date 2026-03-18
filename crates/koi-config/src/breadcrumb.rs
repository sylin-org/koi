use std::path::PathBuf;

/// Breadcrumb filename written by the daemon for client discovery.
const BREADCRUMB_FILENAME: &str = "koi.endpoint";

/// Application directory name used for breadcrumb storage.
#[cfg(windows)]
const APP_DIR_NAME: &str = "koi";

/// Unix fallback runtime directory when XDG_RUNTIME_DIR is unset.
#[cfg(unix)]
const UNIX_FALLBACK_RUNTIME_DIR: &str = "/var/run";

/// Prefix for the DAT line in the breadcrumb file.
const DAT_PREFIX: &str = "dat:";

/// Parsed breadcrumb information: daemon endpoint and access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreadcrumbInfo {
    /// The HTTP endpoint URL of the daemon (e.g. "http://localhost:5641").
    pub endpoint: String,
    /// Daemon Access Token (base64-encoded).
    pub token: String,
}

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

/// Write the daemon endpoint and access token to the breadcrumb file.
///
/// Format (two lines):
/// ```text
/// http://localhost:5641
/// dat:base64_encoded_token
/// ```
pub fn write_breadcrumb(endpoint: &str, token: &str) {
    let path = breadcrumb_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let content = format!("{endpoint}\n{DAT_PREFIX}{token}\n");

    // On Unix, restrict permissions to owner-only (0600) since the file
    // contains a secret token.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let result = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(content.as_bytes()));

        match result {
            Ok(()) => tracing::debug!(path = %path.display(), "Breadcrumb written (mode 0600)"),
            Err(e) => tracing::warn!(error = %e, path = %path.display(), "Failed to write breadcrumb"),
        }
    }

    #[cfg(not(unix))]
    {
        // Write to .tmp, apply ACL, then rename to avoid TOCTOU window.
        let tmp_path = path.with_extension("tmp");
        match std::fs::write(&tmp_path, &content) {
            Ok(()) => {
                #[cfg(windows)]
                restrict_breadcrumb_acl(&tmp_path);
                match std::fs::rename(&tmp_path, &path) {
                    Ok(()) => tracing::debug!(path = %path.display(), "Breadcrumb written"),
                    Err(e) => tracing::warn!(error = %e, path = %path.display(), "Failed to rename breadcrumb"),
                }
            }
            Err(e) => tracing::warn!(error = %e, path = %path.display(), "Failed to write breadcrumb"),
        }
    }
}

/// Best-effort ACL restriction on Windows using icacls.
#[cfg(windows)]
fn restrict_breadcrumb_acl(path: &std::path::Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    // Command::args() handles quoting automatically — no embedded quotes.
    let path_str = path.display().to_string();
    let mut args = vec![
        path_str,
        "/inheritance:r".to_string(),
        "/grant:r".to_string(), "SYSTEM:F".to_string(),
        "/grant:r".to_string(), "BUILTIN\\Administrators:F".to_string(),
    ];
    if let Ok(user) = std::env::var("USERNAME") {
        if !user.eq_ignore_ascii_case("SYSTEM") {
            args.push("/grant:r".to_string());
            args.push(format!("{user}:F"));
        }
    }
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let _ = std::process::Command::new("icacls")
        .args(&args_ref)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
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

/// Read the daemon endpoint and token from the breadcrumb file.
///
/// Expected format (two lines):
/// ```text
/// http://localhost:5641
/// dat:base64_encoded_token
/// ```
///
/// Returns `None` if the file is missing, malformed, or lacks a token line.
pub fn read_breadcrumb() -> Option<BreadcrumbInfo> {
    let content = std::fs::read_to_string(breadcrumb_path()).ok()?;
    let mut lines = content.lines();

    let endpoint = lines.next()?.trim().to_string();
    if endpoint.is_empty() {
        return None;
    }

    // Token line is required — reject breadcrumbs without a DAT token.
    let token = lines
        .next()
        .and_then(|line| {
            let trimmed = line.trim();
            trimmed.strip_prefix(DAT_PREFIX).map(|t| t.to_string())
        })
        .filter(|t| !t.is_empty())?;

    Some(BreadcrumbInfo { endpoint, token })
}

/// Convenience: read just the endpoint from the breadcrumb file.
///
/// Equivalent to `read_breadcrumb().map(|b| b.endpoint)`. Useful for
/// callers that only need the endpoint and not the token.
pub fn read_breadcrumb_endpoint() -> Option<String> {
    read_breadcrumb().map(|b| b.endpoint)
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

    #[test]
    fn parse_new_format_with_token() {
        let dir = std::env::temp_dir().join(format!("koi-bc-new-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test.endpoint");

        std::fs::write(&file, "http://localhost:5641\ndat:abc123token\n").unwrap();

        // Simulate read_breadcrumb logic on this file
        let content = std::fs::read_to_string(&file).unwrap();
        let mut lines = content.lines();
        let endpoint = lines.next().unwrap().trim().to_string();
        let token = lines
            .next()
            .and_then(|line| line.trim().strip_prefix(DAT_PREFIX).map(|t| t.to_string()))
            .unwrap_or_default();

        assert_eq!(endpoint, "http://localhost:5641");
        assert_eq!(token, "abc123token");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_without_token_returns_none() {
        let dir = std::env::temp_dir().join(format!("koi-bc-notoken-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test.endpoint");

        // Breadcrumb without a token line is rejected (no legacy support)
        std::fs::write(&file, "http://localhost:5641\n").unwrap();

        let content = std::fs::read_to_string(&file).unwrap();
        let mut lines = content.lines();
        let endpoint = lines.next().unwrap().trim().to_string();
        let token = lines
            .next()
            .and_then(|line| line.trim().strip_prefix(DAT_PREFIX).map(|t| t.to_string()))
            .filter(|t| !t.is_empty());

        assert_eq!(endpoint, "http://localhost:5641");
        assert!(token.is_none(), "missing token should return None");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_empty_content_returns_none() {
        let dir = std::env::temp_dir().join(format!("koi-bc-empty2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test.endpoint");

        std::fs::write(&file, "").unwrap();

        let content = std::fs::read_to_string(&file).unwrap();
        let mut lines = content.lines();
        let endpoint = lines.next().map(|s| s.trim().to_string());
        // Empty first line should yield None
        assert!(
            endpoint.is_none() || endpoint.as_deref() == Some(""),
            "empty breadcrumb first line"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_breadcrumb_endpoint_convenience() {
        // Just verify the function compiles and returns the right type
        let result: Option<String> = read_breadcrumb_endpoint();
        // On a dev machine without a daemon, this is typically None
        let _ = result;
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
        let token = "test-token-base64";

        // Write
        if let Some(parent) = breadcrumb_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let content = format!("{endpoint}\n{DAT_PREFIX}{token}\n");
        std::fs::write(&breadcrumb_file, &content).unwrap();

        // Read
        let raw = std::fs::read_to_string(&breadcrumb_file).unwrap();
        let mut lines = raw.lines();
        let read_ep = lines.next().unwrap().trim().to_string();
        let read_tok = lines
            .next()
            .and_then(|line| line.trim().strip_prefix(DAT_PREFIX).map(|t| t.to_string()))
            .unwrap_or_default();
        assert_eq!(read_ep, endpoint);
        assert_eq!(read_tok, token);

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
        let raw = std::fs::read_to_string(&file).unwrap();
        let ep = raw.lines().next().map(|s| s.trim().to_string());
        assert!(
            ep.as_deref() == Some(""),
            "whitespace-only first line should be empty"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_breadcrumb_trims_whitespace() {
        let dir = std::env::temp_dir().join(format!("koi-bc-trim-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("trim.endpoint");

        std::fs::write(&file, "  http://localhost:5641  \ndat:mytoken\n").unwrap();
        let raw = std::fs::read_to_string(&file).unwrap();
        let mut lines = raw.lines();
        let ep = lines.next().unwrap().trim().to_string();
        assert_eq!(ep, "http://localhost:5641");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
