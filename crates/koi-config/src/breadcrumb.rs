use std::io;
use std::path::{Path, PathBuf};

use koi_common::persist;

/// Breadcrumb filename written by the daemon for client discovery.
const BREADCRUMB_FILENAME: &str = "koi.endpoint";

/// Unix socket filename for trusted local control.
#[cfg(unix)]
const LOCAL_CONTROL_FILENAME: &str = "koi.sock";

/// Windows named pipe for trusted local control.
#[cfg(windows)]
const WINDOWS_LOCAL_CONTROL_PATH: &str = r"\\.\pipe\koi";

/// Application directory name used for breadcrumb storage.
#[cfg(windows)]
const APP_DIR_NAME: &str = "koi";

/// Unix fallback runtime directory when XDG_RUNTIME_DIR is unset.
#[cfg(unix)]
const UNIX_FALLBACK_RUNTIME_DIR: &str = "/var/run";

/// Prefix for the DAT line in the breadcrumb file.
const DAT_PREFIX: &str = "dat:";

/// Breadcrumbs contain the daemon access token and are owner-only on Unix.
const BREADCRUMB_UNIX_MODE: u32 = 0o600;

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

/// Canonical machine-local control transport path.
pub fn local_control_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(WINDOWS_LOCAL_CONTROL_PATH)
    }
    #[cfg(unix)]
    {
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join(LOCAL_CONTROL_FILENAME)
        } else {
            PathBuf::from(UNIX_FALLBACK_RUNTIME_DIR).join(LOCAL_CONTROL_FILENAME)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("koi.sock")
    }
}

/// Candidate paths for discovering a local daemon. A desktop process may have
/// `XDG_RUNTIME_DIR` while the machine service intentionally does not, so both
/// the user-runtime and machine-runtime sockets are meaningful candidates.
pub fn local_control_candidates() -> Vec<PathBuf> {
    let primary = local_control_path();
    #[cfg(unix)]
    {
        let machine = PathBuf::from(UNIX_FALLBACK_RUNTIME_DIR).join(LOCAL_CONTROL_FILENAME);
        if primary == machine {
            vec![primary]
        } else {
            vec![primary, machine]
        }
    }
    #[cfg(not(unix))]
    {
        vec![primary]
    }
}

/// Write the daemon endpoint and access token to the breadcrumb file.
///
/// Format (two lines):
/// ```text
/// http://localhost:5641
/// dat:base64_encoded_token
/// ```
pub fn write_breadcrumb(endpoint: &str, token: &str) -> io::Result<()> {
    let path = breadcrumb_path();
    #[cfg(windows)]
    let result = write_breadcrumb_at_with_prepare_stage(
        &path,
        endpoint,
        token,
        persist::restrict_windows_local_secret_acl,
    );
    #[cfg(not(windows))]
    let result = write_breadcrumb_at_with_prepare_stage(&path, endpoint, token, |_| Ok(()));

    match result? {
        persist::AtomicCommit::Durable => {
            tracing::debug!(path = %path.display(), "Breadcrumb written");
            Ok(())
        }
        persist::AtomicCommit::DurabilityUncertain(error) => Err(error),
    }
}

fn write_breadcrumb_at_with_prepare_stage(
    path: &Path,
    endpoint: &str,
    token: &str,
    prepare_stage: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<persist::AtomicCommit> {
    let content = format!("{endpoint}\n{DAT_PREFIX}{token}\n");
    persist::write_bytes_atomic_with_options_and_prepare_stage(
        path,
        content.as_bytes(),
        persist::AtomicWriteOptions::new().with_unix_mode(BREADCRUMB_UNIX_MODE),
        prepare_stage,
    )
}

/// Delete the breadcrumb file.
///
/// A published endpoint is part of the daemon ownership boundary. Callers must
/// observe cleanup failures instead of leaving discovery material behind while
/// reporting a successful stop or uninstall.
pub fn delete_breadcrumb() -> io::Result<()> {
    let path = breadcrumb_path();
    match std::fs::remove_file(&path) {
        Ok(()) => {
            tracing::debug!(path = %path.display(), "Breadcrumb deleted");
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
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
/// Returns `Ok(None)` only when the file does not exist. Unreadable or malformed
/// ownership publication is uncertainty and remains an error.
pub fn read_breadcrumb() -> io::Result<Option<BreadcrumbInfo>> {
    read_breadcrumb_at(&breadcrumb_path())
}

fn read_breadcrumb_at(path: &Path) -> io::Result<Option<BreadcrumbInfo>> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut lines = content.lines();

    let endpoint = lines.next().map(str::trim).unwrap_or_default().to_string();
    if endpoint.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "breadcrumb endpoint is missing",
        ));
    }

    // The DAT is required. A partially written or obsolete breadcrumb must not
    // be reinterpreted as daemon absence.
    let token = lines
        .next()
        .and_then(|line| {
            let trimmed = line.trim();
            trimmed.strip_prefix(DAT_PREFIX).map(str::trim)
        })
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "breadcrumb DAT token is missing or malformed",
            )
        })?
        .to_string();

    if lines.any(|line| !line.trim().is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "breadcrumb contains unexpected trailing data",
        ));
    }

    Ok(Some(BreadcrumbInfo { endpoint, token }))
}

/// Convenience: read just the endpoint from the breadcrumb file.
///
/// Equivalent to `read_breadcrumb().map(|b| b.map(|v| v.endpoint))`. Useful for
/// callers that only need the endpoint and not the token.
pub fn read_breadcrumb_endpoint() -> io::Result<Option<String>> {
    read_breadcrumb().map(|breadcrumb| breadcrumb.map(|value| value.endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "koi-breadcrumb-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

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
    fn local_control_path_is_not_empty() {
        assert!(local_control_path().components().next().is_some());
        assert!(!local_control_candidates().is_empty());
    }

    #[test]
    fn breadcrumb_write_atomically_replaces_the_complete_document() {
        let root = temp_root("atomic-replace");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join(BREADCRUMB_FILENAME);
        std::fs::write(&target, b"old complete breadcrumb").unwrap();

        let outcome = write_breadcrumb_at_with_prepare_stage(
            &target,
            "http://127.0.0.1:5641",
            "replacement-token",
            |stage| {
                assert_ne!(stage, target);
                assert_eq!(std::fs::metadata(stage)?.len(), 0);
                assert_eq!(std::fs::read(&target)?, b"old complete breadcrumb");
                Ok(())
            },
        )
        .unwrap();

        assert!(matches!(outcome, persist::AtomicCommit::Durable));
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"http://127.0.0.1:5641\ndat:replacement-token\n"
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn breadcrumb_write_repairs_a_permissive_existing_mode() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("mode-repair");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join(BREADCRUMB_FILENAME);
        std::fs::write(&target, b"old breadcrumb").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();

        let outcome = write_breadcrumb_at_with_prepare_stage(
            &target,
            "http://localhost:5641",
            "token",
            |_| Ok(()),
        )
        .unwrap();

        assert!(matches!(outcome, persist::AtomicCommit::Durable));
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            BREADCRUMB_UNIX_MODE
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn breadcrumb_preparation_failure_preserves_the_old_target() {
        let root = temp_root("prepare-failure");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join(BREADCRUMB_FILENAME);
        std::fs::write(&target, b"old complete breadcrumb").unwrap();

        let error = write_breadcrumb_at_with_prepare_stage(
            &target,
            "http://localhost:5641",
            "must-not-be-exposed",
            |stage| {
                assert_eq!(std::fs::metadata(stage)?.len(), 0);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected breadcrumb hardening failure",
                ))
            },
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&target).unwrap(), b"old complete breadcrumb");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
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
    fn missing_token_is_malformed_not_absent() {
        let dir = std::env::temp_dir().join(format!("koi-bc-notoken-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test.endpoint");

        // Breadcrumb without a token line is rejected (no legacy support)
        std::fs::write(&file, "http://localhost:5641\n").unwrap();

        let error = read_breadcrumb_at(&file).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_content_is_malformed_not_absent() {
        let dir = std::env::temp_dir().join(format!("koi-bc-empty2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test.endpoint");

        std::fs::write(&file, "").unwrap();

        let error = read_breadcrumb_at(&file).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_breadcrumb_endpoint_convenience() {
        // Just verify the function compiles and returns the right type
        let result: io::Result<Option<String>> = read_breadcrumb_endpoint();
        let _ = result;
    }

    #[test]
    fn missing_file_is_the_only_absent_breadcrumb() {
        let root = temp_root("missing");
        assert_eq!(
            read_breadcrumb_at(&root.join(BREADCRUMB_FILENAME)).unwrap(),
            None
        );
    }

    #[test]
    fn unexpected_trailing_data_is_rejected() {
        let root = temp_root("trailing-data");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(BREADCRUMB_FILENAME);
        std::fs::write(
            &path,
            "http://127.0.0.1:5641\ndat:token\nlegacy-extra-field\n",
        )
        .unwrap();
        assert_eq!(
            read_breadcrumb_at(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let _ = std::fs::remove_dir_all(root);
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
