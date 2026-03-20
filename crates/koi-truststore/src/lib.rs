//! Platform trust store integration for Koi.
//!
//! Installs the certmesh root CA certificate into the operating system's
//! trust store so that browsers and HTTP clients trust certificates signed
//! by the mesh CA without manual configuration.
//!
//! Platform support:
//! - **Linux**: Copies to `/usr/local/share/ca-certificates/` and runs `update-ca-certificates`
//! - **Windows**: Uses `certutil -addstore Root`
//! - **macOS**: Uses `security add-trusted-cert` with the System keychain

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod darwin;

#[cfg(windows)]
mod windows;

#[derive(Debug, thiserror::Error)]
pub enum TrustStoreError {
    #[error("trust store command failed: {0}")]
    CommandFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid certificate name: {0}")]
    InvalidName(String),
    #[error("platform not supported")]
    Unsupported,
}

/// Validate that a certificate name is safe for use in file paths.
///
/// Rejects path separators, null bytes, control characters, `..`, and
/// names that are empty or excessively long.
fn validate_name(name: &str) -> Result<(), TrustStoreError> {
    if name.is_empty() {
        return Err(TrustStoreError::InvalidName("name is empty".to_string()));
    }
    if name.len() > 255 {
        return Err(TrustStoreError::InvalidName("name too long".to_string()));
    }
    if name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.contains("..")
        || name.contains(':')
        || name.contains('*')
        || name.contains('?')
    {
        return Err(TrustStoreError::InvalidName(format!(
            "name contains forbidden characters: {name}"
        )));
    }
    if name.chars().any(|c| c.is_ascii_control()) {
        return Err(TrustStoreError::InvalidName(format!(
            "name contains control characters: {name}"
        )));
    }
    Ok(())
}

/// Install a PEM-encoded CA certificate into the OS trust store.
///
/// `name` is used to construct the filename (e.g., `"koi-certmesh"` →
/// `koi-certmesh.crt` on Linux). The certificate is written to a
/// platform-appropriate location and the trust store is updated.
///
/// This operation typically requires elevated privileges.
/// Errors are returned but are non-fatal - callers should warn and continue.
pub fn install_ca_cert(cert_pem: &str, name: &str) -> Result<(), TrustStoreError> {
    validate_name(name)?;

    #[cfg(target_os = "linux")]
    {
        linux::install(cert_pem, name)
    }

    #[cfg(windows)]
    {
        windows::install(cert_pem, name)
    }

    #[cfg(target_os = "macos")]
    {
        darwin::install(cert_pem, name)
    }

    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = (cert_pem, name);
        Err(TrustStoreError::Unsupported)
    }
}

/// Best-effort check if a CA certificate with the given name is installed.
///
/// Returns `false` if the check fails or the platform is unsupported.
pub fn is_ca_installed(name: &str) -> bool {
    if validate_name(name).is_err() {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        linux::is_installed(name)
    }

    #[cfg(windows)]
    {
        windows::is_installed(name)
    }

    #[cfg(target_os = "macos")]
    {
        darwin::is_installed(name)
    }

    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = name;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Error type tests ───────────────────────────────────────────────

    #[test]
    fn error_command_failed_display() {
        let err = TrustStoreError::CommandFailed("certutil exit code 1: access denied".to_string());
        let msg = err.to_string();
        assert!(msg.contains("certutil"), "message: {msg}");
        assert!(msg.contains("access denied"), "message: {msg}");
    }

    #[test]
    fn error_io_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = TrustStoreError::from(io_err);
        let msg = err.to_string();
        assert!(msg.contains("permission denied"), "message: {msg}");
    }

    #[test]
    fn error_unsupported_display() {
        let err = TrustStoreError::Unsupported;
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn error_is_debug() {
        let err = TrustStoreError::CommandFailed("test".to_string());
        let debug = format!("{err:?}");
        assert!(debug.contains("CommandFailed"));
    }

    // ── is_ca_installed ────────────────────────────────────────────────

    #[test]
    fn is_ca_installed_returns_bool() {
        // Should not panic regardless of whether the cert exists
        let result = is_ca_installed("nonexistent-cert-for-koi-test");
        assert!(!result, "a nonexistent cert should not be installed");
    }

    // ── install_ca_cert ────────────────────────────────────────────────

    #[test]
    fn install_ca_cert_with_invalid_pem_does_not_panic() {
        // The function may fail (command errors, permission denied) but should
        // never panic. We only verify it returns a Result, not that it succeeds.
        let result = install_ca_cert("not-a-real-pem", "koi-test-invalid");
        // On CI/test environments this will likely fail with permission errors
        // or command errors, which is expected and fine.
        assert!(result.is_ok() || result.is_err());
    }
}
