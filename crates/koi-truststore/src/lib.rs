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
    #[error("platform not supported")]
    Unsupported,
}

/// Install a PEM-encoded CA certificate into the OS trust store.
///
/// `name` is used to construct the filename (e.g., `"koi-certmesh"` →
/// `koi-certmesh.crt` on Linux). The certificate is written to a
/// platform-appropriate location and the trust store is updated.
///
/// This operation typically requires elevated privileges.
/// Errors are returned but are non-fatal — callers should warn and continue.
pub fn install_ca_cert(cert_pem: &str, name: &str) -> Result<(), TrustStoreError> {
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
