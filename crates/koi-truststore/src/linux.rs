//! Linux trust store integration via `update-ca-certificates`.

use std::path::Path;
use std::process::Command;

use super::TrustStoreError;

const CA_CERTS_DIR: &str = "/usr/local/share/ca-certificates";

pub fn install(cert_pem: &str, name: &str) -> Result<(), TrustStoreError> {
    let cert_path = Path::new(CA_CERTS_DIR).join(format!("{name}.crt"));

    std::fs::write(&cert_path, cert_pem)?;

    let output = Command::new("update-ca-certificates").output()?;

    if output.status.success() {
        tracing::info!(name, path = %cert_path.display(), "Root CA installed in system trust store");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(name, stderr = %stderr, "update-ca-certificates failed");
        Err(TrustStoreError::CommandFailed(format!(
            "update-ca-certificates exit code {}: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        )))
    }
}

pub fn is_installed(name: &str) -> bool {
    let cert_path = Path::new(CA_CERTS_DIR).join(format!("{name}.crt"));
    cert_path.exists()
}

pub fn remove(name: &str) -> Result<(), TrustStoreError> {
    let cert_path = Path::new(CA_CERTS_DIR).join(format!("{name}.crt"));

    // Removing the source file then re-running with --fresh regenerates the
    // bundle without our cert. Tolerate a missing file (already gone).
    match std::fs::remove_file(&cert_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(name, path = %cert_path.display(), "cert file already absent");
        }
        Err(e) => return Err(TrustStoreError::Io(e)),
    }

    let output = Command::new("update-ca-certificates")
        .arg("--fresh")
        .output()?;

    if output.status.success() {
        tracing::info!(name, "Root CA removed from system trust store");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(name, stderr = %stderr, "update-ca-certificates --fresh failed");
        Err(TrustStoreError::CommandFailed(format!(
            "update-ca-certificates --fresh exit code {}: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        )))
    }
}
