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
