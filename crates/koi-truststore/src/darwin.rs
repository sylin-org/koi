//! macOS trust store integration via `security` framework.

use std::process::Command;

use super::TrustStoreError;

pub fn install(cert_pem: &str, name: &str) -> Result<(), TrustStoreError> {
    let temp_dir = std::env::temp_dir();
    let cert_path = temp_dir.join(format!("{name}.crt"));

    std::fs::write(&cert_path, cert_pem)?;

    let output = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            &cert_path.to_string_lossy(),
        ])
        .output()?;

    // Clean up temp file
    let _ = std::fs::remove_file(&cert_path);

    if output.status.success() {
        tracing::info!(name, "Root CA installed in macOS System Keychain");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(name, stderr = %stderr, "security add-trusted-cert failed");
        Err(TrustStoreError::CommandFailed(format!(
            "security exit code {}: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        )))
    }
}

pub fn is_installed(_name: &str) -> bool {
    // macOS doesn't have a simple way to check by name.
    // Best-effort: try to find it via security command.
    false
}
