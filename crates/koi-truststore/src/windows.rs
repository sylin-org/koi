//! Windows trust store integration via `certutil`.

use std::process::Command;

use super::TrustStoreError;

pub fn install(cert_pem: &str, name: &str) -> Result<(), TrustStoreError> {
    let temp_dir = std::env::temp_dir();
    let cert_path = temp_dir.join(format!("{name}.crt"));

    std::fs::write(&cert_path, cert_pem)?;

    let output = Command::new("certutil")
        .args(["-addstore", "Root", &cert_path.to_string_lossy()])
        .output()?;

    // Clean up temp file regardless of result
    let _ = std::fs::remove_file(&cert_path);

    if output.status.success() {
        tracing::info!(name, "Root CA installed in Windows certificate store");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(name, stderr = %stderr, "certutil -addstore failed");
        Err(TrustStoreError::CommandFailed(format!(
            "certutil exit code {}: {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        )))
    }
}

pub fn is_installed(name: &str) -> bool {
    // Use certutil -verifystore to check if the cert exists
    let output = Command::new("certutil")
        .args(["-verifystore", "Root", name])
        .output();

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}
