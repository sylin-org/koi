//! Certificate file writing to the standard path.
//!
//! Writes cert/key/CA/fullchain files to `~/.koi/certs/<hostname>/`.
//! On Unix, `key.pem` is set to 0600 permissions.

use std::path::{Path, PathBuf};

use crate::ca::IssuedCert;

/// Write all certificate files for a host to the standard path.
///
/// Creates the directory `~/.koi/certs/<hostname>/` and writes:
/// - `cert.pem` — service certificate
/// - `key.pem` — service private key (0600 on Unix)
/// - `ca.pem` — root CA public certificate
/// - `fullchain.pem` — cert.pem + ca.pem concatenated
///
/// Returns the directory path where files were written.
pub fn write_cert_files(hostname: &str, issued: &IssuedCert) -> Result<PathBuf, std::io::Error> {
    let cert_dir = koi_common::paths::koi_certs_dir().join(hostname);
    write_cert_files_to(&cert_dir, issued)
}

/// Write certificate files to a specific directory (for testing).
pub fn write_cert_files_to(
    cert_dir: &Path,
    issued: &IssuedCert,
) -> Result<PathBuf, std::io::Error> {
    std::fs::create_dir_all(cert_dir)?;

    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");
    let ca_path = cert_dir.join("ca.pem");
    let fullchain_path = cert_dir.join("fullchain.pem");

    std::fs::write(&cert_path, &issued.cert_pem)?;
    std::fs::write(&key_path, &issued.key_pem)?;
    std::fs::write(&ca_path, &issued.ca_pem)?;
    std::fs::write(&fullchain_path, &issued.fullchain_pem)?;

    // Set restrictive permissions on key.pem (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!(
        path = %cert_dir.display(),
        "Certificate files written"
    );

    Ok(cert_dir.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::IssuedCert;
    use chrono::Utc;

    fn dummy_issued() -> IssuedCert {
        IssuedCert {
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n"
                .to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----\n"
                .to_string(),
            ca_pem: "-----BEGIN CERTIFICATE-----\ntest-ca\n-----END CERTIFICATE-----\n"
                .to_string(),
            fullchain_pem: "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\ntest-ca\n-----END CERTIFICATE-----\n"
                .to_string(),
            fingerprint: "abcdef1234567890".to_string(),
            expires: Utc::now(),
        }
    }

    #[test]
    fn writes_all_four_files() {
        let dir = std::env::temp_dir().join("koi-certmesh-test-certfiles");
        let _ = std::fs::remove_dir_all(&dir);

        let issued = dummy_issued();
        let result = write_cert_files_to(&dir, &issued).unwrap();

        assert_eq!(result, dir);
        assert!(dir.join("cert.pem").exists());
        assert!(dir.join("key.pem").exists());
        assert!(dir.join("ca.pem").exists());
        assert!(dir.join("fullchain.pem").exists());

        let cert = std::fs::read_to_string(dir.join("cert.pem")).unwrap();
        assert!(cert.contains("test-cert"));

        let fullchain = std::fs::read_to_string(dir.join("fullchain.pem")).unwrap();
        assert!(fullchain.contains("test-cert"));
        assert!(fullchain.contains("test-ca"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
