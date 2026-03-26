//! Resolved filesystem paths for certmesh operations.
//!
//! Constructed once at startup and stored as an immutable field on
//! `CertmeshState`. Tests inject a tempdir-rooted instance; production
//! code uses `CertmeshPaths::default()` which reads the platform data dir.

use std::path::{Path, PathBuf};

const CERTMESH_DIR: &str = "certmesh";
const CA_SUBDIR: &str = "ca";
const CERTS_DIR: &str = "certs";
const LOGS_DIR: &str = "logs";
const CA_KEY_FILENAME: &str = "ca-key.enc";
const CA_CERT_FILENAME: &str = "ca-cert.pem";
const SLOT_TABLE_FILENAME: &str = "unlock-slots.json";
const AUTH_FILENAME: &str = "auth.json";
const ROSTER_FILENAME: &str = "roster.json";
const AUDIT_FILENAME: &str = "certmesh-audit.log";
const AUTO_UNLOCK_KEY_FILENAME: &str = "auto-unlock-key";

/// Resolved filesystem paths for all certmesh operations.
///
/// Every path is derived from a single root `data_dir`. Production code
/// constructs this via `Default` (which reads the platform data dir);
/// test code injects a tempdir via `with_data_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertmeshPaths {
    data_dir: PathBuf,
}

impl CertmeshPaths {
    /// Create paths rooted at a specific directory (typically a tempdir for testing).
    pub fn with_data_dir(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    /// Root data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Certmesh state directory (`data_dir/certmesh/`).
    pub fn certmesh_dir(&self) -> PathBuf {
        self.data_dir.join(CERTMESH_DIR)
    }

    /// CA state directory (`data_dir/certmesh/ca/`).
    pub fn ca_dir(&self) -> PathBuf {
        self.certmesh_dir().join(CA_SUBDIR)
    }

    /// Encrypted CA key file.
    pub fn ca_key_path(&self) -> PathBuf {
        self.ca_dir().join(CA_KEY_FILENAME)
    }

    /// CA certificate PEM file.
    pub fn ca_cert_path(&self) -> PathBuf {
        self.ca_dir().join(CA_CERT_FILENAME)
    }

    /// Auth credential file.
    pub fn auth_path(&self) -> PathBuf {
        self.ca_dir().join(AUTH_FILENAME)
    }

    /// Roster file.
    pub fn roster_path(&self) -> PathBuf {
        self.certmesh_dir().join(ROSTER_FILENAME)
    }

    /// Unlock slot table file.
    pub fn slot_table_path(&self) -> PathBuf {
        self.ca_dir().join(SLOT_TABLE_FILENAME)
    }

    /// Certificate files directory (`data_dir/certs/`).
    pub fn certs_dir(&self) -> PathBuf {
        self.data_dir.join(CERTS_DIR)
    }

    /// Log directory (`data_dir/logs/`).
    pub fn log_dir(&self) -> PathBuf {
        self.data_dir.join(LOGS_DIR)
    }

    /// Audit log file.
    pub fn audit_log_path(&self) -> PathBuf {
        self.log_dir().join(AUDIT_FILENAME)
    }

    /// Auto-unlock key file.
    pub fn auto_unlock_key_path(&self) -> PathBuf {
        self.certmesh_dir().join(AUTO_UNLOCK_KEY_FILENAME)
    }

    /// Check if CA has been initialized (encrypted key file exists on disk).
    pub fn is_ca_initialized(&self) -> bool {
        self.ca_key_path().exists()
    }

    /// Check if envelope encryption slot table exists on disk.
    pub fn has_slot_table(&self) -> bool {
        self.slot_table_path().exists()
    }
}

impl Default for CertmeshPaths {
    fn default() -> Self {
        Self {
            data_dir: koi_common::paths::koi_data_dir(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_derive_from_data_dir() {
        let paths = CertmeshPaths::with_data_dir(PathBuf::from("/test/root"));
        assert_eq!(paths.certmesh_dir(), PathBuf::from("/test/root/certmesh"));
        assert_eq!(paths.ca_dir(), PathBuf::from("/test/root/certmesh/ca"));
        assert_eq!(
            paths.ca_key_path(),
            PathBuf::from("/test/root/certmesh/ca/ca-key.enc")
        );
        assert_eq!(
            paths.ca_cert_path(),
            PathBuf::from("/test/root/certmesh/ca/ca-cert.pem")
        );
        assert_eq!(
            paths.auth_path(),
            PathBuf::from("/test/root/certmesh/ca/auth.json")
        );
        assert_eq!(
            paths.roster_path(),
            PathBuf::from("/test/root/certmesh/roster.json")
        );
        assert_eq!(
            paths.slot_table_path(),
            PathBuf::from("/test/root/certmesh/ca/unlock-slots.json")
        );
        assert_eq!(paths.certs_dir(), PathBuf::from("/test/root/certs"));
        assert_eq!(
            paths.audit_log_path(),
            PathBuf::from("/test/root/logs/certmesh-audit.log")
        );
        assert_eq!(
            paths.auto_unlock_key_path(),
            PathBuf::from("/test/root/certmesh/auto-unlock-key")
        );
    }

    #[test]
    fn is_ca_initialized_false_for_nonexistent_dir() {
        let paths = CertmeshPaths::with_data_dir(PathBuf::from("/nonexistent/path"));
        assert!(!paths.is_ca_initialized());
    }

    #[test]
    fn has_slot_table_false_for_nonexistent_dir() {
        let paths = CertmeshPaths::with_data_dir(PathBuf::from("/nonexistent/path"));
        assert!(!paths.has_slot_table());
    }
}
