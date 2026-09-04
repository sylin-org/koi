//! Observation-only access to Certmesh's durable read model.
//!
//! A live [`crate::CertmeshCore`] publishes the authoritative in-memory status.
//! This boundary exists for local tools running without that daemon: it projects
//! the same domain-owned status and CA anchor without constructing runtime state,
//! recovering transactions, replaying credential cleanup, or opening the vault.

use koi_common::diagnosis::TrustDiagnosis;

use crate::repository::CertmeshRepository;
use crate::roster::Roster;
use crate::{status, CertmeshCaAnchor, CertmeshError, CertmeshPaths, CertmeshStatus};

/// One coherent, data-only view of Certmesh's durable state.
///
/// The revision is process-local and therefore starts at zero. Authority state
/// is projected as locked because an offline reader intentionally does not open
/// the credential vault or decrypt the CA key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertmeshObservation {
    status: CertmeshStatus,
    ca_anchor: Option<CertmeshCaAnchor>,
}

impl CertmeshObservation {
    /// Read Certmesh's persisted status and verification anchor without side effects.
    ///
    /// A transaction journal makes the durable generation ambiguous until the
    /// daemon-owned bootstrap recovery runs, so observation fails closed and
    /// leaves the journal untouched. The repository's stable cross-process
    /// fence keeps the complete projection on one durable generation.
    pub fn read(paths: &CertmeshPaths, local_hostname: &str) -> Result<Self, CertmeshError> {
        crate::validate_hostname(local_hostname)?;
        let repository = CertmeshRepository::new(paths.data_dir().to_path_buf());
        repository.observe(|| Self::project(paths, local_hostname))
    }

    fn project(paths: &CertmeshPaths, local_hostname: &str) -> Result<Self, CertmeshError> {
        let roster = if paths.is_ca_initialized() {
            crate::roster::load_roster(&paths.roster_path())?
        } else {
            Roster::empty()
        };
        let status = status::build(paths, Some(local_hostname), false, None, &roster, None, 0);
        let ca_anchor = status::observe_ca_anchor(paths, Some(local_hostname), status.role)
            .map_err(|reason| {
                CertmeshError::Internal(format!("Certmesh CA-anchor observation failed: {reason}"))
            })?;
        Ok(Self { status, ca_anchor })
    }

    /// The canonical Certmesh status projected from the observed generation.
    pub fn status(&self) -> &CertmeshStatus {
        &self.status
    }

    /// Certmesh's canonical trust diagnosis from the same observed generation.
    pub fn diagnosis(&self) -> &TrustDiagnosis {
        &self.status.diagnosis
    }

    /// The verification anchor, including PEM, from the same observed generation.
    pub fn ca_anchor(&self) -> Option<&CertmeshCaAnchor> {
        self.ca_anchor.as_ref()
    }

    /// The CA certificate PEM used by local Trust integration, when present.
    pub fn ca_certificate_pem(&self) -> Option<&str> {
        self.ca_anchor()
            .map(|anchor| anchor.certificate_pem.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use koi_common::diagnosis::CheckStatus;

    use super::*;

    fn snapshot_tree(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        fn visit(root: &Path, path: &Path, entries: &mut Vec<(PathBuf, Option<Vec<u8>>)>) {
            let Ok(children) = std::fs::read_dir(path) else {
                return;
            };
            for child in children {
                let child = child.expect("read directory entry");
                let path = child.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("path below root")
                    .to_path_buf();
                if child.file_type().expect("read file type").is_dir() {
                    entries.push((relative, None));
                    visit(root, &path, entries);
                } else {
                    entries.push((relative, Some(std::fs::read(&path).expect("read file"))));
                }
            }
        }

        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries.sort();
        entries
    }

    #[test]
    fn absent_storage_remains_absent() {
        let temp = tempfile::tempdir().expect("temporary parent");
        let data_dir = temp.path().join("absent");
        let paths = CertmeshPaths::with_data_dir(data_dir.clone());

        let observation =
            CertmeshObservation::read(&paths, "test-host").expect("observe open Certmesh");

        assert_eq!(observation.status().role, crate::CertmeshRole::Open);
        assert!(observation.ca_anchor().is_none());
        assert!(
            !data_dir.exists(),
            "observation must not create domain storage"
        );
    }

    #[test]
    fn pending_transaction_is_not_recovered_or_interpreted() {
        let temp = tempfile::tempdir().expect("temporary data directory");
        let journal = temp.path().join(".koi-certmesh-transaction");
        std::fs::create_dir(&journal).expect("create pending journal");
        std::fs::write(journal.join("manifest.json"), b"pending-generation")
            .expect("write pending manifest");
        let before = snapshot_tree(temp.path());
        let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());

        let error = CertmeshObservation::read(&paths, "test-host")
            .expect_err("pending recovery must fence reads");

        assert!(matches!(error, CertmeshError::Conflict(_)));
        assert_eq!(snapshot_tree(temp.path()), before);
    }

    #[test]
    fn cleanup_is_reported_without_consumption_or_vault_access() {
        let temp = tempfile::tempdir().expect("temporary data directory");
        let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        let cleanup_dir = paths.credential_cleanup_dir();
        std::fs::create_dir(&cleanup_dir).expect("create cleanup outbox");
        std::fs::write(cleanup_dir.join("pending.json"), b"owned-platform-effect")
            .expect("write cleanup sentinel");
        let before = snapshot_tree(temp.path());

        let observation =
            CertmeshObservation::read(&paths, "test-host").expect("observe cleanup state");

        let cleanup = observation
            .diagnosis()
            .checks
            .iter()
            .find(|check| check.name == "credential_cleanup")
            .expect("cleanup warning belongs to canonical diagnosis");
        assert_eq!(cleanup.status, CheckStatus::Warn);
        assert_eq!(snapshot_tree(temp.path()), before);
        assert!(
            !temp.path().join("vault").exists(),
            "observation must not open or create the credential vault"
        );
    }

    #[test]
    fn authority_observation_reuses_status_and_anchor_projections() {
        let temp = tempfile::tempdir().expect("temporary data directory");
        let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        crate::ca::create_ca("test-passphrase", &[91_u8; 32], &paths)
            .expect("create authority fixture");
        let roster = Roster::empty();
        crate::roster::save_roster(&roster, &paths.roster_path()).expect("save roster fixture");
        let before = snapshot_tree(temp.path());

        let observation =
            CertmeshObservation::read(&paths, "test-host").expect("observe authority");
        let expected_status =
            status::build(&paths, Some("test-host"), false, None, &roster, None, 0);
        let expected_anchor =
            status::observe_ca_anchor(&paths, Some("test-host"), expected_status.role)
                .expect("observe expected CA anchor");

        assert_eq!(observation.status(), &expected_status);
        assert_eq!(observation.ca_anchor(), expected_anchor.as_ref());
        assert_eq!(observation.status().role, crate::CertmeshRole::Authority);
        assert!(observation.status().authority.as_ref().unwrap().locked);
        assert_eq!(snapshot_tree(temp.path()), before);
        assert!(
            !temp.path().join("vault").exists(),
            "locked observation must not probe auto-unlock credentials"
        );
    }

    #[test]
    fn corrupt_authority_roster_fails_closed_without_mutation() {
        let temp = tempfile::tempdir().expect("temporary data directory");
        let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        std::fs::create_dir_all(paths.ca_dir()).expect("create authority directory");
        std::fs::write(paths.ca_key_path(), b"durable-authority-marker")
            .expect("write authority marker");
        std::fs::create_dir_all(paths.certmesh_dir()).expect("create Certmesh directory");
        std::fs::write(paths.roster_path(), b"not-json").expect("write corrupt roster");
        let before = snapshot_tree(temp.path());

        let error = CertmeshObservation::read(&paths, "test-host")
            .expect_err("corrupt roster must fail closed");

        assert!(matches!(error, CertmeshError::Io(_)));
        assert_eq!(snapshot_tree(temp.path()), before);
        assert!(
            !temp.path().join("vault").exists(),
            "failed observation must not fall through to boot or vault access"
        );
    }

    #[test]
    fn corrupt_authority_anchor_is_an_observation_error_not_absence() {
        let temp = tempfile::tempdir().expect("temporary data directory");
        let paths = CertmeshPaths::with_data_dir(temp.path().to_path_buf());
        crate::ca::create_ca("test-passphrase", &[92_u8; 32], &paths)
            .expect("create authority fixture");
        crate::roster::save_roster(&Roster::empty(), &paths.roster_path())
            .expect("save roster fixture");
        std::fs::write(paths.ca_cert_path(), b"not-a-certificate")
            .expect("damage authority anchor");
        let before = snapshot_tree(temp.path());

        let error = CertmeshObservation::read(&paths, "test-host")
            .expect_err("damaged anchor must fail closed");

        assert!(error.to_string().contains("invalid PEM"));
        assert_eq!(snapshot_tree(temp.path()), before);
    }
}
