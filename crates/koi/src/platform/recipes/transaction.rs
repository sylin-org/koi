//! Durable file snapshots shared by service-manager install transactions.

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use koi_common::persist::{self, AtomicWriteOptions, FileIntegrity};

const BACKUP_SUFFIX: &str = ".koi-install-backup";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::platform) struct FileSnapshot {
    pub(in crate::platform) path: PathBuf,
    pub(in crate::platform) backup: PathBuf,
    pub(in crate::platform) existed: bool,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    integrity: Option<FileIntegrity>,
}

impl FileSnapshot {
    pub(in crate::platform) fn inspect(path: PathBuf) -> anyhow::Result<Self> {
        let backup = backup_path(&path);
        if backup.try_exists()? {
            // A durable manifest is the sole authority for rollback. With no
            // manifest, a backup can only be debris after a committed install.
            let outcome = persist::remove_file_durable(&backup).map_err(|error| {
                anyhow::anyhow!(
                    "could not remove stale installer backup {}: {error}",
                    backup.display()
                )
            })?;
            persist::require_durable(outcome, "removing a stale installer backup")?;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    anyhow::bail!(
                        "refusing to replace non-regular installation target {}",
                        path.display()
                    );
                }
                Ok(Self {
                    path,
                    backup,
                    existed: true,
                    mode: Some(metadata.mode()),
                    uid: Some(metadata.uid()),
                    gid: Some(metadata.gid()),
                    integrity: None,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path,
                backup,
                existed: false,
                mode: None,
                uid: None,
                gid: None,
                integrity: None,
            }),
            Err(error) => Err(error.into()),
        }
    }

    pub(in crate::platform) fn prepare(&mut self) -> anyhow::Result<()> {
        if !self.existed {
            return Ok(());
        }
        let options = self.mode.map_or_else(AtomicWriteOptions::new, |mode| {
            AtomicWriteOptions::new().with_unix_mode(mode)
        });
        let (outcome, integrity) = persist::copy_file_atomic_new_with_options_and_prepare_stage(
            &self.path,
            &self.backup,
            options,
            |stage| self.apply_metadata(stage).map_err(anyhow_to_io),
        )?;
        persist::require_durable(outcome, "checkpointing an installer backup")?;
        self.integrity = Some(integrity);
        Ok(())
    }

    pub(in crate::platform) fn validate_backup(
        &self,
        require_integrity: bool,
    ) -> anyhow::Result<()> {
        if !self.existed {
            return Ok(());
        }
        if !std::fs::symlink_metadata(&self.backup)
            .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            anyhow::bail!(
                "installer recovery is incomplete: expected backup {} for {}",
                self.backup.display(),
                self.path.display()
            );
        }
        match &self.integrity {
            Some(expected) => {
                let actual = persist::file_integrity(&self.backup)?;
                if &actual != expected {
                    anyhow::bail!(
                        "installer recovery is unsafe: backup {} for {} changed (expected {} bytes / {}, found {} bytes / {})",
                        self.backup.display(),
                        self.path.display(),
                        expected.len,
                        expected.sha256,
                        actual.len,
                        actual.sha256
                    );
                }
            }
            None if require_integrity => anyhow::bail!(
                "installer recovery is unsafe: backup {} for {} has no recorded integrity",
                self.backup.display(),
                self.path.display()
            ),
            None => {}
        }
        Ok(())
    }

    pub(in crate::platform) fn restore(&self) -> anyhow::Result<()> {
        if !self.existed {
            let outcome = persist::remove_file_durable(&self.path)?;
            persist::require_durable(outcome, "removing a newly installed file during rollback")?;
            return Ok(());
        }

        let options = self.mode.map_or_else(AtomicWriteOptions::new, |mode| {
            AtomicWriteOptions::new().with_unix_mode(mode)
        });
        let outcome = if let Some(expected) = &self.integrity {
            persist::copy_file_atomic_verified_with_options_and_prepare_stage(
                &self.backup,
                &self.path,
                expected,
                options,
                |stage| self.apply_metadata(stage).map_err(anyhow_to_io),
            )?
        } else {
            persist::copy_file_atomic_with_options_and_prepare_stage(
                &self.backup,
                &self.path,
                options,
                |stage| self.apply_metadata(stage).map_err(anyhow_to_io),
            )?
            .0
        };
        persist::require_durable(outcome, "restoring an installer backup")?;
        Ok(())
    }

    fn apply_metadata(&self, path: &Path) -> anyhow::Result<()> {
        if let (Some(uid), Some(gid)) = (self.uid, self.gid) {
            chown(path, uid, gid)?;
        }
        // chown may clear setuid/setgid bits, so restore the exact mode after
        // ownership while the stage is still empty and private.
        if let Some(mode) = self.mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    }

    pub(in crate::platform) fn cleanup(&self) -> anyhow::Result<()> {
        let outcome = persist::remove_file_durable(&self.backup)?;
        persist::require_durable(outcome, "removing installer backup debris")?;
        Ok(())
    }
}

pub(in crate::platform) fn staged_restore_path(path: &Path) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_os_string();
    value.push(".koi-install-restore");
    PathBuf::from(value)
}

fn backup_path(path: &Path) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_os_string();
    value.push(BACKUP_SUFFIX);
    PathBuf::from(value)
}

fn chown(path: &Path, uid: u32, gid: u32) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `path` is a live NUL-terminated string and chown has no other
    // pointer preconditions.
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn anyhow_to_io(error: anyhow::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}
