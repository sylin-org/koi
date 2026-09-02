//! Durable file snapshots shared by service-manager install transactions.

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const BACKUP_SUFFIX: &str = ".koi-install-backup";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct FileSnapshot {
    pub(super) path: PathBuf,
    pub(super) backup: PathBuf,
    pub(super) existed: bool,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

impl FileSnapshot {
    pub(super) fn inspect(path: PathBuf) -> anyhow::Result<Self> {
        let backup = backup_path(&path);
        if backup.exists() {
            // A durable manifest is the sole authority for rollback. With no
            // manifest, a backup can only be debris after a committed install.
            std::fs::remove_file(&backup).map_err(|error| {
                anyhow::anyhow!(
                    "could not remove stale installer backup {}: {error}",
                    backup.display()
                )
            })?;
        }
        match std::fs::metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    anyhow::bail!(
                        "refusing to replace non-file installation target {}",
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
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path,
                backup,
                existed: false,
                mode: None,
                uid: None,
                gid: None,
            }),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn prepare(&self) -> anyhow::Result<()> {
        if !self.existed {
            return Ok(());
        }
        if let Some(parent) = self.backup.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&self.path, &self.backup)?;
        self.apply_metadata(&self.backup)?;
        std::fs::File::open(&self.backup)?.sync_all()?;
        Ok(())
    }

    pub(super) fn validate_backup(&self) -> anyhow::Result<()> {
        if self.existed && !self.backup.is_file() {
            anyhow::bail!(
                "installer recovery is incomplete: expected backup {} for {}",
                self.backup.display(),
                self.path.display()
            );
        }
        Ok(())
    }

    pub(super) fn restore(&self) -> anyhow::Result<()> {
        if !self.existed {
            match std::fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(());
        }

        let staged = staged_restore_path(&self.path);
        std::fs::copy(&self.backup, &staged)?;
        self.apply_metadata(&staged)?;
        std::fs::File::open(&staged)?.sync_all()?;
        koi_common::persist::replace_file(&staged, &self.path)?;
        Ok(())
    }

    fn apply_metadata(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(mode) = self.mode {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
        if let (Some(uid), Some(gid)) = (self.uid, self.gid) {
            chown(path, uid, gid)?;
        }
        Ok(())
    }

    pub(super) fn cleanup(&self) -> anyhow::Result<()> {
        match std::fs::remove_file(&self.backup) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub(super) fn staged_restore_path(path: &Path) -> PathBuf {
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
