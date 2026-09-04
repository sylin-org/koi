//! Certmesh aggregate persistence.
//!
//! A Certmesh command often changes several files (roster, identity material,
//! member metadata, or CA material). Per-file atomic renames are insufficient:
//! a later failure can otherwise expose a mixed generation. This repository
//! stages the complete write-set, keeps rollback copies, and leaves a recovery
//! journal until every replacement succeeds. The result distinguishes a
//! confirmed durable generation from one that is already visible but whose
//! crash durability could not be confirmed, so the aggregate can publish the
//! visible truth without acknowledging semantic success.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use koi_common::persist::AtomicCommit;
use serde::{Deserialize, Serialize};

use crate::CertmeshError;

const TRANSACTION_DIR: &str = ".koi-certmesh-transaction";
const REPOSITORY_LOCK_SUFFIX: &str = ".koi-certmesh-repository.lock";
const REPOSITORY_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const REPOSITORY_LOCK_POLL: Duration = Duration::from_millis(10);
const MANIFEST_FILE: &str = "manifest.json";
const COMMITTED_FILE: &str = "committed";
const COMMITTED_CONTENTS: &[u8] = b"committed\n";

#[derive(Default)]
pub(crate) struct ArtifactTransaction {
    changes: Vec<ArtifactChange>,
}

impl ArtifactTransaction {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn write(&mut self, path: PathBuf, bytes: impl Into<Vec<u8>>, private: bool) {
        self.replace_change(ArtifactChange {
            path,
            operation: ArtifactOperation::Write {
                bytes: bytes.into(),
                private,
            },
        });
    }

    pub(crate) fn remove(&mut self, path: PathBuf) {
        self.replace_change(ArtifactChange {
            path,
            operation: ArtifactOperation::Remove,
        });
    }

    /// Add every non-directory entry below `root` to this transaction's remove
    /// set. Directories are intentionally housekeeping rather than aggregate
    /// artifacts: after commit they may be removed only if still empty.
    pub(crate) fn remove_tree(&mut self, root: &Path) -> Result<(), CertmeshError> {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(CertmeshError::Io(error)),
        };
        for entry in entries {
            let entry = entry.map_err(CertmeshError::Io)?;
            let file_type = entry.file_type().map_err(CertmeshError::Io)?;
            if file_type.is_dir() {
                self.remove_tree(&entry.path())?;
            } else {
                self.remove(entry.path());
            }
        }
        Ok(())
    }

    pub(crate) fn append(
        &mut self,
        path: PathBuf,
        bytes: impl AsRef<[u8]>,
        private: bool,
    ) -> Result<(), CertmeshError> {
        if let Some(existing) = self
            .changes
            .iter_mut()
            .find(|existing| existing.path == path)
        {
            match &mut existing.operation {
                ArtifactOperation::Write {
                    bytes: contents,
                    private: existing_private,
                } => {
                    contents.extend_from_slice(bytes.as_ref());
                    *existing_private |= private;
                }
                ArtifactOperation::Remove => {
                    existing.operation = ArtifactOperation::Write {
                        bytes: bytes.as_ref().to_vec(),
                        private,
                    };
                }
            }
            return Ok(());
        }
        let mut contents = match std::fs::read(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(CertmeshError::Io(error)),
        };
        contents.extend_from_slice(bytes.as_ref());
        self.write(path, contents, private);
        Ok(())
    }

    fn replace_change(&mut self, change: ArtifactChange) {
        if let Some(existing) = self
            .changes
            .iter_mut()
            .find(|existing| existing.path == change.path)
        {
            *existing = change;
        } else {
            self.changes.push(change);
        }
    }

    fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

struct ArtifactChange {
    path: PathBuf,
    operation: ArtifactOperation,
}

enum ArtifactOperation {
    Write { bytes: Vec<u8>, private: bool },
    Remove,
}

pub(crate) struct CertmeshRepository {
    root: PathBuf,
    #[cfg(test)]
    fail_after_replacements: std::sync::atomic::AtomicIsize,
    #[cfg(test)]
    make_marker_durability_uncertain: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_marker_before_replace: std::sync::atomic::AtomicBool,
    /// Deterministic cancellation probe: pause after the durable commit is
    /// externally visible but before control returns to the aggregate tail.
    #[cfg(test)]
    pause_after_commit: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    commit_paused: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    release_paused_commit: std::sync::atomic::AtomicBool,
}

/// Stable cross-process fence for one Certmesh data root.
///
/// The sidecar is adjacent to the data root, rather than below it: bootstrap
/// can therefore serialize recovery before the root exists, destroy cannot
/// unlink a live lock, and observation remains side-effect free within the
/// domain's data directory. `File` locking maps to `flock` on Unix and
/// `LockFileEx` on Windows.
struct RepositoryLock {
    _file: File,
}

impl RepositoryLock {
    fn acquire(root: &Path) -> Result<Self, CertmeshError> {
        Self::acquire_with_timeout(root, REPOSITORY_LOCK_TIMEOUT)
    }

    fn acquire_with_timeout(root: &Path, timeout: Duration) -> Result<Self, CertmeshError> {
        let path = repository_lock_path(root)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(CertmeshError::Io)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(CertmeshError::Io)?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(TryLockError::WouldBlock) if started.elapsed() < timeout => {
                    let remaining = timeout.saturating_sub(started.elapsed());
                    std::thread::sleep(REPOSITORY_LOCK_POLL.min(remaining));
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(CertmeshError::Conflict(format!(
                        "Certmesh data root '{}' remained busy for {} ms",
                        root.display(),
                        timeout.as_millis()
                    )));
                }
                Err(TryLockError::Error(error))
                    if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(TryLockError::Error(error)) => return Err(CertmeshError::Io(error)),
            }
        }
    }
}

fn repository_lock_path(root: &Path) -> Result<PathBuf, CertmeshError> {
    let name = root.file_name().ok_or_else(|| {
        CertmeshError::InvalidPayload(format!(
            "Certmesh data root '{}' has no lockable final component",
            root.display()
        ))
    })?;
    let mut lock_name = name.to_os_string();
    lock_name.push(REPOSITORY_LOCK_SUFFIX);
    Ok(root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(lock_name))
}

impl CertmeshRepository {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root,
            #[cfg(test)]
            fail_after_replacements: std::sync::atomic::AtomicIsize::new(-1),
            #[cfg(test)]
            make_marker_durability_uncertain: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_marker_before_replace: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            pause_after_commit: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            commit_paused: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            release_paused_commit: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Project one offline read model while excluding every command/recovery
    /// writer for this data root.
    ///
    /// A pending journal remains daemon-owned recovery evidence. Observation
    /// fails closed without interpreting or modifying it.
    pub(crate) fn observe<R>(
        &self,
        project: impl FnOnce() -> Result<R, CertmeshError>,
    ) -> Result<R, CertmeshError> {
        let _repository = RepositoryLock::acquire(&self.root)?;
        let transaction_dir = self.root.join(TRANSACTION_DIR);
        match std::fs::symlink_metadata(&transaction_dir) {
            Ok(_) => return Err(CertmeshError::Conflict(
                "Certmesh recovery is pending; start the Koi service before reading offline state"
                    .into(),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(CertmeshError::Io(error)),
        }
        project()
    }

    /// Recover an interrupted command by restoring the complete prior write-set.
    pub(crate) fn recover(&self) -> Result<(), CertmeshError> {
        let _repository = RepositoryLock::acquire(&self.root)?;
        self.recover_locked()
    }

    fn recover_locked(&self) -> Result<(), CertmeshError> {
        let transaction_dir = self.root.join(TRANSACTION_DIR);
        if !transaction_dir.exists() {
            return Ok(());
        }
        // A durable commit marker means every target and parent directory was
        // synced. Recovery only has stale journal housekeeping left to do.
        if std::fs::read(transaction_dir.join(COMMITTED_FILE))
            .is_ok_and(|contents| contents == COMMITTED_CONTENTS)
        {
            remove_journal(&transaction_dir, &self.root).map_err(CertmeshError::Io)?;
            return Ok(());
        }
        let manifest_path = transaction_dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            // Targets are never touched before the manifest is durable, so a
            // manifest-less staging directory is safe to discard.
            remove_journal(&transaction_dir, &self.root).map_err(CertmeshError::Io)?;
            return Ok(());
        }
        let manifest: Manifest =
            koi_common::persist::read_json(&manifest_path).map_err(CertmeshError::Io)?;
        self.rollback(&transaction_dir, &manifest)
            .map_err(CertmeshError::Io)?;
        remove_journal(&transaction_dir, &self.root).map_err(CertmeshError::Io)?;
        Ok(())
    }

    /// Atomically commit a complete Certmesh artifact write-set.
    ///
    /// `DurabilityUncertain` means the new generation is already visible and
    /// must be accepted by the live aggregate, but semantic success must wait
    /// for repository recovery to confirm it.
    pub(crate) fn commit(
        &self,
        transaction: ArtifactTransaction,
    ) -> Result<AtomicCommit, CertmeshError> {
        let _repository = RepositoryLock::acquire(&self.root)?;
        if transaction.is_empty() {
            self.recover_locked()?;
            return Ok(AtomicCommit::Durable);
        }
        std::fs::create_dir_all(&self.root).map_err(CertmeshError::Io)?;
        self.recover_locked()?;

        let transaction_dir = self.root.join(TRANSACTION_DIR);
        std::fs::create_dir(&transaction_dir).map_err(CertmeshError::Io)?;
        // The journal directory itself must survive a crash before any target
        // replacement does, otherwise boot would have no rollback evidence.
        sync_directory(&self.root).map_err(CertmeshError::Io)?;
        let prepared = self.prepare(&transaction_dir, transaction);
        let manifest = match prepared {
            Ok(manifest) => manifest,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&transaction_dir);
                return Err(CertmeshError::Io(error));
            }
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| CertmeshError::Internal(format!("serialize transaction: {error}")))?;
        write_synced(&transaction_dir.join(MANIFEST_FILE), &manifest_bytes, true)
            .map_err(CertmeshError::Io)?;
        sync_directory(&transaction_dir).map_err(CertmeshError::Io)?;

        #[cfg(test)]
        let fail_after = self
            .fail_after_replacements
            .swap(-1, std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let fail_after = -1;

        let applied = self.apply(&transaction_dir, &manifest, fail_after);
        if let Err(error) = applied {
            if let Err(rollback_error) = self.rollback(&transaction_dir, &manifest) {
                // Preserve the journal and backups: a later boot may be able to
                // finish recovery, while deleting them would make the mixed
                // generation permanent.
                return Err(CertmeshError::Internal(format!(
                    "Certmesh transaction failed ({error}); rollback failed ({rollback_error})"
                )));
            }
            remove_journal(&transaction_dir, &self.root).map_err(CertmeshError::Io)?;
            return Err(CertmeshError::Io(error));
        }

        // This marker is the sole commit point. The common atomic primitive
        // returns Err only before replacement; after replacement, a directory
        // flush failure is a visible commit with uncertain crash durability.
        // Returning Err in that state would make callers restore old memory
        // while this process and a normal restart both observe the new marker.
        let marker = match self.write_commit_marker(&transaction_dir) {
            Ok(marker) => marker,
            Err(error) => {
                // Err is guaranteed to be pre-replacement. Restore the prior
                // generation before telling aggregate callers to restore their
                // prior in-memory model too.
                if let Err(rollback_error) = self.rollback(&transaction_dir, &manifest) {
                    return Err(CertmeshError::Internal(format!(
                        "Certmesh commit marker failed ({error}); rollback failed ({rollback_error})"
                    )));
                }
                remove_journal(&transaction_dir, &self.root).map_err(CertmeshError::Io)?;
                return Err(CertmeshError::Io(error));
            }
        };
        match &marker {
            AtomicCommit::Durable => {
                if let Err(error) = remove_journal(&transaction_dir, &self.root) {
                    tracing::warn!(
                        %error,
                        "Certmesh commit durable; journal cleanup deferred to boot"
                    );
                }
            }
            AtomicCommit::DurabilityUncertain(error) => {
                // Keep the visible marker and recovery evidence together. A
                // non-crash restart accepts the new generation; after a crash,
                // either old or new is permitted by this explicitly weaker
                // durability outcome. No fallible work may escape from here.
                tracing::error!(
                    path = %transaction_dir.join(COMMITTED_FILE).display(),
                    %error,
                    "Certmesh commit is visible, but its crash durability could not be confirmed; journal cleanup deferred to boot"
                );
            }
        }
        #[cfg(test)]
        if self
            .pause_after_commit
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.commit_paused
                .store(true, std::sync::atomic::Ordering::Release);
            while !self
                .release_paused_commit
                .load(std::sync::atomic::Ordering::Acquire)
            {
                std::thread::yield_now();
            }
            self.commit_paused
                .store(false, std::sync::atomic::Ordering::Release);
            self.release_paused_commit
                .store(false, std::sync::atomic::Ordering::Release);
        }
        Ok(marker)
    }

    /// Commit for bootstrap/offline callers that have no live aggregate model
    /// in which to accept a visible-but-unconfirmed generation.
    pub(crate) fn commit_durable(
        &self,
        transaction: ArtifactTransaction,
    ) -> Result<(), CertmeshError> {
        match self.commit(transaction)? {
            AtomicCommit::Durable => Ok(()),
            AtomicCommit::DurabilityUncertain(error) => Err(durability_uncertain_error(error)),
        }
    }

    fn write_commit_marker(&self, transaction_dir: &Path) -> io::Result<AtomicCommit> {
        #[cfg(test)]
        if self
            .fail_marker_before_replace
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(io::Error::other(
                "injected pre-replace Certmesh marker failure",
            ));
        }
        let outcome = koi_common::persist::write_bytes_atomic(
            &transaction_dir.join(COMMITTED_FILE),
            COMMITTED_CONTENTS,
        )?;
        #[cfg(test)]
        let outcome = if self
            .make_marker_durability_uncertain
            .swap(false, std::sync::atomic::Ordering::SeqCst)
            && matches!(outcome, AtomicCommit::Durable)
        {
            AtomicCommit::DurabilityUncertain(io::Error::other(
                "injected post-replace Certmesh marker durability uncertainty",
            ))
        } else {
            outcome
        };
        Ok(outcome)
    }

    fn prepare(
        &self,
        transaction_dir: &Path,
        transaction: ArtifactTransaction,
    ) -> io::Result<Manifest> {
        let mut entries = Vec::with_capacity(transaction.changes.len());
        for (index, change) in transaction.changes.into_iter().enumerate() {
            let relative = self.relative_target(&change.path)?;
            let existed = change.path.exists();
            let backup = if existed {
                if !change.path.is_file() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "transaction target is not a file: {}",
                            change.path.display()
                        ),
                    ));
                }
                let name = format!("backup-{index}");
                let backup_path = transaction_dir.join(&name);
                std::fs::copy(&change.path, &backup_path)?;
                std::fs::File::open(&backup_path)?.sync_all()?;
                Some(name)
            } else {
                None
            };
            let (kind, staged) = match change.operation {
                ArtifactOperation::Write { bytes, private } => {
                    let name = format!("staged-{index}");
                    write_synced(&transaction_dir.join(&name), &bytes, private)?;
                    (ManifestOperation::Write, Some(name))
                }
                ArtifactOperation::Remove => (ManifestOperation::Remove, None),
            };
            entries.push(ManifestEntry {
                target: relative,
                kind,
                staged,
                backup,
                existed,
            });
        }
        Ok(Manifest {
            version: 1,
            entries,
        })
    }

    fn apply(
        &self,
        transaction_dir: &Path,
        manifest: &Manifest,
        fail_after: isize,
    ) -> io::Result<()> {
        let mut replacements = 0isize;
        for entry in &manifest.entries {
            if fail_after >= 0 && replacements == fail_after {
                return Err(io::Error::other("injected Certmesh transaction failure"));
            }
            let target = self.root.join(&entry.target);
            match entry.kind {
                ManifestOperation::Write => {
                    if let Some(parent) = target.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let staged = transaction_dir.join(
                        entry
                            .staged
                            .as_deref()
                            .ok_or_else(|| io::Error::other("write has no staged artifact"))?,
                    );
                    koi_common::persist::replace_file(&staged, &target)?;
                    if let Some(parent) = target.parent() {
                        sync_directory(parent)?;
                    }
                }
                ManifestOperation::Remove => match std::fs::remove_file(&target) {
                    Ok(()) => {
                        if let Some(parent) = target.parent() {
                            sync_directory(parent)?;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                },
            }
            replacements += 1;
        }
        // This is the important crash window after every target is durable but
        // before the commit marker acknowledges the new generation.
        if fail_after >= 0 && replacements == fail_after {
            return Err(io::Error::other("injected Certmesh transaction failure"));
        }
        Ok(())
    }

    fn rollback(&self, transaction_dir: &Path, manifest: &Manifest) -> io::Result<()> {
        for (index, entry) in manifest.entries.iter().enumerate().rev() {
            let target = self.root.join(&entry.target);
            if entry.existed {
                let backup = transaction_dir.join(
                    entry
                        .backup
                        .as_deref()
                        .ok_or_else(|| io::Error::other("existing target has no backup"))?,
                );
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let restore = target.with_extension(format!("koi-rollback-{index}"));
                std::fs::copy(backup, &restore)?;
                std::fs::File::open(&restore)?.sync_all()?;
                koi_common::persist::replace_file(&restore, &target)?;
                if let Some(parent) = target.parent() {
                    sync_directory(parent)?;
                }
            } else {
                match std::fs::remove_file(&target) {
                    Ok(()) => {
                        if let Some(parent) = target.parent() {
                            sync_directory(parent)?;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn relative_target(&self, target: &Path) -> io::Result<PathBuf> {
        let relative = target.strip_prefix(&self.root).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("transaction target escapes data root: {}", target.display()),
            )
        })?;
        if relative.as_os_str().is_empty()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid transaction target: {}", target.display()),
            ));
        }
        Ok(relative.to_path_buf())
    }

    #[cfg(test)]
    pub(crate) fn fail_next_commit_after(&self, replacements: usize) {
        self.fail_after_replacements.store(
            isize::try_from(replacements).unwrap_or(isize::MAX),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    #[cfg(test)]
    pub(crate) fn make_next_marker_durability_uncertain(&self) {
        self.make_marker_durability_uncertain
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn fail_next_marker_before_replace(&self) {
        self.fail_marker_before_replace
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn pause_next_commit_after_durable(&self) {
        self.release_paused_commit
            .store(false, std::sync::atomic::Ordering::Release);
        self.pause_after_commit
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn is_commit_paused(&self) -> bool {
        self.commit_paused
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn release_commit(&self) {
        self.release_paused_commit
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

pub(crate) fn durability_uncertain_error(error: io::Error) -> CertmeshError {
    CertmeshError::DurabilityUncertain(error.to_string())
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u8,
    entries: Vec<ManifestEntry>,
}

#[derive(Serialize, Deserialize)]
struct ManifestEntry {
    target: PathBuf,
    kind: ManifestOperation,
    staged: Option<String>,
    backup: Option<String>,
    existed: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestOperation {
    Write,
    Remove,
}

fn write_synced(path: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = options.open(path)?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}

fn remove_journal(transaction_dir: &Path, root: &Path) -> io::Result<()> {
    std::fs::remove_dir_all(transaction_dir)?;
    sync_directory(root)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    // Windows directory handles require platform-specific flags. Target files
    // themselves are still flushed before replacement; MoveFileEx provides the
    // atomic replacement guarantee used by koi-common.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK_CHILD_ROOT: &str = "KOI_CERTMESH_REPOSITORY_LOCK_CHILD_ROOT";

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        existing: PathBuf,
        removed: PathBuf,
        created: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("temporary repository");
            let root = temp.path().join("data");
            std::fs::create_dir_all(root.join("nested")).expect("create fixture root");
            let existing = root.join("existing");
            let removed = root.join("nested/removed");
            let created = root.join("nested/created");
            std::fs::write(&existing, b"old-existing").expect("existing fixture");
            std::fs::write(&removed, b"old-removed").expect("removed fixture");
            Self {
                _temp: temp,
                root,
                existing,
                removed,
                created,
            }
        }

        fn transaction(&self) -> ArtifactTransaction {
            let mut transaction = ArtifactTransaction::new();
            transaction.write(self.existing.clone(), b"new-existing".to_vec(), true);
            transaction.remove(self.removed.clone());
            transaction.write(self.created.clone(), b"new-created".to_vec(), false);
            transaction
        }

        fn assert_old_generation(&self) {
            assert_eq!(std::fs::read(&self.existing).unwrap(), b"old-existing");
            assert_eq!(std::fs::read(&self.removed).unwrap(), b"old-removed");
            assert!(!self.created.exists());
        }

        fn assert_new_generation(&self) {
            assert_eq!(std::fs::read(&self.existing).unwrap(), b"new-existing");
            assert!(!self.removed.exists());
            assert_eq!(std::fs::read(&self.created).unwrap(), b"new-created");
        }
    }

    fn stage(repo: &CertmeshRepository, transaction: ArtifactTransaction) -> (PathBuf, Manifest) {
        let transaction_dir = repo.root.join(TRANSACTION_DIR);
        std::fs::create_dir(&transaction_dir).expect("create journal");
        sync_directory(&repo.root).expect("sync root");
        let manifest = repo
            .prepare(&transaction_dir, transaction)
            .expect("prepare transaction");
        write_synced(
            &transaction_dir.join(MANIFEST_FILE),
            &serde_json::to_vec_pretty(&manifest).unwrap(),
            true,
        )
        .expect("write manifest");
        sync_directory(&transaction_dir).expect("sync journal");
        (transaction_dir, manifest)
    }

    #[test]
    fn commit_failure_rolls_back_every_replacement_boundary() {
        // Three change boundaries plus the post-final/pre-marker window.
        for failure_boundary in 0..=3 {
            let fixture = Fixture::new();
            let repo = CertmeshRepository::new(fixture.root.clone());
            repo.fail_next_commit_after(failure_boundary);
            assert!(repo.commit(fixture.transaction()).is_err());
            fixture.assert_old_generation();
            assert!(!fixture.root.join(TRANSACTION_DIR).exists());
        }
    }

    #[test]
    fn boot_recovery_rolls_back_crashes_at_every_replacement_boundary() {
        for failure_boundary in 0..=3 {
            let fixture = Fixture::new();
            let repo = CertmeshRepository::new(fixture.root.clone());
            let (transaction_dir, manifest) = stage(&repo, fixture.transaction());
            assert!(repo
                .apply(&transaction_dir, &manifest, failure_boundary)
                .is_err());

            repo.recover().expect("recover interrupted transaction");
            fixture.assert_old_generation();
            assert!(!transaction_dir.exists());
        }
    }

    #[test]
    fn durable_commit_marker_keeps_the_new_generation() {
        let fixture = Fixture::new();
        let repo = CertmeshRepository::new(fixture.root.clone());
        let (transaction_dir, manifest) = stage(&repo, fixture.transaction());
        repo.apply(&transaction_dir, &manifest, -1)
            .expect("apply transaction");
        assert!(matches!(
            repo.write_commit_marker(&transaction_dir)
                .expect("write commit marker"),
            AtomicCommit::Durable
        ));

        repo.recover().expect("clean acknowledged journal");
        fixture.assert_new_generation();
        assert!(!transaction_dir.exists());
    }

    #[test]
    fn post_replace_marker_uncertainty_keeps_live_and_restart_on_new_generation() {
        let fixture = Fixture::new();
        let repo = CertmeshRepository::new(fixture.root.clone());
        repo.make_next_marker_durability_uncertain();

        let outcome = repo
            .commit(fixture.transaction())
            .expect("a visible uncertain marker is still committed");
        let AtomicCommit::DurabilityUncertain(error) = outcome else {
            panic!("fault injection must preserve the typed uncertain outcome");
        };
        assert!(error.to_string().contains("injected post-replace"));
        fixture.assert_new_generation();

        // Uncertain commits retain their journal. A fresh domain instance sees
        // the marker as the authority and must keep exactly the same generation.
        let transaction_dir = fixture.root.join(TRANSACTION_DIR);
        assert_eq!(
            std::fs::read(transaction_dir.join(COMMITTED_FILE)).unwrap(),
            COMMITTED_CONTENTS
        );
        let restarted = CertmeshRepository::new(fixture.root.clone());
        restarted.recover().expect("recover committed journal");
        fixture.assert_new_generation();
        assert!(!transaction_dir.exists());
    }

    #[test]
    fn pre_replace_marker_failure_restores_old_generation_before_return() {
        let fixture = Fixture::new();
        let repo = CertmeshRepository::new(fixture.root.clone());
        repo.fail_next_marker_before_replace();

        repo.commit(fixture.transaction())
            .expect_err("a marker failure before commit must be rejected");
        fixture.assert_old_generation();
        assert!(!fixture.root.join(TRANSACTION_DIR).exists());
    }

    #[test]
    fn corrupt_manifest_fails_closed_and_preserves_recovery_evidence() {
        let fixture = Fixture::new();
        let repo = CertmeshRepository::new(fixture.root.clone());
        let transaction_dir = fixture.root.join(TRANSACTION_DIR);
        std::fs::create_dir(&transaction_dir).unwrap();
        std::fs::write(transaction_dir.join(MANIFEST_FILE), b"{truncated").unwrap();

        assert!(repo.recover().is_err());
        assert!(transaction_dir.exists());
        fixture.assert_old_generation();
    }

    #[test]
    fn failed_rollback_preserves_the_journal_and_backups() {
        let fixture = Fixture::new();
        let repo = CertmeshRepository::new(fixture.root.clone());
        let (transaction_dir, manifest) = stage(&repo, fixture.transaction());
        repo.apply(&transaction_dir, &manifest, 1)
            .expect_err("stop after first replacement");
        let backup = manifest.entries[0]
            .backup
            .as_deref()
            .expect("first artifact has backup");
        std::fs::remove_file(transaction_dir.join(backup)).unwrap();

        assert!(repo.recover().is_err());
        assert!(transaction_dir.exists());
        assert!(transaction_dir.join(MANIFEST_FILE).exists());
    }

    #[test]
    fn invalid_commit_marker_is_not_an_acknowledgement() {
        let fixture = Fixture::new();
        let repo = CertmeshRepository::new(fixture.root.clone());
        let (transaction_dir, manifest) = stage(&repo, fixture.transaction());
        repo.apply(&transaction_dir, &manifest, -1)
            .expect("apply transaction");
        std::fs::write(transaction_dir.join(COMMITTED_FILE), b"").unwrap();

        repo.recover().expect("invalid marker rolls back");
        fixture.assert_old_generation();
    }

    #[test]
    fn independent_repositories_serialize_complete_write_sets() {
        let fixture = Fixture::new();
        let first = std::sync::Arc::new(CertmeshRepository::new(fixture.root.clone()));
        let second = std::sync::Arc::new(CertmeshRepository::new(fixture.root.clone()));
        let held = RepositoryLock::acquire(&fixture.root).expect("hold repository fence");
        let first_path = fixture.root.join("first");
        let second_path = fixture.root.join("second");
        let start = std::sync::Arc::new(std::sync::Barrier::new(3));

        let first_write = std::thread::spawn({
            let repository = std::sync::Arc::clone(&first);
            let start = std::sync::Arc::clone(&start);
            let path = first_path.clone();
            move || {
                start.wait();
                let mut transaction = ArtifactTransaction::new();
                transaction.write(path, b"first".to_vec(), true);
                repository.commit(transaction)
            }
        });
        let second_write = std::thread::spawn({
            let repository = std::sync::Arc::clone(&second);
            let start = std::sync::Arc::clone(&start);
            let path = second_path.clone();
            move || {
                start.wait();
                let mut transaction = ArtifactTransaction::new();
                transaction.write(path, b"second".to_vec(), true);
                repository.commit(transaction)
            }
        });
        start.wait();
        assert!(!first_path.exists());
        assert!(!second_path.exists());
        drop(held);

        assert!(matches!(
            first_write.join().unwrap().unwrap(),
            AtomicCommit::Durable
        ));
        assert!(matches!(
            second_write.join().unwrap().unwrap(),
            AtomicCommit::Durable
        ));
        assert_eq!(std::fs::read(first_path).unwrap(), b"first");
        assert_eq!(std::fs::read(second_path).unwrap(), b"second");
        assert!(!fixture.root.join(TRANSACTION_DIR).exists());
    }

    #[test]
    fn repository_lock_process_child() {
        let Some(root) = std::env::var_os(LOCK_CHILD_ROOT) else {
            return;
        };
        let root = PathBuf::from(root);
        std::fs::write(root.join("child-ready"), b"ready").expect("announce child admission");
        let repository = CertmeshRepository::new(root.clone());
        let mut transaction = ArtifactTransaction::new();
        transaction.write(root.join("child-effect"), b"settled".to_vec(), true);
        repository
            .commit_durable(transaction)
            .expect("child commit");
    }

    #[test]
    fn repository_fence_excludes_a_second_process() {
        let fixture = Fixture::new();
        let held = RepositoryLock::acquire(&fixture.root).expect("hold repository fence");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "repository::tests::repository_lock_process_child",
                "--nocapture",
            ])
            .env(LOCK_CHILD_ROOT, &fixture.root)
            .spawn()
            .expect("spawn repository contender");

        let ready = fixture.root.join("child-ready");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "child never reached the repository command");
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            !fixture.root.join("child-effect").exists(),
            "a second process crossed the held repository fence"
        );

        drop(held);
        let status = child.wait().expect("wait for repository contender");
        assert!(status.success());
        assert_eq!(
            std::fs::read(fixture.root.join("child-effect")).unwrap(),
            b"settled"
        );
    }
}
