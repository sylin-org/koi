use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const STAGE_CREATE_ATTEMPTS: usize = 16;

/// Outcome of an atomic file replacement.
///
/// `DurabilityUncertain` is not a failed commit: the replacement is already visible, but the
/// platform reported an error while flushing the directory metadata that makes it survive a
/// crash. Callers must accept the visible value into their in-memory model and may additionally
/// surface or retry the durability warning.
#[derive(Debug)]
#[must_use = "an atomic commit outcome must be reconciled with the caller's in-memory state"]
pub enum AtomicCommit {
    Durable,
    DurabilityUncertain(io::Error),
}

/// Security metadata applied to an atomic write before its staged bytes become visible.
///
/// Unix modes are set on the newly created stage before any bytes are written, then travel with
/// that file through the atomic replacement. Other platforms ignore the Unix-only option while
/// retaining their native replacement guarantees.
#[derive(Debug, Clone, Copy, Default)]
pub struct AtomicWriteOptions {
    unix_mode: Option<u32>,
}

/// Content identity recorded beside a transaction backup.
///
/// Length catches truncation directly and SHA-256 makes recovery reject any
/// other changed backup rather than installing bytes it never checkpointed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileIntegrity {
    pub len: u64,
    pub sha256: String,
}

impl AtomicWriteOptions {
    pub const fn new() -> Self {
        Self { unix_mode: None }
    }

    /// Set the target's Unix permission bits before replacement.
    ///
    /// This option has no effect on non-Unix platforms.
    pub const fn with_unix_mode(mut self, mode: u32) -> Self {
        self.unix_mode = Some(mode);
        self
    }
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, io::Error> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn read_json_if_exists<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, io::Error> {
    if !path.exists() {
        return Ok(None);
    }
    read_json(path).map(Some)
}

pub fn read_json_or_default<T: DeserializeOwned + Default>(path: &Path) -> Result<T, io::Error> {
    match read_json_if_exists(path)? {
        Some(value) => Ok(value),
        None => Ok(T::default()),
    }
}

/// Atomically replace one JSON document without exposing a partially written target.
///
/// This compatibility surface accepts a visible replacement whose final metadata flush failed,
/// logs that loss of crash-durability at error level, and returns success so existing domain
/// models cannot remain behind disk. New repository code should use
/// [`write_json_pretty_commit`] when it can surface or retry the exact outcome.
pub fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), io::Error> {
    match write_json_pretty_commit(path, value)? {
        AtomicCommit::Durable => {}
        AtomicCommit::DurabilityUncertain(error) => {
            // The rename has happened. Treating this as an ordinary failure would leave every
            // legacy caller's memory/status behind the value it will read from disk immediately
            // and may read after restart. Preserve coherence and make the durability loss loud.
            tracing::error!(
                path = %path.display(),
                %error,
                "atomic replacement is visible, but its crash durability could not be confirmed"
            );
        }
    }
    Ok(())
}

/// Serialize and atomically replace one JSON document, retaining the exact commit outcome.
pub fn write_json_pretty_commit<T: Serialize>(path: &Path, value: &T) -> io::Result<AtomicCommit> {
    write_json_pretty_commit_with_options(path, value, AtomicWriteOptions::default())
}

/// Serialize and atomically replace one JSON document with pre-commit file metadata.
pub fn write_json_pretty_commit_with_options<T: Serialize>(
    path: &Path,
    value: &T,
    options: AtomicWriteOptions,
) -> io::Result<AtomicCommit> {
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_bytes_atomic_with_options(path, &json, options)
}

/// Atomically replace `path` with `bytes` without exposing partially written contents.
///
/// Every error returned through [`Err`] occurs before the replacement. Once replacement has
/// happened, a parent-directory flush failure is returned as
/// [`AtomicCommit::DurabilityUncertain`], allowing the domain to keep its live state coherent
/// with the newly visible file.
pub fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> io::Result<AtomicCommit> {
    write_bytes_atomic_with_options(path, bytes, AtomicWriteOptions::default())
}

/// Atomically replace `path` with `bytes`, applying file metadata before replacement.
pub fn write_bytes_atomic_with_options(
    path: &Path,
    bytes: &[u8],
    options: AtomicWriteOptions,
) -> io::Result<AtomicCommit> {
    write_bytes_atomic_with_options_and_prepare_stage(path, bytes, options, |_| Ok(()))
}

/// Atomically replace `path`, hardening its empty stage before any bytes are written.
///
/// `prepare_stage` runs after the stage has been created exclusively and after the options above
/// have been applied, but before `bytes` are copied into it. A preparation error removes the
/// empty stage and leaves an existing target untouched. The callback must only adjust security
/// metadata; it must not write, rename, or remove the staged file.
pub fn write_bytes_atomic_with_options_and_prepare_stage(
    path: &Path,
    bytes: &[u8],
    options: AtomicWriteOptions,
    prepare_stage: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<AtomicCommit> {
    write_bytes_atomic_with_options_and_sync(
        path,
        bytes,
        options,
        prepare_stage,
        DirectorySync::sync,
    )
}

/// Atomically create a new file, refusing to replace a path that appeared
/// concurrently.
///
/// The complete, synced contents are first written to a unique sibling. Unix
/// publishes that inode with `link(2)`; Windows uses a write-through move
/// without the replace flag. Both operations fail with `AlreadyExists` when a
/// concurrent creator won.
pub fn write_bytes_atomic_new_with_options(
    path: &Path,
    bytes: &[u8],
    options: AtomicWriteOptions,
) -> io::Result<AtomicCommit> {
    let parent = parent_directory(path);
    create_dir_all_durable(parent)?;

    let (stage, mut file) = create_unique_stage(path, options)?;
    let prepared = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = prepared {
        let _ = std::fs::remove_file(&stage);
        return Err(error);
    }

    let parent_sync = match DirectorySync::open(parent).and_then(|handle| {
        handle.sync()?;
        Ok(handle)
    }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = std::fs::remove_file(&stage);
            return Err(error);
        }
    };

    if let Err(error) = publish_file_new(&stage, path) {
        let _ = std::fs::remove_file(&stage);
        return Err(error);
    }

    let outcome = match parent_sync.sync() {
        Ok(()) => AtomicCommit::Durable,
        Err(error) => AtomicCommit::DurabilityUncertain(error),
    };

    // `hard_link` leaves the private stage name behind on Unix. The target is
    // already a complete commit, so failure to remove cleanup debris must not
    // be reported as a failed target commit.
    cleanup_published_stage(&stage, &parent_sync);
    Ok(outcome)
}

/// Copy a file through the same durable atomic-replacement boundary used by
/// byte and JSON persistence, returning the identity of the exact bytes that
/// were staged.
pub fn copy_file_atomic_with_options(
    source: &Path,
    target: &Path,
    options: AtomicWriteOptions,
) -> io::Result<(AtomicCommit, FileIntegrity)> {
    copy_file_atomic_with_options_and_prepare_stage(source, target, options, |_| Ok(()))
}

/// Copy a file atomically after hardening the empty stage and before copying
/// any source bytes into it.
pub fn copy_file_atomic_with_options_and_prepare_stage(
    source: &Path,
    target: &Path,
    options: AtomicWriteOptions,
    prepare_stage: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<(AtomicCommit, FileIntegrity)> {
    copy_file_atomic_checked(source, target, options, prepare_stage, None)
}

/// Copy and atomically replace only when the exact bytes staged still match a
/// previously recorded transaction identity.
///
/// This closes the validation/use gap during recovery: changing a backup
/// after the initial validation still fails before replacement becomes
/// visible.
pub fn copy_file_atomic_verified_with_options_and_prepare_stage(
    source: &Path,
    target: &Path,
    expected: &FileIntegrity,
    options: AtomicWriteOptions,
    prepare_stage: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<AtomicCommit> {
    copy_file_atomic_checked(source, target, options, prepare_stage, Some(expected))
        .map(|(outcome, _)| outcome)
}

fn copy_file_atomic_checked(
    source: &Path,
    target: &Path,
    options: AtomicWriteOptions,
    prepare_stage: impl FnOnce(&Path) -> io::Result<()>,
    expected: Option<&FileIntegrity>,
) -> io::Result<(AtomicCommit, FileIntegrity)> {
    let parent = parent_directory(target);
    create_dir_all_durable(parent)?;

    let mut source = std::fs::File::open(source)?;
    if !source.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic copy source is not a regular file",
        ));
    }
    let (stage, mut staged) = create_unique_stage(target, options)?;
    if let Err(error) = prepare_stage(&stage) {
        drop(staged);
        let _ = std::fs::remove_file(&stage);
        return Err(error);
    }

    let copied = copy_and_hash(&mut source, &mut staged).and_then(|integrity| {
        staged.sync_all()?;
        Ok(integrity)
    });
    drop(staged);
    let integrity = match copied {
        Ok(integrity) => integrity,
        Err(error) => {
            let _ = std::fs::remove_file(&stage);
            return Err(error);
        }
    };
    if let Some(expected) = expected {
        if expected != &integrity {
            let _ = std::fs::remove_file(&stage);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "atomic copy source changed: expected {} bytes / {}, staged {} bytes / {}",
                    expected.len, expected.sha256, integrity.len, integrity.sha256
                ),
            ));
        }
    }

    let parent_sync = match DirectorySync::open(parent).and_then(|handle| {
        handle.sync()?;
        Ok(handle)
    }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = std::fs::remove_file(&stage);
            return Err(error);
        }
    };
    let outcome = replace_then_sync(&stage, target, || parent_sync.sync());
    if outcome.is_err() {
        let _ = std::fs::remove_file(&stage);
    }
    outcome.map(|outcome| (outcome, integrity))
}

/// Copy a file into a new target without ever replacing a concurrently
/// created path.
pub fn copy_file_atomic_new_with_options_and_prepare_stage(
    source: &Path,
    target: &Path,
    options: AtomicWriteOptions,
    prepare_stage: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<(AtomicCommit, FileIntegrity)> {
    let parent = parent_directory(target);
    create_dir_all_durable(parent)?;

    let mut source = std::fs::File::open(source)?;
    if !source.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic copy source is not a regular file",
        ));
    }
    let (stage, mut staged) = create_unique_stage(target, options)?;
    if let Err(error) = prepare_stage(&stage) {
        drop(staged);
        let _ = std::fs::remove_file(&stage);
        return Err(error);
    }
    let copied = copy_and_hash(&mut source, &mut staged).and_then(|integrity| {
        staged.sync_all()?;
        Ok(integrity)
    });
    drop(staged);
    let integrity = match copied {
        Ok(integrity) => integrity,
        Err(error) => {
            let _ = std::fs::remove_file(&stage);
            return Err(error);
        }
    };

    let parent_sync = match DirectorySync::open(parent).and_then(|handle| {
        handle.sync()?;
        Ok(handle)
    }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = std::fs::remove_file(&stage);
            return Err(error);
        }
    };
    if let Err(error) = publish_file_new(&stage, target) {
        let _ = std::fs::remove_file(&stage);
        return Err(error);
    }
    let outcome = match parent_sync.sync() {
        Ok(()) => AtomicCommit::Durable,
        Err(error) => AtomicCommit::DurabilityUncertain(error),
    };
    cleanup_published_stage(&stage, &parent_sync);
    Ok((outcome, integrity))
}

/// Compute the integrity tuple used by installer recovery validation.
pub fn file_integrity(path: &Path) -> io::Result<FileIntegrity> {
    let mut source = std::fs::File::open(path)?;
    if !source.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut sink = io::sink();
    copy_and_hash(&mut source, &mut sink)
}

/// Remove a file and flush the containing directory.
///
/// A missing path is successful only after the parent has been flushed, which
/// also makes a prior interrupted removal durable on retry.
pub fn remove_file_durable(path: &Path) -> io::Result<AtomicCommit> {
    let parent = parent_directory(path);
    let parent_sync = match DirectorySync::open(parent) {
        Ok(parent) => parent,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !path.try_exists()? => {
            return Ok(AtomicCommit::Durable);
        }
        Err(error) => return Err(error),
    };
    parent_sync.sync()?;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(AtomicCommit::Durable);
        }
        Err(error) => return Err(error),
    }
    Ok(match parent_sync.sync() {
        Ok(()) => AtomicCommit::Durable,
        Err(error) => AtomicCommit::DurabilityUncertain(error),
    })
}

/// Reject a visible-but-not-proven-durable commit at boundaries which must be
/// crash-safe before a native side effect starts.
pub fn require_durable(outcome: AtomicCommit, action: impl fmt::Display) -> io::Result<()> {
    match outcome {
        AtomicCommit::Durable => Ok(()),
        AtomicCommit::DurabilityUncertain(error) => Err(io::Error::new(
            error.kind(),
            format!("{action} is visible, but crash durability is uncertain: {error}"),
        )),
    }
}

fn copy_and_hash(
    source: &mut impl io::Read,
    target: &mut impl io::Write,
) -> io::Result<FileIntegrity> {
    let mut hasher = Sha256::new();
    let mut len = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        target.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        len = len
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("file length overflow while hashing"))?;
    }
    Ok(FileIntegrity {
        len,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn cleanup_published_stage(stage: &Path, parent: &DirectorySync) {
    match std::fs::remove_file(stage) {
        Ok(()) => {
            if let Err(error) = parent.sync() {
                tracing::warn!(
                    path = %stage.display(),
                    %error,
                    "atomic create committed, but stage cleanup durability could not be confirmed"
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            path = %stage.display(),
            %error,
            "atomic create committed, but its stage could not be removed"
        ),
    }
}

/// Restrict an empty Windows secret-file stage before any secret bytes are written.
///
/// The local machine identity policy deliberately grants full control only to SYSTEM, the
/// built-in Administrators group, and (for an interactive invocation) the current process user.
/// Callers should pass this function to
/// [`write_bytes_atomic_with_options_and_prepare_stage`], so a failed ACL command remains a
/// pre-commit error and cannot expose either new bytes or a partially hardened target.
#[cfg(windows)]
pub fn restrict_windows_local_secret_acl(path: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // Passing the path directly lets Command preserve non-Unicode Windows paths and perform the
    // required CreateProcess quoting itself.
    let output = std::process::Command::new("icacls")
        .arg(path)
        .args(windows_local_secret_acl_args(
            std::env::var_os("USERNAME").as_deref(),
            std::env::var_os("COMPUTERNAME").as_deref(),
        ))
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(io::Error::other(format!(
        "icacls failed with {}{}",
        output.status,
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    )))
}

#[cfg(any(windows, test))]
fn windows_local_secret_acl_args(
    username: Option<&std::ffi::OsStr>,
    computer_name: Option<&std::ffi::OsStr>,
) -> Vec<std::ffi::OsString> {
    let mut args = [
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:F",
        "/grant:r",
        "BUILTIN\\Administrators:F",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<Vec<_>>();

    if let Some(username) = windows_interactive_acl_principal(username, computer_name) {
        let mut grant = username;
        grant.push(":F");
        args.push(std::ffi::OsString::from("/grant:r"));
        args.push(grant);
    }
    args
}

/// Restrict a Windows private directory to machine administrators and the
/// interactive caller. Service identities are already covered by SYSTEM and
/// must not be reinterpreted from the ambient `USERNAME` value.
#[cfg(windows)]
pub fn restrict_windows_private_directory_acl(path: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut args = [
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:(OI)(CI)F",
        "/grant:r",
        "BUILTIN\\Administrators:(OI)(CI)F",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<Vec<_>>();
    if let Some(mut principal) = windows_interactive_acl_principal(
        std::env::var_os("USERNAME").as_deref(),
        std::env::var_os("COMPUTERNAME").as_deref(),
    ) {
        principal.push(":(OI)(CI)F");
        args.push(std::ffi::OsString::from("/grant:r"));
        args.push(principal);
    }

    let output = std::process::Command::new("icacls")
        .arg(path)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(io::Error::other(format!(
        "icacls failed with {}{}",
        output.status,
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    )))
}

#[cfg(any(windows, test))]
fn windows_interactive_acl_principal(
    username: Option<&std::ffi::OsStr>,
    computer_name: Option<&std::ffi::OsStr>,
) -> Option<std::ffi::OsString> {
    let username = username?;
    let comparable = username.to_string_lossy();
    let username = comparable.trim();
    if username.is_empty()
        || username.eq_ignore_ascii_case("SYSTEM")
        || username.ends_with('$')
        || computer_name.is_some_and(|computer| {
            username.eq_ignore_ascii_case(&format!("{}$", computer.to_string_lossy().trim()))
        })
    {
        return None;
    }
    Some(std::ffi::OsString::from(username))
}

fn write_bytes_atomic_with_options_and_sync(
    path: &Path,
    bytes: &[u8],
    options: AtomicWriteOptions,
    prepare_stage: impl FnOnce(&Path) -> io::Result<()>,
    sync_committed_parent: impl FnOnce(&DirectorySync) -> io::Result<()>,
) -> io::Result<AtomicCommit> {
    let parent = parent_directory(path);
    create_dir_all_durable(parent)?;

    let (tmp, mut staged) = create_unique_stage(path, options)?;
    if let Err(error) = prepare_stage(&tmp) {
        drop(staged);
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    let prepared = staged.write_all(bytes).and_then(|()| staged.sync_all());
    drop(staged);
    if let Err(error) = prepared {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }

    // Establish and exercise the directory handle before the commit point. Unsupported
    // directory flushing and ordinary permission failures must not first appear after rename.
    let parent_sync = match DirectorySync::open(parent).and_then(|handle| {
        handle.sync()?;
        Ok(handle)
    }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
    };

    let committed = replace_then_sync(&tmp, path, || sync_committed_parent(&parent_sync));
    if committed.is_err() {
        // A replace failure leaves the stage at its original path. Once replace succeeds the
        // path no longer exists, and a post-commit sync failure is represented in the value.
        let _ = std::fs::remove_file(&tmp);
    }
    committed
}

/// Create `path` and every missing ancestor, flushing each new directory entry on Unix.
///
/// Windows has no equivalent portable directory flush through `std`; directory creation uses
/// the synchronous standard API, while replacement durability comes from
/// `MOVEFILE_WRITE_THROUGH`. Existing directories are validated but otherwise left untouched.
pub fn create_dir_all_durable(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }

    // An absolute walk gives a relative first component a real parent (`current_dir`) whose
    // entry can be flushed too. `create_dir_all` alone cannot tell us which ancestors were new.
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut missing = Vec::new();
    let mut cursor = path.as_path();
    loop {
        match std::fs::metadata(cursor) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a directory", cursor.display()),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{} has no existing ancestor", path.display()),
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }

    for directory in missing.into_iter().rev() {
        match std::fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !std::fs::metadata(&directory)?.is_dir() {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
        sync_directory(&directory)?;
        if let Some(parent) = directory.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(())
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn create_unique_stage(
    path: &Path,
    options: AtomicWriteOptions,
) -> io::Result<(PathBuf, std::fs::File)> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    create_unique_stage_with(path, options, || {
        format!(
            "koi-stage-{}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            uuid::Uuid::now_v7().simple()
        )
    })
}

fn create_unique_stage_with(
    path: &Path,
    options: AtomicWriteOptions,
    mut suffix: impl FnMut() -> String,
) -> io::Result<(PathBuf, std::fs::File)> {
    #[cfg(not(unix))]
    let _ = options;

    for _ in 0..STAGE_CREATE_ATTEMPTS {
        let tmp = staged_path(path, &suffix());
        let mut open = std::fs::OpenOptions::new();
        open.create_new(true).write(true);
        #[cfg(unix)]
        if let Some(mode) = options.unix_mode {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(mode);
        }
        match open.open(&tmp) {
            Ok(file) => {
                #[cfg(unix)]
                if let Some(mode) = options.unix_mode {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(mode))
                    {
                        drop(file);
                        let _ = std::fs::remove_file(&tmp);
                        return Err(error);
                    }
                }
                return Ok((tmp, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "could not allocate a unique atomic-write stage for {} after {STAGE_CREATE_ATTEMPTS} attempts",
            path.display()
        ),
    ))
}

fn staged_path(path: &Path, suffix: &str) -> PathBuf {
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(format!(".{suffix}.tmp"));
    PathBuf::from(tmp_name)
}

fn replace_then_sync(
    source: &Path,
    target: &Path,
    sync_parent: impl FnOnce() -> io::Result<()>,
) -> io::Result<AtomicCommit> {
    replace_file(source, target)?;
    Ok(match sync_parent() {
        Ok(()) => AtomicCommit::Durable,
        Err(error) => AtomicCommit::DurabilityUncertain(error),
    })
}

#[cfg(not(windows))]
fn publish_file_new(source: &Path, target: &Path) -> io::Result<()> {
    std::fs::hard_link(source, target)
}

#[cfg(windows)]
fn publish_file_new(source: &Path, target: &Path) -> io::Result<()> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct DirectorySync {
    #[cfg(unix)]
    directory: std::fs::File,
}

impl DirectorySync {
    fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                directory: std::fs::File::open(path)?,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(Self {})
        }
    }

    fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.directory.sync_all()
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Replace `target` with a staged file from the same filesystem.
///
/// Unix `rename(2)` already replaces atomically. Windows' Rust `rename` refuses
/// an existing destination, so use the native replace flag rather than deleting
/// the durable file first and creating a crash window.
#[cfg(not(windows))]
pub fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    std::fs::rename(source, target)
}

#[cfg(windows)]
pub fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    /// Concurrent replacers of one target transiently deny access to one
    /// another (sharing-violation class); a racing writer must cost latency,
    /// not a failed persist.
    const RETRY_WINDOW: Duration = Duration::from_secs(2);
    const RETRY_SLEEP: Duration = Duration::from_millis(10);

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let deadline = Instant::now() + RETRY_WINDOW;
    loop {
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } != 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        let transient = matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_ACCESS_DENIED as i32
                    || code == ERROR_SHARING_VIOLATION as i32
        );
        if !transient || Instant::now() + RETRY_SLEEP >= deadline {
            return Err(error);
        }
        std::thread::sleep(RETRY_SLEEP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("koi-persist-{name}-{nanos}"))
    }

    #[test]
    fn read_json_invalid_returns_invalid_data() {
        let dir = temp_path("invalid");
        let path = dir.join("bad.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "{broken json").unwrap();

        let err = read_json::<serde_json::Value>(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_json_or_default_missing_returns_default() {
        let dir = temp_path("missing");
        let path = dir.join("missing.json");

        let value: Vec<String> = read_json_or_default(&path).unwrap();
        assert!(value.is_empty());
    }

    #[test]
    fn write_json_pretty_creates_parent_dir() {
        let path = temp_path("write").join("nested").join("value.json");
        write_json_pretty(&path, &vec!["a", "b"]).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn atomic_apis_report_durable_success() {
        let root = temp_path("outcome-durable");
        let bytes_path = root.join("nested").join("value.bin");
        assert!(matches!(
            write_bytes_atomic(&bytes_path, b"complete bytes").unwrap(),
            AtomicCommit::Durable
        ));
        assert_eq!(std::fs::read(&bytes_path).unwrap(), b"complete bytes");

        let json_path = root.join("value.json");
        assert!(matches!(
            write_json_pretty_commit(&json_path, &vec!["a", "b"]).unwrap(),
            AtomicCommit::Durable
        ));
        assert_eq!(read_json::<Vec<String>>(&json_path).unwrap(), ["a", "b"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn atomic_create_new_has_exactly_one_winner() {
        let root = temp_path("create-new-race");
        std::fs::create_dir_all(&root).unwrap();
        let target = std::sync::Arc::new(root.join("config.toml"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        let workers = (0..12)
            .map(|index| {
                let target = std::sync::Arc::clone(&target);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let body = format!("writer={index}\n");
                    barrier.wait();
                    write_bytes_atomic_new_with_options(
                        &target,
                        body.as_bytes(),
                        AtomicWriteOptions::new().with_unix_mode(0o600),
                    )
                    .map(|outcome| (body, outcome))
                })
            })
            .collect::<Vec<_>>();

        let mut winner = None;
        for worker in workers {
            match worker.join().unwrap() {
                Ok((body, AtomicCommit::Durable)) => {
                    assert!(winner.replace(body).is_none(), "only one create may win");
                }
                Ok((_, AtomicCommit::DurabilityUncertain(error))) => {
                    panic!("test filesystem did not confirm create durability: {error}")
                }
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::AlreadyExists),
            }
        }
        assert_eq!(std::fs::read_to_string(&*target).unwrap(), winner.unwrap());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn atomic_copy_reports_the_identity_of_staged_bytes() {
        let root = temp_path("copy-integrity");
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let target = root.join("target");
        std::fs::write(&source, b"abc").unwrap();

        let (outcome, integrity) = copy_file_atomic_with_options(
            &source,
            &target,
            AtomicWriteOptions::new().with_unix_mode(0o600),
        )
        .unwrap();
        assert!(matches!(outcome, AtomicCommit::Durable));
        assert_eq!(integrity.len, 3);
        assert_eq!(
            integrity.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(file_integrity(&target).unwrap(), integrity);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn atomic_copy_new_refuses_to_replace_a_backup() {
        let root = temp_path("copy-new-no-clobber");
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let target = root.join("backup");
        std::fs::write(&source, b"new snapshot").unwrap();
        std::fs::write(&target, b"prior snapshot").unwrap();

        let error = copy_file_atomic_new_with_options_and_prepare_stage(
            &source,
            &target,
            AtomicWriteOptions::new().with_unix_mode(0o600),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"prior snapshot");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verified_copy_rejects_changed_source_before_replacement() {
        let root = temp_path("verified-copy");
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("backup");
        let target = root.join("target");
        std::fs::write(&source, b"checkpoint").unwrap();
        std::fs::write(&target, b"live state").unwrap();
        let expected = file_integrity(&source).unwrap();
        std::fs::write(&source, b"changed after validation").unwrap();

        let error = copy_file_atomic_verified_with_options_and_prepare_stage(
            &source,
            &target,
            &expected,
            AtomicWriteOptions::new().with_unix_mode(0o600),
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&target).unwrap(), b"live state");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn durable_remove_is_idempotent() {
        let root = temp_path("durable-remove");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        std::fs::write(&target, b"value").unwrap();
        assert!(matches!(
            remove_file_durable(&target).unwrap(),
            AtomicCommit::Durable
        ));
        assert!(!target.exists());
        assert!(matches!(
            remove_file_durable(&target).unwrap(),
            AtomicCommit::Durable
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn post_replace_sync_failure_is_an_accepted_uncertain_commit() {
        let root = temp_path("outcome-uncertain");
        create_dir_all_durable(&root).unwrap();
        let target = root.join("target");
        std::fs::write(&target, b"old value").unwrap();

        let outcome = write_bytes_atomic_with_options_and_sync(
            &target,
            b"new visible value",
            AtomicWriteOptions::new().with_unix_mode(0o600),
            |_| Ok(()),
            |_| Err(io::Error::other("injected post-replace sync failure")),
        )
        .expect("replacement itself succeeds");

        match outcome {
            AtomicCommit::DurabilityUncertain(error) => {
                assert_eq!(error.kind(), io::ErrorKind::Other);
                assert!(error.to_string().contains("post-replace sync failure"));
            }
            AtomicCommit::Durable => panic!("failed post-replace sync cannot report durable"),
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"new visible value");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stage_preparation_precedes_bytes_and_replacement() {
        let root = temp_path("stage-prepare-order");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        std::fs::write(&target, b"old value").unwrap();

        let outcome = write_bytes_atomic_with_options_and_prepare_stage(
            &target,
            b"new value",
            AtomicWriteOptions::default(),
            |stage| {
                assert_ne!(stage, target);
                assert_eq!(std::fs::metadata(stage)?.len(), 0);
                assert_eq!(std::fs::read(&target)?, b"old value");
                Ok(())
            },
        )
        .unwrap();

        assert!(matches!(outcome, AtomicCommit::Durable));
        assert_eq!(std::fs::read(&target).unwrap(), b"new value");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_stage_preparation_preserves_target_and_removes_empty_stage() {
        let root = temp_path("stage-prepare-failure");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        std::fs::write(&target, b"old value").unwrap();

        let error = write_bytes_atomic_with_options_and_prepare_stage(
            &target,
            b"secret bytes",
            AtomicWriteOptions::default(),
            |stage| {
                assert_eq!(std::fs::metadata(stage)?.len(), 0);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected stage-hardening failure",
                ))
            },
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&target).unwrap(), b"old value");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn windows_local_secret_acl_policy_is_intentionally_narrow() {
        use std::ffi::{OsStr, OsString};

        let machine_only = [
            "/inheritance:r",
            "/grant:r",
            "SYSTEM:F",
            "/grant:r",
            "BUILTIN\\Administrators:F",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();

        assert_eq!(
            windows_local_secret_acl_args(Some(OsStr::new("SYSTEM")), None),
            machine_only
        );
        assert_eq!(
            windows_local_secret_acl_args(Some(OsStr::new("")), None),
            machine_only
        );
        assert_eq!(
            windows_local_secret_acl_args(
                Some(OsStr::new("LEO-MAIN$")),
                Some(OsStr::new("LEO-MAIN"))
            ),
            machine_only
        );

        let mut interactive = machine_only;
        interactive.extend([OsString::from("/grant:r"), OsString::from("Alice:F")]);
        assert_eq!(
            windows_local_secret_acl_args(Some(OsStr::new("Alice")), Some(OsStr::new("LEO-MAIN"))),
            interactive
        );
    }

    #[cfg(unix)]
    #[test]
    fn requested_unix_mode_is_present_on_stage_before_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("stage-mode");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target.json");
        let (staged, file) = create_unique_stage_with(
            &target,
            AtomicWriteOptions::new().with_unix_mode(0o640),
            || "mode-check".to_string(),
        )
        .unwrap();

        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o640);
        drop(file);
        std::fs::remove_file(staged).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn durable_directory_creation_builds_every_missing_ancestor() {
        let root = temp_path("durable-directories");
        let nested = root.join("one").join("two").join("three");
        create_dir_all_durable(&nested).unwrap();
        assert!(nested.is_dir());
        create_dir_all_durable(&nested).expect("existing directories are a no-op");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn preexisting_stage_collision_is_skipped_without_modification() {
        let root = temp_path("stage-collision");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target.json");
        let occupied = staged_path(&target, "occupied");
        let fresh = staged_path(&target, "fresh");
        std::fs::write(&occupied, b"do not touch").unwrap();
        let mut suffixes = ["occupied", "fresh"].into_iter();

        let (selected, file) =
            create_unique_stage_with(&target, AtomicWriteOptions::default(), || {
                suffixes.next().expect("two candidates suffice").to_string()
            })
            .unwrap();
        drop(file);

        assert_eq!(selected, fresh);
        assert_eq!(std::fs::read(&occupied).unwrap(), b"do not touch");
        std::fs::remove_file(selected).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_stage_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;

        let root = temp_path("stage-symlink");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target.json");
        let protected = root.join("protected");
        let occupied = staged_path(&target, "symlink");
        let fresh = staged_path(&target, "fresh");
        std::fs::write(&protected, b"protected contents").unwrap();
        symlink(&protected, &occupied).unwrap();
        let mut suffixes = ["symlink", "fresh"].into_iter();

        let (selected, file) =
            create_unique_stage_with(&target, AtomicWriteOptions::default(), || {
                suffixes.next().expect("two candidates suffice").to_string()
            })
            .unwrap();
        drop(file);

        assert_eq!(selected, fresh);
        assert_eq!(std::fs::read(&protected).unwrap(), b"protected contents");
        assert!(std::fs::symlink_metadata(&occupied)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_file(selected).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn write_json_pretty_fails_on_directory_path() {
        let dir = temp_path("dir");
        std::fs::create_dir_all(&dir).unwrap();

        let result = write_json_pretty(&dir, &vec!["a"]);
        assert!(result.is_err());
    }

    #[test]
    fn failed_replace_removes_its_staged_file() {
        let root = temp_path("cleanup");
        let target = root.join("target.json");
        std::fs::create_dir_all(&target).unwrap();

        assert!(write_json_pretty(&target, &vec!["a"]).is_err());
        let entries = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![target.file_name().unwrap()]);
    }

    #[test]
    fn write_json_pretty_concurrent_same_path_no_error() {
        // Regression: a deterministic temp file made concurrent writers to the
        // same path race on rename() (the loser hit ENOENT). With a unique temp
        // per write, many threads can write the same path without error.
        let dir = temp_path("concurrent");
        std::fs::create_dir_all(&dir).unwrap();
        let path = std::sync::Arc::new(dir.join("shared.json"));

        let handles: Vec<_> = (0..16)
            .map(|i| {
                let p = std::sync::Arc::clone(&path);
                std::thread::spawn(move || write_json_pretty(&p, &vec![i]))
            })
            .collect();

        for h in handles {
            h.join().unwrap().expect("concurrent write must not error");
        }
        assert!(path.exists());
        // The file is valid JSON written by exactly one of the writers.
        let _: Vec<i32> = read_json(&path).expect("final file is valid JSON");
    }
}
