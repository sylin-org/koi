//! One machine-local writer for native installation state.
//!
//! The lock inode is stable and deliberately retained between runs. Deleting
//! lock files creates split-brain opportunities when a waiter still holds the
//! old inode, so ownership is released only by closing the native handle.

use std::path::{Path, PathBuf};

const INSTALL_LOCK_FILENAME: &str = "koi-install.lock";

pub(crate) struct InstallLock {
    _file: std::fs::File,
}

impl InstallLock {
    /// Serialize mutations of the machine-global service, binary, and native
    /// firewall/service-manager objects even when two invocations selected
    /// different Koi data roots.
    pub(crate) fn acquire_system() -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        let path = PathBuf::from("/run/lock").join(INSTALL_LOCK_FILENAME);
        #[cfg(all(unix, not(target_os = "linux")))]
        let path = PathBuf::from("/var/run").join(INSTALL_LOCK_FILENAME);
        #[cfg(windows)]
        let path = {
            let program_data =
                std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
            PathBuf::from(program_data)
                .join("koi")
                .join("state")
                .join(INSTALL_LOCK_FILENAME)
        };
        Self::acquire_at(&path)
    }

    /// User installs still mutate one HOME-owned binary/unit shape. Keep the
    /// lock independent of a configurable Koi data root so two invocations
    /// cannot evade serialization by choosing different data directories.
    #[cfg(unix)]
    pub(crate) fn acquire_user() -> anyhow::Result<Self> {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("HOME is not set; cannot locate the user install lock")
            })?;
        Self::acquire_at(
            &PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("koi")
                .join(INSTALL_LOCK_FILENAME),
        )
    }

    fn acquire_at(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            koi_common::persist::create_dir_all_durable(parent)?;
        }
        let file = acquire_native(path).map_err(|error| {
            anyhow::anyhow!(
                "could not acquire installer lock {} (another install or recovery may be active): {error}",
                path.display()
            )
        })?;
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
fn acquire_native(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    // SAFETY: the descriptor belongs to `file` for the duration of the call;
    // `flock` neither retains it nor accesses Rust memory.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(windows)]
fn acquire_native(path: &Path) -> std::io::Result<std::fs::File> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_ALWAYS,
    };

    let path = path
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    // No sharing is the Windows lock: a second installer cannot open this
    // stable file until this handle closes.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_NONE,
            std::ptr::null(),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a unique owned handle and `File` becomes
    // its sole owner, closing it exactly once on drop.
    Ok(unsafe { std::fs::File::from_raw_handle(handle as RawHandle) })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE_PATH: &str = "KOI_INSTALL_LOCK_PROBE_PATH";
    const PROBE_EXPECT_FREE: &str = "KOI_INSTALL_LOCK_PROBE_EXPECT_FREE";

    fn test_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "koi-install-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn only_one_installer_can_hold_the_machine_lock() {
        let root = test_root();
        let path = root.join(INSTALL_LOCK_FILENAME);
        let first = InstallLock::acquire_at(&path).unwrap();
        let error = InstallLock::acquire_at(&path)
            .err()
            .expect("second lock fails");
        assert!(error.to_string().contains("another install or recovery"));
        drop(first);
        InstallLock::acquire_at(&path).expect("dropping the owner releases the lock");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn installer_lock_is_enforced_across_processes() {
        let root = test_root();
        let path = root.join(INSTALL_LOCK_FILENAME);
        let owner = InstallLock::acquire_at(&path).unwrap();

        run_process_probe(&path, false);
        drop(owner);
        run_process_probe(&path, true);

        let _ = std::fs::remove_dir_all(root);
    }

    fn run_process_probe(path: &Path, expect_free: bool) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("install_lock_process_probe")
            .env(PROBE_PATH, path)
            .env(PROBE_EXPECT_FREE, if expect_free { "1" } else { "0" })
            .status()
            .unwrap();
        assert!(status.success(), "child lock probe failed: {status}");
    }

    #[test]
    fn install_lock_process_probe() {
        let Some(path) = std::env::var_os(PROBE_PATH) else {
            return;
        };
        let expect_free =
            std::env::var_os(PROBE_EXPECT_FREE).as_deref() == Some(std::ffi::OsStr::new("1"));
        let acquired = InstallLock::acquire_at(Path::new(&path));
        assert_eq!(
            acquired.is_ok(),
            expect_free,
            "cross-process installer lock state did not match expectation"
        );
    }
}
