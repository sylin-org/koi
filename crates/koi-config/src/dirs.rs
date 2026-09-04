//! Explicit preparation of the daemon-owned data root.

use std::io;
use std::path::Path;

/// Create and secure the exact data root selected by the composition host.
///
/// Domain repositories create their own children when they commit domain
/// state. This boundary only establishes the private parent they share; it
/// never consults ambient path policy and never manufactures a config file.
pub fn prepare_data_root(data_dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    restrict_data_root(data_dir)
}

#[cfg(unix)]
fn restrict_data_root(data_dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn restrict_data_root(data_dir: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut command = std::process::Command::new("icacls");
    command.arg(data_dir).args([
        "/inheritance:r",
        "/grant:r",
        "SYSTEM:(OI)(CI)F",
        "/grant:r",
        "BUILTIN\\Administrators:(OI)(CI)F",
    ]);
    if let Some(username) = std::env::var_os("USERNAME") {
        let comparable = username.to_string_lossy();
        if !comparable.trim().is_empty() && !comparable.trim().eq_ignore_ascii_case("SYSTEM") {
            let mut grant = username;
            grant.push(":(OI)(CI)F");
            command.arg("/grant:r").arg(grant);
        }
    }
    let output = command.creation_flags(CREATE_NO_WINDOW).output()?;
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

#[cfg(not(any(unix, windows)))]
fn restrict_data_root(_data_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepares_only_the_injected_root() {
        let root = std::env::temp_dir().join(format!(
            "koi-explicit-data-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));

        prepare_data_root(&root).expect("prepare root");
        assert!(root.is_dir());
        assert_eq!(std::fs::read_dir(&root).expect("read root").count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&root)
                    .expect("root metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(root).expect("remove root");
    }
}
