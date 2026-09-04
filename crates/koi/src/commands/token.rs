//! `koi token` — daemon access token (DAT) distribution utility.
//!
//! The daemon writes its current token to the breadcrumb file on startup; these
//! commands read it back so an operator can view it or mount it into a container
//! as a secret. Charter principle 5 — the secure path is the easy path: `show`
//! refuses to print the secret to a non-tty unless `--force`, and `write`
//! creates the file owner-only (0600 on Unix; ACL-restricted on Windows).

use std::io::{self, IsTerminal};
use std::path::Path;

use crate::cli::{TokenCommand, TokenSubcommand};
use koi_common::persist;

const TOKEN_FILE_UNIX_MODE: u32 = 0o600;

pub fn run(cmd: &TokenCommand, json: bool) -> anyhow::Result<()> {
    match &cmd.command {
        None => {
            eprintln!("Usage: koi token <show|write>");
            eprintln!("  koi token show           print the daemon token (tty only)");
            eprintln!("  koi token show --force   print even when stdout is not a tty");
            eprintln!("  koi token write <path>   write the token to a 0600 file for containers");
            Ok(())
        }
        Some(TokenSubcommand::Show { force }) => show(*force, json),
        Some(TokenSubcommand::Write { path }) => write(path),
    }
}

/// Reads the current daemon token from the breadcrumb, or returns a friendly
/// error if the daemon is not running.
fn load_token() -> anyhow::Result<String> {
    match koi_client::observe_local_daemon_access() {
        koi_client::LocalDaemonObservation::Present(access) => Ok(access.token),
        koi_client::LocalDaemonObservation::Absent => anyhow::bail!(
            "no daemon token found — is the Koi daemon running? The token is \
             available from the trusted local daemon while it is running."
        ),
        koi_client::LocalDaemonObservation::Uncertain(error) => anyhow::bail!(
            "the local daemon token could not be read safely because ownership is uncertain: {error}"
        ),
    }
}

fn show(force: bool, json: bool) -> anyhow::Result<()> {
    let token = load_token()?;

    // Never echo a secret into a pipe by accident.
    if !force && !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "refusing to print the daemon token to a non-tty (it could be captured in \
             logs or scrollback). Re-run with --force, or use `koi token write <path>` \
             to write a 0600 file for mounting."
        );
    }

    if json {
        crate::commands::print_json(&serde_json::json!({ "token": token }))?;
    } else {
        println!("{token}");
    }
    Ok(())
}

fn write(path: &Path) -> anyhow::Result<()> {
    let token = load_token()?;
    write_secret_file(path, &token)?;
    // Confirmation goes to stderr so stdout stays clean for scripting.
    eprintln!("Wrote daemon token to {} (owner-only)", path.display());
    Ok(())
}

fn write_secret_file(path: &Path, token: &str) -> anyhow::Result<()> {
    #[cfg(windows)]
    let outcome = write_secret_file_with_prepare_stage(
        path,
        token,
        persist::restrict_windows_local_secret_acl,
    )?;
    #[cfg(not(windows))]
    let outcome = write_secret_file_with_prepare_stage(path, token, |_| Ok(()))?;

    if let persist::AtomicCommit::DurabilityUncertain(error) = outcome {
        // Replacement already happened. Reporting a write failure here would contradict the
        // file containers and subsequent commands can immediately consume.
        tracing::error!(
            path = %path.display(),
            %error,
            "token file is visible, but its crash durability could not be confirmed"
        );
    }
    Ok(())
}

fn write_secret_file_with_prepare_stage(
    path: &Path,
    token: &str,
    prepare_stage: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<persist::AtomicCommit> {
    let contents = format!("{token}\n");
    persist::write_bytes_atomic_with_options_and_prepare_stage(
        path,
        contents.as_bytes(),
        persist::AtomicWriteOptions::new().with_unix_mode(TOKEN_FILE_UNIX_MODE),
        prepare_stage,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "koi-token-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    #[test]
    fn secret_file_atomically_replaces_the_complete_token() {
        let root = temp_root("atomic-replace");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("token");
        std::fs::write(&target, b"old-complete-token\n").unwrap();

        let outcome = write_secret_file_with_prepare_stage(&target, "replacement-token", |stage| {
            assert_ne!(stage, target);
            assert_eq!(std::fs::metadata(stage)?.len(), 0);
            assert_eq!(std::fs::read(&target)?, b"old-complete-token\n");
            Ok(())
        })
        .unwrap();

        assert!(matches!(outcome, persist::AtomicCommit::Durable));
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement-token\n");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_repairs_a_permissive_existing_mode() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("mode-repair");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("token");
        std::fs::write(&target, b"old-token\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();

        let outcome =
            write_secret_file_with_prepare_stage(&target, "replacement-token", |_| Ok(())).unwrap();

        assert!(matches!(outcome, persist::AtomicCommit::Durable));
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            TOKEN_FILE_UNIX_MODE
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn secret_file_preparation_failure_preserves_the_old_target() {
        let root = temp_root("prepare-failure");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("token");
        std::fs::write(&target, b"old-complete-token\n").unwrap();

        let error = write_secret_file_with_prepare_stage(&target, "must-not-be-exposed", |stage| {
            assert_eq!(std::fs::metadata(stage)?.len(), 0);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected token hardening failure",
            ))
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&target).unwrap(), b"old-complete-token\n");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }
}
