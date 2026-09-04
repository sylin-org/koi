//! Factory reset command handler.
//!
//! Destroys the entire Koi data directory and recreates it from scratch.
//! If a daemon is running, attempts graceful shutdown first.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context as _;

use crate::client::{KoiClient, LocalDaemonObservation};

const OWNER_STOP_TIMEOUT: Duration = Duration::from_secs(20);
const OWNER_STOP_POLL: Duration = Duration::from_millis(100);

/// Execute the factory-reset command.
///
/// 1. Run the single destructive-confirmation gate (token word + danger line
///    come from the `factory-reset` CommandMeta). `--json`/non-tty without
///    `--yes` refuses; `--yes` skips the prompt.
/// 2. If a daemon is running (breadcrumb exists), shut it down gracefully.
/// 3. Remove the entire data directory.
/// 4. Print success message.
pub fn run(json: bool, yes: bool, data_dir: &Path) -> anyhow::Result<()> {
    // ── Confirmation gate ───────────────────────────────────────────
    // The one gate. Runs before any destructive action: a non-interactive
    // invocation (`--json` / piped) without `--yes` refuses up front, so
    // `koi --json factory-reset` no longer silently wipes data.
    let meta = crate::help::get("factory-reset")
        .ok_or_else(|| anyhow::anyhow!("internal: missing meta for 'factory-reset'"))?;
    crate::help::confirm::gate_meta(meta, json, yes)?;

    // ── Shut down running daemon if reachable ───────────────────────
    let daemon_was_running = stop_daemon_owner(data_dir)?;

    // ── Remove data directory ───────────────────────────────────────
    if data_dir.exists() {
        std::fs::remove_dir_all(data_dir).map_err(|e| {
            anyhow::anyhow!(
                "Failed to remove data directory {}: {e}\n\
                 You may need elevated permissions (run as administrator/root).",
                data_dir.display()
            )
        })?;
    }

    // ── Recreate empty data directory ───────────────────────────────
    koi_config::dirs::prepare_data_root(data_dir).with_context(|| {
        format!(
            "Failed to recreate and secure data directory {}",
            data_dir.display()
        )
    })?;

    // ── Output ──────────────────────────────────────────────────────
    if json {
        println!(
            "{}",
            serde_json::json!({
                "reset": true,
                "data_dir": data_dir.display().to_string(),
                "daemon_stopped": daemon_was_running,
            })
        );
    } else {
        println!("Factory reset complete.");
        println!("  Data directory: {}", data_dir.display());
        if daemon_was_running {
            println!("  Daemon was stopped before reset.");
        }
        println!();
        println!("Koi is now in a clean state. Run `koi install` to reinstall the service.");
    }
    Ok(())
}

/// Attempt to shut down a running daemon via the breadcrumb endpoint.
/// Returns `true` if a daemon was detected and shutdown was attempted.
fn stop_daemon_owner(data_dir: &Path) -> anyhow::Result<bool> {
    let access = match koi_client::observe_local_daemon_access() {
        LocalDaemonObservation::Present(access) => access,
        LocalDaemonObservation::Absent => return Ok(false),
        LocalDaemonObservation::Uncertain(error) => anyhow::bail!(
            "factory reset cannot prove whether a local Koi owner is running: {error}. No data was removed"
        ),
    };

    let active_root = match koi_client::observe_local_daemon_info() {
        LocalDaemonObservation::Present(info) => PathBuf::from(info.data_root),
        LocalDaemonObservation::Absent => anyhow::bail!(
            "the local Koi owner published HTTP access but not its control boundary. No data was removed"
        ),
        LocalDaemonObservation::Uncertain(error) => anyhow::bail!(
            "the local Koi owner did not provide an authoritative data root: {error}. No data was removed"
        ),
    };
    if !same_existing_root(data_dir, &active_root)? {
        anyhow::bail!(
            "the active Koi service owns {}, but this invocation selected {}. Refusing to reset a different root",
            active_root.display(),
            data_dir.display()
        );
    }

    let client = KoiClient::with_token(&access.endpoint, &access.token);
    client
        .shutdown()
        .context("requesting graceful shutdown from the local Koi owner")?;
    tracing::info!(endpoint = %access.endpoint, "Daemon shutdown requested successfully");

    let deadline = Instant::now() + OWNER_STOP_TIMEOUT;
    let mut last_uncertainty = None;
    loop {
        match koi_client::observe_local_daemon_access() {
            LocalDaemonObservation::Absent => return Ok(true),
            LocalDaemonObservation::Present(_) => {}
            LocalDaemonObservation::Uncertain(error) => {
                // Closing a local socket can briefly surface EOF/reset between
                // its last accepted session and path removal. It is never
                // evidence of absence, but the owner still has the rest of the
                // shutdown deadline to publish a positively absent boundary.
                last_uncertainty = Some(error.to_string());
            }
        }
        if Instant::now() >= deadline {
            let detail = last_uncertainty.as_deref().map_or(String::new(), |error| {
                format!(" Last observation: {error}.")
            });
            anyhow::bail!(
                "the local Koi owner did not release its discovery boundary within {} seconds.{detail} No data was removed",
                OWNER_STOP_TIMEOUT.as_secs(),
            )
        }
        std::thread::sleep(OWNER_STOP_POLL);
    }
}

fn same_existing_root(selected: &Path, active: &Path) -> anyhow::Result<bool> {
    let selected = std::fs::canonicalize(selected)
        .with_context(|| format!("resolving selected data root {}", selected.display()))?;
    let active = std::fs::canonicalize(active)
        .with_context(|| format!("resolving active data root {}", active.display()))?;
    #[cfg(windows)]
    {
        Ok(selected
            .to_string_lossy()
            .eq_ignore_ascii_case(&active.to_string_lossy()))
    }
    #[cfg(not(windows))]
    {
        Ok(selected == active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "koi-factory-reset-roots-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let first = base.join("first");
        let second = base.join("second");
        std::fs::create_dir_all(&first).expect("first root");
        std::fs::create_dir_all(&second).expect("second root");
        (first, second)
    }

    #[test]
    fn reset_target_must_be_the_active_existing_root() {
        let (first, second) = roots();
        assert!(same_existing_root(&first, &first).expect("same root"));
        assert!(!same_existing_root(&first, &second).expect("different roots"));
        std::fs::remove_dir_all(first.parent().expect("test base")).expect("remove roots");
    }

    #[cfg(unix)]
    #[test]
    fn reset_target_compares_filesystem_identity_not_spelling() {
        let (first, second) = roots();
        let alias = first.parent().expect("test base").join("alias");
        std::os::unix::fs::symlink(&first, &alias).expect("root alias");
        assert!(same_existing_root(&alias, &first).expect("aliased root"));
        std::fs::remove_dir_all(first.parent().expect("test base")).expect("remove roots");
        let _ = second;
    }
}
