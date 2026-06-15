//! Factory reset command handler.
//!
//! Destroys the entire Koi data directory and recreates it from scratch.
//! If a daemon is running, attempts graceful shutdown first.

use crate::client::KoiClient;

/// Execute the factory-reset command.
///
/// 1. Run the single destructive-confirmation gate (token word + danger line
///    come from the `factory-reset` CommandMeta). `--json`/non-tty without
///    `--yes` refuses; `--yes` skips the prompt.
/// 2. If a daemon is running (breadcrumb exists), shut it down gracefully.
/// 3. Remove the entire data directory.
/// 4. Print success message.
pub fn run(json: bool, yes: bool) -> anyhow::Result<()> {
    // Per-process composition root: this CLI command has no running core.
    #[allow(clippy::disallowed_methods)]
    let data_dir = koi_common::paths::koi_data_dir();

    // ── Confirmation gate ───────────────────────────────────────────
    // The one gate. Runs before any destructive action: a non-interactive
    // invocation (`--json` / piped) without `--yes` refuses up front, so
    // `koi --json factory-reset` no longer silently wipes data.
    let meta = crate::help::get("factory-reset")
        .ok_or_else(|| anyhow::anyhow!("internal: missing meta for 'factory-reset'"))?;
    crate::help::confirm::gate_meta(meta, json, yes)?;

    // ── Shut down running daemon if reachable ───────────────────────
    let daemon_was_running = try_shutdown_daemon();

    // ── Remove data directory ───────────────────────────────────────
    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir).map_err(|e| {
            anyhow::anyhow!(
                "Failed to remove data directory {}: {e}\n\
                 You may need elevated permissions (run as administrator/root).",
                data_dir.display()
            )
        })?;
    }

    // ── Recreate empty data directory ───────────────────────────────
    std::fs::create_dir_all(&data_dir).map_err(|e| {
        anyhow::anyhow!(
            "Failed to recreate data directory {}: {e}",
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
fn try_shutdown_daemon() -> bool {
    let breadcrumb = match koi_config::breadcrumb::read_breadcrumb() {
        Some(bc) => bc,
        None => return false,
    };

    let client = KoiClient::with_token(&breadcrumb.endpoint, &breadcrumb.token);

    match client.shutdown() {
        Ok(()) => {
            tracing::info!("Daemon shutdown requested successfully");
            // Give the daemon a moment to wind down before we delete its files.
            std::thread::sleep(std::time::Duration::from_secs(2));
            true
        }
        Err(e) => {
            tracing::warn!("Could not shut down daemon (may already be stopped): {e}");
            // Breadcrumb exists but daemon is unreachable - stale breadcrumb.
            // Proceed with reset anyway.
            true
        }
    }
}
