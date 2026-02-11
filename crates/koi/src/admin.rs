//! Admin CLI command handlers.
//!
//! These use `KoiClient` to manage a running daemon's registrations.

use crate::client::KoiClient;
use crate::format;

// ── Status ──────────────────────────────────────────────────────────

pub fn status(endpoint: &str, json: bool) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    let status = client.admin_status()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Koi daemon v{}", status.version);
        println!("  Platform: {}", status.platform);
        println!("  Uptime:   {}s", status.uptime_secs);
        let r = &status.registrations;
        println!(
            "  Services: {} total ({} alive, {} draining, {} permanent)",
            r.total, r.alive, r.draining, r.permanent,
        );
    }
    Ok(())
}

// ── List ─────────────────────────────────────────────────────────────

pub fn list(endpoint: &str, json: bool) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    let registrations = client.admin_registrations()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&registrations)?);
    } else if registrations.is_empty() {
        println!("No registrations.");
    } else {
        println!(
            "{:<10} {:<20} {:<16} {:>5}  {:<10} {:<10}",
            "ID", "NAME", "TYPE", "PORT", "STATE", "MODE"
        );
        for reg in &registrations {
            format::registration_row(reg);
        }
    }
    Ok(())
}

// ── Inspect ──────────────────────────────────────────────────────────

pub fn inspect(endpoint: &str, id: &str, json: bool) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    let reg = client.admin_inspect(id)?;
    if json {
        let body = serde_json::to_string_pretty(&reg)?;
        println!("{body}");
    } else {
        format::registration_detail(&reg);
    }
    Ok(())
}

// ── Force unregister ─────────────────────────────────────────────────

pub fn unregister(endpoint: &str, id: &str, json: bool) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    client.admin_force_unregister(id)?;
    if json {
        println!(
            "{}",
            serde_json::json!({"unregistered": id, "source": "admin"})
        );
    } else {
        println!("Force-unregistered {id}");
    }
    Ok(())
}

// ── Drain ────────────────────────────────────────────────────────────

pub fn drain(endpoint: &str, id: &str, json: bool) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    client.admin_drain(id)?;
    if json {
        println!("{}", serde_json::json!({"drained": id}));
    } else {
        println!("Draining {id}");
    }
    Ok(())
}

// ── Revive ───────────────────────────────────────────────────────────

pub fn revive(endpoint: &str, id: &str, json: bool) -> anyhow::Result<()> {
    let client = KoiClient::new(endpoint);
    client.admin_revive(id)?;
    if json {
        println!("{}", serde_json::json!({"revived": id}));
    } else {
        println!("Revived {id}");
    }
    Ok(())
}
