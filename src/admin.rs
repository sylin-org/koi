//! Admin CLI command handlers.
//!
//! These use `KoiClient` to manage a running daemon's registrations.

use crate::client::KoiClient;
use crate::protocol::AdminRegistration;

/// Max displayed length of registration IDs in tabular output.
const ID_DISPLAY_LEN: usize = 8;

/// Max displayed length of service names before truncation.
const NAME_DISPLAY_MAX: usize = 18;

/// Where to truncate service names (leaves room for "..." suffix).
const NAME_TRUNCATE_AT: usize = 15;

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
            format_registration_row(reg);
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
        println!("{}", body);
    } else {
        format_registration_detail(&reg);
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

// ── Formatting helpers ───────────────────────────────────────────────

fn format_registration_row(reg: &AdminRegistration) {
    let id_short = if reg.id.len() > ID_DISPLAY_LEN {
        &reg.id[..ID_DISPLAY_LEN]
    } else {
        &reg.id
    };
    let name_short = if reg.name.len() > NAME_DISPLAY_MAX {
        format!("{}...", &reg.name[..NAME_TRUNCATE_AT])
    } else {
        reg.name.clone()
    };
    println!(
        "{:<10} {:<20} {:<16} {:>5}  {:<10} {:<10}",
        id_short,
        name_short,
        reg.service_type,
        reg.port,
        format!("{:?}", reg.state).to_lowercase(),
        format!("{:?}", reg.mode).to_lowercase(),
    );
}

fn format_registration_detail(reg: &AdminRegistration) {
    println!("{}", reg.name);
    println!("  ID:           {}", reg.id);
    println!("  Type:         {}", reg.service_type);
    println!("  Port:         {}", reg.port);
    println!("  Mode:         {:?}", reg.mode);
    println!("  State:        {:?}", reg.state);
    if let Some(lease) = reg.lease_secs {
        println!("  Lease:        {}s", lease);
    }
    if let Some(remaining) = reg.remaining_secs {
        println!("  Remaining:    {}s", remaining);
    }
    println!("  Grace:        {}s", reg.grace_secs);
    if let Some(session) = &reg.session_id {
        println!("  Session:      {session}");
    }
    println!("  Registered:   {}", reg.registered_at);
    println!("  Last seen:    {}", reg.last_seen);
    if !reg.txt.is_empty() {
        let txt = reg
            .txt
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("  TXT:          {txt}");
    }
}
