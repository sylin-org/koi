//! Human-readable CLI output formatting.
//!
//! This is the **single presentation layer** for all CLI output.
//! JSON output bypasses this module entirely — it goes through
//! `PipelineResponse` serialization in the protocol layer.

use std::collections::HashMap;

use koi_common::types::ServiceRecord;
use koi_mdns::protocol::AdminRegistration;

// ── Admin display constants ─────────────────────────────────────────

/// Max displayed length of registration IDs in tabular output.
const ID_DISPLAY_LEN: usize = 8;

/// Max displayed length of service names before truncation.
const NAME_DISPLAY_MAX: usize = 18;

/// Where to truncate service names (leaves room for "..." suffix).
const NAME_TRUNCATE_AT: usize = 15;

// ── mDNS formatting ─────────────────────────────────────────────────

/// Print a single-line summary of a discovered service.
///
/// Format: `NAME\tTYPE\tIP:PORT\tHOST[\tTXT]`
pub fn service_line(record: &ServiceRecord) {
    let ip_port = match (&record.ip, record.port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        (None, Some(port)) => format!("?:{port}"),
        (Some(ip), None) => ip.clone(),
        (None, None) => String::new(),
    };
    let host = record.host.as_deref().unwrap_or("");
    let txt = txt_inline(&record.txt);
    if txt.is_empty() {
        println!(
            "{}\t{}\t{}\t{}",
            record.name, record.service_type, ip_port, host
        );
    } else {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            record.name, record.service_type, ip_port, host, txt
        );
    }
}

/// Print detailed multi-line info for a resolved service instance.
pub fn resolved_detail(record: &ServiceRecord) {
    println!("{}", record.name);
    println!("  Type: {}", record.service_type);
    if let Some(host) = &record.host {
        println!("  Host: {host}");
    }
    if let Some(ip) = &record.ip {
        println!("  IP:   {ip}");
    }
    if let Some(port) = record.port {
        println!("  Port: {port}");
    }
    if !record.txt.is_empty() {
        let txt = txt_inline(&record.txt);
        println!("  TXT:  {txt}");
    }
}

/// Print a lifecycle event from a subscribe stream.
///
/// Format: `[KIND]\tNAME\tTYPE\tIP:PORT\tHOST`
pub fn subscribe_event(kind: &str, record: &ServiceRecord) {
    let detail = match (&record.ip, record.port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        _ => String::new(),
    };
    let host = record.host.as_deref().unwrap_or("");
    println!(
        "[{kind}]\t{}\t{}\t{}\t{}",
        record.name, record.service_type, detail, host
    );
}

// ── Client-mode browse/subscribe formatting ─────────────────────────

/// Format a browse event from a daemon SSE stream (JSON → human).
pub fn browse_event_json(json: &serde_json::Value, is_meta: bool) {
    if let Some(found) = json.get("found") {
        if let Ok(record) = serde_json::from_value::<ServiceRecord>(found.clone()) {
            if is_meta {
                println!("{}", record.name);
            } else {
                service_line(&record);
            }
        }
    } else if json.get("event").and_then(|e| e.as_str()) == Some("removed") {
        if let Some(name) = json
            .get("service")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
        {
            println!("[removed]\t{name}");
        }
    }
}

/// Format a subscribe event from a daemon SSE stream (JSON → human).
pub fn subscribe_event_json(json: &serde_json::Value) {
    if let Some(event_kind) = json.get("event").and_then(|e| e.as_str()) {
        if let Some(service) = json.get("service") {
            if let Ok(record) = serde_json::from_value::<ServiceRecord>(service.clone()) {
                subscribe_event(event_kind, &record);
            }
        }
    }
}

// ── Admin formatting ────────────────────────────────────────────────

/// Print a single row in the admin registration table.
pub fn registration_row(reg: &AdminRegistration) {
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

/// Print detailed multi-line info for a single admin registration.
pub fn registration_detail(reg: &AdminRegistration) {
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

// ── Unified status formatting ───────────────────────────────────────

/// Print the daemon's unified status response (JSON → human).
pub fn unified_status(json: &serde_json::Value) {
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let platform = json
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let uptime = json.get("uptime_secs").and_then(|v| v.as_u64());

    println!("Koi v{version}");
    println!("  Platform:  {platform}");
    if let Some(secs) = uptime {
        println!("  Uptime:    {secs}s");
    }
    println!("  Daemon:    running");

    if let Some(caps) = json.get("capabilities").and_then(|v| v.as_array()) {
        for cap in caps {
            let name = cap.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let summary = cap.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let healthy = cap
                .get("healthy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let marker = if healthy { "+" } else { "-" };
            println!("  [{marker}] {name}:  {summary}");
        }
    }
}

// ── Certmesh formatting ─────────────────────────────────────────────

/// Print a success message after CA creation.
pub fn certmesh_create_success(
    hostname: &str,
    cert_dir: &std::path::Path,
    profile: &koi_certmesh::profiles::TrustProfile,
    ca_fingerprint: &str,
) {
    println!("\nCertificate mesh created!");
    println!("  Profile:      {profile}");
    println!("  CA fingerprint: {ca_fingerprint}");
    println!("  Primary host: {hostname}");
    println!("  Certificates: {}", cert_dir.display());
}

/// Print the roster status for `koi certmesh status`.
pub fn certmesh_status(roster: &koi_certmesh::roster::Roster) {
    println!("Certificate Mesh Status");
    println!("  Profile:    {}", roster.metadata.trust_profile);
    println!(
        "  Enrollment: {:?}",
        roster.metadata.enrollment_state
    );
    if let Some(op) = &roster.metadata.operator {
        println!("  Operator:   {op}");
    }
    println!(
        "  Members:    {} active",
        roster.active_count()
    );
    println!();

    for member in &roster.members {
        let role = format!("{:?}", member.role).to_lowercase();
        let status = format!("{:?}", member.status).to_lowercase();
        println!(
            "  {} ({role}, {status})",
            member.hostname
        );
        println!(
            "    Fingerprint: {}",
            member.cert_fingerprint
        );
        println!(
            "    Expires:     {}",
            member.cert_expires.format("%Y-%m-%d")
        );
        println!(
            "    Cert path:   {}",
            member.cert_path
        );
    }
}

// ── Shared helpers ──────────────────────────────────────────────────

/// Format TXT record entries as inline `key=value` pairs.
fn txt_inline(txt: &HashMap<String, String>) -> String {
    txt.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}
