//! Human-readable CLI output formatting.
//!
//! This is the **presentation layer** for verb subcommands.
//! JSON output bypasses this module entirely — it goes through
//! `PipelineResponse` serialization in the protocol layer.

use std::collections::HashMap;

use koi_common::types::ServiceRecord;

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

/// Format TXT record entries as inline `key=value` pairs.
fn txt_inline(txt: &HashMap<String, String>) -> String {
    txt.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
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
