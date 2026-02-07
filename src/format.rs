//! Human-readable CLI output formatting.
//!
//! This is the **presentation layer** for verb subcommands.
//! JSON output bypasses this module entirely — it goes through
//! `PipelineResponse` serialization in the protocol layer.

use std::collections::HashMap;

use crate::protocol::ServiceRecord;

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
