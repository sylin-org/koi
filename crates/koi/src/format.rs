//! Human-readable CLI output formatting.
//!
//! This is the **single presentation layer** for all CLI output.
//! JSON output bypasses this module entirely — it goes through
//! `PipelineResponse` serialization in the protocol layer.
//!
//! All functions return `String` so callers can `print!` the result
//! and the functions themselves are pure and testable.

use std::collections::HashMap;
use std::fmt::Write as _;

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

/// Format a single-line summary of a discovered service.
///
/// Format: `NAME\tTYPE\tIP:PORT\tHOST[\tTXT]\n`
pub fn service_line(record: &ServiceRecord) -> String {
    let ip_port = match (&record.ip, record.port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        (None, Some(port)) => format!("?:{port}"),
        (Some(ip), None) => ip.clone(),
        (None, None) => String::new(),
    };
    let host = record.host.as_deref().unwrap_or("");
    let txt = txt_inline(&record.txt);
    if txt.is_empty() {
        format!(
            "{}\t{}\t{}\t{}\n",
            record.name, record.service_type, ip_port, host
        )
    } else {
        format!(
            "{}\t{}\t{}\t{}\t{}\n",
            record.name, record.service_type, ip_port, host, txt
        )
    }
}

/// Format detailed multi-line info for a resolved service instance.
pub fn resolved_detail(record: &ServiceRecord) -> String {
    let mut out = format!("{}\n", record.name);
    let _ = writeln!(out, "  Type: {}", record.service_type);
    if let Some(host) = &record.host {
        let _ = writeln!(out, "  Host: {host}");
    }
    if let Some(ip) = &record.ip {
        let _ = writeln!(out, "  IP:   {ip}");
    }
    if let Some(port) = record.port {
        let _ = writeln!(out, "  Port: {port}");
    }
    if !record.txt.is_empty() {
        let txt = txt_inline(&record.txt);
        let _ = writeln!(out, "  TXT:  {txt}");
    }
    out
}

/// Format a lifecycle event from a subscribe stream.
///
/// Format: `[KIND]\tNAME\tTYPE\tIP:PORT\tHOST\n`
pub fn subscribe_event(kind: &str, record: &ServiceRecord) -> String {
    let detail = match (&record.ip, record.port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        _ => String::new(),
    };
    let host = record.host.as_deref().unwrap_or("");
    format!(
        "[{kind}]\t{}\t{}\t{}\t{}\n",
        record.name, record.service_type, detail, host
    )
}

// ── Client-mode browse/subscribe formatting ─────────────────────────

/// Format a browse event from a daemon SSE stream (JSON → human).
/// Returns `Some(line)` if there's something to print, `None` otherwise.
pub fn browse_event_json(json: &serde_json::Value, is_meta: bool) -> Option<String> {
    if let Some(found) = json.get("found") {
        if let Ok(record) = serde_json::from_value::<ServiceRecord>(found.clone()) {
            if is_meta {
                return Some(format!("{}\n", record.name));
            } else {
                return Some(service_line(&record));
            }
        }
    } else if json.get("event").and_then(|e| e.as_str()) == Some("removed") {
        if let Some(name) = json
            .get("service")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
        {
            return Some(format!("[removed]\t{name}\n"));
        }
    }
    None
}

/// Format a subscribe event from a daemon SSE stream (JSON → human).
/// Returns `Some(line)` if there's something to print, `None` otherwise.
pub fn subscribe_event_json(json: &serde_json::Value) -> Option<String> {
    if let Some(event_kind) = json.get("event").and_then(|e| e.as_str()) {
        if let Some(service) = json.get("service") {
            if let Ok(record) = serde_json::from_value::<ServiceRecord>(service.clone()) {
                return Some(subscribe_event(event_kind, &record));
            }
        }
    }
    None
}

// ── Admin formatting ────────────────────────────────────────────────

/// Format a single row in the admin registration table.
pub fn registration_row(reg: &AdminRegistration) -> String {
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
    format!(
        "{:<10} {:<20} {:<16} {:>5}  {:<10} {:<10}\n",
        id_short,
        name_short,
        reg.service_type,
        reg.port,
        format!("{:?}", reg.state).to_lowercase(),
        format!("{:?}", reg.mode).to_lowercase(),
    )
}

/// Format detailed multi-line info for a single admin registration.
pub fn registration_detail(reg: &AdminRegistration) -> String {
    let mut out = format!("{}\n", reg.name);
    let _ = writeln!(out, "  ID:           {}", reg.id);
    let _ = writeln!(out, "  Type:         {}", reg.service_type);
    let _ = writeln!(out, "  Port:         {}", reg.port);
    let _ = writeln!(out, "  Mode:         {:?}", reg.mode);
    let _ = writeln!(out, "  State:        {:?}", reg.state);
    if let Some(lease) = reg.lease_secs {
        let _ = writeln!(out, "  Lease:        {}s", lease);
    }
    if let Some(remaining) = reg.remaining_secs {
        let _ = writeln!(out, "  Remaining:    {}s", remaining);
    }
    let _ = writeln!(out, "  Grace:        {}s", reg.grace_secs);
    if let Some(session) = &reg.session_id {
        let _ = writeln!(out, "  Session:      {session}");
    }
    let _ = writeln!(out, "  Registered:   {}", reg.registered_at);
    let _ = writeln!(out, "  Last seen:    {}", reg.last_seen);
    if !reg.txt.is_empty() {
        let txt = reg
            .txt
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(out, "  TXT:          {txt}");
    }
    out
}

// ── Unified status formatting ───────────────────────────────────────

/// Format the daemon's unified status response (JSON → human).
pub fn unified_status(json: &serde_json::Value) -> String {
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let platform = json
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let uptime = json.get("uptime_secs").and_then(|v| v.as_u64());

    let mut out = format!("Koi v{version}\n");
    let _ = writeln!(out, "  Platform:  {platform}");
    if let Some(secs) = uptime {
        let _ = writeln!(out, "  Uptime:    {secs}s");
    }
    let _ = writeln!(out, "  Daemon:    running");

    if let Some(caps) = json.get("capabilities").and_then(|v| v.as_array()) {
        for cap in caps {
            let name = cap.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let summary = cap.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let healthy = cap
                .get("healthy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let marker = if healthy { "+" } else { "-" };
            let _ = writeln!(out, "  [{marker}] {name}:  {summary}");
        }
    }
    out
}

// ── Phase 3 certmesh formatting ────────────────────────────────────

/// Format success message after promoting a host to standby CA.
pub fn promote_success(hostname: &str) -> String {
    let mut out = String::from("\nPromotion complete!\n");
    let _ = writeln!(out, "  Hostname: {hostname}");
    let _ = writeln!(out, "  Role:     standby");
    let _ = writeln!(out);
    let _ = writeln!(out, "This node now holds an encrypted copy of the CA key.");
    let _ = writeln!(
        out,
        "It will take over automatically if the primary goes offline."
    );
    out
}

/// Format the result of a certificate renewal for a member.
/// Used by the renewal push flow when displaying results.
#[allow(dead_code)]
pub fn renewal_result(
    hostname: &str,
    success: bool,
    hook_result: Option<&koi_certmesh::protocol::HookResult>,
) -> String {
    let mut out = if success {
        format!("  [ok] {hostname}")
    } else {
        format!("  [fail] {hostname}")
    };
    if let Some(hr) = hook_result {
        if hr.success {
            out.push_str(" (hook: ok)\n");
        } else {
            out.push_str(" (hook: failed)\n");
        }
    } else {
        out.push('\n');
    }
    out
}

// ── Shared helpers ──────────────────────────────────────────────────

/// Format TXT record entries as inline `key=value` pairs.
fn txt_inline(txt: &HashMap<String, String>) -> String {
    txt.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use koi_mdns::protocol::{LeaseMode, LeaseState};

    fn test_record() -> ServiceRecord {
        ServiceRecord {
            name: "My NAS".into(),
            service_type: "_http._tcp".into(),
            host: Some("nas.local".into()),
            ip: Some("192.168.1.42".into()),
            port: Some(8080),
            txt: HashMap::from([("version".into(), "1.0".into())]),
        }
    }

    fn test_record_minimal() -> ServiceRecord {
        ServiceRecord {
            name: "Bare".into(),
            service_type: "_http._tcp".into(),
            host: None,
            ip: None,
            port: None,
            txt: HashMap::new(),
        }
    }

    fn test_admin_reg() -> AdminRegistration {
        AdminRegistration {
            id: "a1b2c3d4e5f6".into(),
            name: "My App".into(),
            service_type: "_http._tcp".into(),
            port: 8080,
            mode: LeaseMode::Heartbeat,
            state: LeaseState::Alive,
            lease_secs: Some(90),
            remaining_secs: Some(45),
            grace_secs: 30,
            session_id: Some("sess1234".into()),
            registered_at: "2026-01-15T10:00:00Z".into(),
            last_seen: "2026-01-15T10:01:00Z".into(),
            txt: HashMap::from([("env".into(), "prod".into())]),
        }
    }

    // ── txt_inline ──────────────────────────────────────────────────

    #[test]
    fn txt_inline_empty_map() {
        assert_eq!(txt_inline(&HashMap::new()), "");
    }

    #[test]
    fn txt_inline_single_entry() {
        let txt = HashMap::from([("version".into(), "1.0".into())]);
        assert_eq!(txt_inline(&txt), "version=1.0");
    }

    #[test]
    fn txt_inline_multiple_entries() {
        let txt = HashMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]);
        let result = txt_inline(&txt);
        // HashMap ordering is non-deterministic, so check both parts
        assert!(result.contains("a=1"));
        assert!(result.contains("b=2"));
        assert!(result.contains(' '));
    }

    // ── service_line ────────────────────────────────────────────────

    #[test]
    fn service_line_full_record() {
        let out = service_line(&test_record());
        assert!(out.contains("My NAS"));
        assert!(out.contains("_http._tcp"));
        assert!(out.contains("192.168.1.42:8080"));
        assert!(out.contains("nas.local"));
        assert!(out.contains("version=1.0"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn service_line_no_ip_shows_question_mark() {
        let record = ServiceRecord {
            ip: None,
            port: Some(80),
            ..test_record_minimal()
        };
        let out = service_line(&record);
        assert!(out.contains("?:80"));
    }

    #[test]
    fn service_line_ip_only_no_port() {
        let record = ServiceRecord {
            ip: Some("10.0.0.1".into()),
            port: None,
            ..test_record_minimal()
        };
        let out = service_line(&record);
        assert!(out.contains("10.0.0.1"));
        // ip_port should not have a colon since there's no port
        assert!(!out.contains("10.0.0.1:"));
    }

    #[test]
    fn service_line_no_ip_no_port() {
        let out = service_line(&test_record_minimal());
        // Should have empty ip_port field between tabs
        assert!(out.contains("\t\t"));
    }

    #[test]
    fn service_line_empty_txt_omits_fifth_column() {
        let out = service_line(&test_record_minimal());
        // 4 tab-separated columns = 3 tabs
        assert_eq!(out.matches('\t').count(), 3);
    }

    #[test]
    fn service_line_with_txt_has_fifth_column() {
        let out = service_line(&test_record());
        // 5 tab-separated columns = 4 tabs
        assert_eq!(out.matches('\t').count(), 4);
    }

    // ── resolved_detail ─────────────────────────────────────────────

    #[test]
    fn resolved_detail_full_record() {
        let out = resolved_detail(&test_record());
        assert!(out.starts_with("My NAS\n"));
        assert!(out.contains("  Type: _http._tcp"));
        assert!(out.contains("  Host: nas.local"));
        assert!(out.contains("  IP:   192.168.1.42"));
        assert!(out.contains("  Port: 8080"));
        assert!(out.contains("  TXT:  version=1.0"));
    }

    #[test]
    fn resolved_detail_minimal_omits_optional_fields() {
        let out = resolved_detail(&test_record_minimal());
        assert!(out.starts_with("Bare\n"));
        assert!(out.contains("  Type: _http._tcp"));
        assert!(!out.contains("Host:"));
        assert!(!out.contains("IP:"));
        assert!(!out.contains("Port:"));
        assert!(!out.contains("TXT:"));
    }

    // ── subscribe_event ─────────────────────────────────────────────

    #[test]
    fn subscribe_event_found() {
        let out = subscribe_event("found", &test_record());
        assert!(out.starts_with("[found]\t"));
        assert!(out.contains("My NAS"));
        assert!(out.contains("192.168.1.42:8080"));
        assert!(out.contains("nas.local"));
    }

    #[test]
    fn subscribe_event_removed_no_ip_port() {
        let out = subscribe_event("removed", &test_record_minimal());
        assert!(out.starts_with("[removed]\t"));
        // detail should be empty when no ip+port
        assert!(out.contains("\t\t"));
    }

    // ── browse_event_json ───────────────────────────────────────────

    #[test]
    fn browse_event_json_found_normal() {
        let json = serde_json::json!({
            "found": {
                "name": "Server",
                "type": "_http._tcp",
                "port": 80
            }
        });
        let out = browse_event_json(&json, false).unwrap();
        assert!(out.contains("Server"));
        assert!(out.contains("_http._tcp"));
    }

    #[test]
    fn browse_event_json_found_meta_mode() {
        let json = serde_json::json!({
            "found": {
                "name": "_http._tcp",
                "type": "_services._dns-sd._udp.local.",
                "port": 0
            }
        });
        let out = browse_event_json(&json, true).unwrap();
        assert_eq!(out, "_http._tcp\n");
    }

    #[test]
    fn browse_event_json_removed_event() {
        let json = serde_json::json!({
            "event": "removed",
            "service": { "name": "Dead Service" }
        });
        let out = browse_event_json(&json, false).unwrap();
        assert_eq!(out, "[removed]\tDead Service\n");
    }

    #[test]
    fn browse_event_json_unknown_returns_none() {
        let json = serde_json::json!({"status": "ongoing"});
        assert!(browse_event_json(&json, false).is_none());
    }

    // ── subscribe_event_json ────────────────────────────────────────

    #[test]
    fn subscribe_event_json_formats_event() {
        let json = serde_json::json!({
            "event": "resolved",
            "service": {
                "name": "My Service",
                "type": "_http._tcp",
                "host": "host.local",
                "ip": "10.0.0.1",
                "port": 443
            }
        });
        let out = subscribe_event_json(&json).unwrap();
        assert!(out.starts_with("[resolved]\t"));
        assert!(out.contains("My Service"));
        assert!(out.contains("10.0.0.1:443"));
    }

    #[test]
    fn subscribe_event_json_missing_event_returns_none() {
        let json = serde_json::json!({"found": {}});
        assert!(subscribe_event_json(&json).is_none());
    }

    #[test]
    fn subscribe_event_json_missing_service_returns_none() {
        let json = serde_json::json!({"event": "found"});
        assert!(subscribe_event_json(&json).is_none());
    }

    // ── registration_row ────────────────────────────────────────────

    #[test]
    fn registration_row_truncates_long_id() {
        let reg = test_admin_reg();
        let out = registration_row(&reg);
        // ID "a1b2c3d4e5f6" > 8 chars, should be truncated to "a1b2c3d4"
        assert!(out.contains("a1b2c3d4"));
        assert!(!out.contains("e5f6"));
    }

    #[test]
    fn registration_row_short_id_not_truncated() {
        let mut reg = test_admin_reg();
        reg.id = "short".into();
        let out = registration_row(&reg);
        assert!(out.contains("short"));
    }

    #[test]
    fn registration_row_truncates_long_name() {
        let mut reg = test_admin_reg();
        reg.name = "This Is A Very Long Service Name".into();
        let out = registration_row(&reg);
        assert!(out.contains("This Is A Very ..."));
    }

    #[test]
    fn registration_row_shows_state_and_mode() {
        let out = registration_row(&test_admin_reg());
        assert!(out.contains("alive"));
        assert!(out.contains("heartbeat"));
    }

    #[test]
    fn registration_row_draining_permanent() {
        let mut reg = test_admin_reg();
        reg.state = LeaseState::Draining;
        reg.mode = LeaseMode::Permanent;
        let out = registration_row(&reg);
        assert!(out.contains("draining"));
        assert!(out.contains("permanent"));
    }

    // ── registration_detail ─────────────────────────────────────────

    #[test]
    fn registration_detail_all_fields() {
        let out = registration_detail(&test_admin_reg());
        assert!(out.contains("My App"));
        assert!(out.contains("ID:           a1b2c3d4e5f6"));
        assert!(out.contains("Type:         _http._tcp"));
        assert!(out.contains("Port:         8080"));
        assert!(out.contains("Mode:         Heartbeat"));
        assert!(out.contains("State:        Alive"));
        assert!(out.contains("Lease:        90s"));
        assert!(out.contains("Remaining:    45s"));
        assert!(out.contains("Grace:        30s"));
        assert!(out.contains("Session:      sess1234"));
        assert!(out.contains("Registered:   2026-01-15T10:00:00Z"));
        assert!(out.contains("Last seen:    2026-01-15T10:01:00Z"));
        assert!(out.contains("TXT:          env=prod"));
    }

    #[test]
    fn registration_detail_omits_optional_fields_when_none() {
        let mut reg = test_admin_reg();
        reg.lease_secs = None;
        reg.remaining_secs = None;
        reg.session_id = None;
        reg.txt = HashMap::new();
        let out = registration_detail(&reg);
        assert!(!out.contains("Lease:"));
        assert!(!out.contains("Remaining:"));
        assert!(!out.contains("Session:"));
        assert!(!out.contains("TXT:"));
    }

    // ── unified_status ──────────────────────────────────────────────

    #[test]
    fn unified_status_basic() {
        let json = serde_json::json!({
            "version": "0.2.0",
            "platform": "windows",
            "uptime_secs": 120
        });
        let out = unified_status(&json);
        assert!(out.contains("Koi v0.2.0"));
        assert!(out.contains("Platform:  windows"));
        assert!(out.contains("Uptime:    120s"));
        assert!(out.contains("Daemon:    running"));
    }

    #[test]
    fn unified_status_with_capabilities() {
        let json = serde_json::json!({
            "version": "0.2.0",
            "platform": "linux",
            "capabilities": [
                {"name": "mdns", "summary": "3 registered", "healthy": true},
                {"name": "certmesh", "summary": "locked", "healthy": false}
            ]
        });
        let out = unified_status(&json);
        assert!(out.contains("[+] mdns:  3 registered"));
        assert!(out.contains("[-] certmesh:  locked"));
    }

    #[test]
    fn unified_status_missing_fields_uses_defaults() {
        let json = serde_json::json!({});
        let out = unified_status(&json);
        assert!(out.contains("Koi vunknown"));
        assert!(out.contains("Platform:  unknown"));
        assert!(!out.contains("Uptime:"));
    }

    // ── promote_success ─────────────────────────────────────────────

    #[test]
    fn promote_success_output() {
        let out = promote_success("stone-05");
        assert!(out.contains("Promotion complete!"));
        assert!(out.contains("Hostname: stone-05"));
        assert!(out.contains("Role:     standby"));
        assert!(out.contains("encrypted copy of the CA key"));
        assert!(out.contains("take over automatically"));
    }

    // ── renewal_result ──────────────────────────────────────────────

    #[test]
    fn renewal_result_success_no_hook() {
        let out = renewal_result("stone-01", true, None);
        assert_eq!(out, "  [ok] stone-01\n");
    }

    #[test]
    fn renewal_result_failure_no_hook() {
        let out = renewal_result("stone-01", false, None);
        assert_eq!(out, "  [fail] stone-01\n");
    }

    #[test]
    fn renewal_result_success_hook_ok() {
        let hr = koi_certmesh::protocol::HookResult {
            success: true,
            command: "systemctl reload nginx".into(),
            output: None,
        };
        let out = renewal_result("stone-01", true, Some(&hr));
        assert_eq!(out, "  [ok] stone-01 (hook: ok)\n");
    }

    #[test]
    fn renewal_result_success_hook_failed() {
        let hr = koi_certmesh::protocol::HookResult {
            success: false,
            command: "bad-cmd".into(),
            output: Some("not found".into()),
        };
        let out = renewal_result("stone-01", true, Some(&hr));
        assert_eq!(out, "  [ok] stone-01 (hook: failed)\n");
    }

    #[test]
    fn renewal_result_failure_hook_failed() {
        let hr = koi_certmesh::protocol::HookResult {
            success: false,
            command: "bad-cmd".into(),
            output: None,
        };
        let out = renewal_result("stone-01", false, Some(&hr));
        assert_eq!(out, "  [fail] stone-01 (hook: failed)\n");
    }
}
