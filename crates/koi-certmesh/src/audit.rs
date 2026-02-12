//! Append-only audit log for certmesh operations.
//!
//! Every security-relevant action is logged with a timestamp and metadata.
//! The log is human-readable and append-only (no edits, no deletes).

use std::path::{Path, PathBuf};

use chrono::Utc;

const AUDIT_FILENAME: &str = "certmesh-audit.log";

/// Path to the audit log file.
pub fn audit_log_path() -> PathBuf {
    koi_common::paths::koi_log_dir().join(AUDIT_FILENAME)
}

/// Append an audit entry with the given event name and key=value fields.
///
/// Format: `2026-02-11T10:30:00Z | pond_initialized | operator=Maria | profile=just_me`
pub fn append_entry(event: &str, fields: &[(&str, &str)]) -> Result<(), std::io::Error> {
    let path = audit_log_path();
    append_entry_to(&path, event, fields)
}

/// Append an audit entry to a specific path (for testing).
pub fn append_entry_to(
    path: &Path,
    event: &str,
    fields: &[(&str, &str)],
) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let mut line = format!("{timestamp} | {event}");

    for (key, value) in fields {
        line.push_str(&format!(" | {key}={value}"));
    }
    line.push('\n');

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(line.as_bytes())?;

    tracing::debug!(event, "Audit log entry written");
    Ok(())
}

/// Read all audit log entries from the default path.
pub fn read_log() -> Result<String, std::io::Error> {
    let path = audit_log_path();
    if path.exists() {
        std::fs::read_to_string(&path)
    } else {
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read_entries() {
        let dir = std::env::temp_dir().join("koi-certmesh-test-audit");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test-audit.log");

        append_entry_to(
            &path,
            "pond_initialized",
            &[("operator", "Alice"), ("profile", "just_me")],
        )
        .unwrap();

        append_entry_to(
            &path,
            "member_joined",
            &[("host", "stone-05"), ("approved_by", "Alice")],
        )
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("pond_initialized"));
        assert!(lines[0].contains("operator=Alice"));
        assert!(lines[1].contains("member_joined"));
        assert!(lines[1].contains("host=stone-05"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
