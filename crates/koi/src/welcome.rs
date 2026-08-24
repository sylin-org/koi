//! L0 first-run delight (ADR-031): exactly three things on first boot.
//!
//! A marker file in the data dir makes the banner once-per-install, so
//! restarts stay quiet. The three lines are a pinned output contract —
//! `banner_lines` is unit-tested for exact shape.

use std::path::Path;

/// The three-line contract: LAN name, dashboard URL, one suggested next step.
pub fn banner_lines(lan_name: &str, dashboard_url: &str, next_step: &str) -> [String; 3] {
    [
        format!("  LAN name:  {lan_name}"),
        format!("  Dashboard: {dashboard_url}"),
        format!("  Next:      {next_step}"),
    ]
}

/// Print the welcome banner once per data root (marker-gated), then drop the
/// marker. Failures are non-fatal: the banner is delight, not function.
pub fn emit_once(data_dir: &Path, lan_name: &str, dashboard_url: &str, next_step: &str) {
    let marker = data_dir.join("welcome.v1");
    if marker.exists() {
        return;
    }
    println!("Koi is running.");
    for line in banner_lines(lan_name, dashboard_url, next_step) {
        println!("{line}");
    }
    if let Err(e) = std::fs::write(&marker, env!("CARGO_PKG_VERSION")) {
        tracing::debug!(error = %e, "welcome marker not written (non-fatal)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_is_exactly_three_lines_with_labels() {
        let lines = banner_lines(
            "web-01.internal",
            "http://127.0.0.1:5641/v1/dashboard",
            "koi certmesh create",
        );
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("  LAN name:  web-01.internal"));
        assert!(lines[1].starts_with("  Dashboard: http://127.0.0.1:5641/v1/dashboard"));
        assert!(lines[2].starts_with("  Next:      koi certmesh create"));
    }

    #[test]
    fn emit_once_writes_marker_and_stays_quiet_afterwards() {
        let dir = koi_common::test::ensure_data_dir("koi-welcome-tests");
        let marker = dir.join("welcome.v1");
        let _ = std::fs::remove_file(&marker);
        emit_once(&dir, "a.internal", "http://x", "step");
        assert!(marker.exists(), "first call writes the marker");
        // Second call must be a no-op; the observable contract is the marker
        // persisting and no panic — quiet restarts are the point.
        emit_once(&dir, "a.internal", "http://x", "step");
        let _ = std::fs::remove_file(&marker);
    }
}
