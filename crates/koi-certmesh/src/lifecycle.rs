//! Certificate renewal and reload hook execution.
//!
//! The CA checks enrolled members on a periodic schedule and renews
//! certificates approaching expiry. After writing renewed cert files,
//! the member's reload hook (if set) is executed.

use std::process::Command;

use chrono::{Duration, Utc};

use crate::audit;
use crate::ca::{self, CaState, IssuedCert};
use crate::certfiles;
use crate::error::CertmeshError;
use crate::protocol::HookResult;
use crate::roster::{MemberStatus, Roster, RosterMember};

/// How often the renewal loop checks for expiring certs.
pub const RENEWAL_CHECK_INTERVAL_SECS: u64 = 3600; // 1 hour

/// Certificates are renewed when fewer than this many days remain.
const RENEWAL_THRESHOLD_DAYS: i64 = 10;

/// Return active members whose certificates expire within the renewal threshold.
pub fn members_needing_renewal(roster: &Roster) -> Vec<&RosterMember> {
    let threshold = Utc::now() + Duration::days(RENEWAL_THRESHOLD_DAYS);
    roster
        .members
        .iter()
        .filter(|m| m.status == MemberStatus::Active && m.cert_expires <= threshold)
        .collect()
}

/// Reissue a certificate for a member using the same SANs.
///
/// Delegates to `ca::issue_certificate()` — the roster member's
/// existing `cert_sans` are reused so the renewed cert is equivalent.
pub fn renew_member_cert(ca: &CaState, member: &RosterMember) -> Result<IssuedCert, CertmeshError> {
    ca::issue_certificate(ca, &member.hostname, &member.cert_sans)
}

/// Write renewed certificate files, overwriting the previous ones.
///
/// Returns the directory path where the files were written.
pub fn write_renewed_cert_files(
    hostname: &str,
    issued: &IssuedCert,
) -> Result<std::path::PathBuf, CertmeshError> {
    certfiles::write_cert_files(hostname, issued).map_err(CertmeshError::Io)
}

/// Execute a reload hook command after cert renewal.
///
/// Runs the command via the platform shell, captures stdout+stderr,
/// and returns a structured result. Never panics — failure is reported
/// in the `HookResult`.
pub fn execute_reload_hook(hook: &str) -> HookResult {
    let result = if cfg!(windows) {
        Command::new("cmd").args(["/C", hook]).output()
    } else {
        Command::new("sh").args(["-c", hook]).output()
    };

    match result {
        Ok(output) => {
            let combined = String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr);
            let trimmed = combined.trim().to_string();

            HookResult {
                success: output.status.success(),
                command: hook.to_string(),
                output: if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                },
            }
        }
        Err(e) => HookResult {
            success: false,
            command: hook.to_string(),
            output: Some(e.to_string()),
        },
    }
}

/// Renew a single member's cert and update the roster in place.
///
/// Performs the full cycle: issue → write files → update roster → audit log.
/// If the member has a reload hook, it is executed after the cert files are
/// written, and the result is returned.
pub fn renew_and_update_member(
    ca: &CaState,
    roster: &mut Roster,
    hostname: &str,
) -> Result<Option<HookResult>, CertmeshError> {
    let member = roster
        .find_member(hostname)
        .ok_or_else(|| CertmeshError::RenewalFailed {
            hostname: hostname.to_string(),
            reason: "member not found in roster".to_string(),
        })?;

    // Snapshot fields we need before mutating the roster
    let sans = member.cert_sans.clone();
    let reload_hook = member.reload_hook.clone();

    // Issue new cert with the same SANs
    let issued = ca::issue_certificate(ca, hostname, &sans)?;

    // Write cert files (overwrites existing)
    let cert_dir = certfiles::write_cert_files(hostname, &issued)?;

    // Update roster member
    let member = roster
        .find_member_mut(hostname)
        .ok_or_else(|| CertmeshError::RenewalFailed {
            hostname: hostname.to_string(),
            reason: "member vanished during renewal".to_string(),
        })?;
    member.cert_fingerprint = issued.fingerprint.clone();
    member.cert_expires = issued.expires;
    member.cert_path = cert_dir.display().to_string();

    // Audit log
    let _ = audit::append_entry(
        "cert_renewed",
        &[
            ("hostname", hostname),
            ("fingerprint", &issued.fingerprint),
            ("expires", &issued.expires.to_rfc3339()),
        ],
    );

    // Execute reload hook if set
    let hook_result = reload_hook.map(|hook| {
        let result = execute_reload_hook(&hook);
        if result.success {
            tracing::info!(hostname, hook = %result.command, "Reload hook succeeded");
        } else {
            tracing::warn!(
                hostname,
                hook = %result.command,
                output = ?result.output,
                "Reload hook failed (cert files remain updated)"
            );
        }
        let _ = audit::append_entry(
            "reload_hook_executed",
            &[
                ("hostname", hostname),
                ("command", &result.command),
                ("success", if result.success { "true" } else { "false" }),
            ],
        );
        result
    });

    Ok(hook_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca;
    use crate::profiles::TrustProfile;
    use crate::roster::{MemberRole, MemberStatus, Roster, RosterMember};
    use chrono::{Duration, Utc};

    fn make_test_ca() -> CaState {
        ca::create_ca("test-pass", &[42u8; 32]).unwrap()
    }

    fn make_member(hostname: &str, expires_in_days: i64) -> RosterMember {
        RosterMember {
            hostname: hostname.to_string(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp-placeholder".to_string(),
            cert_expires: Utc::now() + Duration::days(expires_in_days),
            cert_sans: vec![hostname.to_string(), format!("{hostname}.local")],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        }
    }

    #[test]
    fn members_needing_renewal_filters_by_threshold() {
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        // Expires in 5 days — needs renewal (< 10 day threshold)
        roster.members.push(make_member("expiring-soon", 5));
        // Expires in 25 days — does not need renewal
        roster.members.push(make_member("fresh-cert", 25));
        // Expires in 10 days — needs renewal (== threshold, <=)
        roster.members.push(make_member("edge-case", 10));

        let due = members_needing_renewal(&roster);
        assert_eq!(due.len(), 2);
        assert!(due.iter().any(|m| m.hostname == "expiring-soon"));
        assert!(due.iter().any(|m| m.hostname == "edge-case"));
    }

    #[test]
    fn members_needing_renewal_skips_revoked() {
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let mut member = make_member("revoked-host", 1);
        member.status = MemberStatus::Revoked;
        roster.members.push(member);

        let due = members_needing_renewal(&roster);
        assert!(due.is_empty());
    }

    #[test]
    fn members_needing_renewal_empty_roster() {
        let roster = Roster::new(TrustProfile::JustMe, None);
        let due = members_needing_renewal(&roster);
        assert!(due.is_empty());
    }

    #[test]
    fn already_expired_cert_needs_renewal() {
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        // Expired 2 days ago
        roster.members.push(make_member("already-expired", -2));

        let due = members_needing_renewal(&roster);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].hostname, "already-expired");
    }

    #[test]
    fn renew_member_cert_reuses_sans() {
        let ca = make_test_ca();
        let member = make_member("stone-05", 5);

        let issued = renew_member_cert(&ca, &member).unwrap();
        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.key_pem.contains("BEGIN PRIVATE KEY"));
        assert_eq!(issued.fingerprint.len(), 64);
        // Cert expires ~30 days from now (CERT_LIFETIME_DAYS)
        let days_until_expiry = (issued.expires - Utc::now()).num_days();
        assert!((29..=30).contains(&days_until_expiry));
    }

    #[test]
    fn execute_reload_hook_success() {
        let cmd = "echo ok";
        let result = execute_reload_hook(cmd);
        assert!(result.success);
        assert_eq!(result.command, cmd);
        assert!(result.output.is_some());
        assert!(result.output.unwrap().contains("ok"));
    }

    #[test]
    fn execute_reload_hook_failure() {
        let cmd = if cfg!(windows) {
            "cmd /C exit 1"
        } else {
            "exit 1"
        };
        let result = execute_reload_hook(cmd);
        assert!(!result.success);
    }

    #[test]
    fn execute_reload_hook_bad_command() {
        let result = execute_reload_hook("this-command-definitely-does-not-exist-xyz-9999");
        // On Unix, sh -c "bad-command" returns exit code 127 (success=false)
        // On Windows, cmd /C "bad-command" returns a non-zero exit code
        assert!(!result.success);
    }

    #[test]
    fn renew_and_update_member_updates_roster() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        roster.members.push(make_member("stone-05", 5));

        let old_fp = roster.members[0].cert_fingerprint.clone();
        let old_expires = roster.members[0].cert_expires;

        let hook_result = renew_and_update_member(&ca, &mut roster, "stone-05").unwrap();
        assert!(hook_result.is_none()); // No hook set

        // Roster should be updated
        let member = roster.find_member("stone-05").unwrap();
        assert_ne!(member.cert_fingerprint, old_fp);
        assert!(member.cert_expires > old_expires);
    }

    #[test]
    fn renew_and_update_member_not_found() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);

        let result = renew_and_update_member(&ca, &mut roster, "nonexistent");
        assert!(matches!(result, Err(CertmeshError::RenewalFailed { .. })));
    }

    #[test]
    fn renew_and_update_member_with_hook() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let mut member = make_member("stone-05", 5);
        let cmd = "echo renewed";
        member.reload_hook = Some(cmd.to_string());
        roster.members.push(member);

        let hook_result = renew_and_update_member(&ca, &mut roster, "stone-05").unwrap();
        assert!(hook_result.is_some());
        let hr = hook_result.unwrap();
        assert!(hr.success);
        assert!(hr.output.unwrap().contains("renewed"));
    }

    // ── Additional edge case tests ──────────────────────────────────

    #[test]
    fn members_needing_renewal_all_members_due() {
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        roster.members.push(make_member("host-a", 1));
        roster.members.push(make_member("host-b", 3));
        roster.members.push(make_member("host-c", 9));

        let due = members_needing_renewal(&roster);
        assert_eq!(due.len(), 3);
    }

    #[test]
    fn members_needing_renewal_none_due() {
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        roster.members.push(make_member("fresh-a", 20));
        roster.members.push(make_member("fresh-b", 30));

        let due = members_needing_renewal(&roster);
        assert!(due.is_empty());
    }

    #[test]
    fn members_needing_renewal_mixed_roles() {
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let mut primary = make_member("primary-host", 3);
        primary.role = MemberRole::Primary;
        let mut standby = make_member("standby-host", 3);
        standby.role = MemberRole::Standby;

        roster.members.push(primary);
        roster.members.push(standby);

        // All active members regardless of role should be included
        let due = members_needing_renewal(&roster);
        assert_eq!(due.len(), 2);
    }

    #[test]
    fn execute_reload_hook_empty_command() {
        // An empty command string should not panic
        let result = execute_reload_hook("");
        // On both platforms, empty string to sh/cmd produces a result
        // The specific behavior may vary, but it must not panic
        assert_eq!(result.command, "");
    }

    #[test]
    fn execute_reload_hook_captures_stderr() {
        let cmd = "echo stderr_msg >&2";
        let result = execute_reload_hook(cmd);
        assert!(result.success);
        // stderr is captured in the output
        assert!(result
            .output
            .as_deref()
            .unwrap_or("")
            .contains("stderr_msg"));
    }

    #[test]
    fn renew_and_update_member_updates_cert_path() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let mut member = make_member("stone-07", 5);
        member.cert_path = "old/path".to_string();
        roster.members.push(member);

        renew_and_update_member(&ca, &mut roster, "stone-07").unwrap();

        let member = roster.find_member("stone-07").unwrap();
        // cert_path should be updated to the actual write location
        assert_ne!(member.cert_path, "old/path");
    }

    #[test]
    fn renew_and_update_member_cert_expires_is_future() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        roster.members.push(make_member("stone-08", 5));

        renew_and_update_member(&ca, &mut roster, "stone-08").unwrap();

        let member = roster.find_member("stone-08").unwrap();
        // New cert should expire ~30 days from now
        let days_until_expiry = (member.cert_expires - Utc::now()).num_days();
        assert!(
            days_until_expiry >= 29,
            "cert should expire in ~30 days, got {days_until_expiry}"
        );
    }

    #[test]
    fn renew_and_update_member_fingerprint_is_sha256() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        roster.members.push(make_member("stone-09", 5));

        renew_and_update_member(&ca, &mut roster, "stone-09").unwrap();

        let member = roster.find_member("stone-09").unwrap();
        // SHA-256 fingerprints are 64 lowercase hex characters
        assert_eq!(member.cert_fingerprint.len(), 64);
        assert!(member
            .cert_fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn renew_member_cert_produces_distinct_fingerprints() {
        let ca = make_test_ca();
        let member = make_member("stone-10", 5);

        let issued1 = renew_member_cert(&ca, &member).unwrap();
        let issued2 = renew_member_cert(&ca, &member).unwrap();

        // Each issuance produces a unique key → unique fingerprint
        assert_ne!(issued1.fingerprint, issued2.fingerprint);
        assert_ne!(issued1.key_pem, issued2.key_pem);
    }

    #[test]
    fn renew_member_cert_fullchain_contains_both_certs() {
        let ca = make_test_ca();
        let member = make_member("stone-11", 5);

        let issued = renew_member_cert(&ca, &member).unwrap();
        // fullchain should contain both service cert and CA cert
        let cert_count = issued.fullchain_pem.matches("BEGIN CERTIFICATE").count();
        assert_eq!(
            cert_count, 2,
            "fullchain should have exactly 2 certificates"
        );
    }

    #[test]
    fn renew_and_update_member_with_failing_hook_still_updates_roster() {
        let ca = make_test_ca();
        let mut roster = Roster::new(TrustProfile::JustMe, None);
        let mut member = make_member("stone-12", 5);
        let cmd = if cfg!(windows) {
            "cmd /C exit 1"
        } else {
            "exit 1"
        };
        member.reload_hook = Some(cmd.to_string());
        roster.members.push(member);

        let old_fp = roster.members[0].cert_fingerprint.clone();
        let hook_result = renew_and_update_member(&ca, &mut roster, "stone-12").unwrap();

        // Hook failed but cert was still renewed
        assert!(hook_result.is_some());
        assert!(!hook_result.unwrap().success);

        // Roster should still be updated with new fingerprint
        let member = roster.find_member("stone-12").unwrap();
        assert_ne!(member.cert_fingerprint, old_fp);
    }
}
