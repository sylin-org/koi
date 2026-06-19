//! Roster data model and persistence.
//!
//! The roster is the CA's source of truth - all enrolled members,
//! their certificates, and enrollment history.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use koi_common::persist;

/// The complete roster - serialized to `~/.koi/certmesh/roster.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Roster {
    pub metadata: RosterMetadata,
    pub members: Vec<RosterMember>,
    #[serde(default)]
    pub revocation_list: Vec<RevokedMember>,
}

/// Mesh-wide metadata set at creation time.
///
/// The mesh's security posture is two plain booleans:
/// - `enrollment_open` — whether the mesh is currently accepting new members.
/// - `requires_approval` — whether each join needs operator approval at the CA.
///
/// The named presets ("Just Me" / "My Team" / "My Organization") are UX labels
/// only; they are resolved to these booleans at create time and never persisted.
/// CA-held certificate lifecycle policy (ADR-017).
///
/// The CA owns the lifecycle: it applies `leaf_lifetime_days` when it signs, and
/// distributes the policy to members (via `/status` today; via the signed trust
/// bundle in a later phase) so they drive pull-renewal on the CA's schedule and
/// know how long past expiry they may still renew before they must re-enroll.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct CertPolicy {
    /// Issued-leaf validity, in days.
    pub leaf_lifetime_days: u32,
    /// Renew when fewer than this many days remain before expiry.
    pub renew_threshold_days: u32,
    /// Days past expiry a member may still pull-renew before re-enrollment.
    pub grace_days: u32,
}

impl Default for CertPolicy {
    /// Operator-ratified default: 90-day leaves, renew at 30 days remaining,
    /// 14-day post-expiry grace (ADR-017).
    fn default() -> Self {
        Self {
            leaf_lifetime_days: 90,
            renew_threshold_days: 30,
            grace_days: 14,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterMetadata {
    pub created_at: DateTime<Utc>,
    /// Whether the mesh is currently accepting new members.
    #[serde(default)]
    pub enrollment_open: bool,
    /// Whether enrollment requires operator approval.
    #[serde(default)]
    pub requires_approval: bool,
    /// Operator name recorded in the audit log (independent of any preset).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub operator: Option<String>,
    /// CA-held certificate lifecycle policy (ADR-017). Defaults to 90/30/14 for
    /// rosters created before the policy existed.
    #[serde(default)]
    pub policy: CertPolicy,
}

/// Whether the mesh is accepting new members.
///
/// This is the **wire** representation of [`RosterMetadata::enrollment_open`]
/// (see [`CertmeshStatus`](crate::protocol::CertmeshStatus)). The roster stores
/// a bool; this enum is derived from it for serialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentState {
    Open,
    Closed,
}

impl EnrollmentState {
    /// Map an `enrollment_open` bool to the wire enum.
    pub fn from_open(open: bool) -> Self {
        if open {
            Self::Open
        } else {
            Self::Closed
        }
    }
}

/// Role of a member in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Primary,
    Standby,
    Member,
    /// Non-Moss client (e.g. Rake on a workstation)
    Client,
}

/// Active/revoked status of a member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Active,
    Revoked,
}

/// Proxy configuration persisted per member (Phase 8).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyConfigEntry {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    #[serde(default)]
    pub allow_remote: bool,
}

/// A member enrolled in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterMember {
    pub hostname: String,
    pub role: MemberRole,
    pub enrolled_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrolled_by: Option<String>,
    pub cert_fingerprint: String,
    pub cert_expires: DateTime<Utc>,
    pub cert_sans: Vec<String>,
    pub cert_path: String,
    pub status: MemberStatus,
    /// Post-renewal reload hook command (Phase 3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reload_hook: Option<String>,
    /// Last health heartbeat timestamp (Phase 3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_seen: Option<DateTime<Utc>>,
    /// Pinned CA certificate fingerprint for cert pinning (Phase 3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pinned_ca_fingerprint: Option<String>,
    /// Proxy entries configured on this host (Phase 8).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_entries: Vec<ProxyConfigEntry>,
}

/// A revoked member record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedMember {
    pub hostname: String,
    pub revoked_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

const ROSTER_FILENAME: &str = "roster.json";

impl Roster {
    /// Create a minimal empty roster (for uninitialized state).
    pub fn empty() -> Self {
        Self {
            metadata: RosterMetadata {
                created_at: Utc::now(),
                enrollment_open: false,
                requires_approval: false,
                operator: None,
                policy: CertPolicy::default(),
            },
            members: Vec::new(),
            revocation_list: Vec::new(),
        }
    }

    /// Create a new empty roster from the two posture booleans.
    pub fn new(enrollment_open: bool, requires_approval: bool, operator: Option<String>) -> Self {
        Self {
            metadata: RosterMetadata {
                created_at: Utc::now(),
                enrollment_open,
                requires_approval,
                operator,
                policy: CertPolicy::default(),
            },
            members: Vec::new(),
            revocation_list: Vec::new(),
        }
    }

    /// Whether enrollment requires operator approval.
    pub fn requires_approval(&self) -> bool {
        self.metadata.requires_approval
    }

    /// Check if enrollment is currently open.
    pub fn is_enrollment_open(&self) -> bool {
        self.metadata.enrollment_open
    }

    /// The wire representation of the current enrollment state.
    pub fn enrollment_state(&self) -> EnrollmentState {
        EnrollmentState::from_open(self.metadata.enrollment_open)
    }

    /// Open the enrollment window.
    pub fn open_enrollment(&mut self) {
        self.metadata.enrollment_open = true;
    }

    /// Close the enrollment window.
    pub fn close_enrollment(&mut self) {
        self.metadata.enrollment_open = false;
    }

    /// Find a member by hostname.
    pub fn find_member(&self, hostname: &str) -> Option<&RosterMember> {
        self.members.iter().find(|m| m.hostname == hostname)
    }

    /// Check if a hostname is already enrolled.
    pub fn is_enrolled(&self, hostname: &str) -> bool {
        self.members
            .iter()
            .any(|m| m.hostname == hostname && m.status == MemberStatus::Active)
    }

    /// Check if a hostname has been revoked.
    pub fn is_revoked(&self, hostname: &str) -> bool {
        self.revocation_list.iter().any(|r| r.hostname == hostname)
    }

    /// Revoke a member and record the revocation entry.
    pub fn revoke_member(
        &mut self,
        hostname: &str,
        operator: Option<String>,
        reason: Option<String>,
    ) -> Result<(), String> {
        let member = self
            .find_member_mut(hostname)
            .ok_or_else(|| format!("member not found: {hostname}"))?;

        if member.status == MemberStatus::Revoked {
            return Ok(());
        }

        member.status = MemberStatus::Revoked;
        self.revocation_list.push(RevokedMember {
            hostname: hostname.to_string(),
            revoked_at: Utc::now(),
            revoked_by: operator,
            reason,
        });
        Ok(())
    }

    /// Number of active members.
    pub fn active_count(&self) -> usize {
        self.members
            .iter()
            .filter(|m| m.status == MemberStatus::Active)
            .count()
    }

    /// Find the active primary member.
    pub fn primary(&self) -> Option<&RosterMember> {
        self.members
            .iter()
            .find(|m| m.role == MemberRole::Primary && m.status == MemberStatus::Active)
    }

    /// Find all active standby members.
    pub fn standbys(&self) -> Vec<&RosterMember> {
        self.members
            .iter()
            .filter(|m| m.role == MemberRole::Standby && m.status == MemberStatus::Active)
            .collect()
    }

    /// Find a mutable reference to a member by hostname.
    pub fn find_member_mut(&mut self, hostname: &str) -> Option<&mut RosterMember> {
        self.members.iter_mut().find(|m| m.hostname == hostname)
    }

    /// Update the last_seen timestamp for a member.
    pub fn touch_member(&mut self, hostname: &str) {
        if let Some(m) = self.find_member_mut(hostname) {
            m.last_seen = Some(Utc::now());
        }
    }
}

/// Path to the roster file within the certmesh directory.
pub fn roster_path(certmesh_dir: &Path) -> PathBuf {
    certmesh_dir.join(ROSTER_FILENAME)
}

/// Save the roster to disk as pretty-printed JSON.
pub fn save_roster(roster: &Roster, path: &Path) -> Result<(), std::io::Error> {
    persist::write_json_pretty(path, roster)?;
    tracing::debug!(path = %path.display(), "Roster saved");
    Ok(())
}

/// Persist the roster off the async executor.
///
/// This is the single mechanical home for the
/// `clone → spawn_blocking(save_roster) → await` pattern used throughout the
/// crate. It owns the roster clone, the `spawn_blocking` hop, and the error
/// mapping; it does **not** touch the roster lock (callers clone under the lock
/// and drop it before calling).
///
/// # Failure mode
///
/// Returns [`CertmeshError::Io`] whenever the save does not complete — whether
/// the blocking task panicked (`JoinError`) or the underlying write failed
/// (`std::io::Error`). Both are surfaced as `Io` so call sites have one error
/// variant to handle. Callers decide the *policy*: propagate with `?`, or
/// `if let Err(e) = persist_roster(..).await { tracing::warn!(..) }` to warn and
/// continue.
pub(crate) async fn persist_roster(
    roster: &Roster,
    path: &Path,
) -> Result<(), crate::error::CertmeshError> {
    let roster_clone = roster.clone();
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || save_roster(&roster_clone, &path))
        .await
        .map_err(|e| std::io::Error::other(format!("roster save task: {e}")))
        .and_then(|r| r)
        .map_err(crate::error::CertmeshError::Io)
}

/// Load the roster from disk.
pub fn load_roster(path: &Path) -> Result<Roster, std::io::Error> {
    persist::read_json(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Posture booleans for the three named presets (UX labels only).
    const JUST_ME: (bool, bool) = (true, false);
    const MY_TEAM: (bool, bool) = (true, true);
    const MY_ORG: (bool, bool) = (false, true);

    #[test]
    fn new_roster_just_me_is_open() {
        let r = Roster::new(JUST_ME.0, JUST_ME.1, None);
        assert!(r.metadata.enrollment_open);
        assert!(!r.metadata.requires_approval);
        assert_eq!(r.enrollment_state(), EnrollmentState::Open);
        assert!(r.metadata.operator.is_none());
        assert!(r.members.is_empty());
        assert!(r.revocation_list.is_empty());
    }

    #[test]
    fn new_roster_organization_closed() {
        let r = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".to_string()));
        assert!(!r.metadata.enrollment_open);
        assert!(r.metadata.requires_approval);
        assert_eq!(r.enrollment_state(), EnrollmentState::Closed);
        assert_eq!(r.metadata.operator.as_deref(), Some("Admin"));
    }

    #[test]
    fn metadata_bools_round_trip_through_json() {
        // The two posture booleans must survive a serialize/deserialize cycle.
        let r = Roster::new(MY_TEAM.0, MY_TEAM.1, Some("Alice".to_string()));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"enrollment_open\":true"));
        assert!(json.contains("\"requires_approval\":true"));
        let back: Roster = serde_json::from_str(&json).unwrap();
        assert!(back.metadata.enrollment_open);
        assert!(back.metadata.requires_approval);
        assert_eq!(back.metadata.operator.as_deref(), Some("Alice"));
    }

    #[test]
    fn roster_serde_round_trip() {
        let mut r = Roster::new(MY_TEAM.0, MY_TEAM.1, Some("Alice".to_string()));
        r.members.push(RosterMember {
            hostname: "stone-01".to_string(),
            role: MemberRole::Primary,
            enrolled_at: Utc::now(),
            enrolled_by: Some("Alice".to_string()),
            cert_fingerprint: "abc123".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec!["stone-01".to_string(), "stone-01.local".to_string()],
            cert_path: "/home/koi/.koi/certs/stone-01".to_string(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: Some(Utc::now()),
            pinned_ca_fingerprint: Some("cafp123".to_string()),
            proxy_entries: Vec::new(),
        });

        let json = serde_json::to_string(&r).unwrap();
        let deserialized: Roster = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.members.len(), 1);
        assert_eq!(deserialized.members[0].hostname, "stone-01");
        assert_eq!(deserialized.members[0].role, MemberRole::Primary);
    }

    #[test]
    fn save_and_load_roster() {
        let dir = std::env::temp_dir().join("koi-certmesh-test-roster");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("roster.json");

        let r = Roster::new(JUST_ME.0, JUST_ME.1, None);
        save_roster(&r, &path).unwrap();
        let loaded = load_roster(&path).unwrap();

        assert!(loaded.metadata.enrollment_open);
        assert!(!loaded.metadata.requires_approval);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_and_count_members() {
        let mut r = Roster::new(JUST_ME.0, JUST_ME.1, None);
        assert_eq!(r.active_count(), 0);
        assert!(!r.is_enrolled("stone-01"));

        r.members.push(RosterMember {
            hostname: "stone-01".to_string(),
            role: MemberRole::Primary,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "abc".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec![],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });

        assert_eq!(r.active_count(), 1);
        assert!(r.is_enrolled("stone-01"));
        assert!(r.find_member("stone-01").is_some());
        assert!(r.find_member("stone-99").is_none());
    }

    #[test]
    fn backward_compat_deserialize_without_new_fields() {
        // Older roster JSON had no reload_hook, last_seen, or pinned_ca_fingerprint.
        // Verify it still deserializes cleanly via #[serde(default)]. The posture
        // booleans also default (false) when absent.
        let json = r#"{
            "metadata": {
                "created_at": "2026-02-01T00:00:00Z",
                "enrollment_open": true,
                "requires_approval": false
            },
            "members": [{
                "hostname": "old-host",
                "role": "primary",
                "enrolled_at": "2026-02-01T00:00:00Z",
                "cert_fingerprint": "abc",
                "cert_expires": "2026-03-01T00:00:00Z",
                "cert_sans": ["old-host"],
                "cert_path": "/certs/old-host",
                "status": "active"
            }]
        }"#;
        let r: Roster = serde_json::from_str(json).unwrap();
        assert_eq!(r.members.len(), 1);
        assert!(r.metadata.enrollment_open);
        assert!(!r.metadata.requires_approval);
        assert!(r.members[0].reload_hook.is_none());
        assert!(r.members[0].last_seen.is_none());
        assert!(r.members[0].pinned_ca_fingerprint.is_none());
    }

    #[test]
    fn standby_role_serde() {
        let json = r#""standby""#;
        let role: MemberRole = serde_json::from_str(json).unwrap();
        assert_eq!(role, MemberRole::Standby);

        let serialized = serde_json::to_string(&MemberRole::Standby).unwrap();
        assert_eq!(serialized, r#""standby""#);
    }

    #[test]
    fn primary_and_standbys_helpers() {
        let mut r = Roster::new(JUST_ME.0, JUST_ME.1, None);

        // No primary yet
        assert!(r.primary().is_none());
        assert!(r.standbys().is_empty());

        let make_member = |hostname: &str, role: MemberRole| RosterMember {
            hostname: hostname.to_string(),
            role,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec![],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        };

        r.members.push(make_member("stone-01", MemberRole::Primary));
        r.members.push(make_member("stone-02", MemberRole::Standby));
        r.members.push(make_member("stone-03", MemberRole::Member));
        r.members.push(make_member("stone-04", MemberRole::Standby));

        assert_eq!(r.primary().unwrap().hostname, "stone-01");
        let standbys = r.standbys();
        assert_eq!(standbys.len(), 2);
        assert!(standbys.iter().any(|m| m.hostname == "stone-02"));
        assert!(standbys.iter().any(|m| m.hostname == "stone-04"));
    }

    #[test]
    fn find_member_mut_and_touch() {
        let mut r = Roster::new(JUST_ME.0, JUST_ME.1, None);
        r.members.push(RosterMember {
            hostname: "stone-01".to_string(),
            role: MemberRole::Primary,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec![],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });

        // last_seen is None initially
        assert!(r.members[0].last_seen.is_none());

        // touch_member updates last_seen
        r.touch_member("stone-01");
        assert!(r.members[0].last_seen.is_some());

        // touch_member on unknown host is a no-op
        r.touch_member("nonexistent");

        // find_member_mut allows direct mutation
        let m = r.find_member_mut("stone-01").unwrap();
        m.reload_hook = Some("systemctl restart nginx".to_string());
        assert_eq!(
            r.members[0].reload_hook.as_deref(),
            Some("systemctl restart nginx"),
        );
    }

    // ── Enrollment window tests ────────────────────────────────────

    #[test]
    fn open_and_close_enrollment() {
        let mut r = Roster::new(MY_ORG.0, MY_ORG.1, Some("Admin".into()));
        assert!(!r.is_enrollment_open());
        assert_eq!(r.enrollment_state(), EnrollmentState::Closed);

        r.open_enrollment();
        assert!(r.is_enrollment_open());
        assert_eq!(r.enrollment_state(), EnrollmentState::Open);

        r.close_enrollment();
        assert!(!r.is_enrollment_open());
        assert_eq!(r.enrollment_state(), EnrollmentState::Closed);
    }

    #[test]
    fn new_fields_skip_serialization_when_none() {
        let member = RosterMember {
            hostname: "stone-01".to_string(),
            role: MemberRole::Primary,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp".to_string(),
            cert_expires: Utc::now(),
            cert_sans: vec![],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        };
        let json = serde_json::to_string(&member).unwrap();
        // None fields should not appear in JSON
        assert!(!json.contains("reload_hook"));
        assert!(!json.contains("last_seen"));
        assert!(!json.contains("pinned_ca_fingerprint"));
    }
}
