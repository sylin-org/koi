//! Roster data model and persistence.
//!
//! The roster is the CA's source of truth — all enrolled members,
//! their certificates, and enrollment history.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::profiles::TrustProfile;

/// The complete roster — serialized to `~/.koi/certmesh/roster.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Roster {
    pub metadata: RosterMetadata,
    pub members: Vec<RosterMember>,
    #[serde(default)]
    pub revocation_list: Vec<RevokedMember>,
}

/// Mesh-wide metadata set at creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterMetadata {
    pub created_at: DateTime<Utc>,
    pub trust_profile: TrustProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    pub enrollment_state: EnrollmentState,
    /// When the enrollment window automatically closes (if set).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enrollment_deadline: Option<DateTime<Utc>>,
    /// Domain scope constraint (e.g. "lincoln-elementary.local").
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allowed_domain: Option<String>,
    /// Subnet scope constraint as CIDR (e.g. "192.168.1.0/24").
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allowed_subnet: Option<String>,
}

/// Whether the mesh is accepting new members.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentState {
    Open,
    Closed,
}

/// Role of a member in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Primary,
    Standby,
    Member,
}

/// Active/revoked status of a member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Active,
    Revoked,
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
                trust_profile: TrustProfile::default(),
                operator: None,
                enrollment_state: EnrollmentState::Closed,
                enrollment_deadline: None,
                allowed_domain: None,
                allowed_subnet: None,
            },
            members: Vec::new(),
            revocation_list: Vec::new(),
        }
    }

    /// Create a new empty roster with the given profile.
    pub fn new(profile: TrustProfile, operator: Option<String>) -> Self {
        let enrollment_state = if profile.enrollment_default_open() {
            EnrollmentState::Open
        } else {
            EnrollmentState::Closed
        };

        Self {
            metadata: RosterMetadata {
                created_at: Utc::now(),
                trust_profile: profile,
                operator,
                enrollment_state,
                enrollment_deadline: None,
                allowed_domain: None,
                allowed_subnet: None,
            },
            members: Vec::new(),
            revocation_list: Vec::new(),
        }
    }

    /// Check if enrollment is currently open, considering both state and deadline.
    ///
    /// Returns `true` only if the state is `Open` AND any deadline has not passed.
    /// If the deadline has passed, this auto-closes enrollment and returns `false`.
    pub fn is_enrollment_open(&mut self) -> bool {
        if self.metadata.enrollment_state != EnrollmentState::Open {
            return false;
        }
        if let Some(deadline) = self.metadata.enrollment_deadline {
            if Utc::now() >= deadline {
                self.metadata.enrollment_state = EnrollmentState::Closed;
                self.metadata.enrollment_deadline = None;
                tracing::info!("Enrollment window expired, auto-closed");
                return false;
            }
        }
        true
    }

    /// Open the enrollment window, optionally with a deadline.
    pub fn open_enrollment(&mut self, deadline: Option<DateTime<Utc>>) {
        self.metadata.enrollment_state = EnrollmentState::Open;
        self.metadata.enrollment_deadline = deadline;
    }

    /// Close the enrollment window and clear any deadline.
    pub fn close_enrollment(&mut self) {
        self.metadata.enrollment_state = EnrollmentState::Closed;
        self.metadata.enrollment_deadline = None;
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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(roster)
        .map_err(std::io::Error::other)?;
    std::fs::write(path, json)?;
    tracing::debug!(path = %path.display(), "Roster saved");
    Ok(())
}

/// Load the roster from disk.
pub fn load_roster(path: &Path) -> Result<Roster, std::io::Error> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_roster_just_me() {
        let r = Roster::new(TrustProfile::JustMe, None);
        assert_eq!(r.metadata.trust_profile, TrustProfile::JustMe);
        assert_eq!(r.metadata.enrollment_state, EnrollmentState::Open);
        assert!(r.metadata.operator.is_none());
        assert!(r.members.is_empty());
        assert!(r.revocation_list.is_empty());
    }

    #[test]
    fn new_roster_organization_closed() {
        let r = Roster::new(
            TrustProfile::MyOrganization,
            Some("Admin".to_string()),
        );
        assert_eq!(r.metadata.enrollment_state, EnrollmentState::Closed);
        assert_eq!(r.metadata.operator.as_deref(), Some("Admin"));
    }

    #[test]
    fn roster_serde_round_trip() {
        let mut r = Roster::new(TrustProfile::MyTeam, Some("Alice".to_string()));
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

        let r = Roster::new(TrustProfile::JustMe, None);
        save_roster(&r, &path).unwrap();
        let loaded = load_roster(&path).unwrap();

        assert_eq!(loaded.metadata.trust_profile, TrustProfile::JustMe);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_and_count_members() {
        let mut r = Roster::new(TrustProfile::JustMe, None);
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
        });

        assert_eq!(r.active_count(), 1);
        assert!(r.is_enrolled("stone-01"));
        assert!(r.find_member("stone-01").is_some());
        assert!(r.find_member("stone-99").is_none());
    }

    #[test]
    fn backward_compat_deserialize_without_new_fields() {
        // Phase 2 roster JSON had no reload_hook, last_seen, or pinned_ca_fingerprint.
        // Verify old JSON still deserializes cleanly via #[serde(default)].
        let json = r#"{
            "metadata": {
                "created_at": "2026-02-01T00:00:00Z",
                "trust_profile": "just_me",
                "enrollment_state": "open"
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
        let mut r = Roster::new(TrustProfile::JustMe, None);

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
        let mut r = Roster::new(TrustProfile::JustMe, None);
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

    // ── Phase 4 — Enrollment window tests ──────────────────────────

    #[test]
    fn open_and_close_enrollment() {
        let mut r = Roster::new(TrustProfile::MyOrganization, Some("Admin".into()));
        assert_eq!(r.metadata.enrollment_state, EnrollmentState::Closed);
        assert!(!r.is_enrollment_open());

        r.open_enrollment(None);
        assert_eq!(r.metadata.enrollment_state, EnrollmentState::Open);
        assert!(r.is_enrollment_open());

        r.close_enrollment();
        assert_eq!(r.metadata.enrollment_state, EnrollmentState::Closed);
        assert!(!r.is_enrollment_open());
    }

    #[test]
    fn enrollment_with_deadline_auto_closes() {
        use chrono::Duration;
        let mut r = Roster::new(TrustProfile::JustMe, None);

        // Set deadline in the past
        let past = Utc::now() - Duration::seconds(10);
        r.open_enrollment(Some(past));

        // Should auto-close
        assert!(!r.is_enrollment_open());
        assert_eq!(r.metadata.enrollment_state, EnrollmentState::Closed);
        assert!(r.metadata.enrollment_deadline.is_none());
    }

    #[test]
    fn enrollment_with_future_deadline_stays_open() {
        use chrono::Duration;
        let mut r = Roster::new(TrustProfile::JustMe, None);

        let future = Utc::now() + Duration::hours(2);
        r.open_enrollment(Some(future));

        assert!(r.is_enrollment_open());
        assert_eq!(r.metadata.enrollment_state, EnrollmentState::Open);
        assert!(r.metadata.enrollment_deadline.is_some());
    }

    #[test]
    fn close_enrollment_clears_deadline() {
        use chrono::Duration;
        let mut r = Roster::new(TrustProfile::JustMe, None);
        r.open_enrollment(Some(Utc::now() + Duration::hours(1)));
        assert!(r.metadata.enrollment_deadline.is_some());

        r.close_enrollment();
        assert!(r.metadata.enrollment_deadline.is_none());
    }

    #[test]
    fn roster_metadata_scope_fields_serialize_when_set() {
        let mut r = Roster::new(TrustProfile::MyTeam, None);
        r.metadata.allowed_domain = Some("lab.local".to_string());
        r.metadata.allowed_subnet = Some("192.168.1.0/24".to_string());

        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("allowed_domain"));
        assert!(json.contains("lab.local"));
        assert!(json.contains("allowed_subnet"));
        assert!(json.contains("192.168.1.0/24"));
    }

    #[test]
    fn roster_metadata_scope_fields_skip_when_none() {
        let r = Roster::new(TrustProfile::JustMe, None);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("allowed_domain"));
        assert!(!json.contains("allowed_subnet"));
        assert!(!json.contains("enrollment_deadline"));
    }

    #[test]
    fn backward_compat_phase3_roster_without_phase4_fields() {
        // Phase 3 roster JSON had no allowed_domain, allowed_subnet, enrollment_deadline.
        let json = r#"{
            "metadata": {
                "created_at": "2026-02-01T00:00:00Z",
                "trust_profile": "just_me",
                "enrollment_state": "open"
            },
            "members": []
        }"#;
        let r: Roster = serde_json::from_str(json).unwrap();
        assert!(r.metadata.allowed_domain.is_none());
        assert!(r.metadata.allowed_subnet.is_none());
        assert!(r.metadata.enrollment_deadline.is_none());
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
        };
        let json = serde_json::to_string(&member).unwrap();
        // None fields should not appear in JSON
        assert!(!json.contains("reload_hook"));
        assert!(!json.contains("last_seen"));
        assert!(!json.contains("pinned_ca_fingerprint"));
    }
}
