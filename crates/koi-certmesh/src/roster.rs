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
            },
            members: Vec::new(),
            revocation_list: Vec::new(),
        }
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
        });

        assert_eq!(r.active_count(), 1);
        assert!(r.is_enrolled("stone-01"));
        assert!(r.find_member("stone-01").is_some());
        assert!(r.find_member("stone-99").is_none());
    }
}
