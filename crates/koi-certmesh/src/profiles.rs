//! Trust profile definitions.
//!
//! Three profiles drive security defaults for the entire mesh lifecycle.
//! Selected once at `koi certmesh create` time and stored in roster metadata.

use serde::{Deserialize, Serialize};

/// Trust profile — drives security posture for the mesh.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrustProfile {
    /// Personal homelab. No approval required, enrollment always open.
    #[default]
    JustMe,
    /// Small office/lab. Approval required, operator tracked.
    MyTeam,
    /// Institution. Strict controls, enrollment closed by default.
    MyOrganization,
}

impl TrustProfile {
    /// Whether enrollment requires two-party approval at the CA.
    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::MyTeam | Self::MyOrganization)
    }

    /// Whether operator name is required and logged.
    pub fn requires_operator(&self) -> bool {
        matches!(self, Self::MyTeam | Self::MyOrganization)
    }

    /// Whether enrollment is open by default after CA creation.
    pub fn enrollment_default_open(&self) -> bool {
        matches!(self, Self::JustMe | Self::MyTeam)
    }

    /// Default certificate lifetime in days (30 for all profiles).
    pub fn cert_lifetime_days(&self) -> u32 {
        30
    }

    /// Parse from CLI string input.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "just-me" | "justme" | "personal" | "1" => Some(Self::JustMe),
            "team" | "my-team" | "myteam" | "2" => Some(Self::MyTeam),
            "organization" | "org" | "my-organization" | "myorganization" | "3" => {
                Some(Self::MyOrganization)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for TrustProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JustMe => write!(f, "Just Me"),
            Self::MyTeam => write!(f, "My Team"),
            Self::MyOrganization => write!(f, "My Organization"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn just_me_no_approval() {
        let p = TrustProfile::JustMe;
        assert!(!p.requires_approval());
        assert!(!p.requires_operator());
        assert!(p.enrollment_default_open());
        assert_eq!(p.cert_lifetime_days(), 30);
    }

    #[test]
    fn my_team_requires_approval() {
        let p = TrustProfile::MyTeam;
        assert!(p.requires_approval());
        assert!(p.requires_operator());
        assert!(p.enrollment_default_open());
    }

    #[test]
    fn my_organization_strict() {
        let p = TrustProfile::MyOrganization;
        assert!(p.requires_approval());
        assert!(p.requires_operator());
        assert!(!p.enrollment_default_open());
    }

    #[test]
    fn profile_serde_round_trip() {
        let profiles = vec![
            TrustProfile::JustMe,
            TrustProfile::MyTeam,
            TrustProfile::MyOrganization,
        ];
        for p in profiles {
            let json = serde_json::to_string(&p).unwrap();
            let deserialized: TrustProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(p, deserialized);
        }
    }

    #[test]
    fn profile_serializes_to_snake_case() {
        assert_eq!(serde_json::to_value(&TrustProfile::JustMe).unwrap(), "just_me");
        assert_eq!(serde_json::to_value(&TrustProfile::MyTeam).unwrap(), "my_team");
        assert_eq!(
            serde_json::to_value(&TrustProfile::MyOrganization).unwrap(),
            "my_organization"
        );
    }

    #[test]
    fn parse_from_string() {
        assert_eq!(TrustProfile::from_str_loose("just-me"), Some(TrustProfile::JustMe));
        assert_eq!(TrustProfile::from_str_loose("team"), Some(TrustProfile::MyTeam));
        assert_eq!(TrustProfile::from_str_loose("org"), Some(TrustProfile::MyOrganization));
        assert_eq!(TrustProfile::from_str_loose("1"), Some(TrustProfile::JustMe));
        assert_eq!(TrustProfile::from_str_loose("invalid"), None);
    }
}
