//! Management-plane principal authorization (ADR-026 §5/§6).
//!
//! A caller presenting a client certificate that chains to the mesh CA is
//! authorized on a management transport by **CN → roster lookup**: active, not
//! revoked, not expired — else rejected with a named reason (never one opaque
//! error) and an audited, named failure event. This upgrades remote/attribution
//! scenarios without touching the loopback + DAT trust model (ADR-026 §7).

use chrono::Utc;

use crate::error::CertmeshError;
use crate::CertmeshCore;

/// Why a principal was refused management-plane access (ADR-026 §5).
///
/// The JSON error carries the ADR-020 `RejectReason` vocabulary (`unknown_signer`
/// / `revoked` / `expired`); the audit log carries the §6 event names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalReject {
    /// No roster member with this CN (ADR-020 `unknown_signer`).
    Unknown(String),
    /// The member's leaf certificate has expired (ADR-020 `expired`).
    Expired(String),
    /// The member has been revoked (ADR-020 `revoked`; reuses the existing
    /// boundary event name rather than minting a second one).
    Revoked(String),
}

impl PrincipalReject {
    /// The ADR-020 named reason for wire responses.
    pub fn reason(&self) -> &'static str {
        match self {
            PrincipalReject::Unknown(_) => "unknown_signer",
            PrincipalReject::Expired(_) => "expired",
            PrincipalReject::Revoked(_) => "revoked",
        }
    }

    /// The caller CN this rejection is about.
    pub fn cn(&self) -> &str {
        match self {
            PrincipalReject::Unknown(cn)
            | PrincipalReject::Expired(cn)
            | PrincipalReject::Revoked(cn) => cn,
        }
    }

    /// The ADR-026 §6 audit event name.
    fn audit_event(&self) -> &'static str {
        match self {
            PrincipalReject::Unknown(_) => "mtls_unknown_cn",
            PrincipalReject::Expired(_) => "mtls_expired_cn",
            // Revocation at a Koi boundary already audits under this name
            // (renew/promote/health); reuse it so one shape covers the concept.
            PrincipalReject::Revoked(_) => "mtls_revoked_rejected",
        }
    }
}

impl std::fmt::Display for PrincipalReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrincipalReject::Unknown(cn) => {
                write!(f, "{cn} is not a roster member")
            }
            PrincipalReject::Expired(cn) => {
                write!(f, "{cn}'s certificate has expired")
            }
            PrincipalReject::Revoked(cn) => {
                write!(f, "{cn} has been revoked from the mesh")
            }
        }
    }
}

impl From<PrincipalReject> for CertmeshError {
    fn from(rej: PrincipalReject) -> Self {
        CertmeshError::Forbidden(rej.to_string())
    }
}

impl CertmeshCore {
    /// Authorize a management-plane caller by its verified certificate CN
    /// (ADR-026 §5): an active roster member whose leaf is not expired passes;
    /// everyone else is refused with a [`PrincipalReject`] and the matching
    /// named audit event (audited before the error surfaces — the ADR-017 F9/F14
    /// discipline).
    ///
    /// Coarse by design for 1.0 (ADR-026 §5): any active principal holds the
    /// effective authority of the DAT holder minus human-only surfaces; scoping
    /// happens at route mounting, not per-principal.
    pub async fn authorize_principal(&self, cn: &str) -> Result<(), PrincipalReject> {
        let state = &self.state;
        let _transition = state.transition.lock().await;
        let rejection = {
            let roster = state.roster.lock();
            match roster.members.iter().find(|m| m.hostname == cn) {
                None => Some(PrincipalReject::Unknown(cn.to_string())),
                Some(member)
                    if member.status == crate::roster::MemberStatus::Revoked
                        || roster.is_revoked(cn) =>
                {
                    Some(PrincipalReject::Revoked(cn.to_string()))
                }
                Some(member) if member.cert_expires <= Utc::now() => {
                    Some(PrincipalReject::Expired(cn.to_string()))
                }
                Some(_) => None,
            }
        };
        if let Some(rejection) = rejection {
            if let Err(error) = state.commit_audit_under_transition(
                rejection.audit_event(),
                &[("hostname", cn), ("op", "management")],
            ) {
                // Authorization remains fail-closed even if observability is
                // degraded; never turn an audit I/O fault into access.
                tracing::error!(%error, "Could not persist principal rejection audit");
            }
            return Err(rejection);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::{CertPolicy, MemberRole, MemberStatus, Roster, RosterMember};
    use crate::CertmeshPaths;
    use chrono::Duration;

    fn paths(name: &str) -> CertmeshPaths {
        CertmeshPaths::with_data_dir(
            koi_common::test::ensure_data_dir("koi-certmesh-principal-tests").join(name),
        )
    }

    fn member(hostname: &str, status: MemberStatus, expires_in_days: i64) -> RosterMember {
        RosterMember {
            hostname: hostname.to_string(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: "fp".repeat(32),
            cert_expires: Utc::now() + Duration::days(expires_in_days),
            cert_sans: vec![hostname.to_string()],
            cert_path: String::new(),
            status,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        }
    }

    /// Build a core over a hand-written roster without initializing a CA:
    /// authorization reads only the roster + audit path.
    fn core_with_roster(name: &str, members: Vec<RosterMember>) -> CertmeshCore {
        let p = paths(name);
        let mut roster = Roster::new(true, false, None);
        roster.metadata.policy = CertPolicy::default();
        roster.members.extend(members);
        CertmeshCore::locked_with_paths(roster, p)
    }

    #[tokio::test]
    async fn active_member_passes_authorization() {
        let core = core_with_roster("active-ok", vec![member("web-01", MemberStatus::Active, 7)]);
        assert!(core.authorize_principal("web-01").await.is_ok());
    }

    #[tokio::test]
    async fn unknown_cn_is_rejected_and_audited() {
        let core = core_with_roster("unknown-cn", vec![]);
        let err = core.authorize_principal("ghost").await.unwrap_err();
        assert_eq!(err.reason(), "unknown_signer");
        assert_eq!(err.audit_event(), "mtls_unknown_cn");
    }

    #[tokio::test]
    async fn expired_member_is_rejected_with_named_reason() {
        // An EXPIRED-but-active roster row: exactly what a 7-day leaf becomes if
        // its renewal loop dies (ADR-027 makes this window tight by design).
        let core = core_with_roster(
            "expired-cn",
            vec![member("stale-01", MemberStatus::Active, -1)],
        );
        let err = core.authorize_principal("stale-01").await.unwrap_err();
        assert_eq!(err.reason(), "expired");
        assert_eq!(err.audit_event(), "mtls_expired_cn");
    }

    #[tokio::test]
    async fn revoked_member_is_rejected_reusing_the_boundary_event() {
        let core = core_with_roster(
            "revoked-cn",
            vec![member("bad-01", MemberStatus::Revoked, 7)],
        );
        let err = core.authorize_principal("bad-01").await.unwrap_err();
        assert_eq!(err.reason(), "revoked");
        assert_eq!(
            err.audit_event(),
            "mtls_revoked_rejected",
            "one revocation event across boundaries — not a duplicate"
        );
    }
}
