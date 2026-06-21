//! The trust-doctor report (`diagnose()`) — ADR-020 §13.
//!
//! The category's defining failure is **silence** (silent expiry / downgrade /
//! opaque failure / self-only diagnosis). So Koi's moat is **transparency of trust
//! state**: a structured, queryable report whose every finding carries a *distinct*
//! state, a cause, and an *exact, runnable* remedy — never one opaque error, and
//! never a fake aggregate "success" over things it cannot actually verify (the
//! mkcert-#182 honesty rule). The tool **fails loud**: it exits non-zero whenever
//! anything is RED.
//!
//! Wire types only (serde + schema for `/v1/certmesh/diagnose` and the dashboard);
//! the diagnosis *logic* lives in `koi-certmesh`, which reads identity/renewal/
//! roster state.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::posture::Posture;

/// The status of a single diagnosis check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Healthy.
    Ok,
    /// A warning — degraded but not failed (e.g. renewal due soon).
    Warn,
    /// A failure — something is broken now (e.g. cert expired / self revoked).
    Red,
    /// Not applicable in this posture (e.g. identity checks on an Open node).
    NotApplicable,
}

/// The overall rollup of a [`TrustDiagnosis`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosisStatus {
    /// Every check is `Ok`/`NotApplicable`.
    Healthy,
    /// At least one `Warn`, no `Red`.
    Degraded,
    /// At least one `Red` — the tool exits non-zero.
    Red,
}

/// One finding: a distinct state, a human-readable cause, and an exact remedy
/// (ADR-020 §13 — `miette`-style actionable help; the remedy must be runnable, and
/// runnable *remotely*).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DiagnosisCheck {
    /// Stable check id (e.g. `posture`, `renewal`, `self_revocation`).
    pub name: String,
    /// The check's status.
    pub status: CheckStatus,
    /// Human-readable state + cause.
    pub detail: String,
    /// The exact command (or action) that fixes it — present only when there is
    /// something to do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl DiagnosisCheck {
    fn new(name: &str, status: CheckStatus, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            status,
            detail: detail.into(),
            remedy: None,
        }
    }

    /// A healthy check.
    pub fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Ok, detail)
    }

    /// A check that does not apply in this posture.
    pub fn not_applicable(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::NotApplicable, detail)
    }

    /// A warning.
    pub fn warn(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Warn, detail)
    }

    /// A failure.
    pub fn red(name: &str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Red, detail)
    }

    /// Attach the exact remediation command/action.
    pub fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}

/// The trust-doctor's report (ADR-020 §13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TrustDiagnosis {
    /// This node's posture at diagnosis time.
    pub posture: Posture,
    /// The rollup (the worst check wins).
    pub overall: DiagnosisStatus,
    /// Every check, in order.
    pub checks: Vec<DiagnosisCheck>,
}

impl TrustDiagnosis {
    /// Build a diagnosis from its checks, computing the rollup (worst wins): any
    /// `Red` → `Red`, else any `Warn` → `Degraded`, else `Healthy`.
    pub fn from_checks(posture: Posture, checks: Vec<DiagnosisCheck>) -> Self {
        let overall = if checks.iter().any(|c| c.status == CheckStatus::Red) {
            DiagnosisStatus::Red
        } else if checks.iter().any(|c| c.status == CheckStatus::Warn) {
            DiagnosisStatus::Degraded
        } else {
            DiagnosisStatus::Healthy
        };
        Self {
            posture,
            overall,
            checks,
        }
    }

    /// Whether anything is RED — the tool must fail loud (exit non-zero) here.
    pub fn is_red(&self) -> bool {
        self.overall == DiagnosisStatus::Red
    }

    /// Process exit code: non-zero **only** when something is RED (warnings stay
    /// loud in the output but do not fail the command — ADR-020 §13).
    pub fn exit_code(&self) -> i32 {
        if self.is_red() {
            1
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollup_is_worst_check_wins() {
        let healthy = TrustDiagnosis::from_checks(
            Posture::OPEN,
            vec![
                DiagnosisCheck::ok("a", "fine"),
                DiagnosisCheck::not_applicable("b", "n/a"),
            ],
        );
        assert_eq!(healthy.overall, DiagnosisStatus::Healthy);
        assert_eq!(healthy.exit_code(), 0);
        assert!(!healthy.is_red());

        let degraded = TrustDiagnosis::from_checks(
            Posture::OPEN,
            vec![
                DiagnosisCheck::ok("a", "fine"),
                DiagnosisCheck::warn("b", "soon"),
            ],
        );
        assert_eq!(degraded.overall, DiagnosisStatus::Degraded);
        assert_eq!(
            degraded.exit_code(),
            0,
            "warnings are loud but not a failure"
        );

        let red = TrustDiagnosis::from_checks(
            Posture::OPEN,
            vec![
                DiagnosisCheck::warn("a", "soon"),
                DiagnosisCheck::red("b", "broken"),
            ],
        );
        assert_eq!(red.overall, DiagnosisStatus::Red);
        assert_eq!(red.exit_code(), 1, "RED must fail loud (non-zero)");
        assert!(red.is_red());
    }

    #[test]
    fn check_remedy_is_optional_and_omitted_when_absent() {
        let c = DiagnosisCheck::ok("posture", "Authenticated");
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("remedy").is_none(), "no remedy field when None");

        let c =
            DiagnosisCheck::red("renewal", "expired").with_remedy("koi certmesh join <endpoint>");
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["remedy"], "koi certmesh join <endpoint>");
        assert_eq!(json["status"], "red");
    }

    #[test]
    fn status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&CheckStatus::NotApplicable).unwrap(),
            r#""not_applicable""#
        );
        assert_eq!(
            serde_json::to_string(&DiagnosisStatus::Degraded).unwrap(),
            r#""degraded""#
        );
    }

    #[test]
    fn diagnosis_round_trips() {
        let d = TrustDiagnosis::from_checks(
            Posture::new(true, false),
            vec![DiagnosisCheck::ok("posture", "Authenticated")],
        );
        let json = serde_json::to_string(&d).unwrap();
        let back: TrustDiagnosis = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
