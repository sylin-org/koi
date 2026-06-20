//! The trust-doctor *logic* (`diagnose()`) — ADR-020 §13.
//!
//! The report types live in `koi_common::diagnosis`; this assembles them from the
//! node's real trust state, **reusing** the P1–P5 primitives (posture,
//! `Identity`/`RenewalHealth`, the revoked set) rather than re-deriving any of it.
//! [`build_diagnosis`] is pure (all inputs passed in) so every branch is unit
//! -testable without a CA; `CertmeshCore::diagnose` gathers the inputs.
//!
//! Honesty rule (mkcert #182, ADR-020 §13): a check never reports a fake success
//! over something it cannot verify — e.g. OS trust-store membership is not
//! queryable via `os-truststore`, so that check states the limitation + the exact
//! remedy instead of claiming "installed".

use chrono::{DateTime, Utc};
use koi_common::diagnosis::{DiagnosisCheck, TrustDiagnosis};
use koi_common::posture::Posture;
use x509_parser::prelude::FromDer;

use crate::Identity;

/// Days-before-expiry under which an un-overdue leaf is flagged `Warn` ("soon").
const RENEW_SOON_DAYS: i64 = 7;

/// Whether the leaf certificate chains to the CA it carries — a real "is my
/// on-disk identity actually usable" check (catches a corrupted / half-written
/// identity). Parses both PEMs and verifies the leaf's signature against the CA's
/// public key (the same construction `verify_envelope` uses).
pub fn leaf_chains_to_ca(cert_pem: &str, ca_cert_pem: &str) -> bool {
    let (Some(leaf_der), Some(ca_der)) = (
        pem::parse(cert_pem).ok().map(|p| p.contents().to_vec()),
        pem::parse(ca_cert_pem).ok().map(|p| p.contents().to_vec()),
    ) else {
        return false;
    };
    let (Ok((_, leaf)), Ok((_, ca))) = (
        x509_parser::certificate::X509Certificate::from_der(&leaf_der),
        x509_parser::certificate::X509Certificate::from_der(&ca_der),
    ) else {
        return false;
    };
    leaf.verify_signature(Some(ca.public_key())).is_ok()
}

/// Assemble the trust diagnosis (pure). `integrity_ok` is `None` on an Open node
/// (no identity) and `Some(chain-validates)` when secure; `self_revoked` is whether
/// this node's own leaf is in the revoked set; `now` drives the clock line.
pub fn build_diagnosis(
    posture: Posture,
    identity: Option<&Identity>,
    integrity_ok: Option<bool>,
    self_revoked: bool,
    now: DateTime<Utc>,
) -> TrustDiagnosis {
    let mut checks = Vec::new();

    // ── posture (informational) ──
    let level = posture.level();
    let mut posture_check = DiagnosisCheck::ok("posture", format!("{level:?}"));
    if !posture.signed {
        posture_check = posture_check.with_remedy(
            "gain an identity: `koi certmesh join <endpoint>` (or `koi certmesh create`)",
        );
    }
    checks.push(posture_check);

    let Some(id) = identity else {
        // Open node: the identity-dependent checks do not apply.
        checks.push(DiagnosisCheck::not_applicable(
            "identity",
            "Open node — no cryptographic identity (this is valid; not an error)",
        ));
        checks.push(clock_check(now));
        return TrustDiagnosis::from_checks(posture, checks);
    };

    // ── identity ──
    checks.push(DiagnosisCheck::ok(
        "identity",
        format!("{} (CA {})", id.hostname, short_fp(&id.ca_fingerprint)),
    ));

    // ── identity_integrity (cert chains to its CA) ──
    match integrity_ok {
        Some(true) => checks.push(DiagnosisCheck::ok(
            "identity_integrity",
            "on-disk leaf parses and chains to its CA",
        )),
        Some(false) => checks.push(
            DiagnosisCheck::red(
                "identity_integrity",
                "on-disk leaf is unusable (unparseable, or does not chain to its CA) — \
                 the identity may be corrupt or half-written",
            )
            .with_remedy("re-enroll: `koi certmesh join <endpoint>`"),
        ),
        None => {}
    }

    // ── self_revocation (loud — this node was removed from the mesh) ──
    if self_revoked {
        checks.push(
            DiagnosisCheck::red(
                "self_revocation",
                "this node's certificate has been REVOKED by the CA",
            )
            .with_remedy("re-enroll with a fresh invite: `koi certmesh join <endpoint>`"),
        );
    } else {
        checks.push(DiagnosisCheck::ok("self_revocation", "not revoked"));
    }

    // ── renewal health (reuses RenewalHealth) ──
    checks.push(renewal_check(&id.renewal));

    // ── ca_trust_install (honest: not queryable → state the limitation + remedy) ──
    checks.push(
        DiagnosisCheck::ok(
            "ca_trust_install",
            "local apps should trust the mesh root; install status is not queryable \
             via the OS trust API (no fake 'installed' is reported)",
        )
        .with_remedy("ensure it is installed: `koi trust diagnose --fix`"),
    );

    // ── clock / freshness window (informational) ──
    checks.push(clock_check(now));

    TrustDiagnosis::from_checks(posture, checks)
}

/// The renewal check, derived from [`RenewalHealth`](crate::RenewalHealth): expired
/// → Red, overdue/soon → Warn, else Ok.
fn renewal_check(renewal: &crate::RenewalHealth) -> DiagnosisCheck {
    let days = renewal.expires_in_days;
    if renewal.expired {
        DiagnosisCheck::red("renewal", format!("leaf EXPIRED ({} days ago)", -days)).with_remedy(
            "renewal is automatic; if it persists, re-enroll: `koi certmesh join <endpoint>`",
        )
    } else if renewal.renew_overdue {
        DiagnosisCheck::warn(
            "renewal",
            format!(
                "renewal overdue — leaf expires in {days} days; the renewal loop should rotate it"
            ),
        )
        .with_remedy("check the daemon's renewal loop (`koi certmesh status`)")
    } else if days <= RENEW_SOON_DAYS {
        DiagnosisCheck::warn("renewal", format!("leaf expires soon (in {days} days)"))
    } else {
        DiagnosisCheck::ok("renewal", format!("leaf healthy (expires in {days} days)"))
    }
}

/// The clock line: local time + the ±freshness window so an operator understands
/// the skew tolerance (ADR-020 §13 — surface the leeway).
fn clock_check(now: DateTime<Utc>) -> DiagnosisCheck {
    DiagnosisCheck::ok(
        "clock",
        format!(
            "local clock {}; envelopes accept ±{}s skew (run NTP if peers reject for skew)",
            now.to_rfc3339(),
            crate::envelope::FRESHNESS_WINDOW_SECS,
        ),
    )
}

/// First 16 hex chars of a fingerprint for compact display.
fn short_fp(fp: &str) -> String {
    fp.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use koi_common::diagnosis::{CheckStatus, DiagnosisStatus};

    fn renewal(expires_in_days: i64, renew_overdue: bool, expired: bool) -> crate::RenewalHealth {
        let now = Utc::now();
        crate::RenewalHealth {
            expires_at: now + chrono::Duration::days(expires_in_days),
            next_renewal_at: now + chrono::Duration::days(expires_in_days - 30),
            expires_in_days,
            renew_overdue,
            expired,
        }
    }

    fn identity(renewal: crate::RenewalHealth) -> Identity {
        Identity {
            hostname: "web-01".to_string(),
            cert_pem: "x".to_string(),
            key_pem: "x".to_string(),
            ca_cert_pem: "x".to_string(),
            ca_fingerprint: "abcdef0123456789abcdef".to_string(),
            renewal,
        }
    }

    fn find<'a>(d: &'a TrustDiagnosis, name: &str) -> &'a DiagnosisCheck {
        d.checks
            .iter()
            .find(|c| c.name == name)
            .expect("check present")
    }

    #[test]
    fn open_node_marks_identity_checks_not_applicable() {
        let d = build_diagnosis(Posture::OPEN, None, None, false, Utc::now());
        assert_eq!(d.overall, DiagnosisStatus::Healthy);
        assert_eq!(find(&d, "identity").status, CheckStatus::NotApplicable);
        // Open posture carries a remedy to gain an identity.
        assert!(find(&d, "posture").remedy.is_some());
        // No renewal/revocation checks on an Open node.
        assert!(d.checks.iter().all(|c| c.name != "renewal"));
    }

    #[test]
    fn healthy_secure_node_is_healthy() {
        let id = identity(renewal(60, false, false));
        let d = build_diagnosis(
            Posture::new(true, false),
            Some(&id),
            Some(true),
            false,
            Utc::now(),
        );
        assert_eq!(d.overall, DiagnosisStatus::Healthy);
        assert_eq!(find(&d, "renewal").status, CheckStatus::Ok);
        assert_eq!(find(&d, "self_revocation").status, CheckStatus::Ok);
        assert_eq!(find(&d, "identity_integrity").status, CheckStatus::Ok);
    }

    #[test]
    fn expired_leaf_is_red_with_remedy() {
        let id = identity(renewal(-3, true, true));
        let d = build_diagnosis(
            Posture::new(true, false),
            Some(&id),
            Some(true),
            false,
            Utc::now(),
        );
        assert!(d.is_red());
        let r = find(&d, "renewal");
        assert_eq!(r.status, CheckStatus::Red);
        assert!(r.detail.contains("EXPIRED"));
        assert!(r.remedy.is_some());
        assert_eq!(d.exit_code(), 1);
    }

    #[test]
    fn renewal_due_soon_is_a_warning_not_a_failure() {
        let id = identity(renewal(5, false, false));
        let d = build_diagnosis(
            Posture::new(true, false),
            Some(&id),
            Some(true),
            false,
            Utc::now(),
        );
        assert_eq!(find(&d, "renewal").status, CheckStatus::Warn);
        assert_eq!(d.overall, DiagnosisStatus::Degraded);
        assert_eq!(d.exit_code(), 0, "a warning is loud but not a failure");
    }

    #[test]
    fn self_revoked_node_is_red() {
        let id = identity(renewal(60, false, false));
        let d = build_diagnosis(
            Posture::new(true, false),
            Some(&id),
            Some(true),
            true,
            Utc::now(),
        );
        assert!(d.is_red());
        let r = find(&d, "self_revocation");
        assert_eq!(r.status, CheckStatus::Red);
        assert!(r.detail.contains("REVOKED"));
        assert!(r.remedy.as_deref().unwrap().contains("join"));
    }

    #[test]
    fn broken_identity_chain_is_red() {
        let id = identity(renewal(60, false, false));
        let d = build_diagnosis(
            Posture::new(true, false),
            Some(&id),
            Some(false),
            false,
            Utc::now(),
        );
        assert!(d.is_red());
        assert_eq!(find(&d, "identity_integrity").status, CheckStatus::Red);
    }

    #[test]
    fn ca_trust_install_is_honest_not_a_fake_success() {
        let id = identity(renewal(60, false, false));
        let d = build_diagnosis(
            Posture::new(true, false),
            Some(&id),
            Some(true),
            false,
            Utc::now(),
        );
        let c = find(&d, "ca_trust_install");
        // Honest: it does NOT claim "installed"; it states the limitation + a remedy.
        assert!(!c.detail.to_lowercase().contains("installed successfully"));
        assert!(c.detail.contains("not queryable"));
        assert!(c.remedy.is_some());
    }
}
