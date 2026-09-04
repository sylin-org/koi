//! The trust-doctor *logic* (`diagnose()`) — ADR-020 §13.
//!
//! The report types live in `koi_common::diagnosis`; this assembles them from the
//! node's real trust state, **reusing** the P1–P5 primitives (posture,
//! `Identity`/`RenewalHealth`, the revoked set) rather than re-deriving any of it.
//! [`build_diagnosis`] is pure (all inputs passed in) so every branch is unit
//! -testable without a CA; `CertmeshCore::diagnose` gathers the inputs.
//!
//! OS trust-store ownership and diagnosis belong to `koi-trust`; Certmesh reports
//! only the certificate-mesh facts it can authoritatively decide.

use koi_common::diagnosis::{DiagnosisCheck, TrustDiagnosis};
use koi_common::posture::Posture;
use x509_parser::prelude::FromDer;

use crate::Identity;

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

/// Whether a local leaf is a coherent, usable identity for this CA.
///
/// A certificate that merely has the right names and expiry is insufficient: it
/// must chain to the active CA and its public key must match the local private key.
/// Self-enrollment and trust diagnosis share this one evaluation point.
pub fn identity_material_is_usable(cert_pem: &str, key_pem: &str, ca_cert_pem: &str) -> bool {
    if !leaf_chains_to_ca(cert_pem, ca_cert_pem) {
        return false;
    }
    let Ok(key) = koi_crypto::keys::ca_keypair_from_pem(key_pem) else {
        return false;
    };
    crate::ca::key_matches_certificate(&key, cert_pem).unwrap_or(false)
}

/// Assemble the trust diagnosis (pure). `integrity_ok` is `None` on an Open node
/// (no identity) and `Some(chain-validates)` when secure; `self_revoked` is whether
/// this node's own leaf is in the revoked set. `identity_expected` distinguishes a
/// valid Open node from a member whose required identity disappeared, preventing
/// a broken secure node from being reported as healthy/Open.
pub fn build_diagnosis(
    posture: Posture,
    identity: Option<&Identity>,
    integrity_ok: Option<bool>,
    self_revoked: bool,
    identity_expected: bool,
    identity_problem: Option<&str>,
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
        if identity_expected {
            checks.push(
                DiagnosisCheck::red(
                    "identity",
                    identity_problem.unwrap_or(
                        "this node belongs to a mesh but its local identity is unavailable",
                    ),
                )
                .with_remedy("repair or re-enroll: `koi certmesh join <endpoint>`"),
            );
        } else {
            checks.push(DiagnosisCheck::not_applicable(
                "identity",
                "Open node — no cryptographic identity (this is valid; not an error)",
            ));
        }
        checks.push(clock_check());
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

    // ── clock / freshness window (informational) ──
    checks.push(clock_check());

    TrustDiagnosis::from_checks(posture, checks)
}

/// The renewal check, derived from [`RenewalHealth`](crate::RenewalHealth): expired
/// → Red, else Ok. Being inside the CA-scheduled renewal window (`renew_overdue`)
/// is **normal steady-state under short-lived leaves** (ADR-027): every 7-day leaf
/// spends most of its life within 3 days of its renewal point, and the hourly
/// sweep rotates it automatically. Repeated renewal failures surface through
/// `CertRenewalFailed` lifecycle events and Red-on-expiry — never as a permanent
/// degraded posture for healthy identity.
fn renewal_check(renewal: &crate::RenewalHealth) -> DiagnosisCheck {
    let days = renewal.expires_in_days;
    if renewal.expired {
        DiagnosisCheck::red("renewal", format!("leaf EXPIRED ({} days ago)", -days)).with_remedy(
            "renewal is automatic; if it persists, re-enroll: `koi certmesh join <endpoint>`",
        )
    } else if renewal.renew_overdue {
        DiagnosisCheck::ok(
            "renewal",
            format!(
                "leaf in scheduled renewal window (expires in {days} days); the daemon renews automatically"
            ),
        )
    } else {
        DiagnosisCheck::ok("renewal", format!("leaf healthy (expires in {days} days)"))
    }
}

/// The clock line: local time + the ±freshness window so an operator understands
/// the skew tolerance (ADR-020 §13 — surface the leeway).
fn clock_check() -> DiagnosisCheck {
    DiagnosisCheck::ok(
        "clock",
        format!(
            "envelopes accept ±{}s skew (run NTP if peers reject for skew)",
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
    use chrono::Utc;
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
        let d = build_diagnosis(Posture::OPEN, None, None, false, false, None);
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
            true,
            None,
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
            true,
            None,
        );
        assert!(d.is_red());
        let r = find(&d, "renewal");
        assert_eq!(r.status, CheckStatus::Red);
        assert!(r.detail.contains("EXPIRED"));
        assert!(r.remedy.is_some());
        assert_eq!(d.exit_code(), 1);
    }

    #[test]
    fn scheduled_renewal_window_is_healthy_not_degraded() {
        // ADR-027: inside the CA-scheduled renewal window is normal steady-state
        // for a short-lived leaf — Ok, never Warn, never degraded.
        let id = identity(renewal(2, true, false));
        let d = build_diagnosis(
            Posture::new(true, false),
            Some(&id),
            Some(true),
            false,
            true,
            None,
        );
        assert_eq!(find(&d, "renewal").status, CheckStatus::Ok);
        assert!(find(&d, "renewal")
            .detail
            .contains("scheduled renewal window"));
        assert_eq!(d.overall, DiagnosisStatus::Healthy);
        assert_eq!(d.exit_code(), 0);
    }

    #[test]
    fn self_revoked_node_is_red() {
        let id = identity(renewal(60, false, false));
        let d = build_diagnosis(
            Posture::new(true, false),
            Some(&id),
            Some(true),
            true,
            true,
            None,
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
            true,
            None,
        );
        assert!(d.is_red());
        assert_eq!(find(&d, "identity_integrity").status, CheckStatus::Red);
    }

    #[test]
    fn missing_identity_on_a_member_is_red_not_open() {
        let d = build_diagnosis(
            Posture::OPEN,
            None,
            None,
            false,
            true,
            Some("member certificate is missing"),
        );
        assert!(d.is_red());
        assert_eq!(find(&d, "identity").status, CheckStatus::Red);
        assert!(find(&d, "identity").detail.contains("missing"));
    }
}
