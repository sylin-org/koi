//! The signed, monotonic **Trust Bundle** — the single source of mesh truth
//! (ADR-017 P1 / F4).
//!
//! A canonical, CA-signed document describing membership, revocation, the CA
//! identity, and the lifecycle policy. It is served at `GET /v1/certmesh/trust-bundle`
//! (a DAT-exempt read: it is integrity-protected by its own signature, like a CRL)
//! and pulled by members on an interval. A member verifies the detached ES256
//! signature against its **pinned** CA fingerprint and rejects any bundle with
//! `seq <= last_seen` (anti-rollback). The CA's `roster.json` is the private
//! superset; this bundle is its public, integrity-protected projection.
//!
//! Signing uses the CA's P-256 key (`koi_crypto::signing`), **not** HKDF — so the
//! frozen STACK-0001 K3 domain-separation labels are untouched.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use x509_parser::prelude::FromDer;

use crate::roster::{CertPolicy, MemberStatus, Roster};

/// One member as projected into the public bundle (no operator names, hooks, or
/// paths — those stay CA-side in `roster.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct BundleMember {
    pub hostname: String,
    pub cert_fingerprint: String,
    /// RFC 3339 leaf expiry.
    pub not_after: String,
    /// `"active"` or `"revoked"`.
    pub status: String,
}

/// One revocation record in the bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct BundleRevoked {
    pub hostname: String,
    /// The revoked leaf's fingerprint (looked up from the roster member), if known.
    #[serde(default)]
    pub cert_fingerprint: String,
    /// RFC 3339 revocation time.
    pub revoked_at: String,
}

/// The canonical mesh-truth document. Field order is fixed and there are no maps,
/// so [`Self::canonical_bytes`] is deterministic and reproducible by any verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct TrustBundle {
    /// Monotonic sequence; bumped on every roster membership mutation.
    pub seq: u64,
    /// RFC 3339 issue time.
    pub issued_at: String,
    /// SHA-256 of the CA cert DER (lowercase hex).
    pub ca_fingerprint: String,
    /// The CA root certificate (PEM) — lets an offline verifier check the chain.
    pub ca_cert_pem: String,
    /// CA-held lifecycle policy.
    pub policy: CertPolicy,
    pub members: Vec<BundleMember>,
    pub revoked: Vec<BundleRevoked>,
}

/// The wire envelope: the bundle plus a detached signature over its canonical bytes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignedBundle {
    pub bundle: TrustBundle,
    /// Base64 (standard) of the DER-encoded ES256 signature over
    /// `bundle.canonical_bytes()`, produced by the CA key.
    pub signature: String,
}

/// Why a bundle was rejected by a verifier.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    #[error("bundle CA cert is not valid PEM/DER")]
    CaCert,
    #[error("bundle CA fingerprint does not match the pinned CA")]
    PinMismatch,
    #[error("bundle signature is invalid")]
    BadSignature,
    #[error("bundle signature is not valid base64")]
    BadSignatureEncoding,
    #[error("bundle could not be canonicalized for verification")]
    Canonicalize,
    #[error("bundle seq {got} is older than last seen {last_seen} (rollback)")]
    Rollback { got: u64, last_seen: u64 },
}

impl TrustBundle {
    /// Project the roster into a bundle. `issued_at` is supplied by the caller (so
    /// signing is deterministic for a given roster+time).
    pub fn from_roster(
        roster: &Roster,
        ca_cert_pem: &str,
        ca_fingerprint: &str,
        issued_at: String,
    ) -> Self {
        let members = roster
            .members
            .iter()
            .map(|m| BundleMember {
                hostname: m.hostname.clone(),
                cert_fingerprint: m.cert_fingerprint.clone(),
                not_after: m.cert_expires.to_rfc3339(),
                status: match m.status {
                    MemberStatus::Active => "active",
                    MemberStatus::Revoked => "revoked",
                }
                .to_string(),
            })
            .collect();

        let revoked = roster
            .revocation_list
            .iter()
            .map(|r| BundleRevoked {
                hostname: r.hostname.clone(),
                cert_fingerprint: roster
                    .find_member(&r.hostname)
                    .map(|m| m.cert_fingerprint.clone())
                    .unwrap_or_default(),
                revoked_at: r.revoked_at.to_rfc3339(),
            })
            .collect();

        Self {
            seq: roster.metadata.seq,
            issued_at,
            ca_fingerprint: ca_fingerprint.to_string(),
            ca_cert_pem: ca_cert_pem.to_string(),
            policy: roster.metadata.policy.clone(),
            members,
            revoked,
        }
    }

    /// The exact bytes that are signed and verified: **sorted-key, compact** JSON
    /// (ADR-017). Round-tripping through `serde_json::Value` (a `BTreeMap`) sorts
    /// every object's keys recursively, so the signed form is canonical and equals
    /// the bytes the HTTP layer emits (`Json` also serializes via a sorted `Value`)
    /// — letting **any** consumer verify the signature directly from the wire,
    /// independent of Rust struct field order. Returns an error rather than
    /// silently signing/verifying empty bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let sorted = serde_json::to_value(self)?;
        serde_json::to_vec(&sorted)
    }

    /// Whether `hostname` is listed as revoked (or absent) in this bundle.
    pub fn is_revoked(&self, hostname: &str) -> bool {
        self.revoked.iter().any(|r| r.hostname == hostname)
            || self
                .members
                .iter()
                .any(|m| m.hostname == hostname && m.status == "revoked")
    }

    /// Every revoked leaf **fingerprint** carried by this bundle — the union of the
    /// explicit `revoked` list and any member projected with `status == "revoked"`,
    /// deduplicated and sorted (deterministic).
    ///
    /// Both projections are unioned because `BundleRevoked.cert_fingerprint` is
    /// `#[serde(default)]` ("if known") and may be empty, while the `members[]`
    /// projection always carries the fingerprint — so relying on `revoked` alone
    /// could silently miss a revoked leaf. The result is what a member applies into
    /// its local revoked set so `verify`/`open` reject *other* revoked members
    /// (ADR-023 §3), keyed on fingerprint as `verify_envelope` matches.
    pub fn revoked_fingerprints(&self) -> Vec<String> {
        let mut set: Vec<String> = self
            .revoked
            .iter()
            .map(|r| r.cert_fingerprint.clone())
            .chain(
                self.members
                    .iter()
                    .filter(|m| m.status == "revoked")
                    .map(|m| m.cert_fingerprint.clone()),
            )
            .filter(|fp| !fp.is_empty())
            .collect();
        set.sort();
        set.dedup();
        set
    }
}

/// Build and sign a bundle from the roster with the CA key.
pub fn sign(
    roster: &Roster,
    ca: &crate::ca::CaState,
    issued_at: String,
) -> Result<SignedBundle, crate::error::CertmeshError> {
    use base64::Engine;
    let ca_fingerprint = crate::ca::ca_fingerprint(ca);
    let bundle = TrustBundle::from_roster(roster, &ca.cert_pem, &ca_fingerprint, issued_at);
    let bytes = bundle
        .canonical_bytes()
        .map_err(|e| crate::error::CertmeshError::Internal(format!("canonicalize bundle: {e}")))?;
    let sig = koi_crypto::signing::sign_bytes(&ca.key, &bytes);
    Ok(SignedBundle {
        bundle,
        signature: base64::engine::general_purpose::STANDARD.encode(sig),
    })
}

/// Extract the Subject Public Key Info from a certificate PEM as a `PUBLIC KEY` PEM.
fn ca_spki_pem(ca_cert_pem: &str) -> Result<String, BundleError> {
    let der = pem::parse(ca_cert_pem).map_err(|_| BundleError::CaCert)?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.contents())
        .map_err(|_| BundleError::CaCert)?;
    let spki_der = cert.public_key().raw.to_vec();
    Ok(pem::encode(&pem::Pem::new("PUBLIC KEY", spki_der)))
}

/// Verify a signed bundle against a **pinned** CA fingerprint and (optionally) an
/// anti-rollback floor.
///
/// Checks, in order: the embedded CA cert's fingerprint equals `pinned_ca_fingerprint`;
/// the ES256 signature verifies against that CA cert's public key over the bundle's
/// canonical bytes; and (when `last_seen_seq` is `Some`) `bundle.seq > last_seen`.
pub fn verify(
    signed: &SignedBundle,
    pinned_ca_fingerprint: &str,
    last_seen_seq: Option<u64>,
) -> Result<(), BundleError> {
    use base64::Engine;

    // 1. The bundle's CA cert must be the one we pinned.
    let der = pem::parse(&signed.bundle.ca_cert_pem).map_err(|_| BundleError::CaCert)?;
    let derived_fp = koi_crypto::pinning::fingerprint_sha256(der.contents());
    if !koi_crypto::pinning::fingerprints_match(&derived_fp, pinned_ca_fingerprint) {
        return Err(BundleError::PinMismatch);
    }
    // The advertised fingerprint must also be self-consistent.
    if !koi_crypto::pinning::fingerprints_match(&derived_fp, &signed.bundle.ca_fingerprint) {
        return Err(BundleError::PinMismatch);
    }

    // 2. Signature verifies against the pinned CA's public key.
    let sig = base64::engine::general_purpose::STANDARD
        .decode(signed.signature.as_bytes())
        .map_err(|_| BundleError::BadSignatureEncoding)?;
    let spki_pem = ca_spki_pem(&signed.bundle.ca_cert_pem)?;
    let bytes = signed
        .bundle
        .canonical_bytes()
        .map_err(|_| BundleError::Canonicalize)?;
    if !koi_crypto::signing::verify_signature(&spki_pem, &bytes, &sig) {
        return Err(BundleError::BadSignature);
    }

    // 3. Anti-rollback: reject a *strictly older* bundle (a replayed snapshot that
    //    would hide a revocation). An equal `seq` is the same bundle — accepted as
    //    a benign no-op so the member's periodic re-pull is idempotent.
    if let Some(last_seen) = last_seen_seq {
        if signed.bundle.seq < last_seen {
            return Err(BundleError::Rollback {
                got: signed.bundle.seq,
                last_seen,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca;
    use crate::roster::{MemberRole, RosterMember};
    use chrono::Utc;

    fn test_ca() -> ca::CaState {
        let paths = crate::CertmeshPaths::with_data_dir(koi_common::test::ensure_data_dir(
            "koi-certmesh-bundle-tests",
        ));
        ca::create_ca("bundle-pass", &[9u8; 32], &paths).unwrap().0
    }

    fn roster_with_member(hostname: &str, fp: &str) -> Roster {
        let mut r = Roster::new(true, false, None);
        r.members.push(RosterMember {
            hostname: hostname.to_string(),
            role: MemberRole::Member,
            enrolled_at: Utc::now(),
            enrolled_by: None,
            cert_fingerprint: fp.to_string(),
            cert_expires: Utc::now() + chrono::Duration::days(90),
            cert_sans: vec![hostname.to_string()],
            cert_path: String::new(),
            status: MemberStatus::Active,
            reload_hook: None,
            last_seen: None,
            pinned_ca_fingerprint: None,
            proxy_entries: Vec::new(),
        });
        r
    }

    #[test]
    fn sign_then_verify_round_trips_through_json() {
        let ca = test_ca();
        let mut roster = roster_with_member("web-01", "fp-web-01");
        roster.metadata.seq = 7;
        let signed = sign(&roster, &ca, "2026-06-19T00:00:00Z".to_string()).unwrap();

        // Cross the wire: serialize the envelope and verify from the parsed form.
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: SignedBundle = serde_json::from_str(&json).unwrap();

        let pin = ca::ca_fingerprint(&ca);
        assert!(
            verify(&parsed, &pin, Some(6)).is_ok(),
            "fresh bundle verifies"
        );
        assert_eq!(parsed.bundle.seq, 7);
        assert_eq!(parsed.bundle.members.len(), 1);
    }

    #[test]
    fn wire_bundle_bytes_verify_externally() {
        // An external (non-Rust) verifier reads the SignedBundle JSON, takes the
        // `bundle` sub-value WITHOUT struct knowledge, serializes it like any JSON
        // library (sorted keys), and verifies the signature against the CA cert's
        // public key. This must succeed — the signed canonical form equals the
        // wire form. Also a regression guard against serde_json's `preserve_order`.
        use base64::Engine;
        let ca = test_ca();
        let roster = roster_with_member("web-01", "fp");
        let signed = sign(&roster, &ca, "2026-06-19T00:00:00Z".to_string()).unwrap();
        let wire = serde_json::to_string(&signed).unwrap();

        let v: serde_json::Value = serde_json::from_str(&wire).unwrap();
        let bundle_bytes = serde_json::to_vec(&v["bundle"]).unwrap();
        let sig = base64::engine::general_purpose::STANDARD
            .decode(v["signature"].as_str().unwrap())
            .unwrap();
        let spki = ca_spki_pem(&ca.cert_pem).unwrap();
        assert!(
            koi_crypto::signing::verify_signature(&spki, &bundle_bytes, &sig),
            "wire bundle bytes must verify against the CA key (external-verifier path)"
        );
    }

    #[test]
    fn verify_rejects_wrong_pin() {
        let ca = test_ca();
        let roster = roster_with_member("web-01", "fp");
        let signed = sign(&roster, &ca, "t".to_string()).unwrap();
        let err = verify(
            &signed,
            "0000000000000000000000000000000000000000000000000000000000000000",
            None,
        )
        .unwrap_err();
        assert_eq!(err, BundleError::PinMismatch);
    }

    #[test]
    fn verify_rejects_tampered_bundle() {
        let ca = test_ca();
        let roster = roster_with_member("web-01", "fp");
        let mut signed = sign(&roster, &ca, "t".to_string()).unwrap();
        // Tamper: add a member after signing.
        signed.bundle.members.push(BundleMember {
            hostname: "evil".to_string(),
            cert_fingerprint: "x".to_string(),
            not_after: "t".to_string(),
            status: "active".to_string(),
        });
        let pin = ca::ca_fingerprint(&ca);
        assert_eq!(
            verify(&signed, &pin, None).unwrap_err(),
            BundleError::BadSignature
        );
    }

    #[test]
    fn verify_rejects_rollback() {
        let ca = test_ca();
        let mut roster = roster_with_member("web-01", "fp");
        roster.metadata.seq = 3;
        let signed = sign(&roster, &ca, "t".to_string()).unwrap();
        let pin = ca::ca_fingerprint(&ca);
        // last_seen 4 → a seq-3 bundle is strictly older → rollback.
        assert_eq!(
            verify(&signed, &pin, Some(4)).unwrap_err(),
            BundleError::Rollback {
                got: 3,
                last_seen: 4
            }
        );
        // Equal seq is the same bundle → accepted (idempotent re-pull).
        assert!(verify(&signed, &pin, Some(3)).is_ok());
        // Older floor → accepted.
        assert!(verify(&signed, &pin, Some(2)).is_ok());
    }

    #[test]
    fn revoked_member_shows_in_bundle() {
        let ca = test_ca();
        let mut roster = roster_with_member("web-01", "fp-web-01");
        roster
            .revoke_member("web-01", Some("op".into()), Some("compromised".into()))
            .unwrap();
        let signed = sign(&roster, &ca, "t".to_string()).unwrap();
        assert!(signed.bundle.is_revoked("web-01"));
        assert_eq!(signed.bundle.revoked.len(), 1);
        assert_eq!(signed.bundle.revoked[0].cert_fingerprint, "fp-web-01");
    }

    #[test]
    fn revoked_fingerprints_unions_both_projections_dedup_sorted() {
        let ca = test_ca();
        let mut roster = roster_with_member("web-01", "fp-web-01");
        roster
            .members
            .push(roster_with_member("web-02", "fp-web-02").members.remove(0));
        roster
            .revoke_member("web-02", Some("op".into()), Some("x".into()))
            .unwrap();
        let signed = sign(&roster, &ca, "t".to_string()).unwrap();

        // Only the revoked member's fingerprint, exactly once, sorted.
        assert_eq!(
            signed.bundle.revoked_fingerprints(),
            vec!["fp-web-02".to_string()]
        );

        // An empty `BundleRevoked.cert_fingerprint` must not leak an empty string;
        // the members[] projection remains the reliable source.
        let mut hollow = signed.bundle.clone();
        hollow.revoked[0].cert_fingerprint = String::new();
        assert_eq!(
            hollow.revoked_fingerprints(),
            vec!["fp-web-02".to_string()],
            "members[] projection backstops an empty revoked[].cert_fingerprint"
        );
    }
}
