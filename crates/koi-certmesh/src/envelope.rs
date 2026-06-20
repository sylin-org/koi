//! Envelope signing & verification — the `sign`/`verify` *logic* for ADR-020 §3.
//!
//! The wire types live in `koi_common::envelope`; this module is the logic, which
//! needs the identity key, the pinned CA anchor, and the roster's revocations.
//!
//! **Carry-cert model** (ADR-020 §3, the developer-delight choice): the signer
//! embeds its leaf certificate in the envelope, and the verifier validates that
//! leaf against the pinned CA it already trusts — deriving the authoritative CN +
//! public key from the cert, never from a claimed field. This makes verification
//! self-contained and, crucially, able to run on a pure member node that keeps no
//! roster of other members' public keys.
//!
//! These are pure free functions (trust inputs passed in) so verification is
//! exhaustively unit-testable; `CertmeshCore::sign`/`verify` gather the inputs.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use koi_common::envelope::{
    Assurance, Envelope, Freshness, RejectReason, Sig, SigAlg, ENVELOPE_V1,
};
use x509_parser::prelude::FromDer;

/// Domain-separation prefix for the v1 canonical signing bytes. Distinct from
/// every other Koi signing context so a signature can never be replayed across
/// protocols. Frozen when the wire contract is published (ADR-020 §9 / P6).
const ENVELOPE_DOMAIN_V1: &str = "koi-envelope-v1";

/// Freshness/replay window: a timestamp within ±this many seconds of now is
/// `Fresh`. 300s tolerates the un-NTP'd LAN clock drift typical of Koi's
/// deployment surface, where a tighter window spuriously rejects (ADR-020 §13).
pub const FRESHNESS_WINDOW_SECS: i64 = 300;

/// The exact bytes an Envelope's signature covers (v1). Deterministic and
/// trivially reproducible in another language (the cross-sibling wire contract).
/// `pub(crate)` so the conformance-vector validator checks the real construction.
pub(crate) fn canonical_bytes(v: u8, payload: &str, nonce: &str, ts: i64) -> Vec<u8> {
    format!("{ENVELOPE_DOMAIN_V1}\n{v}\n{payload}\n{nonce}\n{ts}").into_bytes()
}

fn freshness(ts: i64, now: i64) -> Freshness {
    if (now - ts).abs() <= FRESHNESS_WINDOW_SECS {
        Freshness::Fresh
    } else {
        Freshness::Stale
    }
}

fn reject(reason: RejectReason) -> Assurance {
    Assurance::Rejected { reason }
}

/// Build a (possibly signed) envelope over `bytes`.
///
/// Pure: `nonce`/`ts` are passed in so signing is deterministic and testable.
/// `signer` is `Some((key_pem, cert_pem))` in Authenticated posture (ES256-signed,
/// carrying the leaf cert) and `None` in Open posture (a freshness-stamped
/// passthrough). A signing failure (unparseable key/cert) falls back to an
/// unsigned envelope rather than panicking.
pub fn build_envelope(
    signer: Option<(&str, &str)>,
    bytes: &[u8],
    nonce: &[u8],
    ts: i64,
) -> Envelope {
    let v = ENVELOPE_V1;
    let payload = B64.encode(bytes);
    let nonce_b64 = B64.encode(nonce);

    let sig = signer.and_then(|(key_pem, cert_pem)| {
        let canonical = canonical_bytes(v, &payload, &nonce_b64, ts);
        let sig_der = koi_crypto::signing::sign_with_key_pem(key_pem, &canonical)?;
        let leaf_der = pem::parse(cert_pem).ok()?.contents().to_vec();
        Some(Sig {
            alg: SigAlg::Es256,
            signature: B64.encode(&sig_der),
            signer_cert: B64.encode(&leaf_der),
        })
    });

    Envelope {
        v,
        payload,
        nonce: nonce_b64,
        ts,
        sig,
    }
}

/// Verify an envelope, returning an [`Assurance`] (ADR-020 §3).
///
/// Pure: the trust inputs are passed in. `ca_cert_pem` is this verifier's pinned
/// CA (the anchor every mesh node already has); `None` (an Open verifier with no
/// anchor) means we can only attest freshness → `Anonymous`, preserving the same
/// code path in both postures. `revoked_fingerprints` is the best-effort revoked
/// set (the CA chain is the hard gate; revocation is eventual-consistent, like the
/// mTLS path).
pub fn verify_envelope(
    env: &Envelope,
    ca_cert_pem: Option<&str>,
    revoked_fingerprints: &[String],
    now: i64,
) -> Assurance {
    let fresh = freshness(env.ts, now);

    // Unsigned (Open passthrough) → anonymous, freshness only.
    let Some(sig) = env.sig.as_ref() else {
        return Assurance::Anonymous { freshness: fresh };
    };
    // Version selects the construction — never the in-band alg (no alg-confusion).
    if env.v != ENVELOPE_V1 || sig.alg != SigAlg::Es256 {
        return reject(RejectReason::UnsupportedVersion);
    }
    // No trust anchor → cannot authenticate; honest anonymous (Open verifier).
    let Some(ca_pem) = ca_cert_pem else {
        return Assurance::Anonymous { freshness: fresh };
    };

    // Decode the carried leaf and the pinned CA.
    let (Some(leaf_der), Some(ca_der)) = (
        B64.decode(sig.signer_cert.as_bytes()).ok(),
        pem::parse(ca_pem).ok().map(|p| p.contents().to_vec()),
    ) else {
        return reject(RejectReason::Malformed);
    };
    let (Ok((_, leaf)), Ok((_, ca))) = (
        x509_parser::certificate::X509Certificate::from_der(&leaf_der),
        x509_parser::certificate::X509Certificate::from_der(&ca_der),
    ) else {
        return reject(RejectReason::Malformed);
    };

    // Chain: the leaf must be issued (signed) by our pinned CA.
    if leaf.verify_signature(Some(ca.public_key())).is_err() {
        return reject(RejectReason::UnknownSigner);
    }
    // The leaf must not be expired.
    if now > leaf.validity().not_after.timestamp() {
        return reject(RejectReason::Expired);
    }
    // Revocation — best-effort against the last trust bundle / roster.
    let leaf_fp = koi_crypto::pinning::fingerprint_sha256(&leaf_der);
    if revoked_fingerprints
        .iter()
        .any(|f| koi_crypto::pinning::fingerprints_match(f, &leaf_fp))
    {
        return reject(RejectReason::Revoked);
    }
    // Verify the envelope signature with the leaf's public key.
    let Some(sig_der) = B64.decode(sig.signature.as_bytes()).ok() else {
        return reject(RejectReason::Malformed);
    };
    let spki_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", leaf.public_key().raw.to_vec()));
    let canonical = canonical_bytes(env.v, &env.payload, &env.nonce, env.ts);
    if !koi_crypto::signing::verify_signature(&spki_pem, &canonical, &sig_der) {
        return reject(RejectReason::BadSignature);
    }

    // Authoritative CN from the certificate (never a claimed field).
    let cn = crate::mtls::extract_cn(&leaf_der).unwrap_or_default();
    Assurance::Authenticated {
        cn,
        freshness: fresh,
    }
}

/// Decode a verified envelope's base64 payload back to the original bytes.
pub fn decode_payload(env: &Envelope) -> Option<Vec<u8>> {
    B64.decode(env.payload.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca;
    use crate::certmesh_paths::CertmeshPaths;

    struct Issued {
        cert_pem: String,
        key_pem: String,
        ca_pem: String,
        fingerprint: String,
    }

    // Create a CA + a leaf for `cn` on an isolated temp data dir.
    fn ca_and_leaf(tag: &str, cn: &str) -> Issued {
        let dir = std::env::temp_dir().join(format!("koi-cm-env-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = CertmeshPaths::with_data_dir(dir);
        let ca = ca::create_ca("test-pass", &[3u8; 32], &paths).unwrap().0;
        let issued = ca::issue_certificate(&ca, cn, &[cn.to_string()], 90).unwrap();
        Issued {
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
            ca_pem: issued.ca_pem,
            fingerprint: issued.fingerprint,
        }
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    #[test]
    fn authenticated_and_fresh_round_trip() {
        let id = ca_and_leaf("ok", "web-01");
        let env = build_envelope(
            Some((&id.key_pem, &id.cert_pem)),
            b"hello world",
            &[7u8; 16],
            now(),
        );
        let a = verify_envelope(&env, Some(&id.ca_pem), &[], now());
        assert_eq!(
            a,
            Assurance::Authenticated {
                cn: "web-01".to_string(),
                freshness: Freshness::Fresh,
            }
        );
        assert_eq!(a.identity(), Some("web-01"));
        assert_eq!(decode_payload(&env).as_deref(), Some(&b"hello world"[..]));
    }

    #[test]
    fn open_passthrough_is_anonymous() {
        let env = build_envelope(None, b"hi", &[1u8; 16], now());
        assert!(env.sig.is_none());
        let a = verify_envelope(&env, Some("ignored"), &[], now());
        assert_eq!(
            a,
            Assurance::Anonymous {
                freshness: Freshness::Fresh,
            }
        );
        assert_eq!(a.identity(), None);
    }

    #[test]
    fn open_verifier_without_anchor_is_anonymous() {
        let id = ca_and_leaf("noanchor", "web-01");
        let env = build_envelope(Some((&id.key_pem, &id.cert_pem)), b"x", &[2u8; 16], now());
        // A signed envelope, but the verifier has no CA anchor → cannot authenticate.
        let a = verify_envelope(&env, None, &[], now());
        assert_eq!(
            a,
            Assurance::Anonymous {
                freshness: Freshness::Fresh,
            }
        );
    }

    #[test]
    fn tampered_payload_is_bad_signature() {
        let id = ca_and_leaf("tamper", "web-01");
        let mut env = build_envelope(
            Some((&id.key_pem, &id.cert_pem)),
            b"original",
            &[5u8; 16],
            now(),
        );
        env.payload = B64.encode(b"tampered"); // signature now covers the old payload
        let a = verify_envelope(&env, Some(&id.ca_pem), &[], now());
        assert_eq!(a, reject(RejectReason::BadSignature));
        assert_eq!(a.identity(), None);
    }

    #[test]
    fn leaf_from_a_different_ca_is_unknown_signer() {
        let signer = ca_and_leaf("ca-a", "web-01");
        let other = ca_and_leaf("ca-b", "web-02");
        let env = build_envelope(
            Some((&signer.key_pem, &signer.cert_pem)),
            b"x",
            &[9u8; 16],
            now(),
        );
        // Verify against the WRONG CA → the leaf does not chain to it.
        let a = verify_envelope(&env, Some(&other.ca_pem), &[], now());
        assert_eq!(a, reject(RejectReason::UnknownSigner));
    }

    #[test]
    fn revoked_leaf_is_rejected() {
        let id = ca_and_leaf("revoke", "web-01");
        let env = build_envelope(Some((&id.key_pem, &id.cert_pem)), b"x", &[4u8; 16], now());
        let a = verify_envelope(
            &env,
            Some(&id.ca_pem),
            std::slice::from_ref(&id.fingerprint),
            now(),
        );
        assert_eq!(a, reject(RejectReason::Revoked));
    }

    #[test]
    fn authenticated_but_stale_does_not_open_the_identity_door() {
        let id = ca_and_leaf("stale", "web-01");
        let old = now() - (FRESHNESS_WINDOW_SECS + 60);
        let env = build_envelope(Some((&id.key_pem, &id.cert_pem)), b"x", &[6u8; 16], old);
        let a = verify_envelope(&env, Some(&id.ca_pem), &[], now());
        assert_eq!(
            a,
            Assurance::Authenticated {
                cn: "web-01".to_string(),
                freshness: Freshness::Stale,
            }
        );
        // The whole point: authenticated-but-stale is NOT a trusted identity.
        assert_eq!(a.identity(), None);
    }
}
