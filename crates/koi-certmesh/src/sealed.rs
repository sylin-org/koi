//! `seal`/`open` — the confidentiality-rung *logic* for ADR-020 §4.
//!
//! The wire types live in `koi_common::sealed`; this is the logic. It is built
//! **on top of** the `sign`/`verify` machinery (ADR-020 §3) rather than
//! re-implementing any of it: a v0 passthrough `Sealed` is exactly a signed
//! [`Envelope`] wrapped with a confidentiality version tag, so `seal` = sign +
//! wrap and `open` = version-dispatch + verify + decode. When the group-key rung
//! (v1) lands it adds an encryption step around the same envelope; the consumer
//! API does not change.
//!
//! Pure free functions (trust inputs passed in) so the behavior is exhaustively
//! unit-testable; `CertmeshCore::seal`/`open` gather the inputs.

use koi_common::sealed::{Opened, Sealed, SEALED_V0_PASSTHROUGH, SEALED_V1_GROUPKEY};

use crate::envelope::{build_envelope, decode_payload, verify_envelope};
use crate::error::CertmeshError;

/// Seal `bytes` into a **v0 passthrough** [`Sealed`] (ADR-020 §4): a signed-but-not
/// -encrypted envelope. Reuses [`build_envelope`] — there is no separate signing
/// path. `signer` is `Some((key_pem, cert_pem))` in Authenticated posture, `None`
/// in Open (a freshness-stamped passthrough). The group-key rung is a future v1.
pub fn seal_passthrough(
    signer: Option<(&str, &str)>,
    bytes: &[u8],
    nonce: &[u8],
    ts: i64,
) -> Sealed {
    Sealed::passthrough(build_envelope(signer, bytes, nonce, ts))
}

/// Open a [`Sealed`], returning the recovered bytes + trust state (ADR-020 §4).
///
/// Dispatches on [`Sealed::v`] (never a guess — the anti-downgrade extension
/// point): v0 verifies the inner envelope and returns its payload. A **rejected**
/// inner envelope (tampered / unknown-signer / expired / revoked) yields an error,
/// never bytes — so a broken seal can't be mistaken for a good one. An
/// Anonymous/Authenticated envelope (both intact) returns the payload.
///
/// `ca_cert_pem` is this verifier's pinned CA anchor (`None` on an Open node →
/// anonymous-but-intact); `revoked` is the best-effort revoked set.
pub fn open_sealed(
    sealed: &Sealed,
    ca_cert_pem: Option<&str>,
    revoked: &[String],
    now: i64,
) -> Result<Opened, CertmeshError> {
    match sealed.v {
        SEALED_V0_PASSTHROUGH => {
            let assurance = verify_envelope(&sealed.envelope, ca_cert_pem, revoked, now);
            if let koi_common::envelope::Assurance::Rejected { reason, .. } = &assurance {
                // Integrity failed → never hand back the bytes (misuse-resistance).
                return Err(CertmeshError::InvalidPayload(format!(
                    "sealed envelope rejected: {reason:?}"
                )));
            }
            let payload = decode_payload(&sealed.envelope)
                .ok_or_else(|| CertmeshError::InvalidPayload("sealed payload not base64".into()))?;
            Ok(Opened {
                payload,
                assurance,
                confidentiality: sealed.confidentiality(),
            })
        }
        SEALED_V1_GROUPKEY => Err(CertmeshError::InvalidPayload(
            "sealed v1 (group-key) is not yet supported by this node".into(),
        )),
        other => Err(CertmeshError::InvalidPayload(format!(
            "unsupported sealed version {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca;
    use crate::certmesh_paths::CertmeshPaths;
    use koi_common::envelope::{Assurance, Freshness};
    use koi_common::sealed::Confidentiality;

    struct Issued {
        cert_pem: String,
        key_pem: String,
        ca_pem: String,
        fingerprint: String,
    }

    fn ca_and_leaf(tag: &str, cn: &str) -> Issued {
        let dir = std::env::temp_dir().join(format!("koi-cm-seal-{tag}-{}", std::process::id()));
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
    fn seal_is_passthrough_not_encrypted() {
        let s = seal_passthrough(None, b"hi", &[1u8; 16], now());
        assert_eq!(s.confidentiality(), Confidentiality::None);
        assert_eq!(s.v, SEALED_V0_PASSTHROUGH);
    }

    #[test]
    fn authenticated_seal_open_round_trip() {
        let id = ca_and_leaf("ok", "web-01");
        let s = seal_passthrough(
            Some((&id.key_pem, &id.cert_pem)),
            b"secret payload",
            &[7u8; 16],
            now(),
        );
        let opened = open_sealed(&s, Some(&id.ca_pem), &[], now()).expect("open");
        assert_eq!(opened.payload, b"secret payload");
        assert_eq!(opened.assurance.identity(), Some("web-01"));
        assert_eq!(opened.confidentiality, Confidentiality::None);
    }

    #[test]
    fn open_node_passthrough_round_trips_anonymous() {
        // Sealed on an Open node (no signer), opened on an Open verifier (no anchor):
        // the same code path, the bytes survive, assurance is anonymous.
        let s = seal_passthrough(None, b"plain", &[2u8; 16], now());
        let opened = open_sealed(&s, None, &[], now()).expect("open");
        assert_eq!(opened.payload, b"plain");
        assert!(matches!(
            opened.assurance,
            Assurance::Anonymous {
                freshness: Freshness::Fresh
            }
        ));
        assert_eq!(opened.assurance.identity(), None);
    }

    #[test]
    fn tampered_seal_never_yields_bytes() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let id = ca_and_leaf("tamper", "web-01");
        let mut s = seal_passthrough(
            Some((&id.key_pem, &id.cert_pem)),
            b"original",
            &[5u8; 16],
            now(),
        );
        // Swap the inner payload after signing → the signature no longer matches.
        s.envelope.payload = B64.encode(b"tampered");
        let err = open_sealed(&s, Some(&id.ca_pem), &[], now()).unwrap_err();
        assert!(
            err.to_string().contains("rejected"),
            "a tampered seal must error, not return bytes; got: {err}"
        );
    }

    #[test]
    fn revoked_signer_seal_is_rejected() {
        let id = ca_and_leaf("revoke", "web-01");
        let s = seal_passthrough(Some((&id.key_pem, &id.cert_pem)), b"x", &[4u8; 16], now());
        let err = open_sealed(
            &s,
            Some(&id.ca_pem),
            std::slice::from_ref(&id.fingerprint),
            now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("rejected"), "got: {err}");
    }

    #[test]
    fn v1_groupkey_is_not_yet_supported() {
        let s = Sealed {
            v: SEALED_V1_GROUPKEY,
            envelope: build_envelope(None, b"x", &[0u8; 16], now()),
        };
        let err = open_sealed(&s, None, &[], now()).unwrap_err();
        assert!(err.to_string().contains("group-key"), "got: {err}");
    }

    #[test]
    fn unknown_version_is_rejected() {
        let s = Sealed {
            v: 200,
            envelope: build_envelope(None, b"x", &[0u8; 16], now()),
        };
        let err = open_sealed(&s, None, &[], now()).unwrap_err();
        assert!(
            err.to_string().contains("unsupported sealed version"),
            "got: {err}"
        );
    }
}
