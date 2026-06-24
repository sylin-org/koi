//! The signed `Envelope` wire type and the `verify` verdict (`Assurance`).
//!
//! ADR-020 §3. `sign(bytes) -> Envelope` returns a freshness-stamped passthrough
//! in Open posture and a real ES256-signed envelope in Authenticated posture —
//! the consumer can't tell and shouldn't have to. `verify(&Envelope) ->
//! Assurance` returns an *assurance level*, never a bool, so authorization keys
//! uniformly off "authenticated-as-CN vs. fresh-but-anonymous".
//!
//! These are the **wire types only** (serde-stable, schema'd for the published
//! contract); the signing/verification *logic* lives in `koi-certmesh` (it needs
//! the identity key + roster). Honesty note on the nonce: it is replay-*uniqueness*
//! input to the canonical signing bytes (ADR-020 §3); **Koi keeps no seen-nonce
//! cache** — application-layer replay defence is the consumer's responsibility.
//! Two misuse-resistance rules from the prior-art research (ADR-020 §13) are
//! encoded here:
//!
//! 1. **One identity door.** [`Assurance::identity`] is the *only* way to read a
//!    trusted CN, and it returns `Some` exclusively for authenticated-AND-fresh —
//!    so the natural `if !rejected { trust }` cannot leak a `Stale` or anonymous
//!    message (the `verify()`-returns-bool footgun).
//! 2. **Version selects the construction.** [`Envelope::v`] (not an
//!    envelope-declared `alg`) picks the verification algorithm from a hard-coded
//!    table — closing the JWT `alg:"none"` / algorithm-confusion class. The
//!    [`SigAlg`] set is closed.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Current envelope wire version. The verifier selects its construction from this
/// (never from the `Sig.alg` field). v1 = ES256 over the canonical envelope bytes.
pub const ENVELOPE_V1: u8 = 1;

/// A versioned, signed (or freshness-stamped) message envelope (ADR-020 §3).
///
/// `payload`/`nonce`/the signature are carried base64-encoded so the envelope is
/// JSON/transport-friendly and transport-agnostic (a consumer applies it to HTTP
/// bodies, its own UDP gossip, anything). In Open posture `sig` is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Envelope {
    /// Wire version — selects the verification construction (see [`ENVELOPE_V1`]).
    pub v: u8,
    /// The signed bytes, base64 (standard) encoded.
    pub payload: String,
    /// A random per-message nonce, base64 (standard) encoded — replay uniqueness.
    pub nonce: String,
    /// Signer's clock at sign time, unix seconds — drives the freshness window.
    pub ts: i64,
    /// The signature block. Absent in Open posture (a freshness-stamped
    /// passthrough); present and verified in Authenticated posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Sig>,
}

/// The signature block of an [`Envelope`] (present only when signed).
///
/// Carries the signer's leaf certificate so verification is **self-contained**: a
/// verifier validates the leaf against the pinned CA it already trusts and derives
/// the authoritative CN + public key from it — never from a claimed field (ADR-020
/// §3, the carry-cert model). This is what lets verification work on a pure member
/// node, which keeps no roster of other members' keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Sig {
    /// Signature algorithm. A closed set pinned by the envelope version; the
    /// verifier still selects its construction from [`Envelope::v`], never trusts
    /// this field to choose a codepath.
    pub alg: SigAlg,
    /// The signature over the canonical envelope bytes, base64 (standard) encoded.
    pub signature: String,
    /// The signer's leaf certificate, DER, base64 (standard) encoded. The CN,
    /// public key, serial, and validity are all read from here (authoritative).
    pub signer_cert: String,
}

/// Signature algorithms Koi will produce/accept. Closed set (no agility): a new
/// algorithm is a new [`Envelope::v`], not a new value negotiated in-band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum SigAlg {
    /// ECDSA P-256 with SHA-256 (the Koi CA's leaf algorithm).
    #[serde(rename = "ES256")]
    Es256,
}

/// Whether a message is within the replay/freshness window (ADR-020 §3, ±300s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// Within the freshness window.
    Fresh,
    /// Outside the freshness window (too old, or too far in the future).
    Stale,
}

/// The verdict of [`verify`](crate::envelope) — an assurance *level*, not a bool
/// (ADR-020 §3). Read a trusted identity only via [`Assurance::identity`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    /// No identity claim (Open posture / unsigned). Carries only a freshness verdict.
    Anonymous { freshness: Freshness },
    /// Signature valid against a current, non-revoked roster member. Freshness is
    /// a sub-field so "authenticated" cannot exist without a freshness verdict.
    Authenticated { cn: String, freshness: Freshness },
    /// The envelope was rejected; `reason` is a distinct, named cause (never one
    /// opaque error — the Istio-503 lesson, ADR-020 §13).
    ///
    /// `signer_cn` is the **authoritative** CN when — and only when — the carried
    /// leaf chained to the verifier's pinned CA but is stale (`Expired`/`Revoked`).
    /// It is `None` for every other reason (`Malformed`, `UnsupportedVersion`,
    /// `BadSignature`, `UnknownSigner`), because there the CN would be an
    /// attacker-controllable claim (an unchained or bad-signature leaf can carry
    /// any CN) and must never be attributed (ADR-022 §2). So `signer_cn` is a
    /// *trusted* attribution or nothing — safe to log, and enough for a warm
    /// "your identity expired — rejoin" by name.
    Rejected {
        reason: RejectReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signer_cn: Option<String>,
    },
}

impl Assurance {
    /// The **only** door to a trusted identity: `Some(cn)` iff the envelope is
    /// both authenticated *and* fresh; `None` otherwise.
    ///
    /// This is what makes the natural `if assurance.identity().is_some()` safe and
    /// `if !matches!(a, Rejected{..})` *insufficient* — a `Stale` or `Anonymous`
    /// message can never be mistaken for a trusted identity.
    pub fn identity(&self) -> Option<&str> {
        match self {
            Assurance::Authenticated {
                cn,
                freshness: Freshness::Fresh,
            } => Some(cn),
            _ => None,
        }
    }

    /// The **request-bound** identity door (ADR-022 §1): `Some(cn)` iff this
    /// assurance is a trusted identity ([`identity`](Self::identity) — Authenticated
    /// *and* Fresh) **and** the envelope's signed payload equals `expected`.
    ///
    /// This closes the silent-impersonation footgun in the obvious
    /// `if a.identity().is_some() { authorize(req) }` — which authorizes a
    /// *captured* envelope replayed against a *different* request. For request
    /// authorization, pass the canonical bytes you expected to be signed (typically
    /// embedding a hash of the request body); authorization succeeds only when the
    /// signer signed *those* bytes.
    ///
    /// `env` must be the same envelope this `Assurance` was produced from. Koi stays
    /// payload-agnostic — the consumer owns its canonicalization. The comparison is a
    /// plain equality: the payload was already cryptographically authenticated by
    /// `verify`, so it is not a secret.
    pub fn identity_for(&self, env: &Envelope, expected: &[u8]) -> Option<&str> {
        let cn = self.identity()?;
        let payload = B64.decode(env.payload.as_bytes()).ok()?;
        (payload == expected).then_some(cn)
    }

    /// Whether the message was rejected outright.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Assurance::Rejected { .. })
    }
}

/// Why an [`Envelope`] failed verification — distinct, named causes so a consumer
/// or `diagnose()` can act on the specific failure (ADR-020 §13).
///
/// Implementation note: an unsigned envelope in Authenticated context produces
/// [`Assurance::Anonymous`], not `Rejected`; a timestamp outside the freshness
/// window produces `Authenticated { freshness: Stale }`, not `Rejected`. Only
/// hard failures (parse error, bad crypto, unknown or revoked signer) reject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// The envelope (or its base64 fields) could not be parsed.
    Malformed,
    /// The envelope version is not understood by this verifier.
    UnsupportedVersion,
    /// The signature did not verify against the signer's public key.
    BadSignature,
    /// The signer's CN is not a current member of the roster (leaf fails to chain
    /// to the verifier's pinned CA).
    UnknownSigner,
    /// The signer's certificate has been revoked.
    Revoked,
    /// The signer's certificate has expired.
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_sig() -> Sig {
        Sig {
            alg: SigAlg::Es256,
            signature: "c2ln".to_string(),     // base64("sig")
            signer_cert: "Y2VydA".to_string(), // base64("cert")
        }
    }

    #[test]
    fn identity_door_only_opens_for_authenticated_and_fresh() {
        let auth_fresh = Assurance::Authenticated {
            cn: "web-01".to_string(),
            freshness: Freshness::Fresh,
        };
        assert_eq!(auth_fresh.identity(), Some("web-01"));

        let auth_stale = Assurance::Authenticated {
            cn: "web-01".to_string(),
            freshness: Freshness::Stale,
        };
        assert_eq!(auth_stale.identity(), None);

        let anon = Assurance::Anonymous {
            freshness: Freshness::Fresh,
        };
        assert_eq!(anon.identity(), None);

        let rejected = Assurance::Rejected {
            reason: RejectReason::BadSignature,
            signer_cn: None,
        };
        assert_eq!(rejected.identity(), None);
        assert!(rejected.is_rejected());
    }

    #[test]
    fn identity_for_binds_authorization_to_the_signed_payload() {
        let env = Envelope {
            v: ENVELOPE_V1,
            payload: B64.encode(b"the-real-request"),
            nonce: B64.encode(b"n"),
            ts: 0,
            sig: None,
        };
        let trusted = Assurance::Authenticated {
            cn: "web-01".to_string(),
            freshness: Freshness::Fresh,
        };

        // Matching expected bytes → the request-bound door opens.
        assert_eq!(
            trusted.identity_for(&env, b"the-real-request"),
            Some("web-01")
        );
        // A captured envelope replayed against a DIFFERENT request → closed
        // (the silent-impersonation footgun, closed).
        assert_eq!(trusted.identity_for(&env, b"a-different-request"), None);

        // Stale / anonymous / rejected never open, even with a matching payload —
        // identity_for can never be looser than identity().
        let stale = Assurance::Authenticated {
            cn: "web-01".to_string(),
            freshness: Freshness::Stale,
        };
        assert_eq!(stale.identity_for(&env, b"the-real-request"), None);
        let anon = Assurance::Anonymous {
            freshness: Freshness::Fresh,
        };
        assert_eq!(anon.identity_for(&env, b"the-real-request"), None);
        let rejected = Assurance::Rejected {
            reason: RejectReason::BadSignature,
            signer_cn: None,
        };
        assert_eq!(rejected.identity_for(&env, b"the-real-request"), None);
    }

    #[test]
    fn open_envelope_omits_sig_field() {
        let env = Envelope {
            v: ENVELOPE_V1,
            payload: "aGk".to_string(),
            nonce: "bm9uY2U".to_string(),
            ts: 1_700_000_000,
            sig: None,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("sig"));
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn signed_envelope_round_trips() {
        let env = Envelope {
            v: ENVELOPE_V1,
            payload: "aGk".to_string(),
            nonce: "bm9uY2U".to_string(),
            ts: 1_700_000_000,
            sig: Some(dummy_sig()),
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("signer_cert"));
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn sig_alg_serializes_as_es256() {
        assert_eq!(serde_json::to_string(&SigAlg::Es256).unwrap(), r#""ES256""#);
    }

    #[test]
    fn freshness_and_reject_reason_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&Freshness::Stale).unwrap(),
            r#""stale""#
        );
        assert_eq!(
            serde_json::to_string(&RejectReason::BadSignature).unwrap(),
            r#""bad_signature""#
        );
        assert_eq!(
            serde_json::to_string(&RejectReason::UnsupportedVersion).unwrap(),
            r#""unsupported_version""#
        );
    }

    #[test]
    fn produced_reject_reasons_are_all_variants() {
        // Document which RejectReason values the verifier actually produces.
        // NoSignature, ClockSkew, NameMismatch were removed because the verifier
        // never emitted them (unsigned→Anonymous, out-of-window→Stale, CN from cert).
        let reasons = [
            RejectReason::Malformed,
            RejectReason::UnsupportedVersion,
            RejectReason::BadSignature,
            RejectReason::UnknownSigner,
            RejectReason::Revoked,
            RejectReason::Expired,
        ];
        for r in &reasons {
            // Each variant round-trips through serde.
            let s = serde_json::to_string(r).unwrap();
            let back: RejectReason = serde_json::from_str(&s).unwrap();
            assert_eq!(r, &back);
        }
    }
}
