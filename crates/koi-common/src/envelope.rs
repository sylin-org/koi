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
//! the identity key + roster). Two misuse-resistance rules from the prior-art
//! research (ADR-020 §13) are encoded here:
//!
//! 1. **One identity door.** [`Assurance::identity`] is the *only* way to read a
//!    trusted CN, and it returns `Some` exclusively for authenticated-AND-fresh —
//!    so the natural `if !rejected { trust }` cannot leak a `Stale` or anonymous
//!    message (the `verify()`-returns-bool footgun).
//! 2. **Version selects the construction.** [`Envelope::v`] (not an
//!    envelope-declared `alg`) picks the verification algorithm from a hard-coded
//!    table — closing the JWT `alg:"none"` / algorithm-confusion class. The
//!    [`SigAlg`] set is closed.

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Sig {
    /// Signature algorithm. A closed set pinned by the envelope version; the
    /// verifier still selects its construction from [`Envelope::v`], never trusts
    /// this field to choose a codepath.
    pub alg: SigAlg,
    /// The signature over the canonical envelope bytes, base64 (standard) encoded.
    pub signature: String,
    /// The signer's claimed CN (verified against the signer's certificate).
    pub signer_cn: String,
    /// The signer's certificate serial, if carried (advisory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
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
    Rejected { reason: RejectReason },
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

    /// Whether the message was rejected outright.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Assurance::Rejected { .. })
    }
}

/// Why an [`Envelope`] failed verification — distinct, named causes so a consumer
/// or `diagnose()` can act on the specific failure (ADR-020 §13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// The envelope (or its base64 fields) could not be parsed.
    Malformed,
    /// A signature was required (Authenticated peer expected) but none was present.
    NoSignature,
    /// The envelope version is not understood by this verifier.
    UnsupportedVersion,
    /// The signature did not verify against the signer's public key.
    BadSignature,
    /// The signer's CN is not a current member of the roster.
    UnknownSigner,
    /// The signer's certificate has been revoked.
    Revoked,
    /// The signer's certificate has expired.
    Expired,
    /// The timestamp is outside the freshness window by more than the allowed
    /// clock-skew tolerance (distinct from `Stale` — this is a hard reject).
    ClockSkew,
    /// The signature's CN does not match the presented certificate.
    NameMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(cn: &str) -> Sig {
        Sig {
            alg: SigAlg::Es256,
            signature: "c2ln".to_string(), // base64("sig")
            signer_cn: cn.to_string(),
            serial: None,
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
        };
        assert_eq!(rejected.identity(), None);
        assert!(rejected.is_rejected());
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
            sig: Some(signed("web-01")),
        };
        let json = serde_json::to_string(&env).unwrap();
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
            serde_json::to_string(&RejectReason::ClockSkew).unwrap(),
            r#""clock_skew""#
        );
        assert_eq!(
            serde_json::to_string(&RejectReason::NoSignature).unwrap(),
            r#""no_signature""#
        );
    }

    #[test]
    fn serial_is_omitted_when_absent() {
        let json = serde_json::to_string(&signed("a")).unwrap();
        assert!(!json.contains("serial"));
    }
}
