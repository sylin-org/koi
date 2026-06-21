//! The `Sealed` confidentiality envelope (ADR-020 §4).
//!
//! `seal(bytes) -> Sealed` / `open(&Sealed) -> Opened` are the confidentiality
//! rung, shipped **today as passthrough**: a `Sealed` carries a signed
//! [`Envelope`] (integrity + freshness) but is **not encrypted**. Consumers code
//! against the final API now; the group-key encryption rung becomes a later
//! Koi-internal upgrade with zero consumer change.
//!
//! Passthrough is a built-in downgrade (the STARTTLS/opportunistic-encryption
//! antipattern), so it is designed against, not left implicit (ADR-020 §13):
//!
//! 1. **The version is the single source of truth.** [`Sealed::v`] selects the
//!    `open` construction and the confidentiality level — never a guess. A new
//!    rung is a new version (v1 group-key), not a renegotiated field.
//! 2. **Confidentiality is type-level.** [`Sealed::confidentiality`] returns
//!    [`Confidentiality`] so passthrough can never be *mistaken* for encrypted;
//!    the level is observable (`/v1/status` `seal:`), not silent.
//!
//! These are the **wire types only** (like [`Envelope`]); the seal/open *logic*
//! (which needs the identity key + CA anchor) lives in `koi-certmesh`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::envelope::{Assurance, Envelope};

/// Sealed wire version: **v0 = passthrough** — a signed but unencrypted envelope
/// (today's rung). Integrity + freshness, no secrecy.
pub const SEALED_V0_PASSTHROUGH: u8 = 0;

/// Sealed wire version: **v1 = group-key AEAD** — the future Confidential rung.
/// Reserved; not yet produced. `open` dispatches on the version so v1 slots in
/// without changing the consumer-facing API, and the v1 derivation will use the
/// new, K3-distinct HKDF label `b"koi-seal-group-v1"` (defined in
/// `koi_crypto::key_agreement::SEAL_GROUP_KEY_HKDF_INFO_V1`).
pub const SEALED_V1_GROUPKEY: u8 = 1;

/// The confidentiality `seal()` currently produces (ADR-020 §4). Today every
/// `Sealed` is passthrough; this becomes [`Confidentiality::GroupKey`] when the v1
/// rung lands. `/v1/status` reports it as `seal:`.
pub const CURRENT_CONFIDENTIALITY: Confidentiality = Confidentiality::None;

/// Type-level confidentiality of a [`Sealed`] message (ADR-020 §4).
///
/// Read from the version, never guessed — so a passthrough message cannot be
/// mistaken for an encrypted one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidentiality {
    /// Signed but not encrypted (passthrough): integrity + freshness, no secrecy.
    None,
    /// Group-key encrypted (the future rung).
    GroupKey,
}

impl Confidentiality {
    /// The stable wire string for `/v1/status` and the published contract:
    /// `passthrough` | `groupkey`.
    pub const fn as_wire(self) -> &'static str {
        match self {
            Confidentiality::None => "passthrough",
            Confidentiality::GroupKey => "groupkey",
        }
    }
}

/// A versioned confidentiality envelope (ADR-020 §4).
///
/// Today every `Sealed` is **v0 passthrough**: it wraps a signed [`Envelope`]
/// (integrity + freshness) and is **not encrypted**. The version is the single
/// source of truth — `open` selects its construction from it and
/// [`confidentiality`](Self::confidentiality) reads the level from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Sealed {
    /// Wire version — selects the `open` construction and the confidentiality level.
    pub v: u8,
    /// The signed envelope. For v0 it carries the cleartext payload (signed, not
    /// encrypted); for v1 it will authenticate the AEAD ciphertext.
    pub envelope: Envelope,
}

impl Sealed {
    /// Wrap a signed [`Envelope`] as a **v0 passthrough** `Sealed` (signed, not
    /// encrypted).
    pub fn passthrough(envelope: Envelope) -> Self {
        Self {
            v: SEALED_V0_PASSTHROUGH,
            envelope,
        }
    }

    /// The type-level confidentiality (ADR-020 §4), read from the version. Unknown
    /// versions conservatively read as [`Confidentiality::None`] — never claim a
    /// secrecy this verifier can't provide (and `open` rejects unknown versions
    /// anyway).
    pub fn confidentiality(&self) -> Confidentiality {
        match self.v {
            SEALED_V1_GROUPKEY => Confidentiality::GroupKey,
            _ => Confidentiality::None,
        }
    }
}

/// The result of `open` (ADR-020 §4): the recovered bytes plus the trust state
/// they arrived with. `open` returns this **only** when the inner envelope was
/// intact — a rejected (tampered / unknown-signer / expired / revoked) message
/// never yields bytes (misuse-resistance, ADR-020 §13). Read a trusted identity
/// via `assurance.identity()`.
#[derive(Clone)]
pub struct Opened {
    /// The recovered plaintext bytes.
    pub payload: Vec<u8>,
    /// The assurance over the inner signed envelope (`Anonymous` on an Open node /
    /// unsigned passthrough, `Authenticated{cn}` when signed by a mesh member).
    pub assurance: Assurance,
    /// What confidentiality protected the message in transit (today: `None`).
    pub confidentiality: Confidentiality,
}

impl std::fmt::Debug for Opened {
    /// Redacts the payload (it may be a secret); shows only its length + trust state.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("payload_len", &self.payload.len())
            .field("assurance", &self.assurance)
            .field("confidentiality", &self.confidentiality)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, Freshness, ENVELOPE_V1};

    fn open_envelope() -> Envelope {
        Envelope {
            v: ENVELOPE_V1,
            payload: "aGk".to_string(),
            nonce: "bm9uY2U".to_string(),
            ts: 1_700_000_000,
            sig: None,
        }
    }

    #[test]
    fn passthrough_is_v0_and_not_encrypted() {
        let s = Sealed::passthrough(open_envelope());
        assert_eq!(s.v, SEALED_V0_PASSTHROUGH);
        assert_eq!(s.confidentiality(), Confidentiality::None);
    }

    #[test]
    fn v1_version_reads_as_groupkey() {
        let s = Sealed {
            v: SEALED_V1_GROUPKEY,
            envelope: open_envelope(),
        };
        assert_eq!(s.confidentiality(), Confidentiality::GroupKey);
    }

    #[test]
    fn unknown_version_is_conservatively_not_encrypted() {
        let s = Sealed {
            v: 99,
            envelope: open_envelope(),
        };
        assert_eq!(s.confidentiality(), Confidentiality::None);
    }

    #[test]
    fn confidentiality_wire_strings() {
        assert_eq!(Confidentiality::None.as_wire(), "passthrough");
        assert_eq!(Confidentiality::GroupKey.as_wire(), "groupkey");
        // The reported current level is passthrough until the v1 rung lands.
        assert_eq!(CURRENT_CONFIDENTIALITY.as_wire(), "passthrough");
    }

    #[test]
    fn confidentiality_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&Confidentiality::GroupKey).unwrap(),
            r#""group_key""#
        );
    }

    #[test]
    fn sealed_round_trips() {
        let s = Sealed::passthrough(open_envelope());
        let json = serde_json::to_string(&s).unwrap();
        let back: Sealed = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn opened_debug_redacts_payload() {
        let opened = Opened {
            payload: b"super-secret-bytes".to_vec(),
            assurance: Assurance::Anonymous {
                freshness: Freshness::Fresh,
            },
            confidentiality: Confidentiality::None,
        };
        let dbg = format!("{opened:?}");
        assert!(dbg.contains("payload_len"));
        assert!(
            !dbg.contains("super-secret"),
            "Debug must not leak the payload"
        );
    }
}
