//! Trust posture — the mode oracle every mode-transparent primitive consults.
//!
//! ADR-020 §0/§1. Koi's native trust vocabulary is "secure/non-secure"
//! (ADR-016 §2); this extends that single bit into two orthogonal dimensions so
//! the *same* consumer code path works whether a node is unsecured,
//! authenticated, or confidential. The dial lives inside Koi's primitives — they
//! all key off this type, and consumers never branch on it.
//!
//! Neutral vocabulary only (STACK-0001 K2): `Open` / `Authenticated` /
//! `Confidential` are standard security terms, never a consumer codename. A
//! consumer layer may *alias* the level as its own "degree"; that naming never
//! enters Koi.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A node's (or a discovered peer's) trust posture: two orthogonal cryptographic
/// dimensions.
///
/// - `signed` — a usable cryptographic identity is present (the node can sign and
///   speak mTLS). This is exactly Koi's historical "secure" bit (ADR-016 §2).
/// - `encrypted` — group-key confidentiality is available (the future
///   Confidential rung; stays `false` until the `seal`/`open` encryption rung
///   lands, ADR-020 §4).
///
/// Every mode-transparent primitive (sign/verify, serve, client_for,
/// require_auth, seal/open) consults this and adapts. Wire-stable (serde +
/// schema) so a peer's posture can travel in discovery and the published wire
/// contract (ADR-020 §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, ToSchema)]
pub struct Posture {
    /// A usable cryptographic identity is present (can sign / speak mTLS).
    pub signed: bool,
    /// Group-key confidentiality is available (the future Confidential rung).
    pub encrypted: bool,
}

impl Posture {
    /// No identity, no confidentiality — the default for an unsecured node.
    pub const OPEN: Posture = Posture {
        signed: false,
        encrypted: false,
    };

    /// Construct from the two dimensions.
    pub const fn new(signed: bool, encrypted: bool) -> Self {
        Self { signed, encrypted }
    }

    /// The named level this posture resolves to.
    ///
    /// `encrypted` without `signed` is meaningless (no confidential trust without
    /// an identity), so any unsigned posture is [`PostureLevel::Open`].
    pub const fn level(self) -> PostureLevel {
        match (self.signed, self.encrypted) {
            (false, _) => PostureLevel::Open,
            (true, false) => PostureLevel::Authenticated,
            (true, true) => PostureLevel::Confidential,
        }
    }

    /// Back-compat with Koi's native "secure/non-secure" vocabulary (ADR-016 §2):
    /// a node is "secure" exactly when it holds an identity.
    pub const fn is_secure(self) -> bool {
        self.signed
    }
}

/// The named trust level derived from a [`Posture`] (ADR-020 §1).
///
/// A graduated ladder; each rung is a superset of the last, so the derived
/// ordering (`Open < Authenticated < Confidential`) answers "at least this
/// level". Neutral, standard security vocabulary (STACK-0001 K2).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PostureLevel {
    /// No identity — plaintext, anonymous (freshness only).
    Open,
    /// A cryptographic identity is present — signed / mTLS, authenticated-as-CN.
    Authenticated,
    /// Authenticated plus group-key confidentiality (the future rung).
    Confidential,
}

impl From<Posture> for PostureLevel {
    fn from(p: Posture) -> Self {
        p.level()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_is_neither_and_not_secure() {
        assert_eq!(Posture::OPEN, Posture::new(false, false));
        assert_eq!(Posture::OPEN.level(), PostureLevel::Open);
        assert!(!Posture::OPEN.is_secure());
    }

    #[test]
    fn default_posture_is_open() {
        assert_eq!(Posture::default(), Posture::OPEN);
    }

    #[test]
    fn signed_only_is_authenticated_and_secure() {
        let p = Posture::new(true, false);
        assert_eq!(p.level(), PostureLevel::Authenticated);
        assert!(p.is_secure());
    }

    #[test]
    fn signed_and_encrypted_is_confidential() {
        let p = Posture::new(true, true);
        assert_eq!(p.level(), PostureLevel::Confidential);
        assert!(p.is_secure());
    }

    #[test]
    fn encrypted_without_signed_degrades_to_open() {
        // Confidentiality without an identity is meaningless.
        let p = Posture::new(false, true);
        assert_eq!(p.level(), PostureLevel::Open);
        assert!(!p.is_secure());
    }

    #[test]
    fn level_ordering_is_a_graduated_ladder() {
        assert!(PostureLevel::Open < PostureLevel::Authenticated);
        assert!(PostureLevel::Authenticated < PostureLevel::Confidential);
    }

    #[test]
    fn from_posture_for_level() {
        assert_eq!(
            PostureLevel::from(Posture::new(true, false)),
            PostureLevel::Authenticated
        );
    }

    #[test]
    fn posture_serde_round_trip() {
        let p = Posture::new(true, false);
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, r#"{"signed":true,"encrypted":false}"#);
        let back: Posture = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn posture_level_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&PostureLevel::Authenticated).unwrap(),
            r#""authenticated""#
        );
        assert_eq!(
            serde_json::to_string(&PostureLevel::Confidential).unwrap(),
            r#""confidential""#
        );
        let back: PostureLevel = serde_json::from_str(r#""open""#).unwrap();
        assert_eq!(back, PostureLevel::Open);
    }
}
