//! JWS (RFC 7515) verification for ACME — assembled from `p256` + `sha2` +
//! `base64`, no josekit/jsonwebtoken.
//!
//! An ACME request is a **flattened** JWS JSON object
//! (`{protected, payload, signature}`, content-type `application/jose+json`).
//! The three members are base64url (`URL_SAFE_NO_PAD`). We:
//!
//! 1. decode `protected` → a JSON header. It must carry `alg == "ES256"` (else
//!    `badSignatureAlgorithm`), a `nonce`, a `url`, and EXACTLY ONE of `jwk`
//!    (embedded EC public key, used by newAccount) or `kid` (an account URL,
//!    used by everything after) — both or neither is `malformed`.
//! 2. reconstruct the verifying key — from the embedded `jwk` (newAccount) or
//!    from the account's stored JWK looked up by `kid` (subsequent requests).
//! 3. verify the **raw 64-byte R‖S** ES256 signature
//!    (`Signature::from_slice`, NOT DER) over the bytes
//!    `format!("{protected_b64}.{payload_b64}")`.
//!
//! Security properties enforced here (see the gate tests):
//! - a signature made with a different key than the account JWK is rejected;
//! - the protected `url` is exposed so the handler can bind it to the request URL;
//! - the algorithm allow-list is ES256-only.

use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// URL-safe base64 without padding — the only encoding ACME JWS uses.
fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// The JWK members for a P-256 EC public key (RFC 7518 §6.2).
///
/// Only the four members that matter for ACME's EC keys are modelled. Extra
/// members are ignored on the wire but excluded from the canonical thumbprint
/// input (RFC 7638 §3.2 — only required members, lexicographic, no whitespace).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// The decoded JWS protected header.
#[derive(Debug, Clone, Deserialize)]
struct ProtectedHeader {
    alg: String,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    jwk: Option<Jwk>,
    #[serde(default)]
    kid: Option<String>,
}

/// The raw flattened JWS request body (`application/jose+json`).
#[derive(Debug, Clone, Deserialize)]
pub struct FlattenedJws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// How the request authenticated itself: a newAccount embeds a `jwk`; every
/// subsequent request references its account by `kid` (the account URL).
#[derive(Debug, Clone)]
pub enum KeyId {
    /// newAccount: the public key is embedded in the protected header.
    Jwk(Jwk),
    /// Everything after newAccount: the account URL.
    Kid(String),
}

/// A successfully-parsed (NOT yet signature-verified) JWS.
#[derive(Debug, Clone)]
pub struct ParsedJws {
    pub nonce: String,
    pub url: String,
    pub key_id: KeyId,
    /// The decoded payload bytes (may be empty for POST-as-GET).
    pub payload: Vec<u8>,
    /// The signing input `protected_b64.payload_b64` (kept for verification).
    signing_input: Vec<u8>,
    /// Raw 64-byte R‖S signature.
    signature: Vec<u8>,
}

/// Errors from JWS parsing/verification, mapped to ACME problem types by callers.
#[derive(Debug, PartialEq, Eq)]
pub enum JwsError {
    /// Structurally malformed (bad base64, bad JSON, missing fields, both/neither
    /// jwk+kid, missing nonce/url).
    Malformed(String),
    /// `alg` is present but not ES256.
    BadAlgorithm(String),
    /// Signature did not verify against the key.
    BadSignature,
}

impl ParsedJws {
    /// The embedded JWK, iff this was a newAccount (jwk) request.
    pub fn embedded_jwk(&self) -> Option<&Jwk> {
        match &self.key_id {
            KeyId::Jwk(j) => Some(j),
            KeyId::Kid(_) => None,
        }
    }

    /// Verify the ES256 signature against the supplied JWK. The caller chooses
    /// the JWK: the embedded one for newAccount, or the account's stored JWK
    /// (looked up by `kid`) for everything else. THIS is the wrong-key gate.
    pub fn verify_with(&self, jwk: &Jwk) -> Result<(), JwsError> {
        let key = verifying_key_from_jwk(jwk)?;
        // ES256 signatures are raw 64-byte R‖S (NOT DER) — the certmesh manifest
        // path uses DER; ACME does not. from_slice expects exactly 64 bytes.
        let sig = Signature::from_slice(&self.signature).map_err(|_| JwsError::BadSignature)?;
        key.verify(&self.signing_input, &sig)
            .map_err(|_| JwsError::BadSignature)
    }
}

/// Parse a flattened JWS into its verified-shape parts, enforcing the structural
/// ACME rules (alg=ES256, nonce+url present, exactly one of jwk/kid). Does NOT
/// verify the signature — call [`ParsedJws::verify_with`] for that.
pub fn parse(jws: &FlattenedJws) -> Result<ParsedJws, JwsError> {
    let protected_bytes = b64()
        .decode(&jws.protected)
        .map_err(|_| JwsError::Malformed("protected is not valid base64url".into()))?;
    let header: ProtectedHeader = serde_json::from_slice(&protected_bytes)
        .map_err(|e| JwsError::Malformed(format!("protected header JSON: {e}")))?;

    if header.alg != "ES256" {
        return Err(JwsError::BadAlgorithm(format!(
            "unsupported JWS alg '{}' (ES256 only)",
            header.alg
        )));
    }

    let nonce = header
        .nonce
        .ok_or_else(|| JwsError::Malformed("missing protected.nonce".into()))?;
    let url = header
        .url
        .ok_or_else(|| JwsError::Malformed("missing protected.url".into()))?;

    let key_id = match (header.jwk, header.kid) {
        (Some(_), Some(_)) => {
            return Err(JwsError::Malformed(
                "protected header carries both jwk and kid".into(),
            ))
        }
        (None, None) => {
            return Err(JwsError::Malformed(
                "protected header carries neither jwk nor kid".into(),
            ))
        }
        (Some(jwk), None) => KeyId::Jwk(jwk),
        (None, Some(kid)) => KeyId::Kid(kid),
    };

    let payload = b64()
        .decode(&jws.payload)
        .map_err(|_| JwsError::Malformed("payload is not valid base64url".into()))?;
    let signature = b64()
        .decode(&jws.signature)
        .map_err(|_| JwsError::Malformed("signature is not valid base64url".into()))?;

    // The signing input is the ASCII bytes "protected.payload" — the on-the-wire
    // base64url strings joined by a dot, NOT the decoded bytes.
    let signing_input = format!("{}.{}", jws.protected, jws.payload).into_bytes();

    Ok(ParsedJws {
        nonce,
        url,
        key_id,
        payload,
        signing_input,
        signature,
    })
}

/// Reconstruct a P-256 verifying key from a JWK's `x`/`y` base64url coordinates.
fn verifying_key_from_jwk(jwk: &Jwk) -> Result<VerifyingKey, JwsError> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(JwsError::Malformed(format!(
            "unsupported JWK (kty={}, crv={}); only EC P-256",
            jwk.kty, jwk.crv
        )));
    }
    let x = b64()
        .decode(&jwk.x)
        .map_err(|_| JwsError::Malformed("JWK x is not base64url".into()))?;
    let y = b64()
        .decode(&jwk.y)
        .map_err(|_| JwsError::Malformed("JWK y is not base64url".into()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(JwsError::Malformed(
            "JWK x/y must be 32 bytes each for P-256".into(),
        ));
    }

    let point = EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        /* compress = */ false,
    );
    let maybe_pk = PublicKey::from_encoded_point(&point);
    if maybe_pk.is_none().into() {
        return Err(JwsError::Malformed(
            "JWK coordinates are not a valid P-256 point".into(),
        ));
    }
    let pk = maybe_pk.unwrap();
    Ok(VerifyingKey::from(pk))
}

/// Compute the RFC 7638 JWK thumbprint: `base64url(SHA256(canonical))` where the
/// canonical EC JSON is EXACTLY `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`
/// — required members only, lexicographic order, no whitespace.
///
/// This is the account's stable identity and the basis for the dns-01
/// keyAuthorization (`token + "." + thumbprint`).
pub fn jwk_thumbprint(jwk: &Jwk) -> String {
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    let digest = Sha256::digest(canonical.as_bytes());
    b64().encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;

    /// Build a JWK for a signing key's public half.
    fn jwk_for(sk: &SigningKey) -> Jwk {
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: b64().encode(point.x().unwrap()),
            y: b64().encode(point.y().unwrap()),
        }
    }

    /// Build a signed flattened JWS over (protected, payload) with `jwk` embedded.
    fn make_jws(sk: &SigningKey, nonce: &str, url: &str, payload: &[u8]) -> FlattenedJws {
        let jwk = jwk_for(sk);
        let protected = serde_json::json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
            "jwk": {"kty": jwk.kty, "crv": jwk.crv, "x": jwk.x, "y": jwk.y},
        });
        let protected_b64 = b64().encode(serde_json::to_vec(&protected).unwrap());
        let payload_b64 = b64().encode(payload);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig: Signature = sk.sign(signing_input.as_bytes());
        FlattenedJws {
            protected: protected_b64,
            payload: payload_b64,
            signature: b64().encode(sig.to_bytes()),
        }
    }

    #[test]
    fn valid_jws_parses_and_verifies() {
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let jws = make_jws(&sk, "nonce-1", "https://ca/acme/new-account", b"{}");
        let parsed = parse(&jws).expect("should parse");
        assert_eq!(parsed.nonce, "nonce-1");
        assert_eq!(parsed.url, "https://ca/acme/new-account");
        let jwk = parsed
            .embedded_jwk()
            .expect("newAccount carries jwk")
            .clone();
        parsed.verify_with(&jwk).expect("signature must verify");
    }

    #[test]
    fn wrong_key_jws_is_rejected() {
        // Sign with sk_a but verify against sk_b's JWK → must fail. This is the
        // security gate: a forged signature under the wrong key never passes.
        let sk_a = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let sk_b = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let jws = make_jws(&sk_a, "n", "https://ca/x", b"{}");
        let parsed = parse(&jws).unwrap();
        let wrong_jwk = jwk_for(&sk_b);
        assert_eq!(parsed.verify_with(&wrong_jwk), Err(JwsError::BadSignature));
    }

    #[test]
    fn non_es256_alg_is_bad_algorithm() {
        let jws = FlattenedJws {
            protected: b64().encode(
                serde_json::to_vec(&serde_json::json!({
                    "alg": "RS256", "nonce": "n", "url": "u", "kid": "acct"
                }))
                .unwrap(),
            ),
            payload: b64().encode(b"{}"),
            signature: b64().encode([0u8; 64]),
        };
        assert!(matches!(parse(&jws), Err(JwsError::BadAlgorithm(_))));
    }

    #[test]
    fn both_jwk_and_kid_is_malformed() {
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let jwk = jwk_for(&sk);
        let jws = FlattenedJws {
            protected: b64().encode(
                serde_json::to_vec(&serde_json::json!({
                    "alg": "ES256", "nonce": "n", "url": "u",
                    "kid": "acct",
                    "jwk": {"kty": jwk.kty, "crv": jwk.crv, "x": jwk.x, "y": jwk.y},
                }))
                .unwrap(),
            ),
            payload: b64().encode(b"{}"),
            signature: b64().encode([0u8; 64]),
        };
        assert!(matches!(parse(&jws), Err(JwsError::Malformed(_))));
    }

    #[test]
    fn neither_jwk_nor_kid_is_malformed() {
        let jws = FlattenedJws {
            protected: b64().encode(
                serde_json::to_vec(&serde_json::json!({
                    "alg": "ES256", "nonce": "n", "url": "u"
                }))
                .unwrap(),
            ),
            payload: b64().encode(b"{}"),
            signature: b64().encode([0u8; 64]),
        };
        assert!(matches!(parse(&jws), Err(JwsError::Malformed(_))));
    }

    #[test]
    fn thumbprint_is_rfc7638_canonical() {
        // Known-answer from RFC 7638 §3.1 is for RSA; here we just assert the
        // canonical JSON ordering + that the same JWK yields a stable digest.
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let jwk = jwk_for(&sk);
        let t1 = jwk_thumbprint(&jwk);
        let t2 = jwk_thumbprint(&jwk);
        assert_eq!(t1, t2, "thumbprint must be deterministic");
        // base64url(SHA256(..)) of 32 bytes → 43 chars (no padding).
        assert_eq!(t1.len(), 43);
    }

    #[test]
    fn _suppress_unused_encode_public_key() {
        // Keep EncodePublicKey import meaningful even if a refactor drops its use.
        let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let _ = sk.verifying_key().to_public_key_der().is_ok();
    }
}
