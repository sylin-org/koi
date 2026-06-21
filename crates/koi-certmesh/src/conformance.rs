//! Conformance-vector validator (ADR-020 §13).
//!
//! `docs/reference/vectors/trust-vectors.json` is the language-neutral, certless,
//! deterministic conformance suite for the trust wire contract (canonical signing
//! bytes, payload round-trip/hash, posture-level mapping, sealed confidentiality).
//! A non-Rust sibling runs the *same file* against its own implementation.
//!
//! This module is the **reference implementation's self-check**: it loads the
//! committed file and asserts the Rust impl reproduces every graded `expect`, so
//! the published vectors can never silently drift from the code. The `generate`
//! test (ignored by default) re-emits the file from the impl.
//!
//! Signed-envelope *verification* (carry-cert) is intentionally not vectored here —
//! ES256 signatures are non-deterministic, so that path is covered by the
//! adversarial unit tests in [`crate::envelope`].

#![cfg(test)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use koi_common::posture::Posture;
use koi_common::sealed::Sealed;

/// The committed conformance vectors, embedded so the test needs no runtime path.
const VECTORS_JSON: &str = include_str!("../../../docs/reference/vectors/trust-vectors.json");

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS_JSON).expect("trust-vectors.json is valid JSON")
}

fn arr<'a>(v: &'a serde_json::Value, key: &str) -> &'a Vec<serde_json::Value> {
    v.get(key)
        .and_then(|s| s.as_array())
        .unwrap_or_else(|| panic!("vectors section `{key}` missing or not an array"))
}

#[test]
fn envelope_canonical_vectors_match_the_impl() {
    for c in arr(&vectors(), "envelope_canonical") {
        let v = c["v"].as_u64().unwrap() as u8;
        let payload = c["payload"].as_str().unwrap();
        let nonce = c["nonce"].as_str().unwrap();
        let ts = c["ts"].as_i64().unwrap();
        let expect = c["expect"]["canonical"].as_str().unwrap();
        let got =
            String::from_utf8(crate::envelope::canonical_bytes(v, payload, nonce, ts)).unwrap();
        assert_eq!(got, expect, "canonical mismatch for `{}`", c["desc"]);
    }
}

#[test]
fn payload_roundtrip_vectors_match_the_impl() {
    for c in arr(&vectors(), "payload_roundtrip") {
        let payload_b64 = c["payload_b64"].as_str().unwrap();
        let bytes = B64.decode(payload_b64).expect("vector payload_b64 decodes");
        let got_hex = koi_common::encoding::hex_encode(&bytes);
        assert_eq!(
            got_hex,
            c["expect"]["bytes_hex"].as_str().unwrap(),
            "bytes_hex mismatch for `{}`",
            c["desc"]
        );
        let got_sha = koi_crypto::pinning::fingerprint_sha256(&bytes);
        assert_eq!(
            got_sha,
            c["expect"]["sha256"].as_str().unwrap(),
            "sha256 mismatch for `{}`",
            c["desc"]
        );
    }
}

#[test]
fn posture_level_vectors_match_the_impl() {
    for c in arr(&vectors(), "posture_level") {
        let posture = Posture::new(
            c["signed"].as_bool().unwrap(),
            c["encrypted"].as_bool().unwrap(),
        );
        assert_eq!(
            posture.level().as_wire(),
            c["expect"]["level"].as_str().unwrap(),
            "level mismatch for `{}`",
            c["desc"]
        );
    }
}

#[test]
fn sealed_confidentiality_vectors_match_the_impl() {
    for c in arr(&vectors(), "sealed_confidentiality") {
        let v = c["v"].as_u64().unwrap() as u8;
        let sealed = Sealed {
            v,
            envelope: crate::envelope::build_envelope(None, b"", &[0u8; 1], 0),
        };
        assert_eq!(
            sealed.confidentiality().as_wire(),
            c["expect"]["confidentiality"].as_str().unwrap(),
            "confidentiality mismatch for `{}`",
            c["desc"]
        );
    }
}

/// Regenerate `trust-vectors.json` from the reference impl (run on demand:
/// `cargo test -p koi-certmesh -- --ignored regenerate_vectors`). Recomputes the
/// deterministic values so a format/version bump is a one-command refresh; the
/// committed file's prose `description` is preserved.
#[test]
#[ignore = "writes docs/reference/vectors/trust-vectors.json; run manually to regenerate"]
fn regenerate_vectors() {
    let mut doc = vectors();

    for c in doc["envelope_canonical"].as_array_mut().unwrap() {
        let v = c["v"].as_u64().unwrap() as u8;
        let (payload, nonce, ts) = (
            c["payload"].as_str().unwrap().to_string(),
            c["nonce"].as_str().unwrap().to_string(),
            c["ts"].as_i64().unwrap(),
        );
        let canonical =
            String::from_utf8(crate::envelope::canonical_bytes(v, &payload, &nonce, ts)).unwrap();
        c["expect"] = serde_json::json!({ "canonical": canonical });
    }
    for c in doc["payload_roundtrip"].as_array_mut().unwrap() {
        let bytes = B64.decode(c["payload_b64"].as_str().unwrap()).unwrap();
        c["expect"] = serde_json::json!({
            "bytes_hex": koi_common::encoding::hex_encode(&bytes),
            "sha256": koi_crypto::pinning::fingerprint_sha256(&bytes),
        });
    }
    for c in doc["posture_level"].as_array_mut().unwrap() {
        let p = Posture::new(
            c["signed"].as_bool().unwrap(),
            c["encrypted"].as_bool().unwrap(),
        );
        c["expect"] = serde_json::json!({ "level": p.level().as_wire() });
    }
    for c in doc["sealed_confidentiality"].as_array_mut().unwrap() {
        let v = c["v"].as_u64().unwrap() as u8;
        let s = Sealed {
            v,
            envelope: crate::envelope::build_envelope(None, b"", &[0u8; 1], 0),
        };
        c["expect"] = serde_json::json!({ "confidentiality": s.confidentiality().as_wire() });
    }

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/reference/vectors/trust-vectors.json"
    );
    let out = format!("{}\n", serde_json::to_string_pretty(&doc).unwrap());
    std::fs::write(path, out).expect("write trust-vectors.json");
}
