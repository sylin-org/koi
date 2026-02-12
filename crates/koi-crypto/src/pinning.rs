//! Certificate fingerprinting for trust pinning.
//!
//! Members record the CA certificate's SHA-256 fingerprint at enrollment
//! time and verify it on subsequent connections to prevent MITM attacks
//! via certificate substitution.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Compute a SHA-256 fingerprint of a DER-encoded certificate.
///
/// Returns the fingerprint as a lowercase hex string.
pub fn fingerprint_sha256(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hex_encode(&hash)
}

/// Compare two fingerprint strings in constant time.
///
/// Returns `true` if both fingerprints are equal. Uses `subtle::ConstantTimeEq`
/// to prevent timing side-channels.
pub fn fingerprints_match(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    a_bytes.ct_eq(b_bytes).into()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        let data = b"test certificate DER data";
        let fp1 = fingerprint_sha256(data);
        let fp2 = fingerprint_sha256(data);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_is_hex_string() {
        let data = b"test certificate DER data";
        let fp = fingerprint_sha256(data);
        // SHA-256 produces 32 bytes = 64 hex chars
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_data_different_fingerprints() {
        let fp1 = fingerprint_sha256(b"cert A");
        let fp2 = fingerprint_sha256(b"cert B");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn matching_fingerprints() {
        let fp = fingerprint_sha256(b"test data");
        assert!(fingerprints_match(&fp, &fp));
    }

    #[test]
    fn non_matching_fingerprints() {
        let fp1 = fingerprint_sha256(b"cert A");
        let fp2 = fingerprint_sha256(b"cert B");
        assert!(!fingerprints_match(&fp1, &fp2));
    }

    #[test]
    fn different_length_fingerprints_dont_match() {
        assert!(!fingerprints_match("abc", "abcd"));
    }
}
