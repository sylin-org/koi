//! Member health heartbeat validation.
//!
//! Members periodically POST a heartbeat containing their pinned CA
//! fingerprint. The CA validates it against the current fingerprint
//! using constant-time comparison to prevent timing side-channels.

/// How often members send health heartbeats (in seconds).
pub const HEARTBEAT_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Validate a member's pinned CA fingerprint against the current one.
///
/// Uses `koi_crypto::pinning::fingerprints_match()` for constant-time
/// comparison. Returns `true` if the pinned fingerprint is still valid.
pub fn validate_pinned_fingerprint(
    current_ca_fingerprint: &str,
    pinned_ca_fingerprint: &str,
) -> bool {
    koi_crypto::pinning::fingerprints_match(current_ca_fingerprint, pinned_ca_fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_fingerprints_are_valid() {
        let fp = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(validate_pinned_fingerprint(fp, fp));
    }

    #[test]
    fn mismatched_fingerprints_are_invalid() {
        let current = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let pinned = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert!(!validate_pinned_fingerprint(current, pinned));
    }

    #[test]
    fn empty_fingerprints_match() {
        assert!(validate_pinned_fingerprint("", ""));
    }

    #[test]
    fn different_length_fingerprints_are_invalid() {
        let current = "a1b2c3d4";
        let pinned = "a1b2c3d4e5";
        assert!(!validate_pinned_fingerprint(current, pinned));
    }

    #[test]
    fn real_fingerprint_round_trip() {
        // Simulate the actual flow: CA produces fingerprint, member pins it, health validates it
        let cert_der = b"test CA certificate DER data";
        let ca_fp = koi_crypto::pinning::fingerprint_sha256(cert_der);
        let pinned = ca_fp.clone();
        assert!(validate_pinned_fingerprint(&ca_fp, &pinned));
    }

    #[test]
    fn fingerprint_comparison_is_case_sensitive() {
        // Constant-time comparison is byte-level — case matters.
        // fingerprint_sha256() always produces lowercase hex, so
        // mixed-case inputs should not match (indicating a bug upstream).
        let lower = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let upper = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        assert!(!validate_pinned_fingerprint(lower, upper));
    }

    #[test]
    fn non_hex_characters_dont_match_valid() {
        let valid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let invalid = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(!validate_pinned_fingerprint(valid, invalid));
    }

    #[test]
    fn single_char_difference_fails() {
        let fp1 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let fp2 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b3";
        assert!(!validate_pinned_fingerprint(fp1, fp2));
    }

    #[test]
    fn whitespace_fingerprints_dont_match_empty() {
        // Whitespace is not equal to empty
        assert!(!validate_pinned_fingerprint("  ", ""));
    }

    #[test]
    fn heartbeat_interval_is_five_minutes() {
        assert_eq!(HEARTBEAT_INTERVAL_SECS, 300);
    }

    #[test]
    fn two_different_certs_produce_different_fingerprints() {
        let cert_a = b"certificate A data";
        let cert_b = b"certificate B data";
        let fp_a = koi_crypto::pinning::fingerprint_sha256(cert_a);
        let fp_b = koi_crypto::pinning::fingerprint_sha256(cert_b);
        assert!(!validate_pinned_fingerprint(&fp_a, &fp_b));
    }
}
