//! ECDSA P-256 signing and verification for roster manifests.
//!
//! The CA signs roster manifests so standby nodes can verify integrity
//! during roster sync. Uses the same P-256 key used for certificate operations.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;

use crate::keys::CaKeyPair;

/// Sign arbitrary bytes with the CA's ECDSA P-256 signing key.
///
/// Returns the DER-encoded signature bytes.
pub fn sign_bytes(key: &CaKeyPair, data: &[u8]) -> Vec<u8> {
    let sig: Signature = key.signing_key().sign(data);
    sig.to_der().as_bytes().to_vec()
}

/// Verify an ECDSA P-256 signature against a public key in PEM format.
///
/// Returns `true` if the signature is valid for the given data and key.
pub fn verify_signature(public_key_pem: &str, data: &[u8], signature: &[u8]) -> bool {
    let verifying_key = match VerifyingKey::from_public_key_pem(public_key_pem) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig = match Signature::from_der(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    use p256::ecdsa::signature::Verifier;
    verifying_key.verify(data, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_ca_keypair;

    #[test]
    fn sign_verify_round_trip() {
        let key = generate_ca_keypair(b"signing test entropy seed 123456");
        let data = b"roster manifest content here";

        let signature = sign_bytes(&key, data);
        let public_pem = key.public_key_pem();

        assert!(verify_signature(&public_pem, data, &signature));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key1 = generate_ca_keypair(b"signing test key one ___________");
        let key2 = generate_ca_keypair(b"signing test key two ___________");
        let data = b"data signed by key1";

        let signature = sign_bytes(&key1, data);
        let wrong_public = key2.public_key_pem();

        assert!(!verify_signature(&wrong_public, data, &signature));
    }

    #[test]
    fn tampered_data_fails_verification() {
        let key = generate_ca_keypair(b"tamper test entropy seed 1234567");
        let data = b"original data";
        let tampered = b"tampered data";

        let signature = sign_bytes(&key, data);
        let public_pem = key.public_key_pem();

        assert!(!verify_signature(&public_pem, tampered, &signature));
    }

    #[test]
    fn invalid_public_key_pem_returns_false() {
        let data = b"test data";
        let signature = vec![0u8; 64];

        assert!(!verify_signature("not a pem", data, &signature));
    }

    #[test]
    fn invalid_signature_bytes_returns_false() {
        let key = generate_ca_keypair(b"invalid sig test entropy 12345!!");
        let data = b"test data";
        let public_pem = key.public_key_pem();

        assert!(!verify_signature(&public_pem, data, &[0u8; 10]));
    }

    #[test]
    fn signature_is_deterministic_length() {
        let key = generate_ca_keypair(b"length test entropy seed 1234567");
        let data = b"test data for length check";

        let sig = sign_bytes(&key, data);
        // DER-encoded P-256 signatures are typically 70-72 bytes
        assert!(
            sig.len() >= 68 && sig.len() <= 73,
            "unexpected sig len: {}",
            sig.len()
        );
    }

    #[test]
    fn sign_empty_data() {
        let key = generate_ca_keypair(b"empty data signing test seed!@#$");
        let data = b"";

        let signature = sign_bytes(&key, data);
        let public_pem = key.public_key_pem();
        assert!(verify_signature(&public_pem, data, &signature));
    }

    #[test]
    fn sign_large_data() {
        let key = generate_ca_keypair(b"large data signing test seed_xyz");
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

        let signature = sign_bytes(&key, &data);
        let public_pem = key.public_key_pem();
        assert!(verify_signature(&public_pem, &data, &signature));
    }

    #[test]
    fn sign_binary_data_with_null_bytes() {
        let key = generate_ca_keypair(b"null byte test entropy seed_____");
        let data = b"\x00\x00\xff\xff\x00\x01\x02\x03";

        let signature = sign_bytes(&key, data);
        let public_pem = key.public_key_pem();
        assert!(verify_signature(&public_pem, data, &signature));
    }

    #[test]
    fn signature_with_truncated_bytes_fails() {
        let key = generate_ca_keypair(b"truncated sig test entropy!12345");
        let data = b"data to sign";

        let signature = sign_bytes(&key, data);
        let public_pem = key.public_key_pem();

        // Truncate signature to half
        let truncated = &signature[..signature.len() / 2];
        assert!(!verify_signature(&public_pem, data, truncated));
    }

    #[test]
    fn signature_with_extra_bytes_appended_fails() {
        let key = generate_ca_keypair(b"extra bytes test entropy_1234567");
        let data = b"data to sign";

        let mut signature = sign_bytes(&key, data);
        let public_pem = key.public_key_pem();

        signature.push(0xFF);
        assert!(!verify_signature(&public_pem, data, &signature));
    }

    #[test]
    fn verify_empty_signature_returns_false() {
        let key = generate_ca_keypair(b"empty sig test entropy seed 1234");
        let data = b"test data";
        let public_pem = key.public_key_pem();

        assert!(!verify_signature(&public_pem, data, &[]));
    }
}
