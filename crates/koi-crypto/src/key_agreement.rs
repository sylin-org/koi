//! Ephemeral X25519 Diffie-Hellman key agreement for secure key transfer.
//!
//! Used during the promotion protocol to establish a shared secret between
//! the primary CA and the standby, so the CA key material can be encrypted
//! with a key that never traverses the wire.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::keys::CryptoError;

/// HKDF info string binding the derived key to the promote-v1 protocol.
const PROMOTE_INFO: &[u8] = b"koi-promote-v1";

/// An ephemeral X25519 key pair for one-time Diffie-Hellman exchange.
///
/// The secret is consumed on `derive_shared_key`, ensuring it cannot
/// be reused (enforced by `EphemeralSecret` move semantics).
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralKeyPair {
    /// Generate a fresh ephemeral key pair using OS randomness.
    pub fn generate() -> Self {
        // Use rand_core 0.6 OsRng (re-exported through p256) for x25519-dalek compat
        let secret = EphemeralSecret::random_from_rng(p256::elliptic_curve::rand_core::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Return the 32-byte public key for sending to the peer.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Consume this key pair and derive a 32-byte shared key from the
    /// peer's public key using X25519 + HKDF-SHA256.
    ///
    /// The returned bytes are suitable as an AES-256-GCM key.
    pub fn derive_shared_key(self, their_public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let their_key = PublicKey::from(*their_public);
        let shared_secret = self.secret.diffie_hellman(&their_key);

        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(PROMOTE_INFO, &mut okm)
            .map_err(|_| CryptoError::KeyDerivation("HKDF-SHA256 expand failed".into()))?;
        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_round_trip_derives_same_shared_key() {
        let alice = EphemeralKeyPair::generate();
        let bob = EphemeralKeyPair::generate();

        let alice_pub = alice.public_key_bytes();
        let bob_pub = bob.public_key_bytes();

        let alice_shared = alice.derive_shared_key(&bob_pub).unwrap();
        let bob_shared = bob.derive_shared_key(&alice_pub).unwrap();

        assert_eq!(alice_shared, bob_shared);
        // Verify the shared key is non-zero
        assert_ne!(alice_shared, [0u8; 32]);
    }

    #[test]
    fn different_peers_produce_different_keys() {
        let alice = EphemeralKeyPair::generate();
        let bob = EphemeralKeyPair::generate();
        let charlie = EphemeralKeyPair::generate();

        let bob_pub = bob.public_key_bytes();
        let charlie_pub = charlie.public_key_bytes();

        let alice_bob = alice.derive_shared_key(&bob_pub).unwrap();
        let charlie_bob = charlie.derive_shared_key(&bob_pub).unwrap();

        // Unless alice and charlie happen to generate the same secret
        // (astronomically unlikely), the shared keys should differ.
        // We also check charlie-bob vs bob's perspective isn't equal to alice-bob.
        // This is a probabilistic test but effectively guaranteed.
        let _ = charlie_pub; // consumed above
        assert_ne!(alice_bob, charlie_bob);
    }

    #[test]
    fn public_key_bytes_are_32_bytes() {
        let kp = EphemeralKeyPair::generate();
        let pk = kp.public_key_bytes();
        assert_eq!(pk.len(), 32);
    }
}
