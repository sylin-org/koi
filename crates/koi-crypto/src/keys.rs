//! ECDSA P-256 key generation and encryption at rest.
//!
//! CA private keys are encrypted with Argon2id (KDF) + AES-256-GCM
//! before writing to disk. The operator's passphrase is required to
//! decrypt after each daemon restart.

use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Salt length for Argon2id key derivation.
const SALT_LEN: usize = 16;

/// Nonce length for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// Encrypted key material stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// ECDSA P-256 signing key with zeroize-on-drop.
pub struct CaKeyPair {
    signing_key: SigningKey,
}

impl CaKeyPair {
    /// Access the inner signing key for certificate operations.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Export the public key in PEM format.
    pub fn public_key_pem(&self) -> String {
        use p256::pkcs8::EncodePublicKey;
        self.signing_key
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .expect("public key PEM encoding should not fail")
    }

    /// Export the private key in PKCS#8 PEM format.
    /// Caller is responsible for zeroizing the returned string.
    pub fn private_key_pem(&self) -> zeroize::Zeroizing<String> {
        self.signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("private key PEM encoding should not fail")
    }
}

impl Drop for CaKeyPair {
    fn drop(&mut self) {
        // SigningKey's inner scalar is zeroized by p256 on drop.
        // We explicitly note this for auditability.
    }
}

/// Generate an ECDSA P-256 keypair seeded by mixing operator entropy
/// with system RNG.
///
/// `entropy_seed` is additional entropy collected from the operator
/// (keyboard mashing, passphrase hash, etc.). It is mixed with the
/// OS CSPRNG to produce the final key — never used alone.
pub fn generate_ca_keypair(entropy_seed: &[u8]) -> CaKeyPair {
    // Mix operator entropy with OS RNG by hashing both together
    // to produce a seed that benefits from both sources.
    let mut hasher = Sha256::new();
    hasher.update(entropy_seed);

    let mut os_random = [0u8; 32];
    OsRng.fill_bytes(&mut os_random);
    hasher.update(os_random);

    let mixed_seed = hasher.finalize();

    // Use the mixed seed to derive an ECDSA key.
    // p256's from_bytes performs modular reduction if needed.
    let signing_key = SigningKey::from_bytes((&*mixed_seed).into())
        .expect("SHA-256 output is always 32 bytes, valid for P-256 scalar");

    os_random.zeroize();

    CaKeyPair { signing_key }
}

/// Encrypt a CA keypair for storage at rest.
///
/// Uses Argon2id to derive an AES-256 key from the passphrase,
/// then encrypts the PKCS#8 DER-encoded private key with AES-256-GCM.
pub fn encrypt_key(
    key: &CaKeyPair,
    passphrase: &str,
) -> Result<EncryptedKey, CryptoError> {
    let der = key
        .signing_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::KeyEncoding(e.to_string()))?;
    let plaintext = der.as_bytes();

    encrypt_bytes(plaintext, passphrase)
}

/// Decrypt a CA keypair from encrypted storage.
pub fn decrypt_key(
    encrypted: &EncryptedKey,
    passphrase: &str,
) -> Result<CaKeyPair, CryptoError> {
    let mut plaintext = decrypt_bytes(encrypted, passphrase)?;

    let signing_key = SigningKey::from_pkcs8_der(&plaintext)
        .map_err(|e| CryptoError::KeyEncoding(e.to_string()))?;

    plaintext.zeroize();

    Ok(CaKeyPair { signing_key })
}

/// Save an encrypted key to a JSON file.
pub fn save_encrypted_key(
    path: &Path,
    encrypted: &EncryptedKey,
) -> Result<(), CryptoError> {
    let json = serde_json::to_string_pretty(encrypted)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, json)?;

    tracing::debug!(path = %path.display(), "Encrypted key saved");
    Ok(())
}

/// Load an encrypted key from a JSON file.
pub fn load_encrypted_key(path: &Path) -> Result<EncryptedKey, CryptoError> {
    let json = std::fs::read_to_string(path)?;
    let encrypted: EncryptedKey = serde_json::from_str(&json)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(encrypted)
}

/// Encrypt arbitrary bytes with passphrase-derived AES-256-GCM.
pub fn encrypt_bytes(
    plaintext: &[u8],
    passphrase: &str,
) -> Result<EncryptedKey, CryptoError> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let aes_key = derive_aes_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
        .clone()
        .try_into()
        .expect("nonce is always NONCE_LEN bytes");
    let nonce = Nonce::from(nonce_arr);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    Ok(EncryptedKey {
        ciphertext,
        salt,
        nonce: nonce_bytes,
    })
}

/// Decrypt bytes encrypted with `encrypt_bytes`.
pub fn decrypt_bytes(
    encrypted: &EncryptedKey,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
    let aes_key = derive_aes_key(passphrase, &encrypted.salt)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;

    let nonce_arr: [u8; NONCE_LEN] = encrypted
        .nonce
        .clone()
        .try_into()
        .map_err(|_| CryptoError::Decryption("invalid nonce length".into()))?;
    let nonce = Nonce::from(nonce_arr);
    let plaintext = cipher
        .decrypt(&nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::Decryption("decryption failed (wrong passphrase?)".into()))?;

    Ok(plaintext)
}

/// Derive a 256-bit AES key from a passphrase using Argon2id.
fn derive_aes_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key encoding: {0}")]
    KeyEncoding(String),
    #[error("encryption: {0}")]
    Encryption(String),
    #[error("decryption: {0}")]
    Decryption(String),
    #[error("key derivation: {0}")]
    KeyDerivation(String),
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_key() {
        let seed = b"test entropy seed material here!";
        let kp = generate_ca_keypair(seed);
        // Should produce a valid PEM
        let pem = kp.public_key_pem();
        assert!(pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let seed = b"round trip test seed 1234567890!";
        let kp = generate_ca_keypair(seed);
        let passphrase = "test-passphrase-123";

        let encrypted = encrypt_key(&kp, passphrase).unwrap();
        let decrypted = decrypt_key(&encrypted, passphrase).unwrap();

        assert_eq!(kp.public_key_pem(), decrypted.public_key_pem());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let seed = b"wrong passphrase test seed 12345";
        let kp = generate_ca_keypair(seed);

        let encrypted = encrypt_key(&kp, "correct").unwrap();
        let result = decrypt_key(&encrypted, "wrong");

        assert!(result.is_err());
    }

    #[test]
    fn different_entropy_produces_different_keys() {
        let kp1 = generate_ca_keypair(b"entropy seed one________________");
        let kp2 = generate_ca_keypair(b"entropy seed two________________");

        assert_ne!(kp1.public_key_pem(), kp2.public_key_pem());
    }

    #[test]
    fn encrypted_key_serialization_round_trip() {
        let seed = b"serialization test seed 12345678";
        let kp = generate_ca_keypair(seed);
        let encrypted = encrypt_key(&kp, "test").unwrap();

        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedKey = serde_json::from_str(&json).unwrap();

        let decrypted = decrypt_key(&deserialized, "test").unwrap();
        assert_eq!(kp.public_key_pem(), decrypted.public_key_pem());
    }

    #[test]
    fn save_and_load_encrypted_key() {
        let dir = std::env::temp_dir().join("koi-crypto-test-keys");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test-key.enc");

        let seed = b"save load test seed material!!!!";
        let kp = generate_ca_keypair(seed);
        let encrypted = encrypt_key(&kp, "save-test").unwrap();

        save_encrypted_key(&path, &encrypted).unwrap();
        let loaded = load_encrypted_key(&path).unwrap();
        let decrypted = decrypt_key(&loaded, "save-test").unwrap();

        assert_eq!(kp.public_key_pem(), decrypted.public_key_pem());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_key_pem_is_valid() {
        let seed = b"private key pem test seed 123456";
        let kp = generate_ca_keypair(seed);
        let pem = kp.private_key_pem();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
    }
}
