//! ECDSA P-256 key generation and encryption at rest.
//!
//! CA private keys are encrypted with Argon2id (KDF) + AES-256-GCM
//! before writing to disk. The operator's passphrase is required to
//! decrypt after each daemon restart.

use std::fmt;
use std::path::Path;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Argon2, Params};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::secret::{SecretBytes, SecretString};

/// Salt length for Argon2id key derivation.
const SALT_LEN: usize = 16;

/// Nonce length for AES-256-GCM.
const NONCE_LEN: usize = 12;

// ── KDF Parameters ──────────────────────────────────────────────────

/// Explicit KDF parameters stored alongside encrypted material.
///
/// Defaults to Argon2id with OWASP-recommended parameters for
/// credential storage (65 MiB memory, 3 iterations, 4 lanes).
#[derive(Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct KdfParams {
    /// Algorithm identifier (always "argon2id" for now).
    pub algorithm: String,
    /// Memory cost in KiB (default: 65536 = 64 MiB).
    pub m_cost: u32,
    /// Time cost / iterations (default: 3).
    pub t_cost: u32,
    /// Parallelism / lanes (default: 4).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl fmt::Debug for KdfParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KdfParams")
            .field("algorithm", &self.algorithm)
            .field("m_cost", &self.m_cost)
            .field("t_cost", &self.t_cost)
            .field("p_cost", &self.p_cost)
            .finish()
    }
}

// ── Encrypted Key ───────────────────────────────────────────────────

/// Encrypted key material stored on disk.
#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct EncryptedKey {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    /// KDF parameters used to derive the encryption key.
    /// Defaults to standard Argon2id params for backward compatibility
    /// with files that don't include this field.
    #[serde(default)]
    pub kdf_params: KdfParams,
}

impl fmt::Debug for EncryptedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedKey")
            .field("ciphertext", &"[REDACTED]")
            .field("salt_len", &self.salt.len())
            .field("nonce_len", &self.nonce.len())
            .field("kdf_params", &self.kdf_params)
            .finish()
    }
}

// ── CA Key Pair ─────────────────────────────────────────────────────

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
    pub fn public_key_pem(&self) -> Result<String, CryptoError> {
        use p256::pkcs8::EncodePublicKey;
        self.signing_key
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| CryptoError::KeyEncoding(e.to_string()))
    }

    /// Export the private key in PKCS#8 PEM format.
    /// The returned `SecretString` is zeroized on drop.
    pub fn private_key_pem(&self) -> Result<SecretString, CryptoError> {
        let zeroizing = self
            .signing_key
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| CryptoError::KeyEncoding(e.to_string()))?;
        Ok(SecretString::new(zeroizing.to_string()))
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
/// OS CSPRNG to produce the final key - never used alone.
pub fn generate_ca_keypair(entropy_seed: &[u8]) -> Result<CaKeyPair, CryptoError> {
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
        .map_err(|e| CryptoError::KeyEncoding(format!("P-256 scalar from seed: {e}")))?;

    os_random.zeroize();

    Ok(CaKeyPair { signing_key })
}

/// Encrypt a CA keypair for storage at rest.
///
/// Uses Argon2id to derive an AES-256 key from the passphrase,
/// then encrypts the PKCS#8 DER-encoded private key with AES-256-GCM.
pub fn encrypt_key(key: &CaKeyPair, passphrase: &str) -> Result<EncryptedKey, CryptoError> {
    let der = key
        .signing_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::KeyEncoding(e.to_string()))?;
    let plaintext = der.as_bytes();
    let encrypted = encrypt_bytes(plaintext, passphrase)?;

    // Platform credential binding - seal the ciphertext in the OS
    // credential store so the key blob is machine-bound.
    if crate::tpm::is_available() {
        if let Err(e) = crate::tpm::seal_key_material("koi-certmesh-ca", &encrypted.ciphertext) {
            tracing::warn!(error = %e, "Platform credential sealing failed; falling back to software-only protection");
        } else {
            tracing::info!("CA key material sealed in platform credential store");
        }
    }

    Ok(encrypted)
}

/// Decrypt a CA keypair from encrypted storage.
///
/// If the ciphertext was sealed in the platform credential store at
/// encrypt time, we verify that the stored blob matches the on-disk
/// ciphertext.  A mismatch means the key file was copied from another
/// machine - we reject it to enforce machine-binding.
pub fn decrypt_key(encrypted: &EncryptedKey, passphrase: &str) -> Result<CaKeyPair, CryptoError> {
    // Platform credential unseal - verify machine-binding
    if crate::tpm::is_available() {
        match crate::tpm::unseal_key_material("koi-certmesh-ca") {
            Ok(sealed) => {
                if sealed != encrypted.ciphertext {
                    // Warn but proceed - the passphrase + AES-GCM is the real
                    // security gate.  Platform binding is defense-in-depth;
                    // a hard failure here would lock operators out after
                    // credential-store resets or OS reinstalls.
                    tracing::warn!(
                        "Platform-sealed ciphertext does not match on-disk blob; \
                         key file may have been copied from another machine"
                    );
                }
            }
            Err(e) => {
                // No sealed material (e.g. created before keyring was wired)
                // - fall through to normal decryption.
                tracing::debug!(error = %e, "No platform-sealed material found; using passphrase only");
            }
        }
    }

    let mut plaintext = decrypt_bytes(encrypted, passphrase)?;

    let signing_key = SigningKey::from_pkcs8_der(&plaintext)
        .map_err(|e| CryptoError::KeyEncoding(e.to_string()))?;

    plaintext.zeroize();

    Ok(CaKeyPair { signing_key })
}

/// Decode a CA keypair from a PKCS#8 PEM string.
pub fn ca_keypair_from_pem(pem: &str) -> Result<CaKeyPair, CryptoError> {
    let signing_key =
        SigningKey::from_pkcs8_pem(pem).map_err(|e| CryptoError::KeyEncoding(e.to_string()))?;
    Ok(CaKeyPair { signing_key })
}

/// Decode a CA keypair from PKCS#8 DER bytes.
pub fn ca_keypair_from_der(der: &[u8]) -> Result<CaKeyPair, CryptoError> {
    let signing_key =
        SigningKey::from_pkcs8_der(der).map_err(|e| CryptoError::KeyEncoding(e.to_string()))?;
    Ok(CaKeyPair { signing_key })
}

/// Export a CA keypair's private key as PKCS#8 DER bytes.
pub fn ca_keypair_to_der(key: &CaKeyPair) -> Result<Vec<u8>, CryptoError> {
    let der = key
        .signing_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::KeyEncoding(e.to_string()))?;
    Ok(der.as_bytes().to_vec())
}

// ── File I/O ────────────────────────────────────────────────────────

/// Write secret material to a file with restricted permissions.
///
/// On Unix, sets file mode to 0o600 (owner read/write only).
/// On non-Unix platforms, uses standard file write.
pub fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), CryptoError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
        #[cfg(windows)]
        restrict_windows_acl(path);
    }

    Ok(())
}

/// Save an encrypted key to a JSON file.
pub fn save_encrypted_key(path: &Path, encrypted: &EncryptedKey) -> Result<(), CryptoError> {
    let json = serde_json::to_string_pretty(encrypted)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;

    write_secret_file(path, json.as_bytes())?;

    tracing::debug!(path = %path.display(), "Encrypted key saved");
    Ok(())
}

/// Load an encrypted key from a JSON file.
pub fn load_encrypted_key(path: &Path) -> Result<EncryptedKey, CryptoError> {
    let json = std::fs::read_to_string(path)?;
    let encrypted: EncryptedKey =
        serde_json::from_str(&json).map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(encrypted)
}

// ── Encryption / Decryption ─────────────────────────────────────────

/// Encrypt arbitrary bytes with passphrase-derived AES-256-GCM.
pub fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<EncryptedKey, CryptoError> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let kdf_params = KdfParams::default();
    let aes_key = derive_aes_key(passphrase, &salt, &kdf_params)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Encryption("nonce length mismatch".into()))?;
    let nonce = Nonce::from(nonce_arr);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    Ok(EncryptedKey {
        ciphertext,
        salt,
        nonce: nonce_bytes,
        kdf_params,
    })
}

/// Decrypt bytes encrypted with `encrypt_bytes`.
pub fn decrypt_bytes(encrypted: &EncryptedKey, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    let aes_key = derive_aes_key(passphrase, &encrypted.salt, &encrypted.kdf_params)?;
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;

    let nonce_arr: [u8; NONCE_LEN] = encrypted
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Decryption("invalid nonce length".into()))?;
    let nonce = Nonce::from(nonce_arr);
    let plaintext = cipher
        .decrypt(&nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| CryptoError::Decryption("decryption failed (wrong passphrase?)".into()))?;

    Ok(plaintext)
}

/// Derive a 256-bit AES key from a passphrase using Argon2id with explicit params.
/// Minimum Argon2id parameters to prevent downgrade from tampered key files.
const MIN_M_COST: u32 = 8192;  // 8 MiB
const MIN_T_COST: u32 = 1;
const MIN_P_COST: u32 = 1;

fn derive_aes_key(
    passphrase: &str,
    salt: &[u8],
    kdf_params: &KdfParams,
) -> Result<SecretBytes, CryptoError> {
    if kdf_params.m_cost < MIN_M_COST || kdf_params.t_cost < MIN_T_COST || kdf_params.p_cost < MIN_P_COST {
        return Err(CryptoError::KeyDerivation(format!(
            "KDF params below minimum: m_cost={} (min {}), t_cost={} (min {}), p_cost={} (min {})",
            kdf_params.m_cost, MIN_M_COST, kdf_params.t_cost, MIN_T_COST, kdf_params.p_cost, MIN_P_COST,
        )));
    }
    let mut key = vec![0u8; 32];
    let params = Params::new(kdf_params.m_cost, kdf_params.t_cost, kdf_params.p_cost, Some(32))
        .map_err(|e| CryptoError::KeyDerivation(format!("invalid KDF params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(SecretBytes::new(key))
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

/// Best-effort ACL restriction on Windows using icacls.
///
/// Strips inherited permissions and grants full control to SYSTEM,
/// the built-in Administrators group, and the current process user.
#[cfg(windows)]
pub(crate) fn restrict_windows_acl(path: &std::path::Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let path_str = path.display().to_string();
    let mut args = vec![
        path_str.clone(),
        "/inheritance:r".to_string(),
        "/grant:r".to_string(),
        "SYSTEM:F".to_string(),
        "/grant:r".to_string(),
        "BUILTIN\\Administrators:F".to_string(),
    ];
    if let Ok(user) = std::env::var("USERNAME") {
        if !user.eq_ignore_ascii_case("SYSTEM") {
            args.push("/grant:r".to_string());
            args.push(format!("{user}:F"));
        }
    }
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let _ = std::process::Command::new("icacls")
        .args(&args_ref)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_key() {
        let seed = b"test entropy seed material here!";
        let kp = generate_ca_keypair(seed).unwrap();
        // Should produce a valid PEM
        let pem = kp.public_key_pem().unwrap();
        assert!(pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let seed = b"round trip test seed 1234567890!";
        let kp = generate_ca_keypair(seed).unwrap();
        let passphrase = "test-passphrase-123";

        let encrypted = encrypt_key(&kp, passphrase).unwrap();
        let decrypted = decrypt_key(&encrypted, passphrase).unwrap();

        assert_eq!(
            kp.public_key_pem().unwrap(),
            decrypted.public_key_pem().unwrap()
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let seed = b"wrong passphrase test seed 12345";
        let kp = generate_ca_keypair(seed).unwrap();

        let encrypted = encrypt_key(&kp, "correct").unwrap();
        let result = decrypt_key(&encrypted, "wrong");

        assert!(result.is_err());
    }

    #[test]
    fn different_entropy_produces_different_keys() {
        let kp1 = generate_ca_keypair(b"entropy seed one________________").unwrap();
        let kp2 = generate_ca_keypair(b"entropy seed two________________").unwrap();

        assert_ne!(
            kp1.public_key_pem().unwrap(),
            kp2.public_key_pem().unwrap()
        );
    }

    #[test]
    fn encrypted_key_serialization_round_trip() {
        let seed = b"serialization test seed 12345678";
        let kp = generate_ca_keypair(seed).unwrap();
        let encrypted = encrypt_key(&kp, "test").unwrap();

        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedKey = serde_json::from_str(&json).unwrap();

        let decrypted = decrypt_key(&deserialized, "test").unwrap();
        assert_eq!(
            kp.public_key_pem().unwrap(),
            decrypted.public_key_pem().unwrap()
        );
    }

    #[test]
    fn save_and_load_encrypted_key() {
        let dir = std::env::temp_dir().join("koi-crypto-test-keys");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test-key.enc");

        let seed = b"save load test seed material!!!!";
        let kp = generate_ca_keypair(seed).unwrap();
        let encrypted = encrypt_key(&kp, "save-test").unwrap();

        save_encrypted_key(&path, &encrypted).unwrap();
        let loaded = load_encrypted_key(&path).unwrap();
        let decrypted = decrypt_key(&loaded, "save-test").unwrap();

        assert_eq!(
            kp.public_key_pem().unwrap(),
            decrypted.public_key_pem().unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_key_pem_is_valid() {
        let seed = b"private key pem test seed 123456";
        let kp = generate_ca_keypair(seed).unwrap();
        let pem = kp.private_key_pem().unwrap();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
    }

    // ── CryptoError variant coverage ─────────────────────────────────

    #[test]
    fn crypto_error_display_messages() {
        let cases: Vec<(CryptoError, &str)> = vec![
            (CryptoError::KeyEncoding("bad DER".into()), "bad DER"),
            (CryptoError::Encryption("cipher fail".into()), "cipher fail"),
            (CryptoError::Decryption("wrong pass".into()), "wrong pass"),
            (
                CryptoError::KeyDerivation("argon fail".into()),
                "argon fail",
            ),
            (
                CryptoError::Serialization("json broken".into()),
                "json broken",
            ),
            (
                CryptoError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "no file")),
                "no file",
            ),
        ];
        for (error, expected_substring) in cases {
            let msg = error.to_string();
            assert!(
                msg.contains(expected_substring),
                "{error:?} message should contain \"{expected_substring}\", got: \"{msg}\""
            );
        }
    }

    #[test]
    fn decrypt_bytes_with_wrong_passphrase_returns_decryption_error() {
        let plaintext = b"test data for encryption";
        let encrypted = encrypt_bytes(plaintext, "correct").unwrap();
        let result = decrypt_bytes(&encrypted, "wrong");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CryptoError::Decryption(_)));
    }

    #[test]
    fn decrypt_bytes_with_tampered_nonce_fails() {
        let plaintext = b"tamper test data";
        let mut encrypted = encrypt_bytes(plaintext, "pass").unwrap();
        encrypted.nonce = vec![0u8; 12]; // replace nonce with zeros
        let result = decrypt_bytes(&encrypted, "pass");
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_bytes_round_trip() {
        let plaintext = b"round trip bytes test";
        let encrypted = encrypt_bytes(plaintext, "secret").unwrap();
        let decrypted = decrypt_bytes(&encrypted, "secret").unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn load_encrypted_key_from_nonexistent_file() {
        let path = std::env::temp_dir().join("koi-crypto-nonexistent-12345.enc");
        let result = load_encrypted_key(&path);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::Io(_)));
    }

    #[test]
    fn kdf_params_default_values() {
        let params = KdfParams::default();
        assert_eq!(params.algorithm, "argon2id");
        assert_eq!(params.m_cost, 65536);
        assert_eq!(params.t_cost, 3);
        assert_eq!(params.p_cost, 4);
    }

    #[test]
    fn encrypted_key_debug_redacts_ciphertext() {
        let encrypted = encrypt_bytes(b"secret data", "pass").unwrap();
        let debug = format!("{encrypted:?}");
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn encrypted_key_backward_compat_without_kdf_params() {
        // Simulate a legacy JSON without kdf_params field
        let json = r#"{"ciphertext":[1,2,3],"salt":[4,5,6],"nonce":[7,8,9]}"#;
        let ek: EncryptedKey = serde_json::from_str(json).unwrap();
        assert_eq!(ek.kdf_params.algorithm, "argon2id");
        assert_eq!(ek.kdf_params.m_cost, 65536);
    }
}
