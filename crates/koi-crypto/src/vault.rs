//! General-purpose encrypted key-value vault.
//!
//! Provides secure credential storage for application secrets (API keys,
//! connection passwords, tokens) with platform-adaptive master key protection.
//!
//! # Backend selection (automatic)
//!
//! | Backend | When | Master key protection |
//! |---------|------|----------------------|
//! | `keyring` | Platform credential store available | Sealed in OS store (DPAPI, Keychain, Secret Service) |
//! | `machine-bound` | Headless / no credential store | Derived from machine ID via Argon2id |
//!
//! # File layout
//!
//! ```text
//! {data_dir}/vault/
//! ├── secrets.json    — per-key encrypted values (AES-256-GCM)
//! └── (master key sealed in platform credential store, or derived from machine ID)
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const VAULT_DIR: &str = "vault";
const SECRETS_FILE: &str = "secrets.json";
const KEYRING_LABEL: &str = "koi-vault-master";
const NONCE_LEN: usize = 12;
const MASTER_KEY_LEN: usize = 32;

// ── Public Types ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("vault encryption error: {0}")]
    Encryption(String),
    #[error("vault decryption error: {0}")]
    Decryption(String),
    #[error("vault master key error: {0}")]
    MasterKey(String),
}

/// Encrypted key-value vault with platform-adaptive master key protection.
pub struct Vault {
    vault_dir: PathBuf,
    master_key: [u8; MASTER_KEY_LEN],
    backend_name: &'static str,
}

impl Vault {
    /// Open (or create) a vault rooted at `data_dir`.
    ///
    /// Automatically selects the strongest available master key backend:
    /// platform credential store first, machine-bound derivation as fallback.
    pub fn open(data_dir: &Path) -> Result<Self, VaultError> {
        let vault_dir = data_dir.join(VAULT_DIR);
        std::fs::create_dir_all(&vault_dir)?;

        let (master_key, backend_name) = if crate::tpm::is_available() {
            match Self::load_or_create_keyring_master() {
                Ok(key) => (key, "keyring"),
                Err(e) => {
                    tracing::warn!("Keyring master key failed, falling back to machine-bound: {e}");
                    (Self::derive_machine_master()?, "machine-bound")
                }
            }
        } else {
            (Self::derive_machine_master()?, "machine-bound")
        };

        Ok(Self {
            vault_dir,
            master_key,
            backend_name,
        })
    }

    /// Which backend protects the master key.
    pub fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    /// Store a secret value under `key`. Overwrites if exists.
    pub fn store(&self, key: &str, value: &str) -> Result<(), VaultError> {
        let mut secrets = self.load_secrets()?;
        secrets.entries.insert(key.to_string(), self.encrypt(value)?);
        self.save_secrets(&secrets)
    }

    /// Retrieve a secret by key. Returns `None` if not found.
    pub fn retrieve(&self, key: &str) -> Result<Option<String>, VaultError> {
        let secrets = self.load_secrets()?;
        match secrets.entries.get(key) {
            Some(entry) => Ok(Some(self.decrypt(entry)?)),
            None => Ok(None),
        }
    }

    /// Delete a secret by key.
    pub fn delete(&self, key: &str) -> Result<(), VaultError> {
        let mut secrets = self.load_secrets()?;
        secrets.entries.remove(key);
        self.save_secrets(&secrets)
    }

    /// List all stored keys (not values).
    pub fn list_keys(&self) -> Result<Vec<String>, VaultError> {
        let secrets = self.load_secrets()?;
        Ok(secrets.entries.keys().cloned().collect())
    }

    // ── Master Key Backends ───────────────────────────────────────────

    /// Load master key from platform credential store, or create + seal a new one.
    fn load_or_create_keyring_master() -> Result<[u8; MASTER_KEY_LEN], VaultError> {
        match crate::tpm::unseal_key_material(KEYRING_LABEL) {
            Ok(data) if data.len() == MASTER_KEY_LEN => {
                let mut key = [0u8; MASTER_KEY_LEN];
                key.copy_from_slice(&data);
                Ok(key)
            }
            _ => {
                // Generate new master key and seal it
                let mut key = [0u8; MASTER_KEY_LEN];
                rand::rng().fill_bytes(&mut key);
                crate::tpm::seal_key_material(KEYRING_LABEL, &key)
                    .map_err(|e| VaultError::MasterKey(e.to_string()))?;
                tracing::info!("Vault master key created and sealed in platform credential store");
                Ok(key)
            }
        }
    }

    /// Derive master key from machine-specific identity (fallback).
    fn derive_machine_master() -> Result<[u8; MASTER_KEY_LEN], VaultError> {
        let machine_id = get_machine_id()
            .map_err(|e| VaultError::MasterKey(format!("machine ID unavailable: {e}")))?;

        let salt = sha2::Sha256::digest(format!("koi-vault-salt:{machine_id}").as_bytes());
        let params = argon2::Params::new(65536, 3, 4, Some(MASTER_KEY_LEN))
            .map_err(|e| VaultError::MasterKey(e.to_string()))?;
        let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut key = [0u8; MASTER_KEY_LEN];
        argon2
            .hash_password_into(machine_id.as_bytes(), &salt[..16], &mut key)
            .map_err(|e| VaultError::MasterKey(e.to_string()))?;
        Ok(key)
    }

    // ── Encryption ────────────────────────────────────────────────────

    fn encrypt(&self, plaintext: &str) -> Result<EncryptedEntry, VaultError> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        Ok(EncryptedEntry {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    fn decrypt(&self, entry: &EncryptedEntry) -> Result<String, VaultError> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| VaultError::Decryption(e.to_string()))?;

        let nonce_arr: [u8; NONCE_LEN] = entry
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Decryption("invalid nonce length".into()))?;
        let nonce = Nonce::from(nonce_arr);

        let plaintext = cipher
            .decrypt(&nonce, entry.ciphertext.as_ref())
            .map_err(|e| VaultError::Decryption(e.to_string()))?;

        String::from_utf8(plaintext)
            .map_err(|e| VaultError::Decryption(format!("not valid UTF-8: {e}")))
    }

    // ── Persistence ───────────────────────────────────────────────────

    fn secrets_path(&self) -> PathBuf {
        self.vault_dir.join(SECRETS_FILE)
    }

    fn load_secrets(&self) -> Result<SecretsFile, VaultError> {
        let path = self.secrets_path();
        if !path.exists() {
            return Ok(SecretsFile {
                version: 1,
                entries: HashMap::new(),
            });
        }
        let data = std::fs::read(&path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    fn save_secrets(&self, secrets: &SecretsFile) -> Result<(), VaultError> {
        let data = serde_json::to_vec_pretty(secrets)?;
        let path = self.secrets_path();
        std::fs::write(&path, &data)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Zeroize master key when vault is dropped
        self.master_key.iter_mut().for_each(|b| *b = 0);
    }
}

// ── File Structures ──────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SecretsFile {
    version: u8,
    entries: HashMap<String, EncryptedEntry>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedEntry {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
}

// ── Machine ID (platform-specific) ──────────────────────────────────

use sha2::Digest;

fn get_machine_id() -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/machine-id")
            .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
            .map(|s| s.trim().to_string())
            .map_err(|e| e.to_string())
    }

    #[cfg(target_os = "windows")]
    {
        // Read MachineGuid from Windows registry
        let output = std::process::Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
            .output()
            .map_err(|e| e.to_string())?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .find_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "MachineGuid" {
                    Some(parts[2].to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| "MachineGuid not found in registry".to_string())
    }

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .map_err(|e| e.to_string())?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .find(|line| line.contains("IOPlatformUUID"))
            .and_then(|line| line.split('"').nth(3))
            .map(|s| s.to_string())
            .ok_or_else(|| "IOPlatformUUID not found".to_string())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_store_retrieve() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Vault::open(tmp.path()).unwrap();

        vault.store("db-password", "s3cret!").unwrap();
        assert_eq!(
            vault.retrieve("db-password").unwrap(),
            Some("s3cret!".to_string())
        );

        vault.store("api-key", "tok_abc123").unwrap();
        let keys = vault.list_keys().unwrap();
        assert!(keys.contains(&"db-password".to_string()));
        assert!(keys.contains(&"api-key".to_string()));

        vault.delete("db-password").unwrap();
        assert_eq!(vault.retrieve("db-password").unwrap(), None);
    }

    #[test]
    fn retrieve_missing_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Vault::open(tmp.path()).unwrap();
        assert_eq!(vault.retrieve("nonexistent").unwrap(), None);
    }

    #[test]
    fn overwrite_replaces_value() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Vault::open(tmp.path()).unwrap();

        vault.store("key", "v1").unwrap();
        vault.store("key", "v2").unwrap();
        assert_eq!(vault.retrieve("key").unwrap(), Some("v2".to_string()));
    }

    #[test]
    fn persistence_across_open() {
        // ensure_data_dir sets KOI_NO_CREDENTIAL_STORE=1, which forces
        // the machine-bound backend for deterministic key derivation.
        // Using the shared helper avoids env var races with parallel tests.
        let _ = koi_common::test::ensure_data_dir("koi-vault-persist-tests");
        let tmp = tempfile::tempdir().unwrap();
        {
            let vault = Vault::open(tmp.path()).unwrap();
            vault.store("persist-test", "hello").unwrap();
        }
        {
            let vault = Vault::open(tmp.path()).unwrap();
            assert_eq!(
                vault.retrieve("persist-test").unwrap(),
                Some("hello".to_string())
            );
        }
    }
}
