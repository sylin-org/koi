//! Envelope encryption with multiple unlock slots (LUKS-inspired).
//!
//! Instead of encrypting the CA private key directly with the passphrase,
//! a random **master key** encrypts the CA key, and each **unlock slot**
//! independently wraps that master key. Any single slot can unlock.
//!
//! # Slot types
//!
//! | Slot | Gate | `slot_kek` source |
//! |------|------|-------------------|
//! | Passphrase | Argon2id KDF | Derived from passphrase + salt |
//! | Auto-unlock | None | Stored as plaintext in local file |
//! | TOTP | Valid 6-digit code | Derived from TOTP shared_secret via HKDF |
//!
//! # File layout
//!
//! ```text
//! {ca_dir}/ca-key.enc          ← master_key-encrypted CA key (EncryptedKey format)
//! {ca_dir}/unlock-slots.json   ← SlotTable with wrapped master_key per slot
//! ```
//!
//! The `ca-key.enc` file format is *unchanged* - callers still see
//! `EncryptedKey { ciphertext, salt, nonce }`. The difference is that
//! the encryption key is now a random master key rather than passphrase-derived.
//! The salt/nonce in `ca-key.enc` are from the master-key encryption, not
//! from any passphrase KDF.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::{decrypt_bytes, encrypt_bytes, CryptoError, EncryptedKey};
use koi_common::encoding::{hex_decode, hex_encode};

/// Length of the master key in bytes (256-bit AES key).
const MASTER_KEY_LEN: usize = 32;

/// HKDF info string for TOTP-based slot key derivation.
const TOTP_SLOT_HKDF_INFO: &[u8] = b"pond-unlock-slot-totp-v1";

/// Platform credential store label for the sealed TOTP shared secret.
const TOTP_CREDENTIAL_LABEL: &str = "koi-certmesh-unlock-totp";

// ── Slot Table ──────────────────────────────────────────────────────

/// Persistent slot table stored as `unlock-slots.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SlotTable {
    /// Version tag for future migrations.
    pub version: u32,
    /// Ordered list of unlock slots.
    pub slots: Vec<UnlockSlot>,
}

/// A single unlock slot that wraps the master key.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UnlockSlot {
    /// Passphrase-based slot (always present, slot 0).
    #[serde(rename = "passphrase")]
    Passphrase {
        /// Master key encrypted with `Argon2id(passphrase, salt) → AES-256-GCM`.
        wrapped_master_key: EncryptedKey,
    },

    /// Auto-unlock slot - master key stored in a local file.
    /// The file path is managed externally (Moss writes/reads it).
    /// This slot records that auto-unlock is enabled.
    #[serde(rename = "auto_unlock")]
    AutoUnlock,

    /// TOTP-based unlock slot.
    ///
    /// The TOTP shared secret is protected at rest: sealed in the platform
    /// credential store when available, or encrypted with a machine-derived
    /// key as a fallback.
    #[serde(rename = "totp")]
    Totp {
        /// Whether the TOTP secret is sealed in the platform credential store.
        #[serde(default)]
        sealed: bool,
        /// Legacy: hex-encoded TOTP secret (plaintext). Kept for backward
        /// compatibility with existing slot tables. New slots leave this `None`.
        #[serde(skip_serializing_if = "Option::is_none")]
        shared_secret_hex: Option<String>,
        /// Encrypted TOTP secret (fallback when platform store unavailable).
        #[serde(skip_serializing_if = "Option::is_none")]
        encrypted_secret: Option<EncryptedKey>,
        /// Master key wrapped with HKDF(shared_secret, TOTP_SLOT_HKDF_INFO).
        wrapped_master_key: EncryptedKey,
    },
}

impl SlotTable {
    /// Create a new slot table with a single passphrase slot.
    pub fn new_with_passphrase(
        master_key: &[u8; MASTER_KEY_LEN],
        passphrase: &str,
    ) -> Result<Self, CryptoError> {
        let wrapped = encrypt_bytes(master_key, passphrase)?;
        Ok(Self {
            version: 1,
            slots: vec![UnlockSlot::Passphrase {
                wrapped_master_key: wrapped,
            }],
        })
    }

    /// Unwrap the master key using the passphrase slot.
    pub fn unwrap_with_passphrase(
        &self,
        passphrase: &str,
    ) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, CryptoError> {
        for slot in &self.slots {
            if let UnlockSlot::Passphrase {
                wrapped_master_key, ..
            } = slot
            {
                let bytes = decrypt_bytes(wrapped_master_key, passphrase)?;
                return bytes_to_master_key(&bytes);
            }
        }
        Err(CryptoError::Decryption("no passphrase slot found".into()))
    }

    /// Add an auto-unlock marker slot.
    pub fn add_auto_unlock(&mut self) {
        // Remove existing auto-unlock slot if present
        self.slots.retain(|s| !matches!(s, UnlockSlot::AutoUnlock));
        self.slots.push(UnlockSlot::AutoUnlock);
    }

    /// Remove the auto-unlock slot.
    pub fn remove_auto_unlock(&mut self) {
        self.slots.retain(|s| !matches!(s, UnlockSlot::AutoUnlock));
    }

    /// Check if auto-unlock is enabled.
    pub fn has_auto_unlock(&self) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s, UnlockSlot::AutoUnlock))
    }

    /// Add a TOTP unlock slot. The shared secret is sealed in the platform
    /// credential store when available, or encrypted with a random key also
    /// sealed in the credential store. The plaintext secret is never stored in JSON.
    pub fn add_totp_slot(
        &mut self,
        master_key: &[u8; MASTER_KEY_LEN],
        shared_secret: &[u8],
    ) -> Result<(), CryptoError> {
        // Remove existing TOTP slot if present
        self.slots.retain(|s| !matches!(s, UnlockSlot::Totp { .. }));

        let slot_kek = derive_totp_slot_kek(shared_secret);
        let slot_kek_hex = Zeroizing::new(hex_encode(&*slot_kek));
        let wrapped = encrypt_bytes(master_key, &slot_kek_hex)?;

        // Try platform credential store first; fallback uses a random key
        // also sealed in the credential store (never hostname-derived).
        let (sealed, encrypted_secret) =
            match crate::tpm::seal_key_material(TOTP_CREDENTIAL_LABEL, shared_secret) {
                Ok(()) => {
                    tracing::info!("TOTP shared secret sealed in platform credential store");
                    (true, None)
                }
                Err(_) => {
                    // Direct seal failed — try the fallback: encrypt with a random key
                    // that is itself sealed in the credential store.
                    let fallback_key = get_or_create_fallback_key()?;
                    let fallback_hex = Zeroizing::new(hex_encode(&*fallback_key));
                    let enc = encrypt_bytes(shared_secret, &fallback_hex)?;
                    tracing::info!("TOTP shared secret encrypted with sealed fallback key");
                    (false, Some(enc))
                }
            };

        self.slots.push(UnlockSlot::Totp {
            sealed,
            shared_secret_hex: None,
            encrypted_secret,
            wrapped_master_key: wrapped,
        });

        Ok(())
    }

    /// Unwrap the master key using a TOTP code.
    ///
    /// Recovers the shared secret from the platform credential store,
    /// encrypted fallback, or legacy plaintext field, then verifies the
    /// code and unwraps the master key.
    pub fn unwrap_with_totp(
        &self,
        code: &str,
    ) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, CryptoError> {
        for slot in &self.slots {
            if let UnlockSlot::Totp {
                sealed,
                shared_secret_hex,
                encrypted_secret,
                wrapped_master_key,
            } = slot
            {
                // Recover the TOTP shared secret from the best available source:
                // 1. Platform credential store (sealed == true)
                // 2. Machine-key encrypted fallback
                // 3. Legacy plaintext hex (backward compat)
                let secret_bytes = Zeroizing::new(if *sealed {
                    crate::tpm::unseal_key_material(TOTP_CREDENTIAL_LABEL).map_err(|e| {
                        CryptoError::Decryption(format!(
                            "failed to unseal TOTP secret from platform store: {e}"
                        ))
                    })?
                } else if let Some(enc) = encrypted_secret {
                    let fallback_key = get_or_create_fallback_key().map_err(|e| {
                        CryptoError::Decryption(format!(
                            "failed to retrieve TOTP fallback key: {e}"
                        ))
                    })?;
                    let fallback_hex = Zeroizing::new(hex_encode(&*fallback_key));
                    decrypt_bytes(enc, &fallback_hex).map_err(|e| {
                        CryptoError::Decryption(format!(
                            "failed to decrypt TOTP secret with fallback key: {e}"
                        ))
                    })?
                } else if let Some(hex) = shared_secret_hex {
                    // Legacy plaintext path — warn operator to re-create the TOTP slot
                    tracing::warn!(
                        "TOTP secret stored in plaintext (legacy format). \
                         Re-create the CA or rotate auth to migrate to encrypted storage."
                    );
                    hex_decode(hex).map_err(|e| {
                        CryptoError::Decryption(format!("invalid TOTP secret hex: {e}"))
                    })?
                } else {
                    return Err(CryptoError::Decryption(
                        "TOTP slot has no recoverable secret".into(),
                    ));
                });

                let secret = crate::totp::TotpSecret::from_bytes(secret_bytes.to_vec());

                // Verify TOTP code
                if !crate::totp::verify_code(&secret, code) {
                    return Err(CryptoError::Decryption("invalid TOTP code".into()));
                }

                // Derive slot_kek and unwrap
                let slot_kek = derive_totp_slot_kek(&secret_bytes);
                drop(secret_bytes);
                let slot_kek_hex = Zeroizing::new(hex_encode(&*slot_kek));
                let bytes = decrypt_bytes(wrapped_master_key, &slot_kek_hex)?;
                return bytes_to_master_key(&bytes);
            }
        }
        Err(CryptoError::Decryption("no TOTP slot found".into()))
    }

    /// Check if a TOTP slot exists.
    pub fn has_totp_slot(&self) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s, UnlockSlot::Totp { .. }))
    }

    /// Describe available unlock methods for status/UI.
    pub fn available_methods(&self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        for slot in &self.slots {
            match slot {
                UnlockSlot::Passphrase { .. } => methods.push("passphrase"),
                UnlockSlot::AutoUnlock => methods.push("auto_unlock"),
                UnlockSlot::Totp { .. } => methods.push("totp"),
            }
        }
        methods
    }

    /// Save the slot table to a JSON file with restricted permissions.
    pub fn save(&self, path: &std::path::Path) -> Result<(), CryptoError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        crate::keys::write_secret_file(path, json.as_bytes())?;
        tracing::debug!(path = %path.display(), "Slot table saved");
        Ok(())
    }

    /// Load a slot table from a JSON file.
    pub fn load(path: &std::path::Path) -> Result<Self, CryptoError> {
        let json = std::fs::read_to_string(path)?;
        let table: Self =
            serde_json::from_str(&json).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        Ok(table)
    }
}

// ── Key derivation helpers ──────────────────────────────────────────

/// Generate a fresh random master key.
pub fn generate_master_key() -> Zeroizing<[u8; MASTER_KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    rand::rng().fill_bytes(key.as_mut());
    key
}

/// Derive a TOTP slot KEK from the TOTP shared secret using HKDF-like
/// construction (SHA-256).
///
/// We use a simple HKDF-extract + expand since we don't have hkdf as
/// a dependency. The shared_secret has enough entropy (256 bits) that
/// a single SHA-256 pass is sufficient.
fn derive_totp_slot_kek(shared_secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(TOTP_SLOT_HKDF_INFO);
    let result = hasher.finalize();
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(&result);
    kek
}

/// Platform credential store label for the TOTP fallback encryption key.
const TOTP_FALLBACK_KEY_LABEL: &str = "koi-certmesh-totp-fallback-key";

/// Retrieve or create a random 32-byte encryption key sealed in the platform
/// credential store, used as the fallback when direct secret sealing fails.
///
/// Unlike the previous hostname-derived key, this key is truly random and
/// machine-bound (only the platform store can unseal it).
fn get_or_create_fallback_key() -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    // Try to retrieve an existing fallback key
    if let Ok(bytes) = crate::tpm::unseal_key_material(TOTP_FALLBACK_KEY_LABEL) {
        if bytes.len() == 32 {
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
    }
    // Generate and seal a new random key, then re-read to confirm
    // (handles concurrent initialization where the second writer wins).
    let mut key = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(key.as_mut());
    crate::tpm::seal_key_material(TOTP_FALLBACK_KEY_LABEL, &*key).map_err(|e| {
        CryptoError::Encryption(format!(
            "cannot seal TOTP fallback key in platform credential store: {e}"
        ))
    })?;
    // Re-read the authoritative value (another process may have written concurrently)
    let confirmed = crate::tpm::unseal_key_material(TOTP_FALLBACK_KEY_LABEL)
        .map_err(|e| CryptoError::Encryption(format!("cannot confirm TOTP fallback key: {e}")))?;
    if confirmed.len() == 32 {
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&confirmed);
        Ok(k)
    } else {
        Ok(key)
    }
}

/// Convert a Vec<u8> to a fixed-size master key array.
fn bytes_to_master_key(bytes: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, CryptoError> {
    if bytes.len() != MASTER_KEY_LEN {
        return Err(CryptoError::Decryption(format!(
            "master key has wrong length: expected {MASTER_KEY_LEN}, got {}",
            bytes.len()
        )));
    }
    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    key.copy_from_slice(bytes);
    Ok(key)
}

// ── Migration ───────────────────────────────────────────────────────

/// Migrate a passphrase-direct encrypted key to envelope encryption.
///
/// 1. Decrypt the CA key with the passphrase (old model).
/// 2. Generate a new random master key.
/// 3. Re-encrypt the CA key with the master key.
/// 4. Create a slot table with a passphrase slot wrapping the master key.
///
/// Returns `(new_encrypted_key, slot_table, master_key)`.
/// The master key is returned so callers can add additional slots
/// before discarding it.
pub fn migrate_to_envelope(
    old_encrypted: &EncryptedKey,
    passphrase: &str,
) -> Result<(EncryptedKey, SlotTable, Zeroizing<[u8; MASTER_KEY_LEN]>), CryptoError> {
    // Decrypt with old passphrase-direct model
    let plaintext = decrypt_bytes(old_encrypted, passphrase)?;

    // Generate new master key
    let master_key = generate_master_key();

    // Re-encrypt CA key with master key
    let master_key_hex = Zeroizing::new(hex_encode(master_key.as_ref()));
    let new_encrypted = encrypt_bytes(&plaintext, &master_key_hex)?;

    // Create slot table with passphrase slot
    let slot_table = SlotTable::new_with_passphrase(&master_key, passphrase)?;

    Ok((new_encrypted, slot_table, master_key))
}

/// Encrypt a CA key with envelope encryption from scratch (for a new CA).
///
/// Returns `(encrypted_key, slot_table, master_key)`.
pub fn envelope_encrypt_new(
    ca_key_der: &[u8],
    passphrase: &str,
) -> Result<(EncryptedKey, SlotTable, Zeroizing<[u8; MASTER_KEY_LEN]>), CryptoError> {
    let master_key = generate_master_key();
    let master_key_hex = Zeroizing::new(hex_encode(master_key.as_ref()));
    let encrypted = encrypt_bytes(ca_key_der, &master_key_hex)?;
    let slot_table = SlotTable::new_with_passphrase(&master_key, passphrase)?;
    Ok((encrypted, slot_table, master_key))
}

/// Decrypt a CA key using the master key (for internal use after slot unwrap).
pub fn decrypt_with_master_key(
    encrypted: &EncryptedKey,
    master_key: &[u8; MASTER_KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let master_key_hex = Zeroizing::new(hex_encode(master_key));
    decrypt_bytes(encrypted, &master_key_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_slot_round_trip() {
        let master_key = generate_master_key();
        let table = SlotTable::new_with_passphrase(&master_key, "test-pass").unwrap();
        let recovered = table.unwrap_with_passphrase("test-pass").unwrap();
        assert_eq!(master_key, recovered);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let master_key = generate_master_key();
        let table = SlotTable::new_with_passphrase(&master_key, "correct").unwrap();
        assert!(table.unwrap_with_passphrase("wrong").is_err());
    }

    // The TOTP unlock slot seals its shared secret (and its fallback key) in the OS
    // credential store, so it requires the `keyring` feature. A lean build without
    // keyring uses passphrase unlock instead.
    #[cfg(feature = "keyring")]
    #[test]
    fn totp_slot_round_trip() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();

        let secret = crate::totp::generate_secret();
        table.add_totp_slot(&master_key, secret.as_bytes()).unwrap();

        // Generate a valid TOTP code and unwrap with it. TOTP codes roll over every 30s,
        // so a single generate→verify can straddle a step boundary and spuriously fail;
        // retry a bounded number of times (two consecutive attempts cannot both straddle
        // a 30s boundary in the milliseconds between them).
        let mut recovered = None;
        for _ in 0..3 {
            let code = crate::totp::current_code(&secret).unwrap();
            if let Ok(key) = table.unwrap_with_totp(&code) {
                recovered = Some(key);
                break;
            }
        }
        assert_eq!(
            master_key,
            recovered.expect("TOTP unwrap should succeed within 3 tries")
        );
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn totp_wrong_code_fails() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();

        let secret = crate::totp::generate_secret();
        table.add_totp_slot(&master_key, secret.as_bytes()).unwrap();

        assert!(table.unwrap_with_totp("000000").is_err());
    }

    #[test]
    fn envelope_encrypt_new_round_trip() {
        let plaintext = b"test CA private key DER bytes";
        let (encrypted, table, master_key) =
            envelope_encrypt_new(plaintext, "my-passphrase").unwrap();

        // Unwrap master key via passphrase slot
        let recovered_mk = table.unwrap_with_passphrase("my-passphrase").unwrap();
        assert_eq!(master_key, recovered_mk);

        // Decrypt CA key with master key
        let recovered = decrypt_with_master_key(&encrypted, &master_key).unwrap();
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn migrate_preserves_ca_key() {
        // Simulate old model: encrypt directly with passphrase
        let ca_key_der = b"simulated CA private key bytes!!";
        let old_encrypted = encrypt_bytes(ca_key_der, "old-pass").unwrap();

        // Migrate
        let (new_encrypted, table, master_key) =
            migrate_to_envelope(&old_encrypted, "old-pass").unwrap();

        // Verify passphrase slot works
        let recovered_mk = table.unwrap_with_passphrase("old-pass").unwrap();
        assert_eq!(master_key, recovered_mk);

        // Verify CA key is recoverable
        let recovered = decrypt_with_master_key(&new_encrypted, &master_key).unwrap();
        assert_eq!(&recovered, ca_key_der);
    }

    #[test]
    fn auto_unlock_marker() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
        assert!(!table.has_auto_unlock());

        table.add_auto_unlock();
        assert!(table.has_auto_unlock());

        table.remove_auto_unlock();
        assert!(!table.has_auto_unlock());
    }

    // Exercises add_totp_slot (credential-store-backed) → requires `keyring`.
    #[cfg(feature = "keyring")]
    #[test]
    fn available_methods_lists_all_slots() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
        assert_eq!(table.available_methods(), vec!["passphrase"]);

        table.add_auto_unlock();
        let secret = crate::totp::generate_secret();
        table.add_totp_slot(&master_key, secret.as_bytes()).unwrap();

        let methods = table.available_methods();
        assert!(methods.contains(&"passphrase"));
        assert!(methods.contains(&"auto_unlock"));
        assert!(methods.contains(&"totp"));
    }

    // Builds a TOTP slot (credential-store-backed) → requires `keyring`.
    #[cfg(feature = "keyring")]
    #[test]
    fn slot_table_serialization_round_trip() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
        table.add_auto_unlock();
        let secret = crate::totp::generate_secret();
        table.add_totp_slot(&master_key, secret.as_bytes()).unwrap();

        let json = serde_json::to_string_pretty(&table).unwrap();
        let loaded: SlotTable = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.slots.len(), 3);
        let recovered = loaded.unwrap_with_passphrase("pass").unwrap();
        assert_eq!(master_key, recovered);
    }
}
