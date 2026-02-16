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
//! | FIDO2 | Assertion verified | Stored on disk, gated by assertion check |
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

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::{decrypt_bytes, encrypt_bytes, CryptoError, EncryptedKey};
use koi_common::encoding::{hex_decode, hex_encode};

/// Length of the master key in bytes (256-bit AES key).
const MASTER_KEY_LEN: usize = 32;

/// HKDF info string for TOTP-based slot key derivation.
const TOTP_SLOT_HKDF_INFO: &[u8] = b"pond-unlock-slot-totp-v1";

// ── Slot Table ──────────────────────────────────────────────────────

/// Persistent slot table stored as `unlock-slots.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotTable {
    /// Version tag for future migrations.
    pub version: u32,
    /// Ordered list of unlock slots.
    pub slots: Vec<UnlockSlot>,
}

/// A single unlock slot that wraps the master key.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(rename = "totp")]
    Totp {
        /// TOTP shared secret (raw bytes, hex-encoded for JSON).
        /// Stored here so the stone can verify codes at unlock time.
        shared_secret_hex: String,
        /// Master key wrapped with HKDF(shared_secret, TOTP_SLOT_HKDF_INFO).
        wrapped_master_key: EncryptedKey,
    },

    /// FIDO2-based unlock slot.
    /// The slot_kek is stored encrypted, released only after assertion verification.
    #[serde(rename = "fido2")]
    Fido2 {
        /// WebAuthn credential ID (base64).
        credential_id: String,
        /// COSE public key (base64) for assertion verification.
        public_key: String,
        /// Relying Party ID.
        rp_id: String,
        /// Sign count for clone detection.
        sign_count: u32,
        /// Master key wrapped with a random slot_kek.
        wrapped_master_key: EncryptedKey,
        /// The slot_kek, encrypted with a key derived from the credential_id.
        /// This is a software gate - assertion verification is the real gate.
        encrypted_slot_kek: EncryptedKey,
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
    ) -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
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

    /// Add a TOTP unlock slot. The shared_secret is stored so the stone
    /// can verify codes at unlock time.
    pub fn add_totp_slot(
        &mut self,
        master_key: &[u8; MASTER_KEY_LEN],
        shared_secret: &[u8],
    ) -> Result<(), CryptoError> {
        // Remove existing TOTP slot if present
        self.slots.retain(|s| !matches!(s, UnlockSlot::Totp { .. }));

        let slot_kek = derive_totp_slot_kek(shared_secret);
        let slot_kek_hex = hex_encode(&slot_kek);
        let wrapped = encrypt_bytes(master_key, &slot_kek_hex)?;

        self.slots.push(UnlockSlot::Totp {
            shared_secret_hex: hex_encode(shared_secret),
            wrapped_master_key: wrapped,
        });

        Ok(())
    }

    /// Unwrap the master key using a TOTP code.
    ///
    /// Verifies the code against the stored shared_secret, then derives
    /// the slot_kek and unwraps the master key.
    pub fn unwrap_with_totp(&self, code: &str) -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
        for slot in &self.slots {
            if let UnlockSlot::Totp {
                shared_secret_hex,
                wrapped_master_key,
            } = slot
            {
                // Decode shared secret
                let secret_bytes = hex_decode(shared_secret_hex).map_err(|e| {
                    CryptoError::Decryption(format!("invalid TOTP secret hex: {e}"))
                })?;
                let secret = crate::totp::TotpSecret::from_bytes(secret_bytes.clone());

                // Verify TOTP code
                if !crate::totp::verify_code(&secret, code) {
                    return Err(CryptoError::Decryption("invalid TOTP code".into()));
                }

                // Derive slot_kek and unwrap
                let slot_kek = derive_totp_slot_kek(&secret_bytes);
                let slot_kek_hex = hex_encode(&slot_kek);
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

    /// Add a FIDO2 unlock slot.
    pub fn add_fido2_slot(
        &mut self,
        master_key: &[u8; MASTER_KEY_LEN],
        credential_id: &[u8],
        public_key: &[u8],
        rp_id: &str,
    ) -> Result<(), CryptoError> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;

        // Remove existing FIDO2 slot if present
        self.slots
            .retain(|s| !matches!(s, UnlockSlot::Fido2 { .. }));

        // Generate a random slot_kek and wrap the master key
        let mut slot_kek = [0u8; 32];
        OsRng.fill_bytes(&mut slot_kek);
        let slot_kek_hex = hex_encode(&slot_kek);
        let wrapped = encrypt_bytes(master_key, &slot_kek_hex)?;

        // Encrypt the slot_kek with a key derived from credential_id
        // This is a software gate - the real gate is assertion verification
        let cred_derived_key = derive_fido2_storage_key(credential_id);
        let encrypted_slot_kek = encrypt_bytes(&slot_kek, &hex_encode(&cred_derived_key))?;

        self.slots.push(UnlockSlot::Fido2 {
            credential_id: b64.encode(credential_id),
            public_key: b64.encode(public_key),
            rp_id: rp_id.to_string(),
            sign_count: 0,
            wrapped_master_key: wrapped,
            encrypted_slot_kek,
        });

        Ok(())
    }

    /// Unwrap the master key after FIDO2 assertion has been verified externally.
    ///
    /// The caller is responsible for verifying the WebAuthn assertion before
    /// calling this. This function just unwraps the cryptographic material.
    pub fn unwrap_with_fido2(
        &self,
        credential_id: &[u8],
    ) -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let target_id = b64.encode(credential_id);

        for slot in &self.slots {
            if let UnlockSlot::Fido2 {
                credential_id: stored_id,
                encrypted_slot_kek,
                wrapped_master_key,
                ..
            } = slot
            {
                if stored_id == &target_id {
                    // Derive storage key from credential_id, decrypt slot_kek
                    let cred_derived_key = derive_fido2_storage_key(credential_id);
                    let slot_kek =
                        decrypt_bytes(encrypted_slot_kek, &hex_encode(&cred_derived_key))?;
                    let slot_kek_hex = hex_encode(&slot_kek);

                    // Unwrap master key
                    let bytes = decrypt_bytes(wrapped_master_key, &slot_kek_hex)?;
                    return bytes_to_master_key(&bytes);
                }
            }
        }
        Err(CryptoError::Decryption(
            "no matching FIDO2 slot found".into(),
        ))
    }

    /// Get the FIDO2 credential info for challenge generation.
    pub fn fido2_credential(&self) -> Option<Fido2SlotInfo> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;

        for slot in &self.slots {
            if let UnlockSlot::Fido2 {
                credential_id,
                public_key,
                rp_id,
                sign_count,
                ..
            } = slot
            {
                return Some(Fido2SlotInfo {
                    credential_id: b64.decode(credential_id).unwrap_or_default(),
                    public_key: b64.decode(public_key).unwrap_or_default(),
                    rp_id: rp_id.clone(),
                    sign_count: *sign_count,
                });
            }
        }
        None
    }

    /// Check if a FIDO2 slot exists.
    pub fn has_fido2_slot(&self) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s, UnlockSlot::Fido2 { .. }))
    }

    /// Update the FIDO2 sign count after successful assertion.
    pub fn update_fido2_sign_count(&mut self, credential_id: &[u8], new_count: u32) {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let target_id = b64.encode(credential_id);

        for slot in &mut self.slots {
            if let UnlockSlot::Fido2 {
                credential_id: stored_id,
                sign_count,
                ..
            } = slot
            {
                if stored_id == &target_id {
                    *sign_count = new_count;
                }
            }
        }
    }

    /// Describe available unlock methods for status/UI.
    pub fn available_methods(&self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        for slot in &self.slots {
            match slot {
                UnlockSlot::Passphrase { .. } => methods.push("passphrase"),
                UnlockSlot::AutoUnlock => methods.push("auto_unlock"),
                UnlockSlot::Totp { .. } => methods.push("totp"),
                UnlockSlot::Fido2 { .. } => methods.push("fido2"),
            }
        }
        methods
    }

    /// Save the slot table to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> Result<(), CryptoError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, json)?;
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

/// FIDO2 credential info extracted from a slot (for challenge generation).
#[derive(Debug, Clone)]
pub struct Fido2SlotInfo {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub rp_id: String,
    pub sign_count: u32,
}

// ── Key derivation helpers ──────────────────────────────────────────

/// Generate a fresh random master key.
pub fn generate_master_key() -> [u8; MASTER_KEY_LEN] {
    let mut key = [0u8; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Derive a TOTP slot KEK from the TOTP shared secret using HKDF-like
/// construction (SHA-256).
///
/// We use a simple HKDF-extract + expand since we don't have hkdf as
/// a dependency. The shared_secret has enough entropy (256 bits) that
/// a single SHA-256 pass is sufficient.
fn derive_totp_slot_kek(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(TOTP_SLOT_HKDF_INFO);
    let result = hasher.finalize();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&result);
    kek
}

/// Derive a storage key from a FIDO2 credential ID for encrypting
/// the slot_kek at rest. This is a software gate - the real security
/// comes from assertion verification.
fn derive_fido2_storage_key(credential_id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pond-fido2-storage-key-v1");
    hasher.update(credential_id);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Convert a Vec<u8> to a fixed-size master key array.
fn bytes_to_master_key(bytes: &[u8]) -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
    if bytes.len() != MASTER_KEY_LEN {
        return Err(CryptoError::Decryption(format!(
            "master key has wrong length: expected {MASTER_KEY_LEN}, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; MASTER_KEY_LEN];
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
) -> Result<(EncryptedKey, SlotTable, [u8; MASTER_KEY_LEN]), CryptoError> {
    // Decrypt with old passphrase-direct model
    let plaintext = decrypt_bytes(old_encrypted, passphrase)?;

    // Generate new master key
    let master_key = generate_master_key();

    // Re-encrypt CA key with master key
    let master_key_hex = hex_encode(&master_key);
    let new_encrypted = encrypt_bytes(&plaintext, &master_key_hex)?;

    // Create slot table with passphrase slot
    let slot_table = SlotTable::new_with_passphrase(&master_key, passphrase)?;

    Ok((new_encrypted, slot_table, master_key))
}

/// Encrypt a CA key with envelope encryption from scratch (for new ponds).
///
/// Returns `(encrypted_key, slot_table, master_key)`.
pub fn envelope_encrypt_new(
    ca_key_der: &[u8],
    passphrase: &str,
) -> Result<(EncryptedKey, SlotTable, [u8; MASTER_KEY_LEN]), CryptoError> {
    let master_key = generate_master_key();
    let master_key_hex = hex_encode(&master_key);
    let encrypted = encrypt_bytes(ca_key_der, &master_key_hex)?;
    let slot_table = SlotTable::new_with_passphrase(&master_key, passphrase)?;
    Ok((encrypted, slot_table, master_key))
}

/// Decrypt a CA key using the master key (for internal use after slot unwrap).
pub fn decrypt_with_master_key(
    encrypted: &EncryptedKey,
    master_key: &[u8; MASTER_KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let master_key_hex = hex_encode(master_key);
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

    #[test]
    fn totp_slot_round_trip() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();

        let secret = crate::totp::generate_secret();
        table.add_totp_slot(&master_key, secret.as_bytes()).unwrap();

        // Generate a valid TOTP code
        let code = crate::totp::current_code(&secret).unwrap();
        let recovered = table.unwrap_with_totp(&code).unwrap();
        assert_eq!(master_key, recovered);
    }

    #[test]
    fn totp_wrong_code_fails() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();

        let secret = crate::totp::generate_secret();
        table.add_totp_slot(&master_key, secret.as_bytes()).unwrap();

        assert!(table.unwrap_with_totp("000000").is_err());
    }

    #[test]
    fn fido2_slot_round_trip() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();

        let cred_id = b"test-credential-id-12345";
        let pub_key = b"fake-cose-public-key-data";
        table
            .add_fido2_slot(&master_key, cred_id, pub_key, "garden.local")
            .unwrap();

        let recovered = table.unwrap_with_fido2(cred_id).unwrap();
        assert_eq!(master_key, recovered);
    }

    #[test]
    fn fido2_wrong_credential_fails() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();

        table
            .add_fido2_slot(&master_key, b"real-cred", b"pub-key", "garden.local")
            .unwrap();

        assert!(table.unwrap_with_fido2(b"wrong-cred").is_err());
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

    #[test]
    fn available_methods_lists_all_slots() {
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
        assert_eq!(table.available_methods(), vec!["passphrase"]);

        table.add_auto_unlock();
        let secret = crate::totp::generate_secret();
        table.add_totp_slot(&master_key, secret.as_bytes()).unwrap();
        table
            .add_fido2_slot(&master_key, b"cred", b"pk", "rp")
            .unwrap();

        let methods = table.available_methods();
        assert!(methods.contains(&"passphrase"));
        assert!(methods.contains(&"auto_unlock"));
        assert!(methods.contains(&"totp"));
        assert!(methods.contains(&"fido2"));
    }

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
