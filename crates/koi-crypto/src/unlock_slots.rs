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
use crate::tpm::{CredentialDelete, TpmError};
use koi_common::encoding::{hex_decode, hex_encode};

/// Length of the master key in bytes (256-bit AES key).
const MASTER_KEY_LEN: usize = 32;

/// Slot-table version that isolates platform credentials per TOTP slot.
const SLOT_TABLE_VERSION: u32 = 2;

/// HKDF info string for TOTP-based slot key derivation.
const TOTP_SLOT_HKDF_INFO: &[u8] = b"koi-unlock-slot-totp-v1";

/// Legacy v1 platform credential store label for the sealed TOTP shared secret.
const TOTP_CREDENTIAL_LABEL: &str = "koi-certmesh-unlock-totp";

/// Exact platform labels a slot-table transaction may need to retire.
///
/// The identifier is generated from the slot's wrapped ciphertext and is
/// validated before use, so persisted recovery state cannot name an arbitrary
/// platform credential.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TotpCredentialOwnership {
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_id: Option<String>,
    secret: bool,
    fallback: bool,
}

trait CredentialStore {
    fn seal(&self, label: &str, data: &[u8]) -> Result<(), TpmError>;
    fn unseal(&self, label: &str) -> Result<Vec<u8>, TpmError>;
    fn delete(&self, label: &str) -> Result<CredentialDelete, TpmError>;
}

struct PlatformCredentialStore;

impl CredentialStore for PlatformCredentialStore {
    fn seal(&self, label: &str, data: &[u8]) -> Result<(), TpmError> {
        crate::tpm::seal_key_material(label, data)
    }

    fn unseal(&self, label: &str) -> Result<Vec<u8>, TpmError> {
        crate::tpm::unseal_key_material(label)
    }

    fn delete(&self, label: &str) -> Result<CredentialDelete, TpmError> {
        crate::tpm::delete_key_material(label)
    }
}

trait SlotPersistence {
    fn persist(&self, table: &SlotTable, path: &std::path::Path) -> Result<(), CryptoError>;
}

struct FileSlotPersistence;

impl SlotPersistence for FileSlotPersistence {
    fn persist(&self, table: &SlotTable, path: &std::path::Path) -> Result<(), CryptoError> {
        table.save_unreconciled(path)
    }
}

// ── Slot Table ──────────────────────────────────────────────────────

/// Persistent slot table stored as `unlock-slots.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SlotTable {
    /// Version tag for future migrations.
    version: u32,
    /// Ordered list of unlock slots.
    slots: Vec<UnlockSlot>,
    /// Exact credentials from an interrupted add, replacement, or removal.
    /// They remain durable until idempotent deletion succeeds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_totp_credentials: Vec<TotpCredentialOwnership>,
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
    /// The file path is managed externally (the host application writes/reads it).
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
            version: SLOT_TABLE_VERSION,
            slots: vec![UnlockSlot::Passphrase {
                wrapped_master_key: wrapped,
            }],
            pending_totp_credentials: Vec::new(),
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
        path: &std::path::Path,
        master_key: &[u8; MASTER_KEY_LEN],
        shared_secret: &[u8],
    ) -> Result<(), CryptoError> {
        self.add_totp_slot_with(
            path,
            master_key,
            shared_secret,
            &PlatformCredentialStore,
            &FileSlotPersistence,
        )
    }

    fn add_totp_slot_with<S: CredentialStore, P: SlotPersistence>(
        &mut self,
        path: &std::path::Path,
        master_key: &[u8; MASTER_KEY_LEN],
        shared_secret: &[u8],
        store: &S,
        persistence: &P,
    ) -> Result<(), CryptoError> {
        self.finish_pending_cleanup_with(path, store, persistence)?;
        let prior_version = self.version;

        let slot_kek = derive_totp_slot_kek(shared_secret);
        let slot_kek_hex = Zeroizing::new(hex_encode(&*slot_kek));
        let wrapped = encrypt_bytes(master_key, &slot_kek_hex)?;
        let ownership = TotpCredentialOwnership::new(SLOT_TABLE_VERSION, &wrapped, true, true);
        let labels = ownership.labels()?;
        let secret_label = labels[0].clone();
        let fallback_label = labels[1].clone();

        // Phase 1: durably claim both exact labels before the first store write.
        self.pending_totp_credentials.push(ownership);
        if let Err(error) = persistence.persist(self, path) {
            self.pending_totp_credentials.pop();
            return Err(error);
        }

        // Try platform credential store first; fallback uses a random key
        // also sealed in the credential store (never hostname-derived).
        let material = match store.seal(&secret_label, shared_secret) {
            Ok(()) => {
                tracing::info!("TOTP shared secret sealed in platform credential store");
                Ok((true, None))
            }
            Err(_) => (|| {
                // Direct seal failed — try the fallback: encrypt with a random key
                // that is itself sealed in the credential store.
                let fallback_key = get_or_create_fallback_key_with(&fallback_label, store)?;
                let fallback_hex = Zeroizing::new(hex_encode(&*fallback_key));
                let enc = encrypt_bytes(shared_secret, &fallback_hex)?;
                tracing::info!("TOTP shared secret encrypted with sealed fallback key");
                Ok((false, Some(enc)))
            })(),
        };

        let (sealed, encrypted_secret) = match material {
            Ok(material) => material,
            Err(error) => {
                let _ = self.finish_pending_cleanup_with(path, store, persistence);
                return Err(error);
            }
        };

        let old_index = self
            .slots
            .iter()
            .position(|slot| matches!(slot, UnlockSlot::Totp { .. }));
        let old_slot = old_index.map(|index| self.slots.remove(index));
        let old_ownership = old_slot
            .as_ref()
            .and_then(|slot| TotpCredentialOwnership::from_slot(self.version, slot));

        // The new label is now represented by the active slot. The old label,
        // if any, remains represented by the durable cleanup ledger.
        self.pending_totp_credentials.retain(|item| {
            item != &TotpCredentialOwnership::new(SLOT_TABLE_VERSION, &wrapped, true, true)
        });
        if let Some(old) = old_ownership {
            self.pending_totp_credentials.push(old);
        }

        self.slots.push(UnlockSlot::Totp {
            sealed,
            shared_secret_hex: None,
            encrypted_secret,
            wrapped_master_key: wrapped,
        });
        self.version = SLOT_TABLE_VERSION;

        // Phase 2: commit the new active slot before retiring the old labels.
        if let Err(error) = persistence.persist(self, path) {
            let new_slot = self
                .slots
                .pop()
                .expect("transaction always appends the new TOTP slot");
            let new_ownership = TotpCredentialOwnership::from_slot(SLOT_TABLE_VERSION, &new_slot)
                .expect("new TOTP slot owns platform credentials");
            if let Some(old) = old_slot {
                let index = old_index.unwrap_or(self.slots.len()).min(self.slots.len());
                self.slots.insert(index, old);
            }
            self.version = prior_version;
            self.pending_totp_credentials.clear();
            self.pending_totp_credentials.push(new_ownership);
            let _ = self.finish_pending_cleanup_with(path, store, persistence);
            return Err(error);
        }

        // Phase 3: idempotently retire old credentials, then clear the ledger.
        self.finish_pending_cleanup_with(path, store, persistence)?;

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
                    let label = totp_credential_label(self.version, wrapped_master_key);
                    crate::tpm::unseal_key_material(&label).map_err(|e| {
                        CryptoError::Decryption(format!(
                            "failed to unseal TOTP secret from platform store: {e}"
                        ))
                    })?
                } else if let Some(enc) = encrypted_secret {
                    let label = totp_fallback_key_label(self.version, wrapped_master_key);
                    let fallback_key = get_or_create_fallback_key(&label).map_err(|e| {
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

    /// Remove the TOTP slot and retire every exact platform label it owns.
    ///
    /// Ownership is persisted before deletion, so an interrupted cleanup is
    /// retried the next time the table is loaded.
    pub fn remove_totp_slot(&mut self, path: &std::path::Path) -> Result<bool, CryptoError> {
        self.remove_totp_slot_with(path, &PlatformCredentialStore, &FileSlotPersistence)
    }

    fn remove_totp_slot_with<S: CredentialStore, P: SlotPersistence>(
        &mut self,
        path: &std::path::Path,
        store: &S,
        persistence: &P,
    ) -> Result<bool, CryptoError> {
        self.finish_pending_cleanup_with(path, store, persistence)?;
        let Some(index) = self
            .slots
            .iter()
            .position(|slot| matches!(slot, UnlockSlot::Totp { .. }))
        else {
            return Ok(false);
        };

        let slot = self.slots.remove(index);
        if let Some(ownership) = TotpCredentialOwnership::from_slot(self.version, &slot) {
            self.pending_totp_credentials.push(ownership);
        }
        if let Err(error) = persistence.persist(self, path) {
            self.pending_totp_credentials.clear();
            self.slots.insert(index, slot);
            return Err(error);
        }

        self.finish_pending_cleanup_with(path, store, persistence)?;
        Ok(true)
    }

    /// Retry durable cleanup records left by an interrupted slot transaction.
    fn finish_pending_cleanup_with<S: CredentialStore, P: SlotPersistence>(
        &mut self,
        path: &std::path::Path,
        store: &S,
        persistence: &P,
    ) -> Result<(), CryptoError> {
        if self.pending_totp_credentials.is_empty() {
            return Ok(());
        }

        for ownership in &self.pending_totp_credentials {
            for label in ownership.labels()? {
                store.delete(&label).map_err(|error| {
                    CryptoError::Encryption(format!(
                        "cannot retire owned TOTP credential '{label}': {error}"
                    ))
                })?;
            }
        }
        self.pending_totp_credentials.clear();
        persistence.persist(self, path)
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
        self.save_unreconciled(path)
    }

    fn save_unreconciled(&self, path: &std::path::Path) -> Result<(), CryptoError> {
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
        let mut table: Self =
            serde_json::from_str(&json).map_err(|e| CryptoError::Serialization(e.to_string()))?;
        table.finish_pending_cleanup_with(path, &PlatformCredentialStore, &FileSlotPersistence)?;
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

/// Derive a TOTP slot KEK from the TOTP shared secret: `SHA-256(secret || info)`.
///
/// This is a hash-based KDF (not HKDF — no extract/expand, no salt), which is
/// sufficient ONLY because `shared_secret` is a full 256-bit random TOTP secret
/// and `TOTP_SLOT_HKDF_INFO` provides domain separation. Do not reuse this helper
/// with a low-entropy input; use `hkdf::Hkdf::<Sha256>` if you need a real KDF.
fn derive_totp_slot_kek(shared_secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(TOTP_SLOT_HKDF_INFO);
    let result = hasher.finalize();
    let mut kek = Zeroizing::new([0u8; 32]);
    kek.copy_from_slice(&result);
    kek
}

/// Legacy v1 platform credential store label for the TOTP fallback encryption key.
const TOTP_FALLBACK_KEY_LABEL: &str = "koi-certmesh-totp-fallback-key";

fn totp_credential_label(version: u32, wrapped_master_key: &EncryptedKey) -> String {
    versioned_credential_label(version, TOTP_CREDENTIAL_LABEL, wrapped_master_key)
}

fn totp_fallback_key_label(version: u32, wrapped_master_key: &EncryptedKey) -> String {
    versioned_credential_label(version, TOTP_FALLBACK_KEY_LABEL, wrapped_master_key)
}

impl TotpCredentialOwnership {
    fn new(version: u32, wrapped_master_key: &EncryptedKey, secret: bool, fallback: bool) -> Self {
        let credential_id = (version >= SLOT_TABLE_VERSION).then(|| {
            let digest = Sha256::digest(&wrapped_master_key.ciphertext);
            hex_encode(&digest[..16])
        });
        Self {
            version,
            credential_id,
            secret,
            fallback,
        }
    }

    fn from_slot(version: u32, slot: &UnlockSlot) -> Option<Self> {
        let UnlockSlot::Totp {
            sealed,
            encrypted_secret,
            wrapped_master_key,
            ..
        } = slot
        else {
            return None;
        };
        if !sealed && encrypted_secret.is_none() {
            return None;
        }
        let modern = version >= SLOT_TABLE_VERSION;
        Some(Self::new(
            version,
            wrapped_master_key,
            modern || *sealed,
            modern || encrypted_secret.is_some(),
        ))
    }

    fn labels(&self) -> Result<Vec<String>, CryptoError> {
        let suffix = if self.version >= SLOT_TABLE_VERSION {
            let id = self.credential_id.as_deref().ok_or_else(|| {
                CryptoError::Serialization("modern TOTP ownership record has no id".into())
            })?;
            if id.len() != 32
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(CryptoError::Serialization(
                    "invalid TOTP credential ownership id".into(),
                ));
            }
            format!("-{id}")
        } else {
            String::new()
        };
        let mut labels = Vec::with_capacity(2);
        if self.secret {
            labels.push(format!("{TOTP_CREDENTIAL_LABEL}{suffix}"));
        }
        if self.fallback {
            labels.push(format!("{TOTP_FALLBACK_KEY_LABEL}{suffix}"));
        }
        Ok(labels)
    }
}

/// v1 used one machine-global credential label. v2 derives a stable, opaque
/// label from the slot's random wrapped ciphertext, isolating data roots and
/// parallel operations without persisting another identifier.
fn versioned_credential_label(
    version: u32,
    legacy_label: &str,
    wrapped_master_key: &EncryptedKey,
) -> String {
    if version < SLOT_TABLE_VERSION {
        return legacy_label.to_string();
    }

    let digest = Sha256::digest(&wrapped_master_key.ciphertext);
    format!("{legacy_label}-{}", hex_encode(&digest[..16]))
}

/// Retrieve or create a random 32-byte encryption key sealed in the platform
/// credential store, used as the fallback when direct secret sealing fails.
///
/// Unlike the previous hostname-derived key, this key is truly random and
/// machine-bound (only the platform store can unseal it).
fn get_or_create_fallback_key(label: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    get_or_create_fallback_key_with(label, &PlatformCredentialStore)
}

fn get_or_create_fallback_key_with<S: CredentialStore>(
    label: &str,
    store: &S,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    // Try to retrieve an existing fallback key
    if let Ok(bytes) = store.unseal(label) {
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
    store.seal(label, &*key).map_err(|e| {
        CryptoError::Encryption(format!(
            "cannot seal TOTP fallback key in platform credential store: {e}"
        ))
    })?;
    // Re-read the authoritative value (another process may have written concurrently)
    let confirmed = store
        .unseal(label)
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
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    #[cfg(feature = "keyring")]
    struct RealStoreGuard {
        labels: Vec<String>,
    }

    #[cfg(feature = "keyring")]
    impl RealStoreGuard {
        fn new() -> Self {
            Self { labels: Vec::new() }
        }

        fn track(&mut self, table: &SlotTable) {
            for slot in &table.slots {
                if let Some(ownership) = TotpCredentialOwnership::from_slot(table.version, slot) {
                    for label in ownership.labels().expect("valid product-owned label") {
                        if !self.labels.contains(&label) {
                            self.labels.push(label);
                        }
                    }
                }
            }
        }
    }

    #[cfg(feature = "keyring")]
    impl Drop for RealStoreGuard {
        fn drop(&mut self) {
            for label in &self.labels {
                let _ = crate::tpm::delete_key_material(label);
            }
        }
    }

    #[cfg(feature = "keyring")]
    fn add_real_totp(
        guard: &mut RealStoreGuard,
        table: &mut SlotTable,
        path: &std::path::Path,
        master_key: &[u8; MASTER_KEY_LEN],
        secret: &[u8],
    ) {
        table
            .add_totp_slot(path, master_key, secret)
            .expect("add TOTP slot");
        guard.track(table);
    }

    #[derive(Default)]
    struct FakeStore {
        values: RefCell<HashMap<String, Vec<u8>>>,
        seal_calls: Cell<usize>,
        delete_calls: Cell<usize>,
        fail_all_seals: Cell<bool>,
        fail_next_delete: Cell<bool>,
    }

    impl CredentialStore for FakeStore {
        fn seal(&self, label: &str, data: &[u8]) -> Result<(), TpmError> {
            self.seal_calls.set(self.seal_calls.get() + 1);
            if self.fail_all_seals.get() {
                return Err(TpmError::Failure("injected seal failure".into()));
            }
            self.values
                .borrow_mut()
                .insert(label.to_string(), data.to_vec());
            Ok(())
        }

        fn unseal(&self, label: &str) -> Result<Vec<u8>, TpmError> {
            self.values
                .borrow()
                .get(label)
                .cloned()
                .ok_or_else(|| TpmError::NotFound(label.to_string()))
        }

        fn delete(&self, label: &str) -> Result<CredentialDelete, TpmError> {
            self.delete_calls.set(self.delete_calls.get() + 1);
            if self.fail_next_delete.replace(false) {
                return Err(TpmError::Failure("injected delete failure".into()));
            }
            Ok(if self.values.borrow_mut().remove(label).is_some() {
                CredentialDelete::Removed
            } else {
                CredentialDelete::Absent
            })
        }
    }

    #[derive(Default)]
    struct FakePersistence {
        calls: Cell<usize>,
        fail_on_call: Cell<Option<usize>>,
        snapshots: RefCell<Vec<String>>,
    }

    impl SlotPersistence for FakePersistence {
        fn persist(&self, table: &SlotTable, _path: &std::path::Path) -> Result<(), CryptoError> {
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if self.fail_on_call.get() == Some(call) {
                return Err(CryptoError::Io(std::io::Error::other(
                    "injected persistence failure",
                )));
            }
            self.snapshots
                .borrow_mut()
                .push(serde_json::to_string(table).unwrap());
            Ok(())
        }
    }

    fn fake_table() -> (Zeroizing<[u8; MASTER_KEY_LEN]>, SlotTable) {
        let master_key = generate_master_key();
        let table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
        (master_key, table)
    }

    #[test]
    fn totp_add_persists_ownership_before_sealing() {
        let (master_key, mut table) = fake_table();
        let store = FakeStore::default();
        let persistence = FakePersistence::default();
        persistence.fail_on_call.set(Some(1));

        let error = table
            .add_totp_slot_with(
                std::path::Path::new("unused"),
                &master_key,
                b"new secret",
                &store,
                &persistence,
            )
            .unwrap_err();

        assert!(error.to_string().contains("injected persistence failure"));
        assert_eq!(store.seal_calls.get(), 0);
        assert!(!table.has_totp_slot());
        assert!(table.pending_totp_credentials.is_empty());
    }

    #[test]
    fn totp_failed_seal_retires_claimed_labels() {
        let (master_key, mut table) = fake_table();
        let store = FakeStore::default();
        store.fail_all_seals.set(true);
        let persistence = FakePersistence::default();

        assert!(table
            .add_totp_slot_with(
                std::path::Path::new("unused"),
                &master_key,
                b"new secret",
                &store,
                &persistence,
            )
            .is_err());

        assert!(!table.has_totp_slot());
        assert!(table.pending_totp_credentials.is_empty());
        assert!(store.values.borrow().is_empty());
        assert_eq!(persistence.calls.get(), 2);
    }

    #[test]
    fn totp_failed_commit_restores_old_table_and_deletes_new_credentials() {
        let (master_key, mut table) = fake_table();
        let store = FakeStore::default();
        let persistence = FakePersistence::default();
        persistence.fail_on_call.set(Some(2));

        assert!(table
            .add_totp_slot_with(
                std::path::Path::new("unused"),
                &master_key,
                b"new secret",
                &store,
                &persistence,
            )
            .is_err());

        assert!(!table.has_totp_slot());
        assert!(table.pending_totp_credentials.is_empty());
        assert!(store.values.borrow().is_empty());
        assert_eq!(persistence.calls.get(), 3);
    }

    #[test]
    fn totp_replace_and_remove_retire_only_owned_labels() {
        let (master_key, mut table) = fake_table();
        let store = FakeStore::default();
        let persistence = FakePersistence::default();
        let path = std::path::Path::new("unused");

        table
            .add_totp_slot_with(path, &master_key, b"first secret", &store, &persistence)
            .unwrap();
        let old_labels = table
            .slots
            .iter()
            .find_map(|slot| TotpCredentialOwnership::from_slot(table.version, slot))
            .unwrap()
            .labels()
            .unwrap();

        table
            .add_totp_slot_with(path, &master_key, b"second secret", &store, &persistence)
            .unwrap();
        for label in old_labels {
            assert!(!store.values.borrow().contains_key(&label));
        }
        assert_eq!(store.values.borrow().len(), 1);

        assert!(table
            .remove_totp_slot_with(path, &store, &persistence)
            .unwrap());
        assert!(store.values.borrow().is_empty());
        assert!(table.pending_totp_credentials.is_empty());
    }

    #[test]
    fn totp_failed_replacement_commit_keeps_old_slot_and_credentials() {
        let (master_key, mut table) = fake_table();
        let store = FakeStore::default();
        let persistence = FakePersistence::default();
        let path = std::path::Path::new("unused");
        table
            .add_totp_slot_with(path, &master_key, b"first secret", &store, &persistence)
            .unwrap();
        let old_labels = table
            .slots
            .iter()
            .find_map(|slot| TotpCredentialOwnership::from_slot(table.version, slot))
            .unwrap()
            .labels()
            .unwrap();
        persistence.fail_on_call.set(Some(4));

        assert!(table
            .add_totp_slot_with(path, &master_key, b"second secret", &store, &persistence)
            .is_err());

        let active_labels = table
            .slots
            .iter()
            .find_map(|slot| TotpCredentialOwnership::from_slot(table.version, slot))
            .unwrap()
            .labels()
            .unwrap();
        assert_eq!(active_labels, old_labels);
        assert!(store.values.borrow().contains_key(&old_labels[0]));
        assert_eq!(store.values.borrow().len(), 1);
        assert!(table.pending_totp_credentials.is_empty());
    }

    #[test]
    fn interrupted_replacement_cleanup_reconciles_from_durable_ledger() {
        let (master_key, mut table) = fake_table();
        let store = FakeStore::default();
        let persistence = FakePersistence::default();
        let path = std::path::Path::new("unused");
        table
            .add_totp_slot_with(path, &master_key, b"first secret", &store, &persistence)
            .unwrap();
        persistence.fail_on_call.set(Some(5));

        assert!(table
            .add_totp_slot_with(path, &master_key, b"second secret", &store, &persistence)
            .is_err());

        let durable_phase_two = persistence.snapshots.borrow().last().cloned().unwrap();
        let mut restarted: SlotTable = serde_json::from_str(&durable_phase_two).unwrap();
        assert_eq!(restarted.pending_totp_credentials.len(), 1);
        persistence.fail_on_call.set(None);
        restarted
            .finish_pending_cleanup_with(path, &store, &persistence)
            .unwrap();
        assert!(restarted.pending_totp_credentials.is_empty());
        assert_eq!(store.values.borrow().len(), 1);
    }

    #[test]
    fn totp_remove_keeps_durable_ledger_until_delete_can_retry() {
        let (master_key, mut table) = fake_table();
        let store = FakeStore::default();
        let persistence = FakePersistence::default();
        let path = std::path::Path::new("unused");
        table
            .add_totp_slot_with(path, &master_key, b"secret", &store, &persistence)
            .unwrap();
        store.fail_next_delete.set(true);

        assert!(table
            .remove_totp_slot_with(path, &store, &persistence)
            .is_err());
        assert!(!table.has_totp_slot());
        assert_eq!(table.pending_totp_credentials.len(), 1);
        let last_snapshot = persistence.snapshots.borrow().last().cloned().unwrap();
        assert!(last_snapshot.contains("pending_totp_credentials"));

        table
            .finish_pending_cleanup_with(path, &store, &persistence)
            .unwrap();
        assert!(table.pending_totp_credentials.is_empty());
        assert!(store.values.borrow().is_empty());
    }

    #[test]
    fn invalid_persisted_ownership_cannot_name_a_foreign_credential() {
        let (_, mut table) = fake_table();
        table
            .pending_totp_credentials
            .push(TotpCredentialOwnership {
                version: SLOT_TABLE_VERSION,
                credential_id: Some("../foreign".into()),
                secret: true,
                fallback: true,
            });
        let store = FakeStore::default();
        let persistence = FakePersistence::default();

        assert!(table
            .finish_pending_cleanup_with(std::path::Path::new("unused"), &store, &persistence,)
            .is_err());
        assert_eq!(store.delete_calls.get(), 0);
    }

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
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("slots.json");
        let mut guard = RealStoreGuard::new();
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();

        let secret = crate::totp::generate_secret();
        add_real_totp(
            &mut guard,
            &mut table,
            &path,
            &master_key,
            secret.as_bytes(),
        );

        let code = crate::totp::current_code(&secret).unwrap();
        let recovered = table.unwrap_with_totp(&code).unwrap();
        assert_eq!(master_key, recovered);
        assert!(table.remove_totp_slot(&path).unwrap());
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn totp_wrong_code_fails() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("slots.json");
        let mut guard = RealStoreGuard::new();
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();

        let secret = crate::totp::generate_secret();
        add_real_totp(
            &mut guard,
            &mut table,
            &path,
            &master_key,
            secret.as_bytes(),
        );

        assert!(table.unwrap_with_totp("000000").is_err());
        assert!(table.remove_totp_slot(&path).unwrap());
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
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("slots.json");
        let mut guard = RealStoreGuard::new();
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
        assert_eq!(table.available_methods(), vec!["passphrase"]);

        table.add_auto_unlock();
        let secret = crate::totp::generate_secret();
        add_real_totp(
            &mut guard,
            &mut table,
            &path,
            &master_key,
            secret.as_bytes(),
        );

        let methods = table.available_methods();
        assert!(methods.contains(&"passphrase"));
        assert!(methods.contains(&"auto_unlock"));
        assert!(methods.contains(&"totp"));
        assert!(table.remove_totp_slot(&path).unwrap());
    }

    // Builds a TOTP slot (credential-store-backed) → requires `keyring`.
    #[cfg(feature = "keyring")]
    #[test]
    fn slot_table_serialization_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("slots.json");
        let mut guard = RealStoreGuard::new();
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
        table.add_auto_unlock();
        let secret = crate::totp::generate_secret();
        add_real_totp(
            &mut guard,
            &mut table,
            &path,
            &master_key,
            secret.as_bytes(),
        );

        let json = serde_json::to_string_pretty(&table).unwrap();
        let loaded: SlotTable = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.version, SLOT_TABLE_VERSION);
        assert_eq!(loaded.slots.len(), 3);
        let recovered = loaded.unwrap_with_passphrase("pass").unwrap();
        assert_eq!(master_key, recovered);
        assert!(table.remove_totp_slot(&path).unwrap());
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn totp_slots_are_isolated_in_the_platform_store() {
        let first_temp = tempfile::tempdir().unwrap();
        let first_path = first_temp.path().join("slots.json");
        let second_temp = tempfile::tempdir().unwrap();
        let second_path = second_temp.path().join("slots.json");
        let mut guard = RealStoreGuard::new();
        let first_key = generate_master_key();
        let mut first = SlotTable::new_with_passphrase(&first_key, "first").unwrap();
        let first_secret = crate::totp::generate_secret();
        add_real_totp(
            &mut guard,
            &mut first,
            &first_path,
            &first_key,
            first_secret.as_bytes(),
        );

        let second_key = generate_master_key();
        let mut second = SlotTable::new_with_passphrase(&second_key, "second").unwrap();
        let second_secret = crate::totp::generate_secret();
        add_real_totp(
            &mut guard,
            &mut second,
            &second_path,
            &second_key,
            second_secret.as_bytes(),
        );

        let first_code = crate::totp::current_code(&first_secret).unwrap();
        let second_code = crate::totp::current_code(&second_secret).unwrap();
        assert_eq!(first.unwrap_with_totp(&first_code).unwrap(), first_key);
        assert_eq!(second.unwrap_with_totp(&second_code).unwrap(), second_key);
        assert!(first.remove_totp_slot(&first_path).unwrap());
        assert!(second.remove_totp_slot(&second_path).unwrap());
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn totp_slot_replacement_uses_new_secret_and_retires_old_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("slots.json");
        let mut guard = RealStoreGuard::new();
        let master_key = generate_master_key();
        let mut table = SlotTable::new_with_passphrase(&master_key, "pass").unwrap();
        let first_secret = crate::totp::generate_secret();
        add_real_totp(
            &mut guard,
            &mut table,
            &path,
            &master_key,
            first_secret.as_bytes(),
        );
        let second_secret = crate::totp::generate_secret();
        add_real_totp(
            &mut guard,
            &mut table,
            &path,
            &master_key,
            second_secret.as_bytes(),
        );

        let second_code = crate::totp::current_code(&second_secret).unwrap();
        assert_eq!(table.unwrap_with_totp(&second_code).unwrap(), master_key);
        assert!(table.remove_totp_slot(&path).unwrap());
    }
}
