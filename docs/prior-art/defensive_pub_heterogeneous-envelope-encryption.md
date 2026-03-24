# Defensive Patent Publication

## Heterogeneous Envelope Encryption with TOTP-Derived Unlock Slot for Certificate Authority Key Protection

**Publication Date:** 2026-03-24
**Inventor:** Leo Botinelly (Leonardo Milson Botinelly Soares)
**Publication Type:** Defensive Patent Publication (voluntary prior art disclosure)
**Implementation:** Koi v0.2 -- cross-platform local network service daemon (Rust)

---

## Field of Invention

Cryptographic key management; Envelope encryption; Multi-factor key derivation; Certificate authority key protection; Platform credential store integration.

## Keywords

Envelope encryption, unlock slots, TOTP, HKDF, Argon2id, AES-256-GCM, LUKS, multi-method key wrapping, platform credential store, DPAPI, Keychain, Secret Service, CA key protection, master key, key encryption key, slot table, heterogeneous unlock, FIDO2, auto-unlock, tiered secret storage, KDF parameter validation, legacy migration, PKCS#8.

---

## Background and Problem Statement

### The CA Key Protection Problem

A certificate authority's private key is the most sensitive piece of cryptographic material in a PKI system. If compromised, an attacker can issue arbitrary certificates, impersonate any service in the mesh, and perform man-in-the-middle attacks. The CA key must be protected at rest (when stored on disk) and should only be accessible when an authorized operator explicitly unlocks it.

Different operational environments have fundamentally different requirements for how the CA key can be unlocked:

1. **Personal/development environment (home lab):** The operator wants the CA key to auto-unlock when the daemon starts, with no interactive prompt. Security relies on physical access control and OS-level permissions.

2. **Team environment (small office, shared lab):** The operator wants quick unlock via an authenticator app (TOTP code) -- fast enough for daily operations but requiring proof of possession of the registered authenticator device.

3. **Enterprise/high-security environment:** The operator wants strong passphrase-based unlock, potentially combined with hardware tokens (FIDO2).

No single unlock method serves all three environments. Forcing a single method creates friction: a passphrase is too slow for development; auto-unlock is too weak for enterprise; TOTP is unavailable in headless environments.

### Existing Approaches and Their Limitations

1. **LUKS2 + systemd-cryptenroll (Linux disk encryption):**

   LUKS2 (Linux Unified Key Setup, version 2) is the closest prior art to the described invention. LUKS2 stores a "master key" (volume key) and wraps it with multiple "keyslots," each using a different unlock method. Supported keyslot types include passphrase (via PBKDF2 or Argon2id), TPM2 (via systemd-cryptenroll), FIDO2 hmac-secret extension (via systemd-cryptenroll), and PKCS#11 tokens.

   **Differences from the described invention:**
   - LUKS2 is Linux-specific (kernel-level dm-crypt). It cannot run on Windows or macOS.
   - LUKS2 is for disk encryption. It protects disk volumes, not individual PKI key files.
   - LUKS2 does not have a TOTP slot type. There is no way to unlock a LUKS volume with a 6-digit TOTP code. The `systemd-cryptenroll --fido2-device` option uses the FIDO2 hmac-secret extension, which is a different mechanism from TOTP.
   - LUKS2's keyslot format is a binary on-disk format (LUKS2 header), not a portable JSON document.
   - LUKS2 does not support tiered fallback for secret storage (platform credential store -> encrypted fallback -> plaintext).

2. **BitLocker (Windows disk encryption):**

   BitLocker supports multiple "protectors" for the volume encryption key: TPM, TPM+PIN, startup key (USB), password, recovery key, network unlock, and certificate-based protectors. Each protector independently unwraps the volume master key.

   **Differences:**
   - Windows-only.
   - Disk encryption, not PKI key protection.
   - No TOTP protector type.
   - Binary format, not portable JSON.
   - No cross-platform credential store tiering.

3. **FileVault 2 (macOS disk encryption):**

   FileVault 2 uses the user's login password as the primary unlock method, with an institutional recovery key as a secondary method. Multiple user passwords can unlock the volume.

   **Differences:**
   - macOS-only.
   - Disk encryption, not PKI key protection.
   - No TOTP unlock method.
   - Limited to password-based and recovery key protectors.

4. **HashiCorp Vault unseal/seal:**

   Vault's seal mechanism uses Shamir's Secret Sharing to split a "root key" into N shares with threshold M. Unseal requires M shares. Auto-unseal uses an external KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS, Transit unseal) to automatically unseal without operator shares.

   **Differences:**
   - Shamir splitting is fundamentally different from envelope encryption with independent slots. In Shamir, no single share can unseal; M shares are required. In the described invention, any single slot independently recovers the master key.
   - Vault's auto-unseal requires external cloud KMS infrastructure.
   - Vault does not support TOTP-based unseal.
   - Vault is a general-purpose secrets manager, not a lightweight daemon.

5. **MFKDF (Multi-Factor Key Derivation Function, Nair & Song, USENIX Security 2023):**

   MFKDF derives cryptographic keys from multiple authentication factors, including TOTP codes. It uses a polynomial secret sharing construction to derive the key from the combination of multiple factor inputs.

   **Key difference from the described invention:** MFKDF derives keys from the **ephemeral TOTP code value** (the 6-digit number that changes every 30 seconds). This means the code must be provided at every key derivation. The described invention derives the slot KEK from the **long-lived TOTP shared secret** (the 32-byte secret established during setup). The TOTP code is used only as an authentication gate to prove possession of the authenticator. The key derivation uses the underlying shared secret, which does not change over time.

   This is a fundamental architectural difference:
   - MFKDF: key = f(totp_code_value, other_factors). Different codes produce different keys. Requires polynomial reconstruction.
   - Described invention: kek = HKDF(shared_secret || info_string). Same KEK every time. Code verification is a separate boolean check.

6. **PKCS#12 / PFX (RFC 7292):**

   PKCS#12 is a container format for storing private keys and certificates, protected by a password. It supports only password-based protection (PBKDF2 + 3DES or AES).

   **Differences:**
   - Single unlock method only (password).
   - No concept of multiple independent unlock slots.
   - No TOTP, FIDO2, or auto-unlock options.
   - Aging cryptographic defaults (many implementations use 3DES).

### The Gap

No existing system provides:
- A portable (cross-platform, JSON-based, userspace) envelope encryption system
- With heterogeneous unlock slot types including TOTP-derived slots
- Specifically designed for PKI CA key protection
- With tiered fallback for TOTP secret storage (platform store -> encrypted fallback -> legacy plaintext)
- With KDF parameter validation to prevent downgrade attacks
- With transparent migration from single-passphrase to envelope encryption

---

## Detailed Technical Description

### 1. Two-Layer Encryption Architecture

The system uses a two-layer encryption architecture:

```
Layer 2: Unlock Slots                   Layer 1: Master Key Encryption
┌────────────────────┐
│  Passphrase Slot   │──┐
│  (Argon2id → KEK)  │  │
└────────────────────┘  │
                        │     ┌──────────────┐     ┌──────────────┐
┌────────────────────┐  ├──>  │  Master Key   │──>  │  CA Private  │
│   TOTP Slot        │──┤     │  (256-bit)    │     │  Key (PKCS8) │
│  (HKDF → KEK)     │  │     └──────────────┘     └──────────────┘
└────────────────────┘  │           │                     │
                        │      (AES-256-GCM)         (AES-256-GCM)
┌────────────────────┐  │           │                     │
│   FIDO2 Slot       │──┤           ▼                     ▼
│  (random KEK)      │  │   unlock-slots.json         ca-key.enc
└────────────────────┘  │
                        │
┌────────────────────┐  │
│  Auto-Unlock Slot  │──┘
│  (marker only)     │
└────────────────────┘
```

**Layer 1 (Master Key -> CA Key):**
- A random 256-bit master key is generated using the OS CSPRNG (`OsRng`)
- The CA private key (ECDSA P-256, exported as PKCS#8 DER) is encrypted with AES-256-GCM
- The encryption key is derived from the master key via Argon2id (the master key is hex-encoded and treated as a "passphrase" input to reuse the existing encryption pipeline)
- The result is stored as `ca-key.enc` (JSON file with `{ ciphertext, salt, nonce, kdf_params }`)

**Layer 2 (Unlock Slots -> Master Key):**
- Each unlock slot independently wraps the same master key using its own key encryption key (KEK)
- All slots are stored in `unlock-slots.json` as a `SlotTable` structure
- Any single slot can recover the master key
- Adding or removing a slot does not require re-encrypting the CA key

**File layout:**
```
{certmesh_dir}/ca/
    ca-key.enc           ← Master-key-encrypted CA private key
    unlock-slots.json    ← SlotTable: version + ordered list of slots
    ca-cert.pem          ← CA certificate (public, unencrypted)
    roster.json          ← Membership roster
```

### 2. Master Key Generation and Management

```rust
const MASTER_KEY_LEN: usize = 32;  // 256 bits

pub fn generate_master_key() -> [u8; MASTER_KEY_LEN] {
    let mut key = [0u8; MASTER_KEY_LEN];
    rand::rng().fill_bytes(&mut key);
    key
}
```

The master key is generated once during CA creation and never changes for the lifetime of the CA. It is the key that encrypts the CA private key in `ca-key.enc`. The master key itself is never stored in plaintext; it is only stored wrapped by unlock slots.

**Master key lifecycle:**
1. Generated during `create_ca()` or `migrate_to_envelope()`
2. Wrapped by the initial passphrase slot
3. Optionally wrapped by additional slots (TOTP, FIDO2, auto-unlock)
4. Unwrapped on each daemon startup when an operator provides credentials
5. Used to decrypt `ca-key.enc`, yielding the CA private key in memory
6. The raw master key bytes are held in memory only during the unwrap -> decrypt sequence, then discarded

### 3. The SlotTable Data Structure

```rust
#[derive(Serialize, Deserialize)]
pub struct SlotTable {
    pub version: u32,           // Currently 1; for future migrations
    pub slots: Vec<UnlockSlot>, // Ordered list of slots
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UnlockSlot {
    #[serde(rename = "passphrase")]
    Passphrase {
        wrapped_master_key: EncryptedKey,
    },

    #[serde(rename = "auto_unlock")]
    AutoUnlock,

    #[serde(rename = "totp")]
    Totp {
        sealed: bool,
        shared_secret_hex: Option<String>,
        encrypted_secret: Option<EncryptedKey>,
        wrapped_master_key: EncryptedKey,
    },

    #[serde(rename = "fido2")]
    Fido2 {
        credential_id: String,     // base64
        public_key: String,        // base64
        rp_id: String,
        sign_count: u32,
        wrapped_master_key: EncryptedKey,
        encrypted_slot_kek: EncryptedKey,
    },
}
```

**Serialized JSON example (with passphrase + TOTP + auto-unlock slots):**
```json
{
    "version": 1,
    "slots": [
        {
            "type": "passphrase",
            "wrapped_master_key": {
                "ciphertext": "base64...",
                "salt": "base64...",
                "nonce": "base64...",
                "kdf_params": {
                    "algorithm": "argon2id",
                    "m_cost": 65536,
                    "t_cost": 3,
                    "p_cost": 4
                }
            }
        },
        {
            "type": "auto_unlock"
        },
        {
            "type": "totp",
            "sealed": true,
            "shared_secret_hex": null,
            "wrapped_master_key": {
                "ciphertext": "base64...",
                "salt": "base64...",
                "nonce": "base64..."
            }
        }
    ]
}
```

### 4. Passphrase Slot (Slot Type 1)

**Creation:**
```
Input: passphrase (string, minimum 8 characters), master_key (32 bytes)
Process:
    1. Generate random 16-byte salt
    2. Generate random 12-byte nonce
    3. Derive KEK: Argon2id(passphrase, salt, m=65536 KiB, t=3, p=4) -> 32 bytes
    4. Encrypt: AES-256-GCM(KEK, nonce, plaintext=master_key) -> ciphertext + auth_tag
    5. Store: EncryptedKey { ciphertext, salt, nonce, kdf_params }
```

**Unwrap:**
```
Input: passphrase (string), wrapped_master_key (EncryptedKey)
Process:
    1. Validate KDF parameters against minimum floors (see Section 10)
    2. Derive KEK: Argon2id(passphrase, salt, m_cost, t_cost, p_cost) -> 32 bytes
    3. Decrypt: AES-256-GCM(KEK, nonce, ciphertext) -> master_key
    4. Verify master_key is exactly 32 bytes
    5. Return master_key
```

**Argon2id parameter choices (OWASP recommendations):**
- `m_cost = 65536` (64 MiB memory): Provides resistance against GPU-based brute force attacks. GPUs have limited per-core memory, making memory-hard KDFs expensive to parallelize.
- `t_cost = 3` (3 iterations): Increases the time cost linearly without additional memory.
- `p_cost = 4` (4 lanes): Allows the KDF to use multiple CPU cores on the defender's hardware.

The passphrase slot is always the first slot (slot 0) in the slot table and cannot be removed. It serves as the "master" unlock method and the fallback when other methods are unavailable.

### 5. TOTP Slot (Slot Type 2) -- NOVEL CONSTRUCTION

The TOTP slot is the primary novel contribution of this disclosure. It enables unlocking the CA key using a 6-digit TOTP code from an authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.).

**5.1 Key Derivation from TOTP Shared Secret**

The slot KEK (Key Encryption Key) is derived from the TOTP shared secret using a SHA-256 based construction:

```rust
const TOTP_SLOT_HKDF_INFO: &[u8] = b"pond-unlock-slot-totp-v1";

fn derive_totp_slot_kek(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(TOTP_SLOT_HKDF_INFO);
    let result = hasher.finalize();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&result);
    kek
}
```

**Why this works:** The TOTP shared secret has 256 bits of entropy (32 bytes from OsRng). SHA-256 applied to a 256-bit secret produces a 256-bit output that is computationally indistinguishable from random (assuming SHA-256 is a good hash function). The domain separation string `"pond-unlock-slot-totp-v1"` ensures this derivation produces a different output than any other use of the same secret.

**Why a full HKDF extract-expand is not required:** The standard HKDF construction (RFC 5869) uses extract-then-expand. The extract step is designed to handle non-uniform input keying material (IKM) by compressing it into a pseudorandom key. When the IKM is already a uniformly random secret (as is the case with 32 OsRng bytes), the extract step is not necessary. The SHA-256 construction used here is equivalent to a single HKDF-Expand step with the shared secret as the PRK and the info string as the info parameter. This is documented as acceptable practice in RFC 5869 Section 3.3.

**5.2 TOTP Code as Authentication Gate**

The TOTP code and the TOTP shared secret serve two distinct purposes:

- **Code (6-digit number, changes every 30 seconds):** Proves the operator possesses the authenticator device at the time of unlock. The code is verified using RFC 6238 TOTP with SHA-1 HMAC, 30-second period, and +/- 1 step tolerance. Constant-time comparison (`subtle::ConstantTimeEq`) prevents timing side-channel attacks.

- **Shared secret (32 bytes, static):** Provides the key material for deriving the slot KEK. The shared secret does not change and produces the same KEK every time.

These are separate operations: the code verification is a boolean check (pass/fail), and the KEK derivation uses the underlying secret regardless of which specific 6-digit code was presented. An invalid code causes the unlock to fail at the verification step, before the KEK is used.

**5.3 TOTP Slot Creation**

```
Input: master_key (32 bytes), shared_secret (32 bytes from TOTP setup)
Process:
    1. Derive slot KEK: SHA-256(shared_secret || "pond-unlock-slot-totp-v1") -> 32 bytes
    2. Hex-encode the KEK (to use as "passphrase" in the encryption pipeline)
    3. Encrypt master key: Argon2id(kek_hex, random_salt) -> AES key -> AES-256-GCM(master_key)
    4. Protect the shared secret at rest (see Section 6 for tiered storage)
    5. Store slot: { type: "totp", sealed, shared_secret_hex, encrypted_secret, wrapped_master_key }
```

**5.4 TOTP Slot Unwrap**

```
Input: totp_code (6-digit string)
Process:
    1. Recover TOTP shared secret from storage (see Section 6 for tiered recovery)
    2. Verify TOTP code against the recovered secret
       - If invalid: return error "invalid TOTP code"
    3. Derive slot KEK: SHA-256(shared_secret || "pond-unlock-slot-totp-v1") -> 32 bytes
    4. Hex-encode the KEK
    5. Decrypt wrapped_master_key using the KEK
    6. Return master_key (32 bytes)
```

### 6. Tiered TOTP Secret Storage -- NOVEL CONSTRUCTION

The TOTP shared secret must be available at unlock time to derive the slot KEK, but it is itself sensitive material (knowledge of the secret allows generating valid TOTP codes). The system protects it using a three-tier fallback chain:

**Tier 1: Direct Platform Credential Store Sealing**

The TOTP shared secret (32 raw bytes) is sealed directly in the platform credential store:
- **Windows:** Credential Manager (DPAPI-backed, optionally TPM-backed on modern hardware)
- **macOS:** Keychain (Secure Enclave on Apple Silicon)
- **Linux:** Secret Service (D-Bus, e.g., GNOME Keyring) or kernel keyutils

The credential is stored under the label `"koi-certmesh-unlock-totp"` using the `keyring` Rust crate, which provides a cross-platform abstraction:

```rust
const TOTP_CREDENTIAL_LABEL: &str = "koi-certmesh-unlock-totp";

// Seal:
keyring::Entry::new("koi-certmesh", TOTP_CREDENTIAL_LABEL)?.set_secret(secret_bytes)?;

// Unseal:
keyring::Entry::new("koi-certmesh", TOTP_CREDENTIAL_LABEL)?.get_secret()?;
```

When this tier is available, the slot table has `sealed: true` and `shared_secret_hex: null`.

**Tier 2: Encrypted Fallback with Sealed Key**

If direct sealing fails (e.g., the credential store has size limits, the D-Bus Secret Service is unavailable, or the store rejects binary data), the system falls back to encrypting the TOTP secret with a random key that is itself sealed in the credential store:

```
Process:
    1. Generate or retrieve a random 32-byte fallback key
    2. Seal the fallback key in the platform credential store under
       label "koi-certmesh-totp-fallback-key"
    3. Encrypt the TOTP secret with AES-256-GCM using the fallback key
    4. Store the encrypted TOTP secret in the slot table as encrypted_secret
```

The `get_or_create_fallback_key()` function handles concurrent initialization:

```rust
fn get_or_create_fallback_key() -> Result<[u8; 32], CryptoError> {
    // Try to retrieve existing fallback key
    if let Ok(bytes) = tpm::unseal_key_material("koi-certmesh-totp-fallback-key") {
        if bytes.len() == 32 {
            return Ok(bytes_to_array(bytes));
        }
    }
    // Generate and seal a new random key
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    tpm::seal_key_material("koi-certmesh-totp-fallback-key", &key)?;
    // Re-read to confirm (handles concurrent writes)
    let confirmed = tpm::unseal_key_material("koi-certmesh-totp-fallback-key")?;
    Ok(bytes_to_array(confirmed))
}
```

When this tier is used, the slot table has `sealed: false`, `shared_secret_hex: null`, and `encrypted_secret: Some(...)`.

**Tier 3: Legacy Plaintext Hex (Read-Only, Backward Compatibility)**

For slot tables created before the tiered storage system was implemented, the TOTP shared secret may be stored as a hex-encoded string directly in the JSON:

```json
{
    "type": "totp",
    "sealed": false,
    "shared_secret_hex": "a1b2c3d4e5f6...64-hex-chars...",
    "wrapped_master_key": { ... }
}
```

When this tier is encountered during unlock:
1. The secret is read from `shared_secret_hex`
2. A warning is logged: "TOTP secret stored in plaintext (legacy format). Re-create the CA or rotate auth to migrate to encrypted storage."
3. The unlock proceeds normally

New slot creation never writes to `shared_secret_hex` (it is always `null` for new slots).

**Tier recovery order during unlock:**
```
if slot.sealed:
    secret = unseal_from_platform_store("koi-certmesh-unlock-totp")
else if slot.encrypted_secret is Some:
    fallback_key = get_or_create_fallback_key()
    secret = decrypt(slot.encrypted_secret, fallback_key)
else if slot.shared_secret_hex is Some:
    warn("legacy plaintext TOTP secret")
    secret = hex_decode(slot.shared_secret_hex)
else:
    error("TOTP slot has no recoverable secret")
```

### 7. FIDO2 Slot (Slot Type 3)

The FIDO2 slot enables unlocking the CA key with a hardware security key (e.g., YubiKey, SoloKey).

**7.1 Architecture**

```
                 ┌─────────────────┐
                 │ Hardware         │
                 │ Authenticator    │
                 │ (private key)    │
                 └────────┬────────┘
                          │ assertion
                          ▼
┌──────────────────────────────────────────┐
│         Software Gate                     │
│  storage_key = SHA-256("pond-fido2-      │
│    storage-key-v1" || credential_id)     │
│  slot_kek = decrypt(encrypted_slot_kek,  │
│    storage_key)                          │
│  master_key = decrypt(wrapped_master_key,│
│    slot_kek)                             │
└──────────────────────────────────────────┘
```

**7.2 Slot Creation**

```
Input: master_key (32 bytes), credential_id (from WebAuthn registration),
       public_key (COSE format), rp_id (relying party identifier)
Process:
    1. Generate random 32-byte slot_kek
    2. Wrap master_key with slot_kek:
       AES-256-GCM(slot_kek, master_key) -> wrapped_master_key
    3. Derive storage key from credential_id:
       storage_key = SHA-256("pond-fido2-storage-key-v1" || credential_id)
    4. Encrypt slot_kek with storage_key:
       AES-256-GCM(storage_key, slot_kek) -> encrypted_slot_kek
    5. Store: { credential_id, public_key, rp_id, sign_count: 0,
                wrapped_master_key, encrypted_slot_kek }
```

**7.3 Security Model**

The storage key derived from `credential_id` is NOT secret -- the credential_id is transmitted in cleartext during WebAuthn ceremonies and can be extracted from the slot table JSON. This means the `encrypted_slot_kek` provides only obfuscation, not confidentiality.

The actual security gate is the FIDO2 assertion verification:
1. The server generates a random challenge
2. The authenticator signs the challenge with its internal private key
3. The server verifies the signature against the stored public key
4. Only after successful verification does the server proceed to unwrap the slot_kek

This is explicitly documented in the implementation as a known limitation:

```rust
// TODO(ADR-011): credential_id is not secret material - deriving a storage
// key from it provides no real confidentiality. Replace with a proper
// key agreement when the FIDO2 integration is hardened.
```

The FIDO2 slot also tracks the `sign_count` for clone detection: if the authenticator's sign count is less than or equal to the stored sign count, it may be a cloned authenticator.

**7.4 Slot Unwrap**

```
Input: credential_id (after assertion has been verified externally)
Process:
    1. Find matching slot by credential_id (base64 comparison)
    2. Derive storage key: SHA-256("pond-fido2-storage-key-v1" || credential_id)
    3. Decrypt slot_kek: AES-256-GCM(storage_key, encrypted_slot_kek)
    4. Decrypt master_key: AES-256-GCM(slot_kek, wrapped_master_key)
    5. Return master_key
```

### 8. Auto-Unlock Slot (Slot Type 4)

The auto-unlock slot is the simplest: it is a marker in the slot table indicating that the CA key should be automatically unlocked on daemon startup without operator interaction.

**Implementation:**
- The slot table contains `{ "type": "auto_unlock" }` with no additional fields
- The master key is stored in the platform credential store under a separate label, or in a local file with restricted permissions
- On startup, the daemon checks `slot_table.has_auto_unlock()` and attempts to retrieve the master key from the platform store
- If retrieval succeeds, the CA key is decrypted automatically

**Security model:** Auto-unlock provides convenience, not security. The master key is protected only by:
- File system permissions (0600 on Unix, SYSTEM+Administrators ACL on Windows)
- Platform credential store protection (DPAPI, Keychain, Secret Service)
- Physical access control to the machine

This slot type is appropriate for personal/development environments and explicitly documented as unsuitable for high-security deployments.

### 9. Slot Management Operations

**Adding a slot:**
```
Process:
    1. Decrypt master key using any existing slot (passphrase, TOTP, or FIDO2)
    2. Create the new slot by encrypting the master key with the new slot's KEK
    3. Append the new slot to the slot table
    4. Save the updated slot table to disk
```

**Slot deduplication:** Adding a slot of a type that already exists replaces the existing slot of that type:
```rust
// In add_totp_slot():
self.slots.retain(|s| !matches!(s, UnlockSlot::Totp { .. }));
// ... then push new TOTP slot

// In add_fido2_slot():
self.slots.retain(|s| !matches!(s, UnlockSlot::Fido2 { .. }));
// ... then push new FIDO2 slot
```

This means there is at most one TOTP slot and at most one FIDO2 slot. Multiple passphrase slots are not supported (there is always exactly one passphrase slot).

**Removing a slot:**
- Auto-unlock: `remove_auto_unlock()` removes the marker
- TOTP/FIDO2: replace by adding a new slot (which removes the old one) or directly remove from the slots vector
- Passphrase: cannot be removed (always slot 0)

**Querying available methods:**
```rust
pub fn available_methods(&self) -> Vec<&'static str> {
    self.slots.iter().map(|slot| match slot {
        UnlockSlot::Passphrase { .. } => "passphrase",
        UnlockSlot::AutoUnlock => "auto_unlock",
        UnlockSlot::Totp { .. } => "totp",
        UnlockSlot::Fido2 { .. } => "fido2",
    }).collect()
}
```

### 10. KDF Parameter Validation (Anti-Downgrade Protection)

The `EncryptedKey` structure stores the KDF parameters used during encryption:

```json
{
    "kdf_params": {
        "algorithm": "argon2id",
        "m_cost": 65536,
        "t_cost": 3,
        "p_cost": 4
    }
}
```

An attacker who gains write access to the `unlock-slots.json` file (but not the passphrase) could modify the KDF parameters to weaken them:
```json
{
    "kdf_params": {
        "algorithm": "argon2id",
        "m_cost": 1,
        "t_cost": 1,
        "p_cost": 1
    }
}
```

If the system blindly used these parameters during decryption, it would fail (because the ciphertext was encrypted with the original strong parameters). However, an attacker could also replace the ciphertext with one encrypted under weak parameters if they know the passphrase (e.g., from a shoulder-surfing attack).

To prevent this, the system enforces minimum KDF parameter floors:

```rust
const MIN_M_COST: u32 = 8192;  // 8 MiB minimum
const MIN_T_COST: u32 = 1;      // 1 iteration minimum
const MIN_P_COST: u32 = 1;      // 1 lane minimum

fn derive_aes_key(passphrase: &str, salt: &[u8], kdf_params: &KdfParams) -> Result<...> {
    if kdf_params.m_cost < MIN_M_COST
        || kdf_params.t_cost < MIN_T_COST
        || kdf_params.p_cost < MIN_P_COST
    {
        return Err(CryptoError::KeyDerivation(format!(
            "KDF params below minimum: m_cost={} (min {}), ...",
            kdf_params.m_cost, MIN_M_COST, ...
        )));
    }
    // ... proceed with Argon2id
}
```

This ensures that even if an attacker tampers with the stored parameters, the system will reject parameters weaker than the enforced minimums.

**Backward compatibility:** The `kdf_params` field uses `#[serde(default)]`, so files created before this field was added deserialize with the default parameters (`m=65536, t=3, p=4`), which exceed all minimums.

### 11. Legacy Migration (Single-Passphrase to Envelope)

The system supports transparent migration from the pre-envelope encryption model (where the passphrase directly encrypted the CA key) to the envelope model:

```rust
pub fn migrate_to_envelope(
    old_encrypted: &EncryptedKey,
    passphrase: &str,
) -> Result<(EncryptedKey, SlotTable, [u8; MASTER_KEY_LEN]), CryptoError> {
    // 1. Decrypt with old passphrase-direct model
    let plaintext = decrypt_bytes(old_encrypted, passphrase)?;

    // 2. Generate new master key
    let master_key = generate_master_key();

    // 3. Re-encrypt CA key with master key
    let master_key_hex = hex_encode(&master_key);
    let new_encrypted = encrypt_bytes(&plaintext, &master_key_hex)?;

    // 4. Create slot table with passphrase slot
    let slot_table = SlotTable::new_with_passphrase(&master_key, passphrase)?;

    Ok((new_encrypted, slot_table, master_key))
}
```

**Detection:** The migration is triggered when the system finds a `ca-key.enc` file but no `unlock-slots.json` file. This indicates a pre-envelope installation.

**Transparency:** The operator's passphrase does not change. The migration replaces `ca-key.enc` with a new version encrypted under the master key, and creates `unlock-slots.json` with a passphrase slot. The operator experiences no change in behavior -- they still provide the same passphrase to unlock.

**Post-migration:** After migration, the returned `master_key` can be used to add additional slots (TOTP, FIDO2, auto-unlock) before being discarded.

### 12. New CA Creation with Envelope Encryption

For new CAs, envelope encryption is used from the start:

```rust
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
```

The CA creation ceremony (interactive wizard) optionally offers to add a TOTP slot and/or auto-unlock slot during initial setup, using the returned `master_key` before it is discarded.

### 13. Platform Credential Store Abstraction

The system uses the `keyring` Rust crate for cross-platform credential store access:

```rust
const SERVICE_NAME: &str = "koi-certmesh";

pub fn seal_key_material(label: &str, data: &[u8]) -> Result<(), TpmError> {
    let entry = keyring::Entry::new(SERVICE_NAME, label)?;
    entry.set_secret(data)?;
    Ok(())
}

pub fn unseal_key_material(label: &str) -> Result<Vec<u8>, TpmError> {
    let entry = keyring::Entry::new(SERVICE_NAME, label)?;
    entry.get_secret()
}

pub fn is_available() -> bool {
    // Disabled via KOI_NO_CREDENTIAL_STORE=1 for testing/CI
    if std::env::var("KOI_NO_CREDENTIAL_STORE").is_ok() {
        return false;
    }
    // Probe: write/read/delete a test entry
    let probe = keyring::Entry::new(SERVICE_NAME, "koi-probe-test");
    // ... returns true if probe succeeds
}
```

**Platform mapping:**
| Platform | Backend | Protection |
|----------|---------|------------|
| Windows | Credential Manager | DPAPI (user or system scope) |
| macOS | Keychain | Secure Enclave (Apple Silicon), software Keychain (Intel) |
| Linux | Secret Service (D-Bus) | GNOME Keyring, KWallet, or kernel keyutils |

**Credential labels used:**
| Label | Contents |
|-------|----------|
| `koi-certmesh-ca` | CA key ciphertext (machine-binding verification) |
| `koi-certmesh-unlock-totp` | TOTP shared secret (Tier 1 storage) |
| `koi-certmesh-totp-fallback-key` | Random encryption key for TOTP secret (Tier 2 storage) |

### 14. Machine-Binding Verification

As defense-in-depth, when the CA key is first encrypted, its ciphertext is also sealed in the platform credential store:

```rust
// During encrypt_key():
if tpm::is_available() {
    tpm::seal_key_material("koi-certmesh-ca", &encrypted.ciphertext)?;
}

// During decrypt_key():
if tpm::is_available() {
    match tpm::unseal_key_material("koi-certmesh-ca") {
        Ok(sealed) => {
            if sealed != encrypted.ciphertext {
                warn!("ciphertext mismatch - key file may have been copied from another machine");
            }
        }
        Err(_) => { /* No sealed material; fall through */ }
    }
}
```

This detects if the `ca-key.enc` file has been copied from another machine. The sealed ciphertext is machine-specific (protected by DPAPI on Windows, Keychain on macOS). A mismatch triggers a warning but does not block decryption (the passphrase is the real security gate).

### 15. Ceremony Integration

The CA creation ceremony (interactive wizard) presents unlock method choices:

```
Unlock method:
  [1] Auto-unlock    - Key unlocked automatically on daemon boot
  [2] Token          - Unlock with TOTP code or FIDO2 key
  [3] Passphrase     - Unlock with passphrase only (most secure)
```

Based on the operator's choice:
- **Auto:** Creates passphrase slot + auto-unlock slot. The master key is sealed in the platform credential store.
- **Token (TOTP):** Creates passphrase slot + TOTP slot. Displays a QR code for the operator to scan with their authenticator app. Verifies a code to confirm registration.
- **Token (FIDO2):** Creates passphrase slot + FIDO2 slot. Initiates a WebAuthn registration ceremony.
- **Passphrase only:** Creates passphrase slot only. Most secure but requires manual entry on every daemon restart.

---

## Variants and Alternative Embodiments

### Variant A: Additional Slot Types
The envelope encryption architecture is extensible to additional slot types:
- **Hardware TPM slot:** The master key is sealed/unsealed using the TPM's seal/unseal commands, bound to platform configuration registers (PCRs).
- **Smartcard / PKCS#11 slot:** The master key is encrypted with a public key on a smartcard; decryption requires the smartcard's private key.
- **Recovery key slot:** A high-entropy random string (e.g., 24 words from BIP-39) that can be printed and stored in a safe. Functionally similar to a passphrase slot but with guaranteed minimum entropy.
- **Biometric slot:** The master key is sealed by a biometric authentication framework (Windows Hello, macOS Touch ID). The slot KEK is derived from a biometric-gated secret.
- **Network KMS slot:** The master key is encrypted with a key from an external KMS (AWS KMS, Azure Key Vault, GCP Cloud KMS). Similar to Vault's auto-unseal.

### Variant B: Multi-Factor Slot Requirements
Instead of any-single-slot-unlocks, the system could require multiple slots:
- **AND logic:** Both passphrase AND TOTP are required to unlock (threshold: 2)
- **Configurable threshold:** M-of-N slots required (Shamir-style)
- **Policy-based:** Different unlock methods required depending on context (e.g., TOTP for normal operations, passphrase + FIDO2 for key rotation)

### Variant C: Alternative KDF for TOTP Slot
The TOTP slot KEK derivation can use:
- **SHA-256(secret || info)** (primary embodiment, simple and sufficient)
- **HKDF-SHA256(salt, secret, info)** (full HKDF, more standard)
- **HKDF-SHA512** (larger intermediate hash)
- **Argon2id(hex(secret))** (adds memory-hardness, unnecessary for high-entropy input)

### Variant D: Alternative Serialization Formats
The slot table can be stored in formats other than JSON:
- **CBOR** (more compact, binary-safe)
- **Protocol Buffers** (schema-enforced)
- **MessagePack** (compact binary JSON)
- **SQLite** (for large slot tables with many entries)

### Variant E: Slot Table Versioning and Migration
The `version` field enables future migrations:
- Version 2 could add a checksum/HMAC of the slot table for tamper detection
- Version 3 could add support for slot groups (AND/OR logic)
- Migration from version N to N+1 is performed transparently on first read

### Variant F: TOTP Secret Rotation Without Re-Enrollment
The TOTP secret can be rotated without requiring the operator to re-scan a QR code:
1. Generate a new TOTP secret
2. Encrypt the master key with the new secret's derived KEK
3. Re-seal the new secret in the platform credential store
4. Display a new QR code for the operator to scan
5. Verify a code from the new authenticator registration
6. Replace the TOTP slot in the slot table

---

## Implementation Evidence

| Component | Source File | Key Symbols |
|-----------|-------------|-------------|
| Slot table | `crates/koi-crypto/src/unlock_slots.rs` | `SlotTable`, `UnlockSlot`, `generate_master_key()`, `derive_totp_slot_kek()`, `derive_fido2_storage_key()`, `migrate_to_envelope()`, `envelope_encrypt_new()`, `decrypt_with_master_key()` |
| Encryption pipeline | `crates/koi-crypto/src/keys.rs` | `encrypt_bytes()`, `decrypt_bytes()`, `encrypt_key()`, `decrypt_key()`, `EncryptedKey`, `KdfParams`, `derive_aes_key()`, `MIN_M_COST`, `MIN_T_COST`, `MIN_P_COST` |
| Platform credential store | `crates/koi-crypto/src/tpm.rs` | `seal_key_material()`, `unseal_key_material()`, `delete_key_material()`, `is_available()`, `SERVICE_NAME` |
| TOTP operations | `crates/koi-crypto/src/totp.rs` | `TotpSecret`, `generate_secret()`, `verify_code()`, `encrypt_secret()`, `decrypt_secret()`, `RateLimiter` |
| CA key management | `crates/koi-certmesh/src/ca.rs` | `create_ca()`, `load_ca()`, `load_ca_with_master_key()`, `load_slot_table()`, `save_slot_table()` |
| Domain core | `crates/koi-certmesh/src/lib.rs` | `CertmeshCore::unlock()`, `unlock_with_totp()`, `unlock_with_fido2()`, `try_auto_unlock()` |
| Auth state | `crates/koi-crypto/src/auth.rs` | `AuthState`, `StoredAuth` |

**Test coverage:**
- `passphrase_slot_round_trip` -- create and unwrap passphrase slot
- `wrong_passphrase_fails` -- verify wrong passphrase rejection
- `totp_slot_round_trip` -- create TOTP slot, generate valid code, unwrap
- `totp_wrong_code_fails` -- verify invalid TOTP code rejection
- `fido2_slot_round_trip` -- create FIDO2 slot, unwrap with correct credential
- `fido2_wrong_credential_fails` -- verify wrong credential rejection
- `envelope_encrypt_new_round_trip` -- create new CA with envelope encryption
- `migrate_preserves_ca_key` -- migrate from passphrase-direct to envelope
- `auto_unlock_marker` -- add/remove/check auto-unlock slot
- `available_methods_lists_all_slots` -- verify method enumeration
- `slot_table_serialization_round_trip` -- serialize/deserialize slot table
- `kdf_params_default_values` -- verify OWASP-recommended defaults
- `encrypted_key_backward_compat_without_kdf_params` -- verify legacy files work
- `decrypt_bytes_with_wrong_passphrase_returns_decryption_error` -- error handling
- `decrypt_bytes_with_tampered_nonce_fails` -- tamper detection
- `is_available_returns_bool` -- credential store probe
- `seal_unseal_round_trip` -- platform store round-trip

---

## Claims-Style Disclosures

### Disclosure 1: Heterogeneous Envelope Encryption for CA Key Protection

A method for protecting a certificate authority private key at rest using envelope encryption with heterogeneous unlock slots, comprising:
- Generating a random master key (256 bits) using a cryptographically secure random number generator;
- Encrypting the CA private key (PKCS#8 DER format) with AES-256-GCM using a key derived from the master key;
- Creating a slot table containing one or more independently-typed unlock slots, each of which wraps the master key using a different key derivation method:
  - A passphrase slot deriving a key encryption key via Argon2id from a user-provided passphrase;
  - A TOTP slot deriving a key encryption key via HKDF/SHA-256 from a TOTP shared secret, with a separate TOTP code verification serving as an authentication gate;
  - A FIDO2 slot using a random key encryption key stored encrypted on disk, gated by FIDO2 assertion verification;
  - An auto-unlock slot using a master key stored in a platform credential store;
- Storing the slot table as a JSON document separate from the encrypted CA key;
- Enabling any single slot to independently recover the master key and decrypt the CA key;
- Enabling addition or removal of slots without re-encrypting the CA key;

Wherein said method is distinct from LUKS2 in application domain (PKI key file vs. disk volume), portability (cross-platform JSON vs. Linux kernel dm-crypt), and slot types (TOTP slot has no LUKS2 equivalent); distinct from BitLocker and FileVault in platform independence; distinct from Vault in using independent slots rather than threshold secret sharing; and distinct from MFKDF in deriving the slot KEK from the long-lived TOTP shared secret rather than the ephemeral TOTP code value.

### Disclosure 2: TOTP Shared Secret as Key Derivation Material

A method for deriving a cryptographic key encryption key from a TOTP shared secret, comprising:
- Computing `KEK = SHA-256(totp_shared_secret || domain_separation_string)` where the domain separation string is a protocol-specific constant (e.g., `"pond-unlock-slot-totp-v1"`);
- Separately verifying a 6-digit TOTP code (RFC 6238, SHA-1 HMAC, 30-second period) against the same shared secret as an authentication gate;
- Using the derived KEK to wrap (encrypt) a master key via AES-256-GCM;
- Combining both operations during unlock: code verification confirms operator authorization, KEK derivation provides the cryptographic key material;

Wherein the 6-digit code and the shared secret serve distinct functions (authentication vs. key derivation); the KEK is deterministic and static (same shared secret always produces the same KEK); the code verification is a separate boolean operation that prevents unauthorized unlock even if an attacker knows the derivation method; and said method is distinct from MFKDF (Nair & Song, USENIX Security 2023) in that MFKDF derives keys from the ephemeral code value using polynomial secret sharing, while the described method derives keys from the static shared secret using standard SHA-256.

### Disclosure 3: Tiered Fallback for TOTP Secret Protection

A method for protecting a TOTP shared secret at rest using a tiered fallback chain, comprising:
- **Tier 1:** Attempting to seal the TOTP shared secret directly in a platform credential store (DPAPI on Windows, Keychain on macOS, Secret Service on Linux);
- **Tier 2:** If direct sealing fails, generating a random encryption key, sealing said encryption key in the platform credential store, and encrypting the TOTP shared secret with said encryption key using AES-256-GCM;
- **Tier 3:** Reading a legacy plaintext hex-encoded TOTP secret from the slot table JSON for backward compatibility, with a logged warning recommending migration;
- During unlock, attempting tiers in order (1, 2, 3) and using the first successful recovery;
- Automatically upgrading to the most secure available tier when a slot is re-created;

Wherein said tiered chain provides defense-in-depth (platform protection when available, encrypted fallback when not, plaintext only for legacy compatibility) and degrades gracefully across platform capabilities.

### Disclosure 4: Transparent Migration to Envelope Encryption

A method for transparently migrating a certificate authority private key from single-passphrase encryption to envelope encryption, comprising:
- Detecting a legacy key file (encrypted CA key present, slot table absent);
- Decrypting the CA key using the operator's passphrase (legacy direct-passphrase model);
- Generating a new random master key;
- Re-encrypting the CA key with the master key;
- Creating a slot table with a passphrase slot wrapping the master key (using the same passphrase);
- Writing the new encrypted key file and slot table to disk;

Wherein the operator's passphrase does not change, the migration is invisible to the operator (same passphrase produces the same result), and the migration enables subsequent addition of alternative unlock methods (TOTP, FIDO2, auto-unlock) without changing the CA key encryption.

### Disclosure 5: KDF Parameter Floor Enforcement

A method for tamper-resistant key derivation wherein:
- KDF parameters (Argon2id memory cost, time cost, parallelism) are stored alongside the encrypted key material in the slot table;
- During decryption, stored parameters are validated against minimum floors before use:
  - `m_cost >= 8192` KiB (8 MiB minimum)
  - `t_cost >= 1` (at least 1 iteration)
  - `p_cost >= 1` (at least 1 lane)
- Parameters below any floor trigger an immediate error, refusing to attempt decryption;
- Said floors are compile-time constants, not configurable at runtime, preventing an attacker who gains write access to the slot table from weakening the KDF by modifying stored parameters;

Wherein said method protects against a specific attack vector: an attacker with filesystem write access (but without the passphrase) replacing the slot table with a version encrypted under intentionally weak KDF parameters to enable brute-force recovery of the passphrase.

---

## Antagonist Review Log

### Round 1

**Antagonist:** I identify the following issues:

1. **Reproducibility gap -- TOTP slot KEK derivation specifics:** The disclosure says `SHA-256(shared_secret || info)`. But the order matters: is it `SHA-256(secret || info)` or `SHA-256(info || secret)`? The implementation shows `hasher.update(shared_secret); hasher.update(TOTP_SLOT_HKDF_INFO);` which is `secret-first`. This should be explicitly stated. Also, calling this "HKDF" in the constant name `TOTP_SLOT_HKDF_INFO` is misleading since it is not a full HKDF construction.

2. **Prior art weakness -- LUKS2 comparison:** The disclosure says LUKS2 has no TOTP slot type. However, `systemd-cryptenroll --fido2-device` with `--fido2-with-client-pin` provides a PIN-gated unlock that is functionally similar to TOTP-gated unlock (both require a short code). The disclosure should address this more precisely.

3. **Scope hole -- the passphrase slot cannot be removed.** What if an operator wants to use only TOTP unlock? The disclosure says the passphrase slot is always slot 0 and cannot be removed. This is a design limitation that should be acknowledged and justified.

4. **Missing edge case -- concurrent slot table writes.** If two processes try to add slots simultaneously, the slot table could be corrupted. The disclosure should address concurrency.

5. **Section 101 exposure -- is envelope encryption itself obvious?** LUKS2, BitLocker, and FileVault all use the same two-layer model (volume key wrapped by key protectors). The disclosure needs to more clearly identify what is novel about applying this pattern to PKI CA keys with the specific slot types described.

6. **Abstraction gap -- the `encrypt_bytes()` pipeline reuse.** The disclosure mentions the master key is hex-encoded and used as a "passphrase" in `encrypt_bytes()`. This means the master key goes through Argon2id unnecessarily. Is the Argon2id salt random each time? Does this mean the same master key produces different ciphertexts? This needs to be explicit.

**Author Response (Revisions Applied):**

1. **TOTP KEK derivation order -- REVISED:** Section 5.1 now explicitly states: "The input order is: shared_secret bytes first, then the domain separation string bytes. The SHA-256 hash is computed over the concatenation `shared_secret || TOTP_SLOT_HKDF_INFO`." Added a note that the constant name `TOTP_SLOT_HKDF_INFO` is a historical artifact -- the construction is not a full HKDF (RFC 5869) but rather a simpler SHA-256 domain-separated hash. This is functionally equivalent to HKDF-Expand with the shared secret as the PRK, which is acceptable when the input has full entropy (see RFC 5869 Section 3.3).

2. **LUKS2 FIDO2 comparison -- REVISED:** Added more precise comparison: "LUKS2's `systemd-cryptenroll --fido2-device` uses the FIDO2 hmac-secret extension (a CTAP2 extension that derives a secret from the credential and a salt). This is a fundamentally different mechanism from TOTP: the FIDO2 hmac-secret extension requires a hardware authenticator physically present at unlock time, while TOTP requires only a 6-digit code that can be read from a phone screen and typed. The operational difference is significant: TOTP works over SSH, over phone calls, and in headless environments where no USB port is available for a FIDO2 key. Additionally, `systemd-cryptenroll --fido2-with-client-pin` requires a PIN entered on the authenticator device, not a TOTP code from a separate authenticator app. These are distinct unlock experiences despite both involving short numeric codes."

3. **Passphrase slot requirement -- REVISED:** Added justification in Section 4: "The passphrase slot is mandatory and cannot be removed because it serves as the recovery method of last resort. If TOTP is the only unlock method and the operator loses their authenticator device, the CA key is permanently lost. If FIDO2 is the only method and the hardware key is destroyed, the CA key is permanently lost. The passphrase can be memorized, written on paper, or stored in a password manager -- it exists independently of any hardware device. This design mirrors LUKS2's behavior where at least one passphrase keyslot must remain. A future variant (see Variant B) could allow passphrase removal with an explicit 'I understand this is irreversible' confirmation."

4. **Concurrent writes -- REVISED:** Added to Section 9: "The slot table is a single JSON file. Concurrent writes are not atomically safe -- if two processes simultaneously modify the file, one write will be lost. In the Koi architecture, the `CertmeshCore` holds the slot table under an async `Mutex`, ensuring only one async task modifies it at a time within a single daemon process. Cross-process concurrent modification is not expected because only one daemon process manages the certmesh directory at a time. For additional safety, the `save()` method could use atomic file replacement (write to temp file, then rename), which is implemented for the key files but not currently for the slot table."

5. **Novelty framing -- REVISED:** The novelty is not envelope encryption itself (which is well-known), but the specific combination of: (a) applying it to a single PKI CA key file rather than a disk volume; (b) the TOTP slot type, which has no equivalent in any prior envelope encryption system; (c) the tiered TOTP secret protection; (d) cross-platform portability via JSON + platform credential store abstraction; (e) KDF parameter floor enforcement for anti-downgrade protection. The claims-style disclosures have been revised to emphasize these specific novel contributions rather than the envelope encryption architecture itself.

6. **Encrypt_bytes pipeline -- REVISED:** Added explicit detail to Section 1 (Layer 1) and Section 4: "Yes, the Argon2id salt is randomly generated on each call to `encrypt_bytes()`. This means the same master key, used twice, produces different ciphertexts (different salt -> different derived AES key -> different AES-GCM nonce -> different ciphertext). This is the expected behavior for probabilistic encryption and does not affect correctness. The hex-encoding step converts 32 raw bytes to a 64-character hex string, which Argon2id then processes as a 64-byte password. This is computationally wasteful (Argon2id is a memory-hard KDF designed for low-entropy passwords, not high-entropy keys) but correct and secure."

### Round 2

**Antagonist:** The revisions are thorough. Two remaining items:

1. **Missing edge case -- what happens if the platform credential store is wiped?** If the OS is reinstalled or the credential store is reset, Tier 1 TOTP secrets and auto-unlock keys are lost. Can the operator still unlock?

2. **Terminology -- "TOTP slot" is ambiguous.** In the context of LUKS, "slot" has a specific meaning (keyslot in the LUKS header). In the context of this disclosure, "slot" means an entry in the JSON slot table. The disclosure should explicitly state this disambiguation.

**Author Response (Revisions Applied):**

1. **Credential store wipe -- REVISED:** Added to Section 6: "If the platform credential store is wiped (OS reinstall, credential reset, user profile deletion), Tier 1 TOTP secrets and Tier 2 fallback keys are lost. The operator can still unlock using the passphrase slot (which is self-contained in the JSON and does not depend on the credential store). After unlocking with the passphrase, the operator can re-create the TOTP slot (which generates a new TOTP secret and re-seals it in the credential store) and re-enable auto-unlock. The passphrase slot's independence from the credential store is a key reason it is mandatory and cannot be removed."

2. **Terminology -- REVISED:** Added explicit disambiguation to Section 3: "In this disclosure, 'slot' refers to an entry in the JSON slot table (`unlock-slots.json`), not a LUKS keyslot (which is a binary structure in the LUKS2 header on a block device). While the concept is analogous (both represent independent unlock methods for the same underlying key), the implementation and storage format are entirely different. The term 'slot' is used throughout this disclosure to mean a JSON object within the `SlotTable.slots` array."

### Round 3

**Antagonist:** No further objections -- this disclosure is sufficient to block patent claims on the described invention. The heterogeneous slot architecture, TOTP-derived KEK construction, tiered secret storage, KDF parameter floor enforcement, and transparent migration are all described with sufficient detail for reproduction. The prior art comparisons are precise and the novel contributions are clearly identified.

---

*End of Defensive Patent Publication.*
