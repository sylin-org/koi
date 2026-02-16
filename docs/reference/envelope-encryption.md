# Envelope Encryption

CA private keys use envelope encryption, inspired by LUKS. A random 256-bit master key encrypts the CA private key via AES-256-GCM. Each unlock slot independently wraps that master key. Any single slot can unlock the CA.

---

## File layout

```
{ca_dir}/
├── ca-key.enc          # Master-key-encrypted CA private key
├── ca-cert.pem         # CA certificate (public)
└── unlock-slots.json   # Slot table with per-slot wrapped master key
```

---

## Slot types

| Slot type | Key derivation | Use case |
|---|---|---|
| `Passphrase` | Argon2id → KEK → AES-256-GCM wrap | Primary unlock (always present) |
| `AutoUnlock` | Master key in separate local file (marker slot) | Unattended boot for single-user profiles |
| `Totp` | HKDF(shared_secret) → KEK → AES-256-GCM wrap | TOTP-based unlock (6-digit code) |
| `Fido2` | Assertion-gated KEK → AES-256-GCM wrap | Hardware security key unlock |

---

## Slot table schema

```json
{
  "version": 1,
  "slots": [
    {
      "type": "passphrase",
      "wrapped_master_key": {
        "ciphertext": "base64...",
        "nonce": "base64...",
        "salt": "base64..."
      }
    },
    { "type": "auto_unlock" },
    {
      "type": "totp",
      "shared_secret_hex": "...",
      "wrapped_master_key": {
        "ciphertext": "base64...",
        "nonce": "base64..."
      }
    }
  ]
}
```

---

## Operations

| Operation | Description |
|---|---|
| `new_with_passphrase(master_key, passphrase)` | Bootstrap with slot 0 |
| `unwrap_with_passphrase(passphrase)` | Derive KEK, unwrap master key |
| `add_auto_unlock()` / `remove_auto_unlock()` | Toggle unattended boot |
| `add_totp_slot(master_key, secret)` | Add TOTP unlock slot |
| `unwrap_with_totp(code)` | Unlock via TOTP code |
| `add_fido2_slot(...)` | Add FIDO2 unlock slot |
| `unwrap_with_fido2(credential_id)` | Unlock via hardware key |
| `available_methods()` | List active slot types |

---

## Migration

Legacy single-passphrase keys (pre-envelope) are auto-migrated on first load via `migrate_to_envelope()`. The function decrypts with the old method, generates a fresh master key, re-encrypts under the master key, and creates a slot table with a passphrase slot.

---

## Certificate details

| Property | Value |
|---|---|
| Algorithm | Ed25519 (CA), ECDSA P-256 (member certs) |
| CA validity | 10 years |
| Member validity | 90 days (auto-renewed) |
| SANs | Hostname, hostname.{zone}, custom entries |

Implementation lives in `koi-crypto/src/keys.rs` (key generation), `koi-crypto/src/unlock_slots.rs` (slot management), and `koi-certmesh/src/ca.rs` (CA operations).
