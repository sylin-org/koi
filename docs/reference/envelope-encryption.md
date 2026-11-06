# CA key storage and unlock slots

Certmesh encrypts the CA private key with a random 256-bit master key using AES-256-GCM. Unlock slots independently wrap or locate that master key. This protects stored CA material according to the selected unlock method; it does not protect an already-unlocked authority from a hostile operator process.

## Stored artifacts

The CA directory contains `ca-key.enc`, public `ca-cert.pem` and `unlock-slots.json`. Identity changes are coordinated through Certmesh's journaled repository; do not manually replace a subset of these files during recovery.

| Slot | Mechanism | Boundary |
| --- | --- | --- |
| Passphrase | Argon2id-derived key wraps the master key with AES-256-GCM | Passphrase is required to unwrap |
| AutoUnlock | Marker for a separately managed local master-key file | Unattended startup depends on host/file security |
| Totp | HKDF of the TOTP secret wraps the master key | Secret protected by platform credential storage or machine-derived fallback |

New TOTP slots do not write the legacy plaintext `shared_secret_hex` field. Supported reading of that legacy field is a compatibility behavior, not a recommended storage format. FIDO2 is not an implemented unlock method.

## Version and cleanup semantics

The slot table carries an explicit version and an ordered list of typed slots. Its optional `pending_totp_credentials` stores exact credential ownership that still needs cleanup after an interrupted change; it is not an enumeration of the platform credential store.

Version 2 derives a stable credential label from each TOTP slot's random wrapped ciphertext, keeping isolated data roots from overwriting one another's secret. Add/replacement/removal/destruction retain durable ownership until idempotent cleanup succeeds. Version 1 remains readable with its legacy labels and transitions when the TOTP slot is replaced. A load reconciles interrupted slot transactions before returning usable state.

A preceding single-passphrase key can migrate through `migrate_to_envelope()`: decrypt with the passphrase, generate a master key, re-encrypt the CA material and persist a passphrase slot. A migration requires access to the actual old key; it is not a reason to reset unknown or corrupt state.

## Operations and policy

The source exposes passphrase unwrap, auto-unlock toggles, transactional TOTP-slot addition/removal and available-method inspection. Operators normally use the guided Certmesh commands instead of editing these structures. Backup/restore and machine-binding policy are covered by [recovery](../guides/certmesh-ha-recovery.md).

CA and member certificates use ECDSA P-256. New meshes default to a 7-day leaf, renewal at 3 days remaining and a 1-day post-expiry renewal grace. Existing meshes retain their stored policy. Koi's renewal protocol can provide its defined grace behavior; ordinary TLS verification still evaluates the actual certificate validity period. A host identity does not automatically authorize arbitrary service SANs.

Implementation: [unlock_slots.rs](../../crates/koi-crypto/src/unlock_slots.rs), [keys.rs](../../crates/koi-crypto/src/keys.rs), [CA operations](../../crates/koi-certmesh/src/ca.rs), [transaction repository](../../crates/koi-certmesh/src/repository.rs).
