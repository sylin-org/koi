# ADR-003: Envelope Encryption for CA Private Keys

**Status:** Accepted  
**Date:** 2025-06-01

## Context

Certmesh manages a private CA whose key must be protected at rest. A single-passphrase approach forces operators to choose between security (manual unlock on every restart) and convenience (storing the passphrase in plaintext). Different environments have different unlock capabilities: server rooms may have no interactive user but can store a local file; developer workstations may have YubiKeys; team environments may use shared TOTP secrets. Supporting multiple unlock methods for the same CA key without re-encrypting the key for each method is the core design challenge.

## Decision

CA private keys use envelope encryption inspired by LUKS. A random 256-bit master key encrypts the CA private key via AES-256-GCM. Each unlock slot independently wraps that master key using its own key derivation. Any single slot can unlock the CA.

Slot types:

- **Passphrase** - Argon2id key derivation → KEK → AES-256-GCM wrap of master key
- **AutoUnlock** - master key stored in a separate local file (for unattended boot on single-user profiles)
- **TOTP** - HKDF from shared secret → KEK → AES-256-GCM wrap
- **FIDO2** - assertion-gated KEK → AES-256-GCM wrap

Files: `ca-key.enc` (master-key-encrypted CA key), `unlock-slots.json` (slot table with per-slot wrapped master key), `ca-cert.pem` (public).

Legacy single-passphrase keys are auto-migrated on first load via `migrate_to_envelope()`.

## Consequences

- Operators can add or remove unlock methods without touching the CA key itself - only the slot table changes.
- AutoUnlock enables unattended service restart for single-user/homelab profiles without weakening multi-user deployments.
- The master key is the single point of compromise - if extracted from memory, all slots are bypassed. Acceptable for a LAN-local CA where the threat model is "protect at rest, not against root-level runtime compromise."
- Adding a new unlock method requires implementing `wrap`/`unwrap` for the new slot type and adding a ceremony step. No changes to the CA key or existing slots.
