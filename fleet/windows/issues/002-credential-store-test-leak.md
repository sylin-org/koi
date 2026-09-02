# Issue 002 — koi-crypto slot tests leak platform credentials until the Windows store quota is exhausted

**Opened:** 2026-09-02 (PH-001 dispatch 2, Windows gate)
**Status:** open — residue cleaned on this machine; test hygiene fix belongs to the shared crate

## Observed

The full workspace suite began failing deterministically in `koi-crypto::unlock_slots`
(five tests, e.g. `totp_slot_round_trip`) with
`seal failed for 'koi-certmesh-totp-fallback-key-…': Platform secure storage failure:
Windows error code 8` (`ERROR_NOT_ENOUGH_MEMORY` from `CredWriteW`). The user's
credential store held **671 entries, 576 of them `koi-certmesh-*`** leaked across
repeated suite runs — the per-user store quota was exhausted, so every new seal
failed. The same suite was green earlier the same day; nothing but repeated test
runs touched the store. Deleting the leaked labels restored 89/89 immediately.

## Why it leaks

The slot-table tests seal credentials with per-slot hashed labels
(`koi-certmesh-unlock-totp-<hash>`, `koi-certmesh-totp-fallback-key-<hash>`) into
the real platform store, and `keyring` has **no enumeration API**, so any path that
skips `delete_key_material` (assert failures, panics between seal and delete, or a
label family with no cleanup at all) strands entries that product code can never
find again. `KOI_NO_CREDENTIAL_STORE=1` exists for tests that want to skip the
store, but the slot tests deliberately exercise the real one.

## Candidate fixes (shared crate)

1. A test fixture that derives labels from a per-run prefix and sweeps that prefix
   before/after (still needs enumeration → a platform helper, e.g. `cmdkey` /
   `security find-generic-password` wrappers behind `#[cfg(test)]`).
2. Make the leaked-label families deterministic per test-binary PID so reruns
   overwrite instead of accumulate, and delete by exact label in a `Drop` guard.
3. Document and enforce a store budget in `is_available()` probing.

## Remediation performed (stone-leaded-sparkle)

Deleted exactly the 576 `LegacyGeneric:target=koi-certmesh-*` entries (the git
push credential and all foreign entries untouched); suite green after cleanup.
