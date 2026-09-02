# Issue 002 — TOTP slot ownership and tests leak platform credentials until the store quota is exhausted

**Opened:** 2026-09-02 (PH-001 dispatch 2, Windows gate)
**Status:** open — residue cleaned on this machine; product and test lifecycle fix belongs to the shared crate

## Observed

The full workspace suite began failing deterministically in `koi-crypto::unlock_slots`
(five tests, e.g. `totp_slot_round_trip`) with
`seal failed for 'koi-certmesh-totp-fallback-key-…': Platform secure storage failure:
Windows error code 8` (`ERROR_NOT_ENOUGH_MEMORY` from `CredWriteW`). The user's
credential store held **671 entries, 576 of them `koi-certmesh-*`** leaked across
repeated suite runs — the per-user store quota was exhausted, so every new seal
failed. The same suite was green earlier the same day; nothing but repeated test
runs touched the store. Deleting the leaked labels restored 89/89 immediately.

## Ownership gap

The slot-table tests seal credentials with per-slot hashed labels
(`koi-certmesh-unlock-totp-<hash>`, `koi-certmesh-totp-fallback-key-<hash>`) into
the real platform store. The tests never delete them, so normal successful runs leak;
assert failures and panics merely make that worse. `KOI_NO_CREDENTIAL_STORE=1` exists
for tests that deliberately do not exercise the store, but these tests need the real
adapter and therefore need scoped ownership rather than a global skip.

This is also a product lifecycle defect. `SlotTable::add_totp_slot` removes an existing
TOTP slot from the aggregate before creating its replacement but never deletes the old
slot's derived credential labels. Certmesh destroy deletes the legacy CA label and then
removes the slot table without first retiring the TOTP labels it identifies. A failure
after sealing new material but before durably saving its slot can orphan the new label as
well. Platform enumeration is unavailable and should not be required: the aggregate
already has enough information to derive every label it owns before discarding the slot.

## Required resolution (shared crate)

1. Make credential ownership explicit in the TOTP slot lifecycle. Replacement, removal,
   failed persistence, and certmesh destroy retire the exact old/new labels in a safe
   transaction order without deleting foreign credentials or losing the still-active
   slot's material.
2. Give real-store tests a scoped guard that records the exact labels they create and
   deletes them on ordinary return and unwinding. Do not depend on global enumeration,
   per-machine cleanup scripts, or a process ID that merely limits accumulation.
3. Add deterministic failure-path tests around seal, slot-table persistence, replacement,
   and destroy. Then run repeated real-store suites plus every currently exposed physical
   slot lifecycle on Windows and attest the credential count returns to its captured
   baseline. Do not invent an endpoint solely for this gate.

## Remediation performed (stone-leaded-sparkle)

Deleted exactly the 576 `LegacyGeneric:target=koi-certmesh-*` entries (the git
push credential and all foreign entries untouched); suite green after cleanup.
