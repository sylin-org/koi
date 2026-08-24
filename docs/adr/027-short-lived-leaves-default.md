# ADR-027: Short-Lived Leaves as the Default Trust Posture

**Status:** Accepted (operator-ratified 2026-08-23) — **Implemented** (defaults 7/3/1 live in `CertPolicy::default` + `DEFAULT_LEAF_LIFETIME_DAYS` + `DEFAULT_CSR_VALIDITY_DAYS`, pinned by `default_policy_is_the_adr_027_short_lived_posture`; diagnosis semantics aligned — the in-renewal-window state is healthy steady-state, not degradation; physical certmesh-lifecycle green both Linux rotations at the new cadence, musl SHA-256 `0c7de764a824e4b025489f4868461a0e9ad06eeb6f3513e1e8fca25a6880fbc1`)
**Date:** 2026-08-23
**Builds on:** ADR-017 (CA-held `CertPolicy` 90/30/14, member-pull rotate-key renewal, grace state machine, trust-bundle policy distribution)
**Relates to:** ADR-015 (enrollment constraints), ADR-024 (honest limits — revocation), ADR-026 (principal identity), V1-03 lab evidence (unexpired revoked leaf accepted by generic TLS verifiers)
**Constrained by:** STACK-0001 (policy is data; no format or crypto changes)

---

## Context

Revocation in certmesh is **roster-level**: revoking a member stops Koi-mediated renewal and
enrollment and is enforced at Koi's own boundaries (trust-bundle check), but an already-issued
leaf remains acceptable to *generic* TLS verifiers until it expires. With today's default
90-day leaves, that worst case is a three-month exposure window recorded honestly in V1-03 lab
evidence and in ADR-024's "when *not* to use" list.

The enterprise answer — CRL/OCSP/AIA distribution infrastructure — is exactly the gravity well
ADR-024 rejects. But PKI has a second lever that fits a zero-infrastructure LAN substrate:
**shorten the leaf lifetime so expiry itself becomes the revocation backstop.** Public ACME
ecosystems converged on ~90-day leaves for agility; private meshes with automated renewal
routinely run days, not months.

The counterweight has always been availability: short leaves punish CA downtime. That
counterweight no longer holds here — ADR-017's member-pull renewal plus the mDNS failover
system make "some CA is reachable within hours" a solved property of this substrate rather
than an operational hope.

---

## Decision

### 1. New defaults for newly created meshes

```
CertPolicy defaults: 7 / 3 / 1        (was 90 / 30 / 14)
leaf_lifetime_days = 7
renew_threshold_days = 3
grace_days = 1
```

Rationale per knob:

- **7-day leaves:** worst-case generic-verifier exposure to a compromised or revoked leaf
  drops from ≤90 days to ≤8 days including grace. Weekly rotation also means weekly key
  rotation (ADR-017 P3 rotates keys on renewal) — a hardening side effect stated openly.
- **3-day renew threshold:** the hourly renewal sweep (`RENEWAL_CHECK_INTERVAL_SECS = 3600`)
  yields ≥72 renewal opportunities before expiry; transient daemon restarts and even a full
  primary→standby promotion consume a trivial fraction of the window.
- **1-day grace:** one day past `not_after` for pull-renewal recovery, then `expired` → fresh
  invite required. Fail-closed by design; the safe direction.

### 2. This is a default change, not a format change

`CertPolicy` remains CA-held data stored in `RosterMetadata` at `certmesh create`, distributed
in the signed trust bundle so members drive their loops on the CA's schedule. Existing meshes
keep their stored 90/30/14 policy indefinitely — no forced migration, no on-disk format
change, no wire change. The ceremony asks no new questions; the policy flags remain advanced/
custom knobs, now documented with a tradeoff table:

| Posture | Lifetime / threshold / grace | Revocation latency | Availability tolerance |
|---|---|---|---|
| **Default (new meshes)** | 7 / 3 / 1 | ≤8 days worst case | Hours-to-days of total CA outage |
| Long-haul (opt-in) | 90 / 30 / 14 | ≤104 days worst case | Weeks of total CA outage |

Long-haul remains the right answer for air-gapped or extremely low-touch nodes; the docs say
so explicitly rather than treating it as legacy.

### 3. Coherence claim (the design bet, stated)

Short-lived leaves make the mesh's **high-availability mechanism and its revocation story the
same mechanism set**: mDNS-detected failover protects issuance continuity, expiry bounds
revocation latency, and neither requires distribution infrastructure. A mesh that wants
90-day comfort is consciously buying back revocation latency with the same knob.

### 4. Documentation honesty sync (required at implementation)

- Overview "when *not* to use": revocation bullet changes from "until it expires (90 days)" to
  "until it expires (≤ leaf lifetime + grace; 8 days at the default posture)".
- Security model + certmesh capability card: policy table gains both postures.
- The V1-03 evidence wording ("no CRL/OCSP distribution") stays — it remains true; only the
  blast-radius number changes.

### 5. Explicit failure mode

A member partitioned from every CA beyond threshold + grace expires → RED diagnosis → re-enroll
via fresh invite. This is the existing grace state machine operating as designed; it is named
here so nobody mistakes it for a defect when the soak first trips it.

---

## Consequences

- **Non-goals:** no OCSP/CRL/AIA; no auto-migration of existing CAs' stored policy; no change
  to the CA certificate's own lifetime (anchor longevity is orthogonal).
- **Interplay with ADR-026:** principals get ClientAuth-only leaves on the same schedule, so a
  revoked principal's residual generic-TLS validity is bounded identically.
- **Load shape:** renewal traffic becomes steady background churn (~one renewal per member per
  week) instead of bursty monthly spikes; immaterial at LAN scale, noted for completeness.

## Validation plan

- Unit tests pin the new defaults end-to-end (ceremony → RosterMetadata → trust bundle
  projection) and prove an existing mesh's stored policy survives upgrade untouched.
- Deterministic-time tests (below hardware tier, per lab rules) cover the 7/3/1 boundaries:
  renew-in-window success, grace-entry, grace-expiry → invite-required.
- Physical lanes are mechanically unaffected (policy is data) but the `certmesh-lifecycle`
  and soak profiles re-run against a 7/3/1 mesh so renewal cadence is exercised at the new
  tempo; any timing assumption baked into harness sleeps gets corrected there, not papered over.
