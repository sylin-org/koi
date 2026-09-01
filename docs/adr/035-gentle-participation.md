# ADR-035: Gentle Participation — Coexistence and Authorized Latitude

**Status:** Accepted (operator-ratified 2026-08-28, after the extended-full-profile shakedown)
**Date:** 2026-08-28
**Builds on:** ADR-030 (mDNS coexistence), ADR-032 (Windows parity / extended full profile), ADR-026-era trust machinery
**Constrained by:** catalog mutation grants; workstation safety rules; exact-restoration doctrine

**Amended 2026-09-01:** ADR-040 makes IPC an independent trusted local-control plane;
it no longer skips with mDNS. ADR-041 replaces W6's one-time free-port/listener assumption
with cooperative UDP+TCP acquisition and visible desired-state retry. The observations
below remain historical evidence, not the current dependency model.

---

## Context

The first end-to-end execution of the extended full profile (25 cases, back-to-back,
unattended) turned red seven times at seven different points. Not one failure was a
product defect: every lane that reached its assertions passed them. The failures were
all the same class of thing — koi, or the lab, assuming away the OS's version of
reality, and the new orchestration layer (25 cases in sequence) meeting a mesh whose
state had drifted since the lanes were authored:

- Debian 13's systemd-resolved binds UDP 5353/5355; the mDNS capability skipped per
  ADR-030; the IPC adapter (which bridges the mDNS core, W2) skipped with it; the
  story lane asserted the resulting koi.sock as a hard precondition.
- The standing root daemons installed by `koi install` watch the same Docker socket
  as the lab's run daemons; both derived the same labeled services and raced for the
  same derived proxy port ("address in use" on brook:16544).
- schannel verified the koi proxy only after the machine trust store had visibly
  settled (SEC_E_INTERNAL_ERROR on the first handshake after a root import).
- test01 suspended mid-profile; a workstation LAN blip reddened an otherwise green
  run through its cleanup.
- Silent bare-`test` guards turned several of these into diagnosis vacuums.

The pattern behind all of it is one architectural fact, now stated as policy.

## Decision

Koi is a **guest on the machines it serves and a participant on the networks it joins.
It detects, yields, declares, and changes only what it is authorized to change —
exactly.** Five disciplines follow, each already encoded in the product or lab:

### 1. Detect, don't assume

Every OS surface koi touches is probed at runtime, never assumed from documentation,
version, or last week. Under ADR-038, each mDNS adapter owns its live evidence and
the supervisor routes only declared, non-overlapping capabilities; native Koi remains
the lowest-priority complete provider. W6 picks a genuinely free port before serving
DNS. Measured OS facts
(schan­nel quirks, ICS on 53, WSAEACCES coexistence semantics) live in the lessons
ledger as data, not folklore.

### 2. Yield, but declare

When a surface is held or unavailable, koi yields the capability and *declares the
yield as data*: the capability ladder (`/v1/status`) carries every rung — including
capabilities that are not mounted — with a skip reason and the dependency that caused
the skip. Silent degradation is the anti-pattern: a log line is not a declaration.
**Implemented this session:** assembly notes (`CapabilityNote`) recorded by
`build_cores`/serve and merged into the ladder; the `ipc` rung joined as the eighth
rung. ADR-040 subsequently removed its mDNS dependency and gives it its own live state.

### 3. Change only what is granted — and exactly

System-touching operations require explicit latitude (catalog mutation grants +
operator elevation/flag), perform the minimum change, record what they did, and
restore exactly. The trust-store grant request/approval/landing (2026-08-27) is the
process working as designed.

### 4. Verify settlement, never intent

OS interfaces report *initiation*, not *completion*. certutil returns before lsass
sees a root; systemctl returns before a unit is active; kill returns before a port is
released. Koi awaits observable settlement before making claims — in the product, a
trust-settlement probe; in the lab, the settle-wait primitives (bounded, loud on
timeout).

### 5. When participants meet, negotiate or scope — never race

This includes koi meeting koi. **Implemented this session:** Docker-watch scoping —
a daemon derives only containers whose `koi.scope` label matches its own scope
(`KOI_SCOPE`); the base-scope daemon derives unlabeled containers only. Two koi
daemons can share one Docker socket and never derive the same container, and never
race for derived surfaces. The lab's reconnect containers carry `koi.scope`; the lab's
run daemons carry the matching scope. ADR-038 is the mDNS-specific expression of the
same principle.

## Consequences

- Functionality is conditional on environment, and that conditionality is *honest*:
  capability state is queryable truth (`/v1/status`), and degradation is declared,
  never silent. Documentation says what koi becomes on a given machine, given what is
  already there.
- Quietly re-enabling a competing surface to make a test or demo pass violates this
  ADR. Environment changes that free contested surfaces (e.g. disabling
  systemd-resolved's mDNS on dedicated lab boxes — done 2026-08-28, both boxes, DNS
  verified working) are legitimate one-time lab configuration and must be recorded.
- Lanes assert *capability state* (via `/v1/status`) rather than file/socket presence.
  A topology change is a pass in a different designed state, not a red.
- The profile's recovery baseline is a snapshot of a mutable world: anything mutating
  the world outside the profile's transactions (a runner restoring services in its
  `finally`) makes recovery refuse by design. Isolation belongs inside the lane
  transactions (reconnect/story stop-restore themselves), which is where it now lives.
- Remaining phases (post-1.0 unless findings force earlier): standing-daemon
  arbitration/delegation as the general answer to shared surfaces; port allocation
  policy beyond the catalog's fixed ranges; environment prerequisites surfaced
  through preflight as first-class blockers.

## Non-goals

Fighting the OS for a surface (no squatter rescues — WSAEACCES is a fact, RL pile);
competing with the system resolver; background services that reconfigure the host
beyond granted latitude; silent capability degradation.
