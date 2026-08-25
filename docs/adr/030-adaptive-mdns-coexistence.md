# ADR-030: Adaptive mDNS — Coexist or Skip, Never Fail

**Status:** Accepted (operator-approved 2026-08-24)
**Date:** 2026-08-24
**Builds on:** ADR-016 §2 (capability ladder), ADR-020 (truthful status), the mDNS boundary rules (.agentic/rules)
**Amends:** implicit mDNS startup behavior (fail → degraded with an error-level log)

---

## Context

Real homelab machines routinely run another mDNS stack: desktop distros ship avahi,
systemd-resolved can hold 5353. test-01 (CachyOS workstation) arrived exactly so.

Koi's mDNS daemon binds UDP 5353 through mdns-sd, which requests reuse semantics.
Two consequences:

1. On a machine where another stack already holds 5353 **exclusively**, `ServiceDaemon::new()`
   fails and the daemon degrades to `mdns: None` — already correct.
2. On a machine where the other stack bound **with reuse**, Koi's bind *succeeds too*.
   Two responders then share one socket: duplicate answers, flappy caches, confused
   peers. This is worse than failure and it is silent.

The product decision: **mDNS capability adapts to the host. If a stack is present,
Koi skips; if not, Koi launches.** Either way every other capability works and
status tells the truth.

## Decision

### 1. Exclusive-bind probe before startup

Before constructing `MdnsCore`, the compose layer attempts an **exclusive** UDP bind
of `0.0.0.0:5353` (no `SO_REUSEADDR`/`SO_REUSEPORT`):

- Bind succeeds → port was free (or only reusers hold it); drop the probe socket and
  start the mDNS daemon normally.
- `EADDRInUse` → another responder is active; **skip** Koi's mDNS for this boot.

The probe-to-bind window has a documented race (a foreign stack could grab the port
in between); closing it would mean owning mdns-sd's socket setup, which is out of
scope. The race fails safe: worst case is today's behavior, never a crash.

**Measured limitation (CI kernel, Ubuntu 24):** a `SO_REUSEADDR` holder does **not**
reliably make a no-reuse probe fail — modern kernels permitted the mixed bind. The
probe therefore *guards against exclusive holders* but cannot portably detect
reuse-holders by bind semantics. Final coexistence behavior on reuse-sharing hosts
(the avahi case) is decided empirically: physical validation runs Koi alongside a
live foreign responder and records whether shared-socket operation is healthy; if it
is not, the skip trigger moves to foreign-responder detection (e.g. D-Bus/service
probe) in a follow-up change to this ADR.

**Measured on Windows (2026-08-24, workstation, physical):** shared-socket
operation is healthy **only when Koi runs elevated** (SCM service, SYSTEM): full
reception, instant — one query burst surfaced 20 service types / 14 devices.
The same binary as an **unelevated user process** receives sparsely (minute-scale
gaps with no inbound multicast despite a program-scoped inbound allow rule) —
announcements may land but resolution queries go unanswered. Verdict: on Windows,
discovery-grade mDNS requires the service path; the unelevated shape degrades to
partial reception and must say so (W5 tracks surfacing this). The foreign-responder
skip trigger remains deferred: skipping would disable discovery entirely, which is
worse than partial reception — the honest fix is mode-aware expectations, not
silence.

### 2. Skipping is coexistence, not error

The skip logs at **info** with reason `port 5353 in use by another mDNS stack` —
distinct from `--no-mdns` ("disabled") and from genuine init failures (still error).
Status and the capability ladder report whatever actually came up, per ADR-020
truthfulness; no synthetic "degraded" rung is invented.

### 3. Derived capabilities follow honestly

With mDNS skipped, everything that derives from it simply does not appear:
orchestrator→mDNS registration, mDNS→DNS alias bridge records, dashboard discovery
views. DNS static entries, health, proxy, certmesh, webhooks, MCP are unaffected.
No lane may claim mDNS-derived evidence on a host where it was skipped.

### 4. Embedded keeps its contract

`fail_fast` consumers (koi-embedded library mode) still receive the error instead of
a silent skip — embedding hosts decide their own coexistence policy.

## Consequences

- Homelab reality (avahi everywhere) becomes a supported first-class shape: Koi on a
  desktop contributes identity/DNS/health/webhooks/MCP without fighting avahi.
- Honest limits: on a skipped host, Koi cannot *discover* via multicast either —
  users pair it with Koi DNS entries or direct addresses. Documented, not hidden.
- Testbed rule "if there's mDNS already, we skip; if not, we launch" is now enforced
  by the product itself, and preflight surfaces which case applies.

## Validation

- Unit: exclusive-probe returns free/taken correctly (ephemeral-port tests; a held
  probe socket must flip the verdict).
- Physical (test-01, avahi active): daemon boots healthy, log shows the coexistence
  skip at info, `/v1/status` reports no active browse, all non-mDNS lanes function.
- Physical (brook, free 5353): unchanged full-mDNS behavior (existing lanes cover).
