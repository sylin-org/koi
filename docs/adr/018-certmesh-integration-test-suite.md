# ADR-018: Certmesh Cross-Participant Integration Test Suite

**Status:** Proposed
**Date:** 2026-06-19
**Builds on:** ADR-015 (Certmesh Enrollment Hardening — F1 CSR custody, F2 invites) and ADR-017 (Certmesh Trust Lifecycle — all four phases **Implemented**). Their *logic* is densely unit- and in-process-tested, but the cross-participant *exchange* those features exist for is verified only by hand. This ADR closes that verification gap.
**Constrained by:** STACK-0001 (the certmesh contract surface — mdns/dns/certmesh/udp/truststore — is the thing under test; the harness must not introduce consumer-name leakage and must keep the SURFACES ledger honest). Pre-1.0: on-disk and wire formats may still change, so tests assert behavior, not byte layouts.
**Relates to:** ADR-011 (dual-port **5641** HTTP+DAT / **5642** mTLS — the two surfaces the harness drives), ADR-008 (embedded facade — the in-process multi-instance vehicle for Tier 1), the SURFACES ledger (the new harness becomes the certmesh row's guard).

---

## Context

A June-2026 audit (8 agents, every test surface, cross-checked against the source) answered one question — *"do we have comprehensive, QA-grade integration tests for cross-platform (Windows↔Linux) certmesh participant exchanges?"* — with a clear **no**, while confirming the per-feature logic is well covered.

**What exists (strong, automated, per-PR):**

- ~258 certmesh tests on every PR across a **3-OS matrix** (`ci.yml` runs `cargo test --locked` on ubuntu **and** windows **and** macos). This proves the code compiles and its in-process tests pass on each OS **in isolation** — never that two OSes exchange certs.
- Real-socket, real-mTLS / real-ES256 integration tests, but **client and server in the same test process** on `127.0.0.1`: `member_pull_renewal_round_trip` and `trust_bundle_pull_round_trip` (lib.rs), the three mTLS handshake tests (mtls.rs), the ACME `instant-acme`-over-real-TLS conformance test (tests/acme.rs).
- The happy-path join (`mint_invite → CSR → enroll → install → mTLS renew`) **is** automated, but **in-process via two `CertmeshCore` instances**, not across processes/hosts/OSes.
- A real-daemon PowerShell harness (`tests/integration.ps1`, ~3500 lines) that spins an actual daemon over real HTTP — but it runs **weekly-cron only (not a merge gate)**, is **single-host**, and its only `/v1/certmesh/join` call is a **negative** invalid-TOTP rejection.

**The gaps (why the answer is "no"):**

1. **No two-process join.** Nothing launches a CA daemon + a separate member process and drives `POST /v1/certmesh/join` to a *successful* enrollment over HTTP.
2. **No cross-host / Windows↔Linux exchange.** 0% automated. The two-host story is manual `plink`/`pscp` against the reserved test box.
3. **Boundary revocation over live mTLS is untested end-to-end.** `renew_handler` returns 403 for a revoked / CN-mismatch member, but no test drives it live; revocation is asserted only at roster/bundle level.
4. **certmesh HTTP success paths** (join/health/promote/revoke) are never exercised through the real axum router with an unlocked CA — only via the in-process facade.
5. **DAT/`x-koi-token` middleware + the `/join` token exemption** (security-sensitive, in the binary crate) and the **pipe/CLI adapters** have zero tests.
6. The designed harnesses (`crates/koi-embedded/tests/whole_story.rs`, the ADR-015 enrollment e2e) are **"Proposed" and absent**.
7. The real-daemon harnesses block nothing (cron-only), so a real-daemon regression can sit on `main` for up to a week.

This is the single biggest test-quality gap before 1.0: the certmesh trust plane's *raison d'être* — participants exchanging certificates — is guarded by hand, not by an automated suite.

---

## Decision

Build a **tiered cross-participant integration test suite** around one canonical scenario (the "whole story"), gated into CI bottom-up so the highest-value coverage lands first and cheapest.

### The canonical "whole story" scenario (every tier drives this)

Two participants, **A** = CA, **B** = member, exchanging over the *real* HTTP (5641) + mTLS (5642) surfaces:

1. **A: create** — `certmesh create` (auto-unlock). Assert CA initialized, `machine.bind` written, audit `ca_initialized`.
2. **A: open enrollment + mint invite** for B's hostname → an `<secret>.<ca_fingerprint>` code.
3. **B: join** with the invite code — B preflights (`GET /status`) and **pins A's fingerprint**, generates its own keypair+CSR locally, `POST /v1/certmesh/join` over real HTTP. Assert: response carries **no** `service_key`, B's `key.pem` is `0600` and local, the installed leaf chains to A's CA, and the pin matches.
4. **B: member-pull renewal** over real **mTLS** (5642). Assert the member key **rotates**, a fresh leaf installs, and A's roster records the new fingerprint.
5. **B: trust-bundle pull** — verify the ES256 bundle against the pinned fingerprint; anti-rollback holds.
6. **A: revoke B** — bundle `seq` bumps; B appears in `revoked[]`.
7. **Boundary revocation:** B's next `/renew` over mTLS → **403**; B's next trust-bundle pull → `self_revoked = true`. *(This is gap #3 — currently 100% untested end-to-end.)*
8. **F3 negative:** a join attempt whose invite carries a *wrong* fingerprint **aborts at preflight, before any CSR is sent**.
9. **F11:** tamper B's `machine.bind` and restart B → B boots **LOCKED** + audits `auto_unlock_refused_machine_changed`.
10. **F7:** three bad-TOTP joins against A → lockout; restart A → **still locked** (persisted).

### Tier 1 — two-process, single-host, **CI PR gate** (primary deliverable)

`crates/koi-embedded/tests/whole_story.rs`: in one `cargo test`, start **A and B as two separate embedded daemons** (distinct loopback ports + data dirs via the koi-embedded builder), and drive the whole story over real HTTP + mTLS. Pure Rust, no shell, no child-process orchestration → **cross-platform by construction**, runnable on the existing 3-OS matrix.

- **Prerequisite check:** the embedded builder must allow distinct **mTLS ports** (two daemons can't share 5642) and a custom data dir + HTTP port. If `mtls_port` isn't yet a builder knob, add it (small, isolated) as the first step.
- Wired into `ci.yml` as a **per-PR gate on all three OSes**. This alone closes gaps #1, #3, #4 and makes the join/renew/revoke logic a real automated gate per-OS.

### Tier 2 — real-daemon HTTP harness, promoted to a gate

Extend the real-daemon path (`tests/integration.ps1` or a new cross-platform driver) to spin a **second daemon (member)** and drive a *successful* create→invite→join→mTLS-renew→revoke over real HTTP against the first — replacing today's negative-only `/join`. Promote the real-daemon harness from weekly-cron to a **PR/merge gate** (or a fast subset). This covers the actual **binary**, the **DAT middleware + `/join` exemption**, and the **pipe/CLI adapters** that the embedded Tier 1 bypasses (gaps #5, #7).

### Tier 3 — docker-compose two-node, cross-**host**

Two containers on a user-defined bridge network (distinct hostnames/IPs), node-a=CA, node-b=member, driving the whole story over the **real container network**. A CI job on the Linux runner. The cheapest path to a true cross-host (distinct-IP) exchange without physical machines.

### Tier 4 — Windows↔Linux, cross-**platform** (the literal answer)

A CI job pairing a **windows runner and a linux runner** over the network — self-hosted runner pair, a reusable workflow with a service container, or an SSH/remote-driven step from one runner to the other — running the whole story between a Windows participant and a Linux participant. Highest effort, lowest *marginal* coverage once Tiers 1–3 guard the logic per-OS, so it is sequenced **last**. (The reserved `stone-granite-spring` box remains the manual smoke target until this lands.)

### Cross-cutting determinism fixes (prerequisite for "QA-grade")

- Enforce the isolation the suite already asks for (`tests/acme.rs` wants `--test-threads=1`; CI ignores it).
- De-flake environment-dependent tests (machine-binding skip when no machine-id; mDNS self-resolve degrade-to-skip) so the suite is deterministic across hosts.

---

## Phased plan

Each tier is independently shippable; the gate `cargo fmt --check && cargo clippy -- -D warnings && cargo test` stays green; each tier is reviewed and (where it touches CI) verified to actually run before the next.

| Tier | Deliverable | Gate | Closes |
|---|---|---|---|
| **1** | `koi-embedded/tests/whole_story.rs` two-process whole-story (real HTTP+mTLS) + builder `mtls_port` knob if missing | `ci.yml` per-PR, 3-OS | #1, #3, #4 |
| **2** | second-daemon successful join/renew/revoke in the real-daemon harness; promote it to a gate | `ci.yml`/gated `qa.yml` | #5, #7 |
| **3** | docker-compose two-node cross-host job | `ci.yml` (linux) | #2 (cross-host) |
| **4** | Windows↔Linux runner-pair job | scheduled or self-hosted | #2 (cross-platform) |
| **0** | determinism fixes (`--test-threads=1`, de-flake) | folded into Tier 1 | QA-grade prerequisite |

---

## Consequences

**Positive.** The certmesh exchange — the product's whole point — becomes guarded by automation: a successful join over HTTP, key-rotating renewal over mTLS, and **live boundary revocation** all become per-OS PR gates instead of hand-run demos. The binary's HTTP/DAT/adapter surfaces gain their first integration coverage. A genuine cross-host and then cross-platform exchange enters CI. The SURFACES certmesh row gets a real exchange guard.

**Cost.** New test infrastructure (an embedded two-instance harness; a docker-compose node pair; runner-pairing). CI minutes rise (a two-process Rust test per OS; a Docker job; eventually a runner pair). Tier 4 may need a self-hosted runner pair, which is operational overhead.

**Residual / out of scope.** Load and performance testing; wire-protocol fuzzing; the deferred CA **re-key** transition (its own future ADR — nothing to test until it exists); peer-to-peer member↔member revocation cross-check (not yet a feature). Tier 4 cross-platform is explicitly lowest priority — Tiers 1–3 deliver ~all the regression protection; Tier 4 is the literal-answer capstone.

## Decisions recorded (2026-06-19)

- The **canonical whole-story scenario** above is the single source of truth every tier drives.
- **Tier 1 (embedded two-process, in CI, per-OS) is the primary deliverable** and lands first.
- The **embedded facade** (not child-process spawning) is the Tier-1 vehicle — pure-Rust, cross-platform by construction.
- Boundary-revocation-over-live-mTLS and the HTTP success paths are **must-have** assertions, not nice-to-haves (they are the highest-risk untested behavior today).
