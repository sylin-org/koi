# ADR-018: Certmesh Cross-Participant Integration Test Suite

**Status:** Accepted — **Tiers 1–3 CI-gated + Tier 4 validated locally** (2026-06-19). All four tiers landed.
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
| **1** ✅ | `koi-embedded/tests/whole_story.rs` two-process whole-story (real HTTP+mTLS) — **implemented 2026-06-19** (the `mtls_port` builder knob proved unnecessary — see Implementation notes) | `cargo test --locked` on the existing 3-OS matrix (no workflow edit) | #1, #3, #4 |
| **2** ✅ | two real `koi` binary daemons; successful join + revoke over DAT-gated HTTP — **implemented 2026-06-19** as a pure-Rust child-process driver (`crates/koi/tests/two_daemon_certmesh.rs`), not a `qa.yml` promotion (see Implementation notes) | `cargo test --locked` on the existing 3-OS matrix (no workflow edit) | #5, #7 |
| **3** ✅ | docker-compose two-node cross-host job — **implemented 2026-06-19**; immediately surfaced + fixed a real CLI bug (join key-custody misroute) | `ci.yml` `cross-host` (linux, gated on test+clippy) | #2 (cross-host) |
| **4** ✅ | Windows↔Linux cross-platform exchange — **validated 2026-06-19** via `scripts/cross-platform-certmesh.ps1` (native Windows `koi.exe` member ↔ Linux container CA) | local / self-hosted (GitHub-hosted runners can't pair OSes) | #2 (cross-platform) |
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

## Implementation notes — Tier 1 (2026-06-19)

`crates/koi-embedded/tests/whole_story.rs` lands four `#[tokio::test]`s, each starting its
own daemon(s) on unique temp data dirs + ephemeral ports (parallel-safe):

- **`whole_story_join_renew_revoke_over_http_and_mtls`** — the canonical scenario, steps
  1–8: create (auto-unlock; asserts `machine.bind` + the `ca_initialized` audit) → invite →
  **B joins over real HTTP** (preflight pins A's fingerprint; the wire response carries no
  `service_key` and no PEM private key under any field; B's key is `0600`) → **B
  rotate-key renewal over real mTLS** (the key rotates and A's roster records the new
  fingerprint; the rotated key stays `0600`) → signed trust-bundle pull (ES256 +
  anti-rollback `seq`) → **A revokes B** → **B's `/renew` over live mTLS = 403** (asserted
  to be the *revocation* path, by body) **+ the next bundle pull reports `self_revoked`
  on a strictly newer `seq`**.
- **`wrong_fingerprint_invite_aborts_at_preflight`** (F3) — a forged-fingerprint invite
  fails the preflight pin check against the live CA, **and** `install_member_cert`
  hard-fails (`InvalidPayload`) on the forged pin while accepting the genuine one.
- **`totp_lockout_persists_across_ca_restart`** (F7) — three bad-TOTP joins lock the CA
  (401, 401, 429); the persisted `totp-throttle.json` deserializes to a locked limiter;
  after a restart the rebuilt CA auto-unlocks and a further bad-TOTP join still returns 429.
- **`tampered_machine_binding_boots_ca_locked`** (F11) — tampering the CA host's
  `machine.bind` boots it **LOCKED** with an `auto_unlock_refused_machine_changed` audit
  entry (the untampered baseline is asserted unlocked first, so the lock is not vacuous).

**Deviation from the Tier-1 prerequisite (no `mtls_port` builder knob).** The prerequisite
assumed both daemons would run an mTLS *server* and thus need distinct ports. The trust
model is **asymmetric**: only the CA runs an mTLS server; a member is a pure mTLS *client*
that learns the CA's port from its persisted `member.json` (`ca_mtls_port`, overridable).
There is exactly one mTLS server in the whole story, so no port to deconflict and no
builder knob needed. The test stands A's `inter_node_routes()` up on an ephemeral
`127.0.0.1:0` port via the public `koi_certmesh::mtls` primitive — the same
`build_server_config` + `serve` the binary's `adapters::mtls::start` wraps — so the
renew-handler / TLS / 403-boundary coverage is identical with **zero new production
surface**. F11 is exercised against the **CA host** (a member holds no CA key,
`machine.bind`, or auto-unlock).

**CI gating (confirmed, no workflow edit).** `ci.yml`'s `test` job already runs
`cargo test --locked` over the whole workspace on `ubuntu-latest` + `windows-latest` +
`macos-latest`, so the new integration test gates on every PR to `main` (including the
`dev → main` release PR) on all three OSes the moment the file lands. (Widening the
`pull_request: branches:[main]` trigger to also gate `dev`-targeting PRs is a separate
team policy decision, out of scope here.) Five pre-existing koi-embedded test-only clippy
findings (`field_reassign_with_default` ×4, `unnecessary_literal_unwrap` ×1) were cleaned
up so the suite is green under the stricter `clippy --all-targets -D warnings` (CI runs
`clippy --locked`, which does not lint `#[cfg(test)]` modules).

**Closes** gaps #1 (two-process join over HTTP), #3 (boundary revocation over live mTLS),
#4 (certmesh HTTP success paths). Gaps #2 (cross-host / cross-platform) and #5/#7
(binary + DAT middleware + adapters; cron-only real-daemon harness) remain for Tiers 2–4.

## Implementation notes — Tier 2 (2026-06-19)

`crates/koi/tests/two_daemon_certmesh.rs` (the koi-net crate's **first** integration test)
spawns **two real `koi` binary daemons** as child processes (`koi --daemon`, certmesh+HTTP
only, isolated data dirs + ephemeral ports, Drop-guarded so a panic still kills them) and
drives a certmesh exchange over **real cross-process HTTP** (reqwest). One `#[tokio::test]`:

- **DAT middleware** — `GET /status` succeeds tokenless (GET-exempt); `POST /create` and
  `POST /invite` without `x-koi-token` return **401** (asserted to be the middleware's
  `unauthorized`, not a handler-level auth error); with A's token they succeed.
- **`/join` exemption** — B generates its own CSR via **its own daemon's** `/member-csr`
  (DAT-gated, B's token; key never leaves B), then **joins A over real HTTP with NO token**
  → success (the one exempt mutation), no PEM key in the response.
- **Successful two-process join** — A's `/status` then lists B with a non-empty fingerprint
  (replacing the prior harness's negative-only invalid-TOTP `/join`). B installs the signed
  leaf via its own daemon's `/member-cert` (the pin-checked custody adapter).
- **Cross-process revocation boundary** — A revokes B (DAT-gated); a fresh re-join is
  refused with **403, typed error code `revoked`** (`process_enrollment` rejects a revoked
  member before the already-enrolled check).

**Decisions / deviations.** Driven over **raw HTTP, not the `koi certmesh` CLI**: the CLI
`join` takes the member hostname from `hostname::get()` with no override, so two daemons on
one host would collide on a single roster hostname (A self-enrolls its Primary under that
name) — raw HTTP lets B join under an explicit hostname. Each daemon's DAT token is random
per boot and persisted only to the **machine-global breadcrumb** (not under `KOI_DATA_DIR`),
so each child gets its own `XDG_RUNTIME_DIR` (Unix) / `ProgramData` (Windows) to isolate it,
and the test reads each token from its own breadcrumb. The revocation boundary is proved
over the **enrollment path** rather than ADR's literal "mTLS-renew": the binary starts its
mTLS listener only at boot-with-CA (`daemon.rs` self-enroll), so a CA created post-boot via
HTTP `/create` would need a daemon restart to bring the listener up — and the mTLS `/renew`
403 boundary is already covered in-process by Tier 1. This was **not** a `qa.yml` promotion
(the cron PowerShell harness): a pure-Rust child-process test auto-gates per-PR on all three
OSes via `cargo test --locked` with no workflow change and no added CI minutes on a separate
job. Validated green on Windows locally (confirming the `ProgramData` breadcrumb isolation,
the largest cross-platform risk). Reviewed (security + rust); the 401-is-DAT and
403-is-`revoked` assertions were tightened from substring to typed checks.

**Closes** gaps #5 (DAT `x-koi-token` middleware + `/join` exemption + the member-csr /
member-cert custody adapters, now tested against the real binary) and #7 (a successful
two-process exchange is now a per-PR gate, not a weekly-cron negative-only check). Gaps #2
(cross-host / cross-platform) remain for Tiers 3–4.

## Implementation notes — Tier 3 (2026-06-19)

`docker/cross-host/` (`Dockerfile` + `docker-compose.yml`) + `scripts/cross-host-certmesh.sh`
+ a `cross-host` job in `ci.yml`: two `koi` daemons run in **separate containers**
(`node-a` = CA, `node-b` = member) with distinct hostnames/IPs on a user-defined bridge
network, and the driver runs the whole story over the **real container network via the real
`koi certmesh` CLI**: `create` (just-me, non-interactive) → mint invite for `node-b` →
**`node-b` joins `node-a` over the bridge** → assert `node-b` enrolled → `revoke node-b` →
a fresh re-join is **refused**. This is the genuine cross-**host** coverage (distinct IPs)
the single-process Tiers 1–2 cannot give, and it additionally exercises the CLI client-mode
path (breadcrumb discovery + DAT token + the member-csr/member-cert custody adapters) end to
end. The image carries a prebuilt static **musl** `koi` binary (built on the host/runner via
`cross` — the release toolchain — and copied in, so the build context is tiny and there is no
compile-in-Docker). `KOI_HTTP_BIND=0.0.0.0` makes `node-a` reachable from `node-b` (mutations
stay DAT-gated; the compose bridge is the only exposure). The CI job is gated on
`needs: [test, clippy]` so a multi-minute cross-build never runs on a tree that does not
compile/lint; `KOI_BIN=<prebuilt koi>` skips the build entirely.

**This tier immediately earned its keep:** the first automated cross-host `koi certmesh join`
surfaced a real, shipping **CLI bug** — the global `--endpoint` and the `join`/`promote`
positional CA endpoint collided on clap's arg id, so a positional CA silently set
`--endpoint`, and `join` then resolved its LOCAL key-custody daemon (member-csr/member-cert,
which generate + keep the member private key) from it → those calls were sent to the remote
CA → 401. Explicit-endpoint join could never succeed; only mDNS-discovery join worked. Fixed
in `fix(certmesh): stop certmesh join from misrouting key custody to the CA` (positional
renamed to `ca_endpoint`; `join`/`promote` resolve the local daemon from the breadcrumb only;
clap regression tests). The cross-host suite now validates the fix end-to-end. This is the
ADR's premise made concrete — the cross-participant exchange was untested, and the first test
of it found a defect.

**Closes** gap #2's cross-**host** axis (distinct-IP exchange). The cross-**platform**
(Windows↔Linux) axis is Tier 4.

## Implementation notes — Tier 4 (2026-06-19)

`scripts/cross-platform-certmesh.ps1` drives a genuine **Windows↔Linux** exchange on a
single host that has both a native Windows `koi.exe` and Docker (Linux containers): a
**Linux container CA** (the Tier-3 musl image, published to `127.0.0.1`) and a **native
Windows `koi.exe` member** that **joins the Linux CA across platforms** — create → mint
invite for the Windows host's reported hostname (read from the member's `/v1/host`, so the
invite binds to exactly what the join presents) → `koi certmesh join` over the
loopback-published CA port → assert the Windows member is enrolled in the Linux CA's roster.
The member dials *out* to the published loopback port (no inbound-firewall dependency); its
own data dir + breadcrumb are isolated via `KOI_DATA_DIR` + `ProgramData`. Validated green
on a Windows 11 + Docker-Desktop host (a Windows member enrolled in a Linux CA); it also
confirms the Tier-3 join bugfix works **across platforms**.

**Why not a GitHub-hosted CI gate.** A hosted GitHub runner is a single OS and cannot pair
a Windows and a Linux participant, and `windows-latest` cannot reliably run Linux
containers. So Tier 4 is, by design (as the ADR anticipated), a **local / self-hosted**
validation — runnable on any Windows+Docker workstation or a self-hosted runner. The
reserved `stone-granite-spring` box stays the manual cross-platform smoke target; this
script makes that exchange reproducible. **Closes** gap #2's cross-platform axis.

## Outcome — all four tiers landed

Tiers 1–3 are per-PR CI gates (Tiers 1–2 via `cargo test --locked` on the 3-OS matrix;
Tier 3 via the `cross-host` job); Tier 4 is a scripted local/self-hosted validation. The
suite covers the certmesh exchange from in-process (T1) → real-binary same-host (T2) →
cross-host containers (T3) → cross-platform Windows↔Linux (T4), and **earned its keep on
day one** by catching the explicit-endpoint `join` key-custody-misroute bug (fixed +
regression-tested + re-validated by T3). All seven audit gaps are addressed.
