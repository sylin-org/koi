# P07 — One Orchestrator · Plan

> Branch: `feat/p07-one-orchestrator` off the current tip (`feat/dashboard-kernel-decouple`,
> 7 commits ahead of dev — includes the data-root SSOT work P07 builds on). Charter:
> research → plan → implement (checkpointed) → verify. Research done via a 6-mapper +
> synthesis workflow; the three-column diff and divergence bug list are below.

## Goal

Daemon composition (construct cores → install cross-domain bridges → generate the DAT
token → start adapters + background loops → ordered shutdown) is hand-written **three
times** and has **diverged into verified user-facing defects**. Build **one composition
layer** all three roots consume, making Windows/embedded parity true *by construction*,
relocating the certmesh state machine into its own crate, and collapsing main.rs to its
stated "zero business logic" shell.

## The verified divergence bug list (the union is the spec; these get fixed for free)

| Sev | Where | Defect |
|---|---|---|
| **HIGH** | Windows `run_service` | never spawns the **certmesh background tasks** — no renewal (certs expire silently), no roster sync, no heartbeat, no failover. `koi install` on Windows = a structurally weaker daemon. |
| **HIGH** | Windows `run_service` | never spawns the **runtime orchestrator** — discovered containers get no mDNS/DNS/health/proxy entries. |
| **MED** | Windows `run_service` | never wires the **enrollment-approval channel** — manual-approval mode is silently inert. |
| **MED** | `koi-embedded start()` | never spawns the **orchestrator**; never spawns **certmesh background tasks** (acceptable for a leaf, a defect for a clustered embedded host). |
| **LOW** | Windows `run_service` | writes the **breadcrumb late** (after full startup) vs early in the daemon — clients can't discover during the startup window. |
| smell | `koi-embedded start()` | runs the unified `koi_dashboard::forward` **and** 6 redundant per-domain subscribe loops (`lib.rs:558-681`) — dead duplication. |
| dup | binary + embedded | `init_certmesh_core` defined 2×; the 5 integration bridges defined 2× (`integrations.rs` vs embedded `lib.rs:1006-1164`, self-admitted); capability-status assembled 4×. |

Inherited-as-solved: the recent data-root commits (`3b6105a`, `ef59213`, `685f39b`)
already unified data-path threading + moved auto-unlock to the koi-crypto vault across all
three roots. P07 does **not** re-unify data paths; it only converges the two
`init_certmesh_core` definitions (the daemon/Windows path then also gains embedded's vault
boot-unlock).

## Design decision (NEEDS OPERATOR CONFIRMATION)

**Recommended: a new `koi-compose` crate** — NOT koi-embedded-as-orchestrator (the
prompt's default). Research found a blocker the prompt anticipated ("unless research
reveals a blocker"):

- `koi-embedded` is a **published library** (consumed by zen-garden/koan for an in-process
  mDNS+DNS leaf). The daemon-only concerns are **not clean opt-in phases**: DAT-token +
  breadcrumb assume a multi-process client/daemon split (no in-process meaning); the IPC
  named-pipe/UDS + mTLS adapters are binary-owned modules; the enrollment **stdin** prompt
  is a CLI affordance; and the certmesh cluster loops use a **blocking `ureq` KoiClient
  over the breadcrumb endpoint** — folding those into the library forces breadcrumb +
  HTTP-client machinery onto every pure embedder.
- `integrations.rs` + `orchestrator.rs` are already clean single-responsibility pieces that
  should **move** into koi-compose (and the embedded duplicate deleted), not be rewritten.
- `koi_common::integration::StatusReporter` already exists, **unused**, anticipating
  exactly the status consolidation.

`koi-compose` owns the **union**: `init_cores`, `wire_bridges` (re-homed from
integrations.rs), `spawn_adapters`, `spawn_background_tasks`, `ordered_shutdown`, and one
async `assemble_capabilities`. All three roots become thin shells:
- `main.rs daemon_mode` → ≤120 lines (Unix-signal delta only).
- `windows.rs run_service` → ≤60 lines (SCM-status delta only) — **calls the same
  spawn_background_tasks + spawn_orchestrator**, so Windows parity is by construction.
- `koi-embedded` depends on koi-compose for core/bridge construction + the status snapshot,
  and **selectively opts into** the daemon-only phases via builder flags.

koi-compose deps: the 6 event-bearing domains + koi-runtime + koi-dashboard + koi-common +
koi-client (the certmesh loops need the blocking client) — it is a composition crate, so
the architecture guard (f9cba98) classifies it Composition. New crate ⇒ add to
`publish.yml` at Layer 5/6 (after koi-dashboard, before koi-embedded + koi-net) and to the
guard's `classify()`.

## Required relocations

1. **Certmesh background machinery → koi-certmesh**, behind
   `CertmeshCore::spawn_background_tasks(deps: CertmeshBackgroundDeps, cancel) ->
   Vec<JoinHandle>`. The 4 loops + the approval handler move in. Cross-domain input
   (failover needs a live `MdnsCore` to subscribe/announce; roster-sync/heartbeat use the
   breadcrumb + blocking KoiClient) crosses via injected deps:
   `CertmeshBackgroundDeps { mdns: Option<Arc<MdnsCore>>, http_port: u16, approval:
   ApprovalDecider }`. Keep breadcrumb + KoiClient access inside koi-certmesh (the wire
   types are already in the kernel per `551283c`); mDNS register/announce crosses via a
   small announce trait in `koi_common::integration` (the AliasFeedback pattern) to honor
   domain isolation (CONTEXT.md §2/§3). `ApprovalDecider` is injected so the daemon supplies
   the stdin prompt, Windows/embedded supply a non-stdin policy.
2. **Status: 4 ladders → 1.** `koi_compose::assemble_capabilities(cores) ->
   Vec<CapabilityStatus>` backs the HTTP `/v1/status` handler, the dashboard snapshot, and
   the embedded snapshot; the **sync** CLI offline view shares the same `StatusReporter`
   abstraction via a config-only impl. Each core already has
   `koi_common::capability::Capability::status()`.
3. **Bridges → koi-compose** (delete the embedded duplicate).
4. **Orchestrator → koi-compose** (so Windows + embedded can spawn it — fixes their
   orchestrator omission).
5. **Event-forwarder**: already unified in `koi_dashboard::forward` (P06). Just delete
   embedded's 6 redundant subscribe loops.
6. **Decompose embedded `start()`** into ≤50-line phase methods.

## Checkpointed step sequence (each independently compilable + committable)

1. Create `koi-compose` crate (empty lib + workspace + guard classify + publish.yml). Binary deps it. No behavior change.
2. Move `integrations.rs` (5 bridges + browse helpers) → `koi_compose::bridges`; re-export from binary. Delete nothing yet.
3. Point koi-embedded at `koi_compose::bridges`; delete its bridge duplicate (~200 LOC). Embedded tests green.
4. Relocate certmesh machinery → `CertmeshCore::spawn_background_tasks` + injectable `ApprovalDecider`; daemon calls it. Behavior unchanged.
5. **Parity fix:** add `spawn_background_tasks` + `spawn_orchestrator` to Windows `run_service` (always-on) and embedded `start()` (opt-in, default-off). Closes the HIGH/MED defects.
6. Extract `init_cores` + `wire_bridges` + `spawn_adapters` + `ordered_shutdown` into koi-compose; rewrite `daemon_mode` + `run_service` as thin shells. main.rs → ≤300.
7. `assemble_capabilities`; refit the 4 status sites onto it. **Golden-JSON tests** assert byte-equivalent `/v1/status` + dashboard + embedded snapshot first (no wire change).
8. Decompose embedded `start()` into ≤50-line phases; delete the 6 redundant subscribe loops. LOC-delta check (≥600 net reduction).

## Test plan (heavy — per the request)

- **Windows-parity task-inventory test** (no SCM): assert the composition's spawned-task
  inventory includes the orchestrator + the 4 certmesh loops when those capabilities are
  on — the same call path Windows uses. This is the acceptance proof for the Windows fix.
- **Status-agreement golden-JSON tests**: capture `/v1/status`, the dashboard snapshot, and
  the embedded snapshot BEFORE step 7; assert byte-equivalence after (the only behavior we
  must NOT change).
- **certmesh `spawn_background_tasks` unit tests** in koi-certmesh: each loop with a stub
  decider / stub deps (no network) — renewal-due triggers `renew_all_due`; approval decider
  is consulted; failover role transitions; task count == expected.
- **koi-embedded integration suite** (`tests/udp.rs`, `tests/embedded.rs`,
  `examples/embedded-integration`) stays green; add an embedded test asserting the
  orchestrator/certmesh opt-in wiring is off by default and on when requested.
- Verify gate: `cargo check` per step; `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check`; certmesh single-threaded; the architecture guard; LOC delta.

## Risks (from research)

- **Status JSON regression** (step 7): the 4 ladders emit subtly different shapes
  (http has `http_bind`/`mdns_browse_active`; dashboard has domain cards; embedded is
  capabilities-only). Golden-JSON capture BEFORE refactor is mandatory.
- **Domain-boundary re-coupling**: certmesh's failover needs a live MdnsCore. Route
  mDNS announce/withdraw through a `koi_common::integration` trait, not a direct
  koi-mdns dep in koi-certmesh — preserves CONTEXT.md §2/§3 + the architecture guard.
- **Windows always-on behavior change**: certmesh loops now actually run under the
  service (blocking ureq + a tty-less approval channel). The `ApprovalDecider` must
  default to **Deny** (log, don't block) on a service, or enrollment hangs.
- **Embedded remote-mode early returns** (`ClientOnly`/`Auto` when localhost:5641 is
  alive) bypass core construction entirely — the compose path must NOT assume it always
  builds cores; the remote-handle branch stays ahead of any compose call.
- **mdns-sd single-import rule**: moving browse helpers into koi-compose must not pull
  `mdns_sd` types across — only Koi `MdnsEvent`/`ServiceRecord` cross. Guarded by the
  existing `no_mdns_sd_outside_daemon_rs` test.
- **Net-LOC target vs scaffolding**: keep deps structs flat; avoid generics-for-generics.

## Operator decisions — RESOLVED (2026-06-14)

1. **koi-compose new crate.** ✓ Chosen. Keeps the published koi-embedded library lean.
2. **Embedded certmesh background tasks: opt-in, default-off** (`.certmesh_background(true)`). ✓
3. Windows/tty-less enrollment approval: **default-Deny + log** (decider injected; never
   hangs). The daemon (tty) keeps the stdin prompt. An HTTP admin-approval endpoint is
   out of scope (P11/P13).
4. **Fix the remote-mode `MdnsHandle::subscribe` silent-swallow** in P07. ✓ Chosen (not
   deferred). Replace the dead receiver with honest behavior: forward the daemon's SSE
   stream where tractable, else a typed `DisabledCapability`/remote error — never a
   silently-dropped subscription. This is the one allowed behavior change; everything
   else stays pure consolidation (no wire/CLI/HTTP shape changes).

## Acceptance-criteria mapping

- One construction site → step 6 (`rg "DnsRuntime::new"` etc. shows koi-compose only). ✓
- Windows parity → steps 4-5 + the task-inventory test. ✓
- main.rs ≤ 300, zero domain logic → step 6 (certmesh machine lives in koi-certmesh). ✓
- One status source; 4 ladders deleted; sites agree → step 7 + golden-JSON tests. ✓
- koi-embedded API unchanged/improved + README compiles → step 8 + README fix. ✓
- Net LOC ≥ 600 → reported after step 8. ✓
- cargo test green incl. embedded integration; clippy/fmt → verify gate. ✓
