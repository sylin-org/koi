# P07 — One Orchestrator

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: L (checkpoint after the extraction step if needed) · Prereqs: ideally after
> P03–P06 · Read `docs/prompts/CHARTER.md` first. This is the highest-leverage
> structural change in the consolidation program.

## Mission

Daemon composition — constructing cores, bridges, adapters, background tasks — is
hand-written **three times** and has already diverged: `main.rs daemon_mode()` (the
full daemon), `platform/windows.rs run_service()` (~400 duplicated lines that *omit*
the runtime orchestrator and all certmesh background tasks — a verified user-facing
defect: `koi install` on Windows yields a weaker daemon), and `koi-embedded`'s
`start()` (a ~560-line monolith whose own comment admits "Duplicated from the binary
crate's integrations.rs"). Auxiliary ladders multiply the copies: capability-status
assembly exists 4×, the dashboard event-forwarder 2×. Build **one composition layer**
that all three consume, making Windows parity true *by construction* and shrinking
main.rs back to its stated "zero business logic" role.

## Load context first

1. `docs/prompts/CHARTER.md`
2. `docs/assessment/findings/verification-2026-06.md` claims 6 and 12;
   `findings/reader-embedded-dx.md` (the two-orchestrator analysis)
3. The three wiring paths in full: `crates/koi/src/main.rs` (esp. daemon_mode 465–866,
   certmesh tasks 917–1292), `crates/koi/src/platform/windows.rs` (run_service
   379–847), `crates/koi-embedded/src/lib.rs` (start() 247–807, bridges 1066–1230)
4. `crates/koi/src/integrations.rs`, `orchestrator.rs`, `adapters/http.rs` (AppState),
   `koi-common/src/capability.rs` and `integration.rs`

## Research phase

Build a three-column diff in your plan file: every step each wiring path performs
(core construction, bridge installation, DAT generation, adapters, dashboard, browser
worker, mTLS, announce, orchestrator, certmesh loops, shutdown order). The union is the
spec; divergences are the bug list. Decide the home: extend **koi-embedded as the
canonical orchestrator** (binary becomes a shell over it) vs a new `koi-compose` crate
both depend on. Default to *koi-embedded-as-orchestrator* unless research reveals a
blocker (e.g., embedded's optional-by-default capabilities vs daemon's all-on — that's
config, not structure); justify in the plan.

## Target architecture (north star)

```rust
// One composition type, one lifecycle:
let daemon = KoiBuilder::from_daemon_config(&config)   // Config -> builder mapping in ONE place
    .build()?;                                          // constructs cores + bridges + tasks
let handle = daemon.start().await?;                     // spawns adapters + background loops
// ...
handle.shutdown(SHUTDOWN_TIMEOUT).await;                // ordered teardown (existing discipline)

// main.rs daemon_mode():        ~40 lines — parse, build, start, wait-for-signal, shutdown
// windows.rs run_service():     ~60 lines — SCM glue around the SAME four calls
// koi-embedded public API:      unchanged surface, now THE implementation
```

Required relocations (each makes a stated rule true again):

- Certmesh background machinery (renewal loop, roster sync, health heartbeat, failover
  watch, approval prompt — main.rs:917–1292) moves into **koi-certmesh** behind
  `CertmeshCore::spawn_background_tasks(deps, cancel) -> Vec<JoinHandle>`; the
  composition layer calls it. (mDNS-event input crosses via the existing integration
  traits — keep domain isolation.)
- The 4 capability-status ladders collapse to **one**: make status async-capable
  (async trait method or a `status() -> impl Future` registry), give the composition
  layer `fn capabilities() -> Vec<(name, CapabilityStatusFuture)>`, and derive HTTP
  unified-status, dashboard snapshot, CLI offline view, and embedded snapshot from it.
- The event-forwarder copies collapse into the single implementation (P06's crate if
  done; otherwise place it with the composition layer).
- koi-embedded's `start()` monolith decomposes into the builder's phase methods —
  no function over ~50 lines in the new layer.

## Plan, then implement

Per charter, with a checkpoint discipline: (1) the three-column diff + design note,
(2) extract composition into the chosen home with main.rs consuming it (windows.rs
untouched, tests green), (3) port windows.rs, (4) port/absorb koi-embedded internals,
(5) certmesh-task relocation, (6) status-ladder unification, (7) delete the dead
copies. Each step is independently compilable and committable.

## Acceptance criteria

- [ ] One place constructs cores/bridges/tasks; `rg "DnsRuntime::new|HealthRuntime::new"`
      etc. shows construction in exactly one non-test location.
- [ ] Windows service parity: run_service and daemon_mode call the same composition;
      the orchestrator and certmesh loops run under the service (assert via the
      composition's task inventory in a unit test — no SCM needed).
- [ ] main.rs ≤ ~300 lines total; zero domain business logic (the certmesh state
      machine lives in koi-certmesh with its own tests).
- [ ] Capability status has one source; the four ladder sites are deleted; dashboard /
      `koi status` / `/v1/status` / embedded snapshot agree (snapshot test comparing
      two of them).
- [ ] koi-embedded's public builder API unchanged or improved (no `.mode()`-style
      README drift — fix the README examples to compile while you're there).
- [ ] Net LOC reduction ≥ 600 lines (report the number).
- [ ] `cargo test` green incl. koi-embedded's integration tests; clippy/fmt clean.

## Verification

Workspace commands per charter; `koi --daemon` smoke on your platform (status, one
announce, dashboard loads); koi-embedded's tests/udp.rs suite passes; on Windows if
available: `koi install` + verify the service log shows orchestrator + renewal tasks
starting (otherwise rely on the task-inventory unit test).

## Do NOT

- Change any CLI surface, HTTP endpoint, or wire shape — this is pure internal
  consolidation.
- Refactor domain crates' internals beyond the certmesh-task relocation.
- Attempt P08's certmesh content diet here — relocation only, same behavior.
