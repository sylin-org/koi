# P10 — Domain Template Extraction

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: P07 (one orchestrator) strongly recommended ·
> Read `docs/prompts/CHARTER.md` first.

## Mission

Adding a domain to Koi costs ~1,000–1,500 lines, of which 65–75% is scaffolding
copy-pasted between crates — and the copies have already drifted (koi-dns rolls its own
`error_response`; koi-runtime skips the `Capability` trait; `BROADCAST_CHANNEL_CAPACITY`
is declared four times; DnsRuntime and HealthRuntime are the same ~80-line start/stop
state machine written twice; three crates carry ~160 lines of identical tests that test
tokio's broadcast channel, not Koi). Extract the template into shared, *small*
machinery in koi-common so the per-domain tax drops and divergence becomes impossible —
without inventing a framework.

## Load context first

1. `docs/prompts/CHARTER.md` (architecture rules; koi-common stays a kernel — shared
   *types and small utilities*, not a runtime framework)
2. `docs/assessment/findings/reader-small-domains.md` (the measured tax + drift list)
3. The five domain crates' src/ (dns, health, proxy, udp, runtime) — specifically each
   one's: paths module, routes(), error mapping, Capability impl, runtime start/stop,
   broadcast wiring; plus `koi-common/src/capability.rs`, `http.rs`, `integration.rs`

## Research phase

Diff the five implementations of each template element and record the union/variance
table in your plan: where they're identical (extract), where variance is *meaningful*
(parameterize), where variance is *drift* (normalize). Confirm the known instances:
dns's private `error_response` (http.rs:~322) vs `koi_common::http::error_response`;
runtime's bespoke `capability_status()`; udp's infinite-SSE-idle default vs mdns's 5s;
the duplicated broadcast self-tests (dns resolver.rs:~741, health lib.rs:~253, proxy
lib.rs:~262). Decide the Capability evolution: the sync trait forced four bypasses —
make status async (`#[async_trait]` is already a workspace dep via runtime, or use a
manual `Pin<Box<dyn Future>>` method; weigh and justify).

## Target shapes (north star)

```rust
// koi-common/src/runtime_state.rs — the shared start/stop state machine (~90 lines, once)
pub struct DomainRuntime<C> { /* state: Stopped | Running(cancel, handle) */ }
impl<C> DomainRuntime<C> {
    pub async fn start(&self, mk: impl FnOnce(CancellationToken) -> (C, JoinHandle<()>)) -> Result<(), AlreadyRunning>;
    pub async fn stop(&self);
    pub fn status(&self) -> RuntimeStatus;  // { running: bool } — the real one
}
// consumers: DnsRuntime, HealthRuntime (delete both bespoke copies), future domains

// koi-common/src/capability.rs — async, uniform, registry-friendly
#[async_trait]
pub trait Capability: Send + Sync {
    fn name(&self) -> &'static str;
    async fn status(&self) -> CapabilityStatus;   // Disabled | Stopped | Running(detail)
}
// the composition layer (P07) holds Vec<Arc<dyn Capability>>; every status surface iterates it

// koi-common/src/events.rs — one constant, one helper
pub const BROADCAST_CHANNEL_CAPACITY: usize = 256;
pub fn event_channel<E: Clone>() -> (broadcast::Sender<E>, broadcast::Receiver<E>);
```

Deliberately **not** extracted: routes() builders and `#[utoipa::path]` annotations
(macro-izing axum/utoipa hurts readability and IDE support for marginal savings — the
paths-module convention stays as a documented pattern, not machinery). Write the
pattern down instead: `docs/reference/domain-template.md` — the checklist for adding a
domain (crate layout, the shared pieces to use, the binary-side touchpoints), so the
"template" is a documented contract with shared primitives, not folklore.

Cleanups riding along: delete the three broadcast self-test blocks and replace each
with one real behavioral test (e.g. `dns add_entry` emits `EntryUpdated` through the
core — none of the five currently verify their event emission end-to-end); normalize
dns onto `koi_common::http::error_response`; runtime onto the Capability trait; delete
verified dead code (`load_entries_with_certmesh`, `DnsCore.started_at`,
`DnsZone::fqdn_suffix`); remove the `Systemd`/`Incus`/`Kubernetes` stub variants from
`RuntimeBackendKind` and `from_str_loose` (an enum of Auto/Docker/Podman is honest;
the CLI help and docs stop advertising vapor backends).

## Plan, then implement

Per charter. Sequence: variance table → shared primitives in koi-common (+unit tests)
→ migrate crates one per commit (dns, health, proxy, udp, runtime) → behavioral-test
swap → stub-variant removal → `domain-template.md` → update `.agentic/CONTEXT.md`'s
"adding a domain" guidance if present.

## Acceptance criteria

- [ ] `DomainRuntime` exists with tests; DnsRuntime/HealthRuntime are thin aliases or
      deleted; no duplicated start/stop state machine remains (`rg "fn start"` audit in
      the five crates).
- [ ] Async `Capability` implemented by all six domains (incl. runtime); the P07
      registry consumes it; zero bespoke status ladders remain in domain crates.
- [ ] `BROADCAST_CHANNEL_CAPACITY` defined exactly once workspace-wide.
- [ ] dns uses the shared error_response; the three broadcast self-tests are replaced
      by three real event-emission tests (each fails if emission breaks).
- [ ] RuntimeBackendKind has no stub variants; `koi --runtime k8s` is a parse error
      with a helpful message; docs/cli help updated.
- [ ] Dead-code list deleted; `docs/reference/domain-template.md` exists and matches
      what the crates actually do.
- [ ] Measured: per-domain scaffolding for koi-udp recomputed and reported in the plan
      file (expect a meaningful drop vs the assessment's ~65–75%).
- [ ] Workspace green per charter commands.

## Do NOT

- Build proc-macros or a plugin framework — shared functions and one trait, nothing
  cleverer.
- Move domain *logic* into koi-common (resolver/checker/forwarder stay put); only
  lifecycle/status/event plumbing moves.
- Break any HTTP endpoint shape or CLI behavior.
