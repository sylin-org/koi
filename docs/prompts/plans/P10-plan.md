# P10 — Domain Template Extraction — Plan

> Branch: `dev` (autonomous). Verify per charter. Research: `p10-domain-template-research`
> workflow (3 facets) — variance table archived in the run transcript.
> koi-udp baseline (for the tax recompute): **686 src lines** (lib 301, http 242, binding 143).

## Variance verdicts (what the research settled)

- **DomainRuntime<C>**: dns + health are **100% identical** ~80-line start/stop machines
  (`Mutex<RuntimeState{running, cancel}>`; differ only in Error/Status type + the spawned
  task body). **Extract** and adopt in those two. proxy (per-entry HashMap), udp
  (reaper-on-construction, external token), runtime (`start_watching` takes an external
  token, no stop) have **genuinely different lifecycles → do NOT force them** onto it.
- **Async Capability**: mechanical. All 6 domain impls (mdns/certmesh/dns/health/proxy/udp)
  just add `#[async_trait]` + `async` — bodies unchanged (they use sync try_lock/try_read).
  runtime's bespoke `capability_status()` **becomes the trait impl**. Consumers add `.await`:
  `assemble_capabilities` (4-5 sites), and the **koi-embedded http status_handler** (which
  still hand-rolls its own 7-rung ladder — refit it onto `assemble_capabilities`, finishing
  P07's unification). dashboard + `build_embedded_snapshot` already `.await` assemble. The
  golden test already `.await`s — **/v1/status output stays byte-identical**.
- **BROADCAST_CHANNEL_CAPACITY**: defined **6×** (mdns, certmesh, dns, health, proxy, runtime)
  → one `koi_common::events` const + `event_channel<E: Clone>()` helper.
- **Dead code**: `DnsZone::fqdn_suffix` (only its own test), `DnsCore.started_at` (only in
  Clone). `load_entries_with_certmesh` **does not exist** (prompt was stale) — skip.
- **Stub backends**: `RuntimeBackendKind::{Systemd, Incus, Kubernetes}` + their
  `from_str_loose` arms → remove; after which `koi --runtime k8s` is a parse error.
- **dns error_response** (http.rs:322) rolls its own → adopt `koi_common::http::error_response`.
- **3 broadcast self-tests** (dns resolver.rs ~747, health lib.rs ~258, proxy lib.rs ~282)
  test tokio's channel, not Koi → replace each with a real **event-emission-through-the-core**
  test (e.g. `dns add_entry` emits `EntryUpdated`).

## Deliberately NOT extracted (per charter — no framework)

routes() builders + `#[utoipa::path]` annotations stay per-crate (macro-izing axum/utoipa
hurts readability for marginal savings). The "template" becomes a **documented contract** in
`docs/reference/domain-template.md` (crate layout, the shared pieces to use, binary touchpoints).

## Execution (per charter)

- **Pass 1 — shared primitives + migrations** (delegated, then verified incl. the golden test):
  1. koi-common: `runtime_state::DomainRuntime<C>` + `RuntimeStatus` (+ unit tests);
     `events::{BROADCAST_CHANNEL_CAPACITY, event_channel}`.
  2. Async `Capability` (atomic: trait + all 6 impls + runtime→trait + `assemble_capabilities`
     `.await` + embedded http status_handler refit). Golden test green.
  3. dns + health adopt `DomainRuntime` (delete the two bespoke machines).
  4. Consolidate the 6 broadcast consts onto `koi_common::events` (+ `event_channel` where it
     reads cleanly).
- **Pass 2 — cleanups + docs** (delegated): dns→shared `error_response`; the 3 self-test
  swaps; delete `fqdn_suffix` + `started_at`; remove the 3 stub backends (+ cli/help/docs
  that advertise them); write `docs/reference/domain-template.md`; update `.agentic/CONTEXT.md`
  "adding a domain" guidance + the stale `command-surface` mention (P09 follow-up).

## Acceptance

DomainRuntime exists+tested, dns/health thin; async Capability on all 6 + runtime, registry
(assemble) consumes it, no bespoke ladders; one broadcast const; dns shared error_response;
3 real event tests; no stub backends (`koi --runtime k8s` parse error); dead code gone;
domain-template.md exists; udp tax recomputed; workspace green.
