# P05 — mDNS Browse Multiplexing Rebuild — Plan

> Work order: [../P05-mdns-browse-rebuild.md](../P05-mdns-browse-rebuild.md) · Charter: [../CHARTER.md](../CHARTER.md)
> Branch: `feat/p05-mdns-browse-rebuild` (from `dev` @ fa4146b). Commit-only; maintainer integrates via squash PR.

## Goal

koi-mdns hands out unlimited "independent" `BrowseHandle`s per service type, but
mdns-sd 0.20 keeps exactly **one querier per type**. A second browse of a type
*overwrites* the first's listener (`service_daemon.rs:3540`, comment 3537-3539), and
`stop_browse` removes the type's only querier **and clears its cache**
(`exec_command_stop_browse`, `cache.remove_service_type`, `service_daemon.rs:3717/3735`).
Verified consequences: two concurrent SSE `discover` streams of one type silently kill
each other; `resolve()` (browse-then-stop_browse) terminates concurrent subscribers;
`BrowseHandle::drop` does the same; the dashboard meta-browse cache permanently loses
any affected type.

Rebuild browsing around **one real browse per type with reference-counted broadcast
fan-out**, hidden inside `MdnsDaemon`, and restore the crate's single-import boundary
(currently violated: `mdns_sd` is imported in both `daemon.rs` **and** `browse.rs`).

## Ground-truth notes (verified against code, this session)

- **mdns-sd is 0.20** (Cargo.lock), not 0.17 as the prompt says. The single-querier
  defect persists identically; the "do NOT upgrade mdns-sd" caveat is already satisfied.
- **85 koi-mdns tests, all unit** (error 3 + http 24 + protocol 29 + registry 29). There
  are **zero real-network browse/resolve tests today**; `MdnsCore`/`MdnsDaemon` are never
  constructed in tests. koi-embedded tests *do* construct a real `ServiceDaemon` and pass
  in CI (v0.3.0 shipped green), so `MdnsDaemon::new()` works under `cargo test`.
- **`ServiceType::parse(s).as_str()` is canonical** → `"_http._tcp.local."`; mdns-sd's
  `browse()` requires that `.local.` suffix (`check_domain_suffix`). The hub **must key on
  this canonical form** for both `discover` and `resolve`, or they'd open two queriers and
  re-trigger the overwrite bug. `META_QUERY = "_services._dns-sd._udp.local."`.
- **`ServiceRemoved(.0, .1)` = `(ty_domain, fullname)`** in 0.20
  (`notify_service_removal`, `service_daemon.rs:3359-3362`). Parse once at the boundary.
- **koi-embedded/src/lib.rs duplicates integrations.rs**: `MdnsBridgeEmbedded` +
  `run_meta_browse_embedded`/`run_type_browse_embedded` mirror the binary crate's
  `MdnsBridge` + `run_meta_browse`/`run_type_browse`, with the same `active`-HashSet
  workaround and the same `extract_*` helpers. Both must be migrated identically.
- **Two different `BrowseHandle`s exist** — only `koi_mdns::BrowseHandle` is in scope.
  `koi_common::browser::BrowseHandle` (mpsc-based, used by `adapters/mdns_browser.rs` and
  `koi-embedded/src/mdns_browse_adapter.rs`) is unrelated and **stays**.

## Design decisions (with the adversarial review folded in)

### Fan-out primitive: per-type `tokio::sync::broadcast` — **chosen**
- Cheap fan-out, no per-subscriber bookkeeping in the pump, and a slow SSE client cannot
  stall others (broadcast drops *oldest* for the lagging receiver only). A per-subscriber
  mpsc registry would force the pump to hold N senders and either head-of-line-block or
  re-implement drop-oldest. The prompt's north star uses broadcast.
- **Capacity:** new constant `TYPE_BROADCAST_CAPACITY = 512` (the core-wide
  `BROADCAST_CHANNEL_CAPACITY = 256` is unchanged). Rationale: when the *first* subscriber
  starts the real browse, mdns-sd's `query_cache_for_service` replays every cached
  instance synchronously; 256 could overflow a large network before the first receiver
  reads. 512 + the records cache (below) makes replay loss non-fatal.
- **Lagged handling (SSE):** map `Lagged(n)` to a logged warning + `continue` (skip the
  gap), `Closed → None` (stream end). We do **not** silently treat Lagged as a normal
  event. A snapshot-re-emit on Lagged is a documented future improvement, not in scope —
  the dashboard keeps its own cache + periodic snapshot, and `resolve()` reads the hub
  records cache, so a lagged discover stream self-heals on the next event.

### subscribe_type is **synchronous** — eliminates the double-browse race structurally
The adversarial review's highest-risk finding: a "release-lock → `await browse` →
re-lock" sequence lets two concurrent vacant inserts both call `daemon.browse()` → the
second overwrites the first's querier (the exact bug), and a refcount-based rollback is
racy (ABA). **Resolution:** `subscribe_type` does **no `.await`**. Under a short
`std::sync::Mutex` critical section it `entry(...).or_insert_with(...)`; the closure
creates the broadcast channel and `tokio::spawn`s the pump (spawning is sync). The pump
performs `daemon.browse().await` as its *first* action. Therefore exactly one pump — and
one real mdns-sd browse — can ever exist per type, and the std-Mutex is never held across
an await. This is strictly stronger than the "only the creator awaits" mitigation.

### Guard `Drop` — std Mutex, short, no `.await`
`BrowseSubscription` owns `Arc<TypeGuard>`. `TypeGuard::drop` locks the hub std-Mutex,
`refcount -= 1`; on zero it removes the entry (matching its generation), `pump.abort()`
(sync, non-blocking), and `stop_browse` via `SyncSender::try_send` (sync, non-blocking,
safe from Drop incl. during runtime teardown — `Disconnected` is logged). No `.await`, no
nested daemon locks. Because `subscribe_type` never holds the lock across an await, the
std-Mutex-in-Drop can never deadlock against it.

### Records cache — **mandatory** (not a nicety)
In daemon mode `MdnsBridge` keeps a permanent meta-browse + a permanent per-type browse
for every discovered type, so those types are already *Live* before any `resolve()` runs.
mdns-sd replays its cache only to the *first* listener at browse-start; a late `resolve()`
that increments refcount on a Live type gets the broadcast receiver with **no replay** and
would spuriously time out for an already-resolved, quiet service. Fix: each `TypeBrowse`
keeps `records: HashMap<instance, ServiceRecord>` updated by the pump (Resolved inserts,
Removed deletes). `resolve()` checks it for an immediate hit before waiting. (Rejected
alternative: "resolve forces a fresh browse" — that re-inserts the listener = overwrite =
double-emits to all subscribers. Do not.)

### Pump feeds **both** channels; zombie-Live guard
Today the core-wide `event_tx` is fed only as a side effect of someone polling a
`BrowseHandle`. The always-running pump now feeds the per-type `tx` **and** the core-wide
`event_tx` exactly once each per surfaced event (fixes the latent "events only flow when
polled" bug; no sink double-counts because per-type vs core-wide are distinct channels and
each consumer picks one). If the pump exits while `refcount > 0` (browse failed to start,
or external SearchStopped), it removes its own entry (generation-matched) so subscribers
get `Closed → None` and the next subscribe re-browses — no zombie Live entry with a dead
pump.

## Target shapes

```rust
// crates/koi-mdns/src/daemon.rs — the ONLY mdns_sd-importing file (browse.rs deleted)
use mdns_sd::ServiceEvent as MdnsServiceEvent;          // renamed for clarity
use crate::events::MdnsEvent as KoiEvent;

const TYPE_BROADCAST_CAPACITY: usize = 512;

struct TypeBrowse {
    tx: broadcast::Sender<KoiEvent>,
    refcount: usize,
    pump: Option<tokio::task::JoinHandle<()>>,
    records: HashMap<String, ServiceRecord>,   // instance name -> record
    gen: u64,
}

pub(crate) struct MdnsDaemon {
    op_tx: Mutex<SyncSender<MdnsOp>>,
    types: Mutex<HashMap<String, TypeBrowse>>, // the hub
    event_tx: broadcast::Sender<KoiEvent>,     // core-wide (moved in from MdnsCore)
    next_gen: AtomicU64,
}

impl MdnsDaemon {
    pub fn new(event_tx: broadcast::Sender<KoiEvent>) -> Result<Self>;
    pub fn subscribe_all(&self) -> broadcast::Receiver<KoiEvent>;     // for MdnsCore::subscribe()
    pub fn subscribe_type(self: &Arc<Self>, key: &str, is_meta: bool) -> BrowseSubscription; // sync
    pub async fn resolve(self: &Arc<Self>, instance: &str) -> Result<ServiceRecord>;         // cache-checked subscription
    // register/unregister/shutdown unchanged; browse()/stop_browse() become internal helpers used by the pump/guard
    #[cfg(test)] pub(crate) fn inject(&self, key: &str, ev: KoiEvent);    // test seam: mimics pump output (broadcast + records + event_tx)
    #[cfg(test)] pub(crate) fn type_refcount(&self, key: &str) -> Option<usize>;
}

pub struct BrowseSubscription {                  // replaces BrowseHandle
    rx: tokio::sync::Mutex<broadcast::Receiver<KoiEvent>>,  // Mutex → recv(&self) preserves old contract
    _guard: Arc<TypeGuard>,
}
impl BrowseSubscription {
    pub async fn recv(&self) -> Option<KoiEvent>;  // Lagged→log+continue, Closed→None  (SAME signature as old BrowseHandle::recv)
}
```

- `recv(&self)` (not `&mut self`) via an internal `tokio::sync::Mutex<Receiver>` so every
  existing `handle.recv()` loop and the `Arc::new(handle)` wrapping in the SSE handlers
  compile **unchanged**.
- Canonical key helper (used by browse + resolve): `META_QUERY → (META_QUERY, is_meta=true)`,
  else `(ServiceType::parse(s)?.as_str().to_string(), false)`.
- Boundary parse helpers in daemon.rs (shared by pump + resolve keying): reuse the
  `find("._")` instance-extraction already in `resolved_to_record`; `service_type` =
  `ty_domain` trimmed of `.`/`.local` (same normalization as `resolved_to_record`).

## File-by-file change list

| File | Change |
|---|---|
| `crates/koi-mdns/src/browse.rs` | **DELETE.** Hub + `BrowseSubscription` + `TypeGuard` + pump move into `daemon.rs` (single-file boundary). |
| `crates/koi-mdns/src/daemon.rs` | Rename mdns_sd alias → `MdnsServiceEvent`; add `KoiEvent`. Add hub fields + `TYPE_BROADCAST_CAPACITY`. `new(event_tx)`. `subscribe_type` (sync), `subscribe_all`, pump (`spawn_type_pump` + `pump_loop` with boundary parse + records update + dual-channel feed + zombie guard), `BrowseSubscription`, `TypeGuard` (Drop). Rewrite `resolve` as cache-checked subscription. `browse()`/`stop_browse()` become internal helpers. `shutdown()` aborts pumps then shuts the worker. Grep boundary test + canonical-key/parse unit tests. |
| `crates/koi-mdns/src/lib.rs` | `pub use self::daemon::BrowseSubscription` (drop `browse` mod + `BrowseHandle`). Create `event_tx` first, pass to `MdnsDaemon::new(event_tx.clone())`; drop the `event_tx` field (or keep a clone solely for `subscribe()` — prefer delegating to `daemon.subscribe_all()`). `browse()` → `subscribe_type()` returning `BrowseSubscription` (async, keeps `ServiceType::parse` validation). `resolve()` delegates unchanged. |
| `crates/koi-mdns/src/http.rs` | `browse_handler`/`events_handler`: `core.browse(..)` → `core.subscribe_type(..)`. recv loops unchanged. `resolve_handler` unchanged. |
| `crates/koi/src/integrations.rs` | `browse`→`subscribe_type` (×2). Param types `BrowseHandle`→`BrowseSubscription` (×2). **Delete** `active` HashSet workaround and `extract_service_type`/`extract_instance_name`; use the now-parsed `Removed { name, service_type }` directly. |
| `crates/koi/src/adapters/dispatch.rs` | `browse`→`subscribe_type` (lines ~47, ~88). recv loops unchanged. resolve unchanged. |
| `crates/koi/src/adapters/mdns_browser.rs` | `self.core.browse`→`subscribe_type` (~72). The `BrowseHandle` here is **koi_common's** — unchanged. Update the stale comment. |
| `crates/koi/src/commands/mdns.rs` | `browse`→`subscribe_type` (~56, ~266). loops unchanged. |
| `crates/koi/src/commands/certmesh.rs` | `browse`→`subscribe_type` (~1176). loop unchanged. |
| `crates/koi/src/main.rs` | `mdns.browse`→`subscribe_type` (~1122). loop unchanged. |
| `crates/koi-embedded/src/lib.rs` | Mirror integrations.rs: `browse`→`subscribe_type`; param types; delete `active` set + inline `extract_*`. |
| `crates/koi-embedded/src/handle.rs` | Import `BrowseSubscription as MdnsBrowseHandle`; `core.browse`→`subscribe_type` (~314). `KoiBrowseHandle::Embedded` wraps the new type; `recv()`/`resolve()`/`subscribe()` unchanged in contract. |
| `crates/koi-embedded/src/mdns_browse_adapter.rs` | `self.core.browse`→`subscribe_type` (~62). koi_common `BrowseHandle` unchanged. |
| `crates/koi-embedded/examples/embedded-integration.rs` | `browse`→`subscribe_type` (~620, ~642, ~975). (Examples compile under `cargo build --examples`/`cargo test` for the package — migrate for the build to stay green.) |
| `.agentic/rules/mdns-boundary.md`, `.agentic/reference/utilities.md`, `docs/reference/architecture.md`, `crates/koi-mdns/README.md` | Update: `BrowseHandle`→`BrowseSubscription`; note the hub/refcount model and that the boundary is restored + grep-guarded; add `TYPE_BROADCAST_CAPACITY`. |

## Test list (TDD — write first; deterministic via the `inject` seam)

Real multicast delivery is intentionally **not** relied on (no existing harness; CI
multicast not guaranteed; a flaky test would regress the green release pipeline). The
fan-out + refcount logic — which *is* the fix for the single-querier bug — is proven
deterministically by injecting post-parse `KoiEvent`s into a Live type, exactly mimicking
the pump's output. A real register+two-subscribe e2e is added as `#[ignore]` (run with
`--ignored` / the prompt's manual smoke covers true end-to-end).

1. `concurrent_subscriptions_both_receive` — two `subscribe_type("_test._tcp.local.")`;
   `inject` a Resolved; both `recv()` it. *(Fails to compile on old code — proves the API
   was 1:1-per-querier.)*
2. `dropping_one_subscription_leaves_the_other_live` — drop sub1; `inject` again; sub2
   still receives. (This is the precise scenario the overwrite/stop_browse bug broke.)
3. `refcount_last_drop_stops_browse` — `type_refcount` goes 1→2 on second subscribe (no
   second querier), 2→1 on one drop, entry removed on last drop.
4. `resolve_during_active_subscription_does_not_terminate_it` — open a subscription;
   `resolve()` (served from the records cache via `inject`); subscription still receives a
   subsequent injected event.
5. `resolve_returns_cached_record_without_waiting` — `inject` a Resolved, then `resolve()`
   returns it well under `RESOLVE_TIMEOUT`.
6. `removed_event_is_parsed_at_boundary` — unit-test the parse helper:
   `("_http._tcp.local.", "My NAS._http._tcp.local.")` → `Removed { name: "My NAS",
   service_type: "_http._tcp" }`.
7. `canonical_browse_key` — `"_http._tcp"`, `"_http._tcp.local."`, `"http"` → same key;
   `META_QUERY` → meta.
8. `no_mdns_sd_outside_daemon_rs` — grep test: every `crates/koi-mdns/src/*.rs` except
   `daemon.rs` contains zero `mdns_sd` occurrences.
9. `meta_query_found_surfaces_type` / `non_meta_found_is_skipped` — pump translation
   semantics preserved.
10. `#[ignore] real_register_two_subscribe_e2e` — real `MdnsCore::new()` + register + two
    subscriptions, generous timeout; documents the live behavior. Plus existing 85 pass.

## Risks / watch-items

- **Send/'static:** `BrowseSubscription` (Mutex<Receiver> + Arc<TypeGuard>) must be
  `Send + 'static` to move into the SSE/embedded spawned tasks — verify no borrowed
  lifetime.
- **Shutdown ordering:** `shutdown()` aborts all pumps before `daemon.shutdown()`; ensure
  no Drop-vs-shutdown deadlock on the hub std-Mutex.
- **Key consistency:** every browse path canonicalizes via the same helper, or
  discover/resolve fork into two queriers.
- **Wire shape:** `Removed` keeps its `ServiceRecord` structure; only the *values* become
  correct (name=instance, type=parsed) — the prompt's mandated fix, not a shape change.
  `browse_event_removed_produces_event_removed` (protocol.rs:503) only checks
  serialization of given inputs, so it stays valid.
- **Out of scope (note only):** Response-enum/wire-shape changes; lease/registry engine;
  mdns-sd upgrade; de-duplicating the integrations.rs ↔ koi-embedded copy (param-type +
  workaround removal only; full extraction is a later prompt).

## Verification

`cargo check -p koi-mdns` after each unit → then `cargo test -p koi-mdns` → `cargo test`
(certmesh single-threaded: `cargo test -p koi-certmesh -- --test-threads=1`) →
`cargo clippy -- -D warnings` → `cargo fmt --check`. Binary crate is `koi-net`.
