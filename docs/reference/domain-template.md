# Adding a Domain — The Koi Domain Template

This is the **contract** for adding a new domain crate to Koi. It is not a framework:
there is no proc-macro, no plugin registry, no codegen. A domain is a small crate that
exposes the three-faced facade (commands / state / events), owns its HTTP routes, and
reuses a handful of shared primitives from `koi-common`. `koi-compose` wires it once; the
binary (`koi`) and embedded facade (`koi-embedded`) consume that composition.

Use this as a checklist. The existing small domains — `koi-dns`, `koi-health`,
`koi-proxy`, `koi-udp`, `koi-runtime` — are the worked examples; copy the closest one.
The commands/state/events contract is defined by
[ADR-043](../adr/043-observable-domain-boundaries.md).

---

## 1. Crate layout

Create `crates/koi-<domain>/` and add it to the workspace `Cargo.toml` `members`. The
canonical file set:

```
crates/koi-<domain>/
├── Cargo.toml          # depends on koi-common (+ axum, tokio, utoipa, thiserror,
│                       #  async-trait as needed) — NEVER on another domain crate
└── src/
    ├── lib.rs          # the facade: re-exports, the *Core type, authoritative
    │                   #   *Status, *Event, and (if it runs a loop) the *Runtime
    ├── <domain>.rs     # core logic (resolver/checker/etc.) — may be inline in lib.rs
    │                   #   for tiny domains
    ├── http.rs         # `pub mod paths`, `pub fn routes(...) -> Router`, the
    │                   #   #[utoipa::path] handlers, and the `*ApiDoc` OpenApi struct
    └── error.rs        # the domain `thiserror` enum (or keep it in lib.rs if small)
```

Rules that the boundary enforces (see `.agentic/CONTEXT.md` §2–§4):

- **Domain crates never import each other.** Cross-domain data flows through the
  `koi_common::integration` traits (below), wired in `koi-compose`.
- **Internal state is `pub(crate)` or private.** Expose an opaque `*Core` whose methods
  are the only entry points (the facade pattern). Never make a `Mutex<T>` or lock handle
  `pub`.
- **Re-export the error type at the crate root**: `pub use error::<Domain>Error;`.

---

## 2. Shared pieces to use (do NOT re-implement these)

These already exist in `koi-common`. Using them is what keeps the per-domain tax low and
prevents the drift P10 cleaned up.

### Latest status — `koi_common::status::StatusFeed`

Every domain owns one immutable, structured status contract. It is the state face of the
facade; `CapabilityStatus` is only a derived presentation summary.

```rust
use std::sync::Arc;
use koi_common::status::StatusFeed;
use tokio::sync::watch;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DomainStatus { // rename for the domain, e.g. DnsRuntimeStatus
    pub revision: u64,
    // domain vocabulary only: running, entries, failures, etc.
}

pub struct DomainCore {
    status_feed: StatusFeed<DomainStatus>, // private delivery primitive
    // private mutable model and event sender
}

impl DomainCore {
    pub fn status(&self) -> Arc<DomainStatus> { self.status_feed.current() }
    pub fn watch_status(&self) -> watch::Receiver<Arc<DomainStatus>> {
        self.status_feed.subscribe()
    }
}
```

- Seed the feed from actual initial state before exposing the facade.
- A status read is an `Arc` clone: no `async`, I/O, network request, or domain lock.
- Increment `revision` only when the semantic projection changes. Revisions are monotonic
  within one running instance, not durable or comparable across domains/nodes. A narrower
  counter may coexist when it names a genuinely narrower epoch: mDNS provider-routing
  `generation`, for example, is distinct from the enclosing domain status `revision`.
- `watch` carries the current value immediately and may coalesce intermediate changes. It is
  for convergence, not history.
- Keep unbounded data behind another `Arc` or a specialized query rather than cloning it on
  every read.
- The domain constructs and publishes status. `StatusFeed` is not a global registry or an
  alternate state owner.

### Event channel — `koi_common::events`

```rust
use koi_common::events::event_channel; // sized at BROADCAST_CHANNEL_CAPACITY (256)

let (event_tx, _rx) = event_channel::<<Domain>Event>();
// store event_tx in the core; subscribers call event_tx.subscribe() later
```

- `BROADCAST_CHANNEL_CAPACITY` is defined **once** here — never declare your own.
- Define your `#[derive(Debug, Clone)] pub enum <Domain>Event { ... }` in the crate.
- Emit through the core: `fn emit(&self, e: <Domain>Event) { let _ = self.event_tx.send(e); }`
  and expose `pub fn subscribe(&self) -> broadcast::Receiver<<Domain>Event>`.
- Events report semantic occurrences. They are best effort and must never be replayed to
  reconstruct current state. On `Lagged`, reread `status()`.
- A successful persistent mutation orders its effects as **durable commit → status publish →
  event emit → success response**. A failed commit publishes neither proposed success state
  nor its success event.

### Command admission and cancellation

Define the command's admission/commit point in domain terms. Validation and pure preparation
may be cancelled before that point. Once durable or native work is admitted, the domain—not
the caller future—owns its completion through model acceptance, every specialized projection,
the primary status, and the semantic event. A dropped HTTP/CLI/embedded waiter must not release
a serialization guard while detached work continues or leave status one generation behind disk
or the platform.

Use the least mechanism the effect needs:

- keep a short, bounded filesystem commit plus model/status/event tail synchronous and free of
  `.await` points;
- put a blocking platform adapter behind one bounded domain-owned worker queue, where enqueue is
  admission and last-owner drop drains accepted work and joins the worker; or
- retain an async native-resource completion task in the domain lifecycle until it settles or is
  explicitly reaped.

Do not add a global command executor. Do not use bare `spawn_blocking` for a mutation whose
result can outlive the guard protecting its model. If a platform effect cannot be transactional,
durably arm exact replay intent first and expose pending/error truth until reconciliation settles
it; never emit a success event for uncertain state.

### Start/stop background loop — domain-owned lifecycle

If the domain runs a background loop, keep its deliberately small lifecycle controller in
that domain. The same owner that starts and stops the loop must publish the `running` fact;
do not introduce a generic second state machine whose flag can disagree with domain status:

```rust
struct Lifecycle {
    generation: u64,
    active: Option<(CancellationToken, JoinHandle<()>)>,
}

pub struct <Domain>Runtime {
    core: Arc<<Domain>Core>,
    lifecycle: Mutex<Lifecycle>,
}

impl <Domain>Runtime {
    pub async fn start(&self) -> Result<bool, <Domain>Error> { /* own one transition */ }
    pub async fn stop(&self) -> bool { /* cancel the active generation */ }
    pub fn status(&self) -> Arc<<Domain>Status> { /* private StatusFeed */ }
    pub fn watch_status(&self) -> watch::Receiver<Arc<<Domain>Status>> {
        /* subscribe to that feed */
    }
}
```

- `start`, natural completion, failure, and `stop` converge through one generation-guarded
  transition and publish before emitting a corresponding event or returning success.
- When the wrapper alone knows start/bind state, it owns the public status feed and includes
  the core's relevant state. Keep the same cheap synchronous read contract.
- Shape lifecycle state around domain semantics: one loop, per-entry listeners, and a
  construction-time reaper are different models and should remain visibly different.
- Retain each `JoinHandle` while awaiting it. Once a restartable `stop` or terminal `shutdown`
  is admitted, a domain-owned completion transaction carries its cancel/abort/reap tail to
  settlement even if the requester disappears; another call may share the acknowledgement but
  must not be required to make the first call take effect. Terminal shutdown applies one
  deadline, then aborts and reaps stragglers. `Drop` cancels and aborts still-owned work as the
  synchronous fail-closed fence. Any temporary task/owner self-retention must be broken on both
  success and panic so it cannot strand resources or waiters.
- A synchronous platform API with no genuine cancellation/deadline is different: its owner
  drains and joins admitted work even if that can delay shutdown. Never claim a timeout while
  silently detaching an external mutation that is still running.

### Capability summary — a projection, never domain truth

`koi-compose` derives the small `CapabilityStatus` ladder from each structured domain
status. Domains do not implement a generic capability trait: prose summaries and
composition-level enabled/absent state are not domain truth. Projection code lives once at
the composition boundary and only reads already-published status:

```rust
fn project_<domain>(status: &<Domain>Status) -> CapabilityStatus {
    CapabilityStatus {
        name: "<domain>".into(),
        summary: /* format from structured facts */,
        healthy: /* derive from structured facts */,
    }
}
```

Do not make prose a machine contract and do not add a competing `capability_status()`.

### HTTP error responses — `koi_common::http::error_response`

```rust
use koi_common::http::error_response; // (ErrorCode, impl Into<String>) -> Response

return error_response(ErrorCode::NotFound, "record_not_found").into_response();
```

`error_response(code, message)` derives the HTTP status from `ErrorCode::http_status()`
and emits the canonical body `{"error": <code>, "message": <msg>}`. Use
`error_response_with_status(status, code, msg)` only when you must override the derived
status. **Never** hand-roll a private `error_response`.
Reuse `koi_common::error::ErrorCode`; add a variant there (with its `http_status()` arm
and the exhaustive-mapping test) if you genuinely need a new wire code.

### Cross-domain wiring — `koi_common::integration`

To issue a cross-domain query/command without crate-to-crate deps, use the trait
bridges (`MdnsSnapshot`, `CertmeshSnapshot`, `DnsProbe`, `ProxySnapshot`,
`AliasFeedback`). A domain that needs another's data takes `Option<Arc<dyn Trait>>` in its
constructor; **`koi-compose`** provides a bridge impl wrapping the concrete core. Prefer an
authoritative status read when it contains the required facts; never have a bridge inspect
another domain's persistence. If your domain produces data others want, add a narrow trait
here and implement it in the composition bridge layer — not by importing the consumer.

Status subscriptions, command/query ports, and semantic event fan-in remain separate typed
paths. Do not hide them behind one global internal bus.

For derived cross-domain configuration, prefer one idempotent complete desired-set command over
individual add/remove bookkeeping. The source status remains authoritative; composition performs
the typed translation; the receiving domain atomically replaces a named process-local scope and
owns validation, merge precedence, status, and events. Never persist a runtime-derived set as
operator configuration, and never create a composition-owned shadow inventory. Explicit durable
operator configuration wins collisions. A restart begins with transient scopes empty and
reconstructs them from the source's current status. Native resources that require acknowledged
withdrawal may additionally use a domain-owned session lease, but that lease is a resource owner,
not another desired-state model.

---

## 3. Per-crate conventions that deliberately stay (not machinery)

These are **not** extracted into shared code on purpose — macro-izing them costs more
readability/IDE support than it saves. Follow the pattern by hand:

- **`pub mod paths`** in `http.rs`: every route path as a `const`, plus a `rel()` helper
  that strips the `PREFIX` so the same constants drive both axum routing and the help/API
  metadata. (See `koi-dns`/`koi-udp` `http.rs`.)
- **`pub fn routes(core: Arc<Core>) -> Router`**: build the `Router` from the `paths::`
  constants and `.with_state(core)` (or `.layer(Extension(core))`). The binary nests it at
  `paths::PREFIX`.
- **`#[utoipa::path(...)]` per handler** + a `#[derive(OpenApi)] pub struct <Domain>ApiDoc`
  listing the handlers and component schemas. Response conventions:
  `Json(PipelineResponse::clean(...))` for success where the pipeline shape applies;
  `error_response(...)` for errors; SSE via `Sse<impl Stream<...>>`.

---

## 4. Composition and adapter touchpoints

Wiring happens in `koi-compose`, `koi-serve`, and the binary/embedded shells; domain crates
stay unaware of their consumers.

1. **`koi-compose` — `Cores` + `build_cores`** (`crates/koi-compose/src/cores.rs`):
   - Add `pub <domain>: Option<Arc<koi_<domain>::<Domain>Core-or-Runtime>>` to `struct Cores`.
   - In `build_cores`, construct it under `if !spec.no_<domain> { ... }`, wiring any
     integration bridges in dependency order, and `tracing::info!` when disabled. Add a
     `no_<domain>: bool` (and any inputs) to `CoreSpec`.

2. **Reactive `KoiStatus`** (`crates/koi-compose/src/status.rs`):
   - Register the domain's current status and `watch_status()` receiver in the aggregate's
     canonical order. Derive its `CapabilityStatus` projection there. `KoiStatusRuntime`, not
     the domain, owns `disabled`/absent and other composition-only state through explicit,
     instance-scoped inputs supplied by `Cores::publish_composition_status(CapabilityReport)`.
     Never add a process-global note/override registry. Update revision, projection, and
     ladder-count tests.

3. **HTTP mount** (`crates/koi-serve/src/http.rs`):
   `app.nest(koi_<domain>::http::paths::PREFIX, koi_<domain>::http::routes(core))`, and
   register `<Domain>ApiDoc` in the composed OpenAPI document + add a tag.
   A serving adapter with its own authoritative feed (such as Pond) explicitly projects that
   status into `KoiStatusRuntime`; it does not publish hidden global composition state.

4. **Runtime capability tunable** (`crates/koi/src/cli.rs`): add `--no-<domain>` /
   `KOI_NO_<DOMAIN>` to `Cli` and `Config`, thread it through `Config::from_cli`, and add
   the `"<domain>"` arm to `Config::require_capability`. Windows service startup parses
   that same launch/env/file/default chain through `Config::from_service_launch`; do not
   introduce a second environment-only configuration builder.
   CLI dispatch calls `config.require_capability("<domain>")?` before running a command.

5. **CLI surface + help meta** (`crates/koi/src/help/`): clap (`cli.rs`) is the source of
   truth for the command tree; add the subcommand enum + leaf commands there. Then add a
   `CommandMeta` entry per leaf in `help/meta.rs` (glyph, category, summary, examples,
   `ApiEndpoint` equivalent, optional confirmation gate). Drift between clap and the meta
   map is a **test failure** (`meta_covers_every_clap_leaf`, `every_example_parses`).

6. **`koi-embedded`** (if the domain should be embeddable): expose a handle in
   `handle.rs`, a builder toggle, and mount its routes in `koi-embedded/src/http.rs`.

---

## 5. Tests the domain must carry

- **Serde round-trips** for new protocol/wire types.
- **Status semantics:** a new subscriber immediately sees the seeded snapshot; a committed
  semantic change advances the revision once; a no-op does not wake it; rapid changes
  converge to the latest value.
- **Mutation ordering:** force persistence failure and prove no success status/event escapes;
  after a real event, assert `status()` contains that transition or a newer revision.
- **Cancellation boundary:** deterministically pause immediately before and after admission,
  abort the caller, and prove either no effect was accepted or the full
  durable/native → model → projections → status → event tail converges without a retry command.
- **Lifecycle ownership:** cancel teardown while a child is retiring, then prove a retry or Drop
  still owns it; assert sockets/threads/tasks are released and no stale status survives.
- **Derived scopes:** prove complete-set replacement, reorder/no-op stability, source removal,
  restart reconstruction, duplicate handling, and explicit operator precedence without writing
  derived values to the durable repository.
- **One real event-emission test per event path**: drive the **core** command that
  broadcasts (e.g. `core.add_entry(...)` / `core.upsert(...)`) and assert the event
  arrives via `core.subscribe()`. Do **not** construct a raw `broadcast::channel` and test
  that tokio delivers — that tests tokio, not Koi (P10 replaced three such self-tests).
- Inject throwaway paths through the production constructors (`DnsCore::open`,
  `HealthCore::open`, or `ProxyCore::open`); `koi_common::test::ensure_data_dir` can provide
  their isolated root. Tests must never touch real on-disk state.

---

## 6. Verification (per charter)

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --locked --workspace -- -D warnings
cargo fmt --all
```
