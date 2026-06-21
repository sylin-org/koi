# Adding a Domain — The Koi Domain Template

This is the **contract** for adding a new domain crate to Koi. It is not a framework:
there is no proc-macro, no plugin registry, no codegen. A domain is a small crate that
exposes the three-faced facade (commands / state / events), owns its HTTP routes, and
reuses a handful of shared primitives from `koi-common`. The binary (`koi`) and the
embedded facade (`koi-embedded`) wire it in.

Use this as a checklist. The existing small domains — `koi-dns`, `koi-health`,
`koi-proxy`, `koi-udp`, `koi-runtime` — are the worked examples; copy the closest one.

---

## 1. Crate layout

Create `crates/koi-<domain>/` and add it to the workspace `Cargo.toml` `members`. The
canonical file set:

```
crates/koi-<domain>/
├── Cargo.toml          # depends on koi-common (+ axum, tokio, utoipa, thiserror,
│                       #  async-trait as needed) — NEVER on another domain crate
└── src/
    ├── lib.rs          # the facade: re-exports, the *Core type, the *Event enum,
    │                   #   the Capability impl, and (if it runs a loop) the *Runtime
    ├── <domain>.rs     # core logic (resolver/checker/etc.) — may be inline in lib.rs
    │                   #   for tiny domains
    ├── http.rs         # `pub mod paths`, `pub fn routes(...) -> Router`, the
    │                   #   #[utoipa::path] handlers, and the `*ApiDoc` OpenApi struct
    └── error.rs        # the domain `thiserror` enum (or keep it in lib.rs if small)
```

Rules that the boundary enforces (see `.agentic/CONTEXT.md` §2–§4):

- **Domain crates never import each other.** Cross-domain data flows through the
  `koi_common::integration` traits (below), wired in the binary.
- **Internal state is `pub(crate)` or private.** Expose an opaque `*Core` whose methods
  are the only entry points (the facade pattern). Never make a `Mutex<T>` or lock handle
  `pub`.
- **Re-export the error type at the crate root**: `pub use error::<Domain>Error;`.

---

## 2. Shared pieces to use (do NOT re-implement these)

These already exist in `koi-common`. Using them is what keeps the per-domain tax low and
prevents the drift P10 cleaned up.

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

### Start/stop background loop — `koi_common::runtime_state::DomainRuntime`

If (and only if) the domain runs a **single** start/stop background loop (like DNS's
server or health's check loop), wrap the core in `DomainRuntime<Core>`:

```rust
pub struct <Domain>Runtime { inner: DomainRuntime<<Domain>Core> }

impl <Domain>Runtime {
    pub fn new(core: Arc<<Domain>Core>) -> Self { Self { inner: DomainRuntime::new(core) } }
    pub fn core(&self) -> Arc<<Domain>Core> { self.inner.core() }
    pub async fn start(&self) -> Result<bool, <Domain>Error> {
        let core = self.inner.core();
        Ok(self.inner
            .start(move |token| tokio::spawn(run_loop(core, token)))
            .await
            .unwrap_or(false))
    }
    pub async fn stop(&self) -> bool { self.inner.stop().await }
    pub async fn status(&self) -> <Domain>RuntimeStatus {
        <Domain>RuntimeStatus { running: self.inner.status().await.running }
    }
}
```

- `start` sets `running = true` synchronously and stores the cancel token; a watcher
  flips it back when the loop ends; `stop` cancels and clears immediately.
- Lifecycles that are **not** a single loop stay bespoke on purpose: `koi-proxy`
  (per-entry listeners), `koi-udp` (reaper spawned at construction). Don't force those
  onto `DomainRuntime`.

### Capability (unified status) — `koi_common::capability::Capability`

Every core implements the **async** `Capability` trait so `koi status`, the dashboard,
and the embedded snapshot all see it through one ladder:

```rust
#[async_trait::async_trait]
impl Capability for <Domain>Core {
    fn name(&self) -> &str { "<domain>" }
    async fn status(&self) -> CapabilityStatus {
        CapabilityStatus { name: "<domain>".into(), summary: /* live detail */, healthy: true }
    }
}
```

Do not roll a bespoke `capability_status()` — the trait is the only status surface.

### HTTP error responses — `koi_common::http::error_response`

```rust
use koi_common::http::error_response; // (ErrorCode, impl Into<String>) -> Response

return error_response(ErrorCode::NotFound, "record_not_found").into_response();
```

`error_response(code, message)` derives the HTTP status from `ErrorCode::http_status()`
and emits the canonical body `{"error": <code>, "message": <msg>}`. Use
`error_response_with_status(status, code, msg)` only when you must override the derived
status. **Never** hand-roll a private `error_response` (koi-dns used to — P10 removed it).
Reuse `koi_common::error::ErrorCode`; add a variant there (with its `http_status()` arm
and the exhaustive-mapping test) if you genuinely need a new wire code.

### Cross-domain wiring — `koi_common::integration`

To consume or expose data across domains without crate-to-crate deps, use the trait
bridges (`MdnsSnapshot`, `CertmeshSnapshot`, `DnsProbe`, `ProxySnapshot`,
`AliasFeedback`). A domain that needs another's data takes `Option<Arc<dyn Trait>>` in its
constructor; the **binary** provides a bridge impl wrapping the concrete core. If your
domain produces data others want, add a new trait here and implement it in the binary's
bridge layer — not by importing the consumer.

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

## 4. Binary-side touchpoints

Wiring happens in the **binary** (`crates/koi`) and `koi-compose`; domain crates stay
unaware of it.

1. **`koi-compose` — `Cores` + `build_cores`** (`crates/koi-compose/src/cores.rs`):
   - Add `pub <domain>: Option<Arc<koi_<domain>::<Domain>Core-or-Runtime>>` to `struct Cores`.
   - In `build_cores`, construct it under `if !spec.no_<domain> { ... }`, wiring any
     integration bridges in dependency order, and `tracing::info!` when disabled. Add a
     `no_<domain>: bool` (and any inputs) to `CoreSpec`.

2. **The capability ladder** (`crates/koi-compose/src/status.rs`):
   - Add a rung to `assemble_capabilities` in the canonical order. Present →
     `CapabilityReport::present(core.status().await)`; runtime-style domains distinguish
     running / `stopped(name)` / `disabled(name)`. Update the ladder-count tests.

3. **HTTP mount** (`crates/koi/src/adapters/http.rs`): `app.nest(koi_<domain>::http::paths::PREFIX, koi_<domain>::http::routes(core))`,
   and register `<Domain>ApiDoc` in the OpenAPI builder (`openapi.rs`) + add a tag.

4. **Runtime capability tunable** (`crates/koi/src/cli.rs`): add `--no-<domain>` /
   `KOI_NO_<DOMAIN>` to `Cli` and `Config`, thread it through `Config::from_cli` (and
   `from_env` on Windows), and add the `"<domain>"` arm to `Config::require_capability`.
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
- **One real event-emission test per event path**: drive the **core** command that
  broadcasts (e.g. `core.add_entry(...)` / `core.upsert(...)`) and assert the event
  arrives via `core.subscribe()`. Do **not** construct a raw `broadcast::channel` and test
  that tokio delivers — that tests tokio, not Koi (P10 replaced three such self-tests).
- Use a throwaway state path/data dir (e.g. `state_path` override,
  `ProxyCore::with_data_dir`, or `koi_common::test::ensure_data_dir`) so tests never touch
  real on-disk state.

---

## 6. Verification (per charter)

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --locked --workspace -- -D warnings
cargo fmt --all
```
