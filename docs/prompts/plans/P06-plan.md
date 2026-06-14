# P06 — Presentation Layer Rebuild · Plan

> Branch: `feat/p06-presentation-layer` (from `dev`). Charter: research → plan →
> implement → verify. This file is the work order's contract; every P06 acceptance
> criterion is mapped to a concrete change + test below.

## Goal

Three entangled problems, one move:

1. **Restore the kernel.** Move the dashboard + mDNS-browser presentation code (60 KB
   HTML, a 563-line browse cache, SSE plumbing) **out of `koi-common`** into a new
   `koi-dashboard` crate, and drop the presentation-only deps koi-common acquired.
2. **Close the verified XSS** (assessment claim 9, High): LAN-attacker-controlled mDNS
   service names break out of double-quoted HTML attributes (`esc()` does not escape
   quotes), and TXT `url=` launch links accept `javascript:`. Fix structurally.
3. **Make the meta-browse lazy.** The always-on LAN-wide browse worker (spawned at
   daemon start whenever mDNS is enabled) becomes lazy: starts on the first browser
   surface request, idles out, and `koi status` reports whether it is active.

## Research conclusions (ground truth, verified against code)

### XSS sites (claim 9 re-verified)
- `crates/koi-common/assets/mdns-browser.html:370` — `esc()` = `textContent→innerHTML`
  escapes `& < >` but **not** `"` / `'`.
- Attacker data interpolated into **double-quoted attributes**:
  - `data-type="..."` lines 477, 500 (filter tags, histogram)
  - launch `href="..."` + `title="Open ..."` lines 558-559, detail `href` line 581
  - `data-key="..."` / `data-detail="..."` lines 563, 574
  A service named `" onmouseover="alert(1)` breaks out → inline-handler XSS on the
  daemon origin (which can reach unauthenticated GETs: certmesh status / audit / roster).
- `inferEndpoint` line 419-424 validates TXT `url=` with bare `new URL()` — `javascript:`
  and `data:` are valid URLs → rendered as a clickable launch link.
- `dashboard.html` routes attacker data (mDNS `d.name` in the activity log) only into
  **text context** via `esc()` (inert) and interpolates only JS-hardcoded literals into
  attributes — **not independently exploitable**.

### koi-common dependency damage (precise)
Crate-path usage in `koi-common/src` (excluding dashboard.rs/browser.rs):
| dep | used outside presentation? | verdict |
|---|---|---|
| `async-stream` | no | **REMOVE** |
| `tokio-stream` | no | **REMOVE** |
| `hostname` | no (only `dashboard.rs::get_snapshot`) | **REMOVE** |
| `tokio-util` | no (only `browser.rs` CancellationToken) | **REMOVE** |
| `chrono` | **yes** — `integration.rs::MemberSummary` (`DateTime<Utc>`) | keep |
| `axum` | **yes** — `error.rs` + `http.rs::error_response` (wire error response) | keep |

So acceptance #1's "presentation-only" removals = **async-stream, tokio-stream,
hostname, tokio-util**. `axum`/`chrono` are *not* presentation-only and stay (see
Divergence D2). The leakage check `cargo tree -p koi-dns | grep axum|chrono` will still
match — koi-dns depends on axum **directly** (it serves routes) and on chrono via
koi-common's legitimate `integration.rs`. The achievable, meaningful assertion: the
removed presentation deps (`async-stream`, `hostname`) no longer appear in koi-dns's
tree — proven by `cargo tree -p koi-dns -i async-stream` / `-i hostname` being empty.

### Duplicated / diverged consumer copies
- **Browse adapter**: `koi/src/adapters/mdns_browser.rs` and
  `koi-embedded/src/mdns_browse_adapter.rs` are **byte-identical** (`MdnsBrowseAdapter`
  wrapping `MdnsCore::subscribe_type`).
- **Event forwarder** (the real divergence): binary's
  `adapters::dashboard::spawn_event_forwarder` forwards mdns/health/dns/certmesh/proxy
  (**5**); koi-embedded's inline forwarder (lib.rs ~445-559) also forwards **runtime**
  (**6** = superset). UDP exposes **no** lifecycle-event broadcast (only per-binding
  datagram streams), so there is nothing to forward for udp (see Divergence D3).
- **Snapshot builders** diverge (`build_snapshot_value` in the binary builds capability
  cards + detail panels; embedded `build_embedded_snapshot` builds capability cards
  **only**). They are **not** a named dedup target; the SnapshotFn injection seam is
  explicitly "keep it". Left per-consumer (Divergence D4).

### Wiring sites that start the dashboard/meta-browse
- `koi/src/main.rs:674-702` (daemon) — dashboard state + forwarder + **eager** browser
  worker.
- `koi/src/platform/windows.rs:632-665` (Windows service) — same wiring, duplicated.
  (`unix.rs`/`macos.rs` delegate to `main.rs`'s daemon path — no duplicate.)
- `koi-embedded/src/lib.rs:411-588` — dashboard state + inline forwarder + **eager**
  browser worker.
- Route mounts: `koi/src/adapters/http.rs:92-109` and `koi-embedded/src/http.rs:85-105`.

## Target architecture

New crate `crates/koi-dashboard/` (a **composition/presentation** crate, peer to the
binary's adapters — NOT a domain crate):

```
crates/koi-dashboard/
  Cargo.toml          # koi-common + koi-mdns,koi-certmesh,koi-dns,koi-health,koi-proxy,
                      #   koi-runtime  (the 6 event-bearing domains) + axum, tokio,
                      #   tokio-util, tokio-stream, async-stream, chrono, hostname,
                      #   uuid, serde, serde_json, tracing
  src/lib.rs          # mod decls + crate docs
  src/dashboard.rs    # DashboardState/Identity/SseEvent, SnapshotFn (injection kept),
                      #   SSE stream, get_dashboard/get_snapshot/get_events handlers
  src/forward.rs      # ForwarderCores + pure per-domain map fns + spawn_event_forwarder
                      #   (THE single forwarder; superset incl. runtime)
  src/browse_source.rs# BrowseSource trait, BrowseHandle, BrowserEvent, ResolvedService,
                      #   BrowseError, MdnsBrowseAdapter (THE single adapter)
  src/browser.rs      # BrowserCache + snapshot types + worker + SSE + routes + handlers
  src/meta_browse.rs  # LazyMetaBrowse controller (lazy-start + idle-stop)
  assets/dashboard.html       # esc() hardened to be attribute-safe (defense-in-depth)
  assets/mdns-browser.html    # REBUILT: DOM construction, http/https launch allowlist
  tests/xss.rs        # JS-free: snapshot-serve inertness + asset structural guard
```

Consumers (`koi`, `koi-embedded`) depend on `koi-dashboard`, mount its routes, and
**delete** their local presentation copies. `koi-common` loses `dashboard.rs`,
`browser.rs`, `assets/`, and the 4 presentation deps.

Why the new crate depends on domains (not koi-common-only as the north-star sketch
says): the forwarder maps concrete `koi_mdns::MdnsEvent` / `koi_runtime::RuntimeEvent`
/ … and the adapter wraps `MdnsCore` — these *are* domain types. To host **one**
forwarder + **one** adapter (acceptance #4) they must live in a crate that can see the
domains. No domain crate depends on `koi-dashboard`, so the kernel and every domain
crate's dependency closure stay clean — the headline restoration is fully achieved.
(Divergence D1.)

## XSS approach (chosen: structural, option (b))

- **mdns-browser.html — full structural rewrite of dynamic rendering.** Build every row,
  histogram bar, filter tag, log entry, and detail pane with `document.createElement` +
  `textContent` + `dataset` (no HTML-string concatenation of dynamic values, no
  `innerHTML = htmlString`). This eliminates the attribute-injection **bug class**: a
  hostile name simply becomes a text node / dataset value, never markup.
- **Launch links — explicit scheme allowlist regardless.** New `safeLaunchUrl(raw)`:
  parse with `new URL()`, return it only if `protocol ∈ {http:, https:}`; else `null`.
  Applied to both TXT `url=` values and constructed endpoints; non-http(s) → no link
  rendered. Kills `javascript:` / `data:` / `file:` etc.
- **dashboard.html — defense-in-depth.** Make `esc()` also escape `"`, `'`, and `` ` ``
  (so any esc-into-attribute is safe). Its dynamic values are operator-controlled and
  land in text context, so a full DOM rewrite is unwarranted risk; the verified-XSS page
  is mdns-browser.html. (Divergence D5.)

## Lazy meta-browse design

- `LazyMetaBrowse` (in `meta_browse.rs`) owns `source: Arc<dyn BrowseSource>`,
  `cache: BrowserCache`, parent `CancellationToken`, idle `Duration`
  (`META_BROWSE_IDLE = 300s`), and `Mutex<{ worker_cancel: Option<CancellationToken>,
  last_active: Instant, supervisor_started: bool }>`.
  - `touch()` (sync): bumps `last_active`; if no worker, spawns `worker(source,cache,
    child_token)` and (once) an idle supervisor.
  - supervisor: 30 s tick; if `last_active.elapsed() > idle` → cancel worker (which tears
    down the meta-browse + per-type browses via the P05 refcount chain) and clears
    `worker_cancel`; a later `touch()` restarts it. Breaks on parent cancel.
  - `is_active() -> bool`.
- `BrowserState { source, cache, meta: Arc<LazyMetaBrowse> }`.
- Browser handlers (`get_page`, browser `get_snapshot`, browser `get_events`) call
  `state.meta.touch()` first → "starts on the first request to a browser surface".
  Dashboard endpoints do **not** trigger it (they query cores directly; the dashboard
  activity-log mdns feed is best-effort and not a reason to flood multicast).
- **`koi status`**: daemon `/v1/status` JSON gains `"mdns_browse_active": <bool>` (read
  from `BrowserState.meta.is_active()`, plumbed through `AppState`);
  `format::unified_status` prints `Browse:  active|idle` when present. Embedded status is
  left unchanged (library surface; daemon is the `koi status` target).
- Daemon startup (main.rs + windows.rs) and embedded build **no longer spawn the worker**
  — they build `BrowserState` with the lazy controller only.

## File-by-file change list

### New: `crates/koi-dashboard/*` (see layout above) + workspace member + workspace dep.

### `koi-common` (kernel restoration)
- DELETE `src/dashboard.rs`, `src/browser.rs`, `assets/dashboard.html`,
  `assets/mdns-browser.html`; drop both `pub mod` lines from `lib.rs`.
- `Cargo.toml`: remove the presentation-only deps — `tokio`, `tokio-stream`,
  `tokio-util`, `async-stream`, `hostname` (5; once the two modules go, nothing else in
  koi-common uses them). Keep `chrono`, `axum`, `utoipa`, serde/serde_json/thiserror/
  uuid/tracing.

### `koi` (binary)
- `Cargo.toml`: add `koi-dashboard`. (axum/async-stream/hostname stay — still used by the
  binary's own http adapter + snapshot builder.)
- `adapters/dashboard.rs`: DELETE `spawn_event_forwarder` (moved). KEEP detail structs +
  `DomainCores` + `build_snapshot_value` + `build_dashboard_state` (build the SnapshotFn;
  uses `koi_dashboard::dashboard::{DashboardIdentity,DashboardState}`).
- `adapters/mdns_browser.rs`: DELETE the file (adapter moved); drop from `adapters/mod.rs`.
- `adapters/http.rs`: `koi_common::{dashboard,browser}::*` → `koi_dashboard::{dashboard,
  browser}::*`; add `mdns_browse: Option<Arc<LazyMetaBrowse>>` to `AppState`; emit
  `mdns_browse_active` in `unified_status_handler`.
- `main.rs:674-702`: forwarder call → `koi_dashboard::dashboard::spawn_event_forwarder`;
  browser wiring → `koi_dashboard::browser::build_state(mdns, cancel)` (lazy, no worker
  spawn).
- `platform/windows.rs:632-665`: identical updates to main.rs.
- `format.rs::unified_status`: print `Browse:` line when `mdns_browse_active` present.

### `koi-embedded`
- `Cargo.toml`: add `koi-dashboard`.
- `mdns_browse_adapter.rs`: DELETE the file; drop its `mod`.
- `lib.rs`: DELETE inline forwarder (445-559) → call
  `koi_dashboard::dashboard::spawn_event_forwarder`. Browser wiring (566-588) →
  `koi_dashboard::browser::build_state` (lazy). DashboardState/SnapshotFn types →
  `koi_dashboard::dashboard::*`. KEEP `build_embedded_snapshot`.
- `http.rs`: `koi_common::{dashboard,browser}::*` → `koi_dashboard::{dashboard,browser}::*`.

### Docs
- `.agentic/CONTEXT.md`: add `koi-dashboard` to crate inventory + dependency graph; note
  koi-common is presentation-free again; update "Binary Crate Module Structure"
  (dashboard.rs thinned, mdns_browser.rs removed; dashboard/browser now in koi-dashboard).
- `docs/reference/architecture.md`: add the crate, its deps/boundary, the lazy meta-browse.
- `.agentic/reference/utilities.md`: relocate DashboardState/BrowserState to koi-dashboard;
  add `META_BROWSE_IDLE`; update koi-common dep rows.
- `docs/SURFACES.md`: dashboard+browser row → `Exercised by: koi-dashboard tests`,
  `Last exercised: 2026-06-13`, `Guard: koi-dashboard tests (ci.yml)`, note XSS closed +
  lazy browse.
- `docs/prompts/PROGRESS.md`: P06 `in-progress` → `done`; divergence rows D1-D5.

## Test list (fail-meaningfully)

1. `tests/xss.rs::asset_uses_dom_construction_no_attr_concat` — reads embedded
   mdns-browser.html; asserts the vulnerable patterns (`href="' +`, `data-key="' +`,
   `data-type="' +`, `title="Open ' +`, `data-detail="' +`) are **absent** and the scheme
   allowlist sentinel (`safeLaunchUrl`) is **present**. Fails on current asset; passes
   after rewrite. (The genuine fail-first XSS guard.)
2. `tests/xss.rs::snapshot_serves_hostile_names_as_inert_json` — builds `BrowserState`
   with a `StubSource` + cache pre-seeded (test seam) with names `"><img src=x
   onerror=alert(1)>` and `" onmouseover="alert(1)` and TXT `url=javascript:alert(1)`;
   `oneshot` GET `/v1/mdns/browser/snapshot`; asserts 200, `content-type: application/
   json`, body parses, hostile names round-trip as JSON string values (server emits inert
   JSON, never HTML).
3. `meta_browse` unit tests (StubSource counts `browse()` calls, `tokio::time` paused):
   - `no_browse_before_touch` — zero browses at construction.
   - `touch_starts_one_meta_browse` + `is_active()` true.
   - `idle_stops_worker` — after advancing past idle, `is_active()` false and browses
     torn down; a later `touch()` restarts.
4. `forward` unit tests on the pure map fns: `map_runtime(Started)` → `runtime.started`
   (proves superset includes runtime); `map_mdns(Removed)` shape; etc.
5. Keep all existing tests green (status offline tests, P03 bind tests, etc.).

## Risks
- **Browser-page rewrite regressions** (sort/filter/expand/launch/SSE/log). Mitigation:
  preserve the snapshot/SSE JSON contract and element IDs/classes; manual `koi launch`
  pass on both pages; keep behavior identical, only the render mechanism changes.
- **Lazy worker teardown correctness** relies on the P05 refcount chain (dropping
  BrowseHandle → adapter relay errors → BrowseSubscription drops → stop_browse). Covered
  by meta_browse tests + manual check.
- **Windows service path** is compile-gated off on this dev machine; mirror main.rs edits
  exactly and rely on `cargo check` (it compiles cfg(windows) blocks? no — verify via
  targeted review; the wiring is a structural copy).
- **certmesh single-threaded** test requirement preserved in the verify gate.

## Divergences (also logged in PROGRESS.md)
- **D1** — `koi-dashboard` depends on the 6 event-bearing domain crates, not
  koi-common-only (north-star sketch). Required to host one forwarder + one adapter
  (they reference domain types). Kernel restoration unaffected; no domain depends on it.
- **D2** — koi-common dep removals are async-stream/tokio-stream/hostname/tokio-util only.
  axum (wire error response) + chrono (integration timestamps) are legitimate kernel uses
  and remain; `cargo tree | grep axum|chrono` still matches via koi-dns's own axum dep +
  koi-common integration chrono — not presentation leakage. Proven via inverted tree.
- **D3** — UDP has no lifecycle-event broadcast; the "incl. udp" forwarder arm has nothing
  to forward. Superset = +runtime (the real divergence).
- **D4** — Snapshot builders not unified (not a named dedup target; embedded omits detail
  panels — unifying would change embedded behavior). SnapshotFn injection kept per prompt.
- **D5** — dashboard.html gets a hardened (attribute-safe) `esc()` rather than a full DOM
  rewrite; it has no attacker→attribute path. Structural rewrite applied to the
  verified-XSS page (mdns-browser.html).

## Verify gate (all green before "done")
`cargo check` after each unit; then `cargo test`, `cargo clippy -- -D warnings`,
`cargo fmt --check`; `cargo test -p koi-certmesh -- --test-threads=1`; leakage:
`cargo tree -p koi-dns -i async-stream` and `-i hostname` empty (presentation deps gone);
security-reviewer over the new render path clean (CRITICAL/HIGH fixed); manual `koi
launch` on both pages incl. a hostile-named service.
