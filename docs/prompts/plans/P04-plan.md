# P04 — Proxy Rebuild: TLS Passthrough — Plan

> Branch: `feat/p04-proxy-rebuild` (from `dev`). Charter protocol: research → plan →
> implement → verify. Break-and-rebuild authorized for `koi-proxy`'s data plane.

## Goal

Replace `koi-proxy`'s broken HTTP-forwarding data plane with a **TLS-terminating TCP
passthrough**, fixing all three structural defects in verification-2026-06 claim 1:

1. **axum 0.8 route panic** — `listener.rs:46` registers `.route("/*path", any(..))`,
   which panics at registration under axum 0.8.8 (`/*wildcard` syntax removed). Built
   inside `tokio::spawn`, so the panic is silent and the daemon keeps reporting healthy.
2. **cert-watch callback panic** — `watch_certs` calls `tokio::spawn` from notify's own
   (non-tokio) thread; the first cert event panics that thread, killing hot reload.
3. **No WebSocket support** — reqwest-based HTTP forwarding can never carry a
   `Connection: Upgrade` / bidirectional stream.

A byte-level TCP passthrough (`TlsAcceptor::accept` → `copy_bidirectional` to a plain
`TcpStream`) fixes all three by construction, is fewer lines, and matches the crate's
honest role: *the pre-wired TLS endpoint for certmesh certs* — not a Caddy competitor.

## Research findings (verified against code)

- **Panic site confirmed**: `listener.rs:44-47` builds `Router::new().route("/*path", ..)`;
  workspace axum is `0.8` (Cargo.lock `axum 0.8.x`). The empirical 10-line test (step 0
  below) will capture the exact panic message before deletion.
- **`status()` hardcodes `running: true`** (`lib.rs:247`) for every entry — failure is
  invisible through API/CLI/dashboard.
- **Cert delivery reality** (important): certmesh writes member certs to
  `koi_certs_dir()/<hostname>/{fullchain.pem,key.pem}` (`koi-certmesh/src/certfiles.rs`),
  but the proxy reads `koi_certs_dir()/<entry.name>/` (`listener.rs:121`). **They only
  align when the entry name equals the hostname.** And `load_tls_config` has **no
  self-signed fallback** despite `docs/guides/proxy.md` claiming one — so today a proxy
  on a fresh machine fails to start entirely (compounding defect 1). The rebuild adds a
  real self-signed fallback and an entry-name → hostname cert search order (see Cert
  resolution). Fully reconciling certmesh↔proxy cert naming is a certmesh concern, left
  to a future prompt; recorded as a divergence.
- **TLS deps already present**: `tokio-rustls 0.26`, `rustls 0.23`, `rustls-pemfile 2`,
  `rcgen 0.13`, `arc-swap 1.8` are all in `Cargo.lock`. `rustls` default crypto provider
  is **aws-lc-rs** (the `ring` rustls feature is not enabled), so the `ServerConfig` is
  built with an explicit `rustls::crypto::aws_lc_rs` provider via `builder_with_provider`
  to avoid relying on a process-global `install_default`.
- **`allow_remote` semantic** (decision, see Risks): current code = "permit a non-loopback
  **backend**" (`safety.rs`, CLI flag `--backend-remote`, doc "Allow non-local backend
  destinations"); the listener always binds `0.0.0.0`. The prompt's parenthetical
  "(loopback vs 0.0.0.0 listen)" describes a *different* (listen-side) semantic that does
  not match the code. **Preserving the existing backend-gate semantic** per "preserve its
  security semantics" + charter rule against silently changing user-visible behavior.

### Consumer inventory (status-shape change blast radius)

| Consumer | File | Reads | Action |
|---|---|---|---|
| HTTP status handler | `koi-proxy/src/http.rs` | `ProxyStatus` → JSON `{proxies}` | new fields; `ProxyStatusResponse` schema → `Vec<ProxyStatus>` |
| Dashboard snapshot | `koi/src/adapters/dashboard.rs:308-315` | `s.running` | switch to `s.state`/`s.error`/`s.cert_source` |
| CLI status | `koi/src/commands/proxy.rs:149-170` | name/backend/listen | render north-star NAME/LISTEN/BACKEND/TLS/STATE table (via `format.rs`) |
| CLI add | `koi/src/commands/proxy.rs:7-25` | `url::Url::parse` + `ensure_backend_allowed(&Url,..)` | use new `ensure_backend_allowed(&str,..)` |
| Embedded status | `koi-embedded/src/http.rs:333` | `status().is_empty()/.len()` | unaffected (still `Vec<ProxyStatus>`) |
| koi-client | `koi-client/src/lib.rs:295` | JSON passthrough | unaffected |
| Embedded handle | `koi-embedded/src/handle.rs` | `runtime.{core,start_all,stop_all}` | unaffected (facade preserved) |
| main.rs / windows.rs | `koi/src/{main.rs,platform/windows.rs}` | `ProxyCore::new`, `ProxyRuntime::new`, `start_all`, `stop_all` | unaffected (facade preserved) |
| orchestrator | `koi/src/orchestrator.rs:443-458` | builds `backend:"http://h:p"`, `core().upsert/remove` | unaffected (tolerant backend parse) |
| health bridge | `koi-common/src/integration.rs` `ProxySnapshot` | `config::load_entries()` | unaffected (`ProxyEntry` shape kept) |
| surface catalog | `koi/src/surface.rs:511-522,1722-1810` | examples/descriptions | reword for passthrough; keep `/v1/proxy/*` paths |
| OpenAPI | `koi-proxy/src/http.rs` `ProxyApiDoc` | schemas | add `ProxyStatus`; keep paths |

**Facade API preserved unchanged** (no call-site churn beyond the status shape):
`ProxyCore::{new, with_data_dir, entries, reload, upsert, remove, subscribe}` + `Capability`;
`ProxyRuntime::{new, core, start_all, reload, stop_all, status, clone}`;
`ProxyEntry{name,listen_port,backend,allow_remote}`; `ProxyEvent`; `ProxyError`.

## Target shapes

```rust
// lib.rs — breaking: `running: bool` removed, state/error/cert_source added
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ProxyStatus {
    pub name: String,
    pub listen_port: u16,
    pub backend: String,
    pub allow_remote: bool,
    pub cert_source: String,   // "certmesh" | "self-signed"
    pub state: String,         // "starting" | "running" | "error" | "stopped"
    pub error: Option<String>, // Some(msg) iff state == "error"
}

// tls.rs — listener liveness, reported via tokio::sync::watch
#[derive(Debug, Clone)]
pub struct ListenerStatus {
    pub state: ListenerState,        // Starting | Running | Error | Stopped
    pub error: Option<String>,
    pub cert_source: CertSource,     // Certmesh | SelfSigned
}

// tls.rs — hot-reloadable cert, free per-handshake swap
struct CertResolver { current: std::sync::RwLock<Arc<rustls::sign::CertifiedKey>> }
impl rustls::server::ResolvesServerCert for CertResolver { /* returns current */ }
```

```console
$ koi proxy status
NAME      LISTEN  BACKEND          TLS          STATE
grafana   :8443   127.0.0.1:3000   certmesh     running
old-app   :9443   127.0.0.1:9000   self-signed  error: address in use
```

### Architecture

```
spawn_listener(entry, cancel) -> watch::Receiver<ListenerStatus>
  task:
    1. resolve cert material (entry-name dir → hostname dir → self-signed) ; set cert_source
    2. build CertResolver(RwLock<Arc<CertifiedKey>>) + ServerConfig(aws_lc_rs provider)
    3. start cert watcher: notify on koi_certs_dir() (recursive) → mpsc try_send(()) →
       tokio bridge task re-resolves & swaps the RwLock  (NO tokio::spawn on notify thread)
    4. TcpListener::bind(0.0.0.0:port) ; on err -> state=Error(msg), return
    5. state=Running ; accept loop:
         conn -> spawn: acceptor.accept(tcp) -> TcpStream::connect(backend)
                        -> copy_bidirectional(tls, upstream)   // WS/full-duplex by bytes
    6. cancel -> state=Stopped
```

Cert hot-reload is **free**: the `TlsAcceptor`/`ServerConfig` are built once and never
rebuilt; `ResolvesServerCert::resolve` reads the current `CertifiedKey` per handshake, so
swapping the `RwLock` content is picked up on the next handshake. `RwLock<Arc<..>>` chosen
over `arc-swap` because handshakes are not a hot loop and writes (reloads) are seconds
apart — no new direct dependency for zero practical benefit.

## File-by-file change list

**`crates/koi-proxy/Cargo.toml`**
- add: `tokio-rustls.workspace = true`, `rcgen.workspace = true`
- remove: `axum-server`, `reqwest`, `http-body-util`, `hyper`, `futures-util` (data-plane only)
- keep: `axum` (management routes), `notify`, `rustls`, `rustls-pemfile`, `url`, `hostname`,
  `tokio`, `tokio-util`, `serde`, `serde_json`, `thiserror`, `tracing`, `utoipa`, `toml`, `koi-common`, `koi-config`

**`crates/koi-proxy/src/forwarder.rs`** — **delete** (HTTP-level forwarding).

**`crates/koi-proxy/src/listener.rs`** — **rewrite** as passthrough: `spawn_listener`,
accept loop, TLS accept + `TcpStream::connect` + `copy_bidirectional`, `ListenerState`,
`ListenerStatus`. No axum, no router, no reqwest.

**`crates/koi-proxy/src/tls.rs`** — **new**: `CertResolver` (ResolvesServerCert),
`resolve_cert_material` (file dirs → self-signed via rcgen), `build_certified_key`
(rustls-pemfile + aws_lc_rs key loader), `server_config`, notify→tokio cert-watch bridge,
`CertSource`. (Split out so each file stays < ~250 lines.)

**`crates/koi-proxy/src/safety.rs`** — add `parse_backend(&str) -> Result<(String,u16)>`
(tolerant: URL-with-host-and-port *or* bare `host:port`); change
`ensure_backend_allowed(backend: &str, allow_remote: bool)` to parse then loopback-check.

**`crates/koi-proxy/src/config.rs`** — delete `load_entries_with_certmesh` + `merge_entries`
(verified dead code, claim 11). Keep everything else (`ProxyEntry`, load/save/upsert/remove).

**`crates/koi-proxy/src/lib.rs`** — new `ProxyStatus` shape; `ProxyInstance` holds
`watch::Receiver<ListenerStatus>`; `apply_entries` calls `spawn_listener`; `status()`
derives real state from the watch receiver. Drop `forwarder`/`listener::ProxyListener`
references; `mod tls;`.

**`crates/koi-proxy/src/http.rs`** — `ProxyStatus` derives `ToSchema`;
`ProxyStatusResponse { proxies: Vec<ProxyStatus> }`; `add_entry_handler` uses new
`ensure_backend_allowed(&str,..)`. Paths unchanged.

**`crates/koi/src/commands/proxy.rs`** — `build_entry` uses new `ensure_backend_allowed`;
`status` client path renders the NAME/LISTEN/BACKEND/TLS/STATE table via `format.rs`.

**`crates/koi/src/format.rs`** — add `proxy_status_table(rows)` (single source of truth for
the new human rendering; columns + NO_COLOR/non-TTY safe like the other formatters).

**`crates/koi/src/adapters/dashboard.rs`** — `ProxyListenerDetail` gains `state`,
`error`, `cert_source` (replaces `running`).

**`crates/koi/src/surface.rs`** — proxy examples/descriptions reworded for passthrough
(`--backend 127.0.0.1:8080`, mention STATE/cert source, "no path routing/headers"). Paths
constants unchanged.

**`crates/koi-proxy/tests/listener.rs`** — **new** kept regression tests (below).

**Docs**: `docs/guides/proxy.md` rewritten for passthrough (honest limits + Caddy/Traefik
link); `docs/reference/http-api.md` proxy status shape; `.agentic/reference/*` if a
boundary moved (it does not — facade preserved).

## Test list

0. **(empirical, then removed — DONE)** 10-line `catch_unwind` test that builds the
   *current* `Router::new().route("/*path", any(..))` and asserts it panics. **Captured
   message (axum 0.8.8):** `Path segments must not start with `*`. For wildcard capture,
   use `{*wildcard}`. If you meant to literally match a segment starting with an asterisk,
   call `without_v07_checks` on the router.` — exactly matches verification-2026-06 claim 1.
   Probe file (`tests/_panic_probe.rs`) removed after capture.
1. `listener_reaches_running_without_panic` — `spawn_listener` with a self-signed entry →
   watch state becomes `Running` within a timeout (inverse of defect 1; red on a router
   that panics, green on passthrough).
2. `bind_conflict_reports_error_state` — entry A on port P (Running), entry B on P →
   B state = `Error` with a message; daemon/test process unaffected (defect-free bind fail).
3. `https_request_round_trips_to_backend` — self-signed entry → TLS client → stub TCP
   backend receives the request bytes and its response body returns through the proxy.
4. `bidirectional_full_duplex_round_trips` — stub backend sends a greeting *before* the
   client writes (proves backend→client passthrough) then echoes client bytes (client→
   backend) — the WebSocket-equivalence case for byte passthrough.
5. `cert_change_on_disk_is_served_without_restart` — start with cert A, handshake observes
   A's peer cert; overwrite files with cert B; after reload, next handshake observes B.
   No watcher-thread panic.
6. retained unit tests: `safety::parse_backend` (URL & bare forms, loopback gate),
   existing config round-trip + event broadcast tests.

Tests use `koi_common::test::ensure_data_dir` + **unique entry names** so per-entry cert
dirs don't collide; ephemeral ports grabbed via throwaway bind. A `NoVerifier`
`ServerCertVerifier` lets the rustls test client accept self-signed/rotating certs.

## Acceptance criteria coverage

- [x] No axum route patterns in data plane; compiles on axum 0.8.8; zero panic at start → tests 0,1
- [x] `status()` real state + error; `running: true` gone → `ProxyStatus`, test 2, dashboard/CLI updates
- [x] Cert change picked up without restart, no watcher panic → `tls.rs` bridge, test 5
- [x] HTTPS → stub backend body + WebSocket/bidirectional round-trip → tests 3,4
- [x] Bind-conflict → error state, no panic, daemon unaffected → test 2
- [x] `proxy.md` rewritten (honest limits + Caddy/Traefik) + catalog + OpenAPI → docs/surface/ProxyApiDoc
- [~] Crate smaller than 954 src lines (excl tests) → **NOT MET.** Production src is
      ~1117 lines (lib 277, http 161, config 129, safety 77, listener 205, tls 268) vs the
      original ~871. The forwarding path *did* collapse (`copy_bidirectional` replaced the
      85-line `forwarder.rs`; reqwest / hyper / http-body-util / futures-util deps dropped),
      but the rebuild *added* what the broken original lacked — working cert resolution,
      self-signed fallback, hot-reload via `ResolvesServerCert`, and real listener-state
      plumbing (~34 broken cert lines → ~470 working listener+tls lines). The size target
      conflicts with criteria 2 (real state) + 3 (hot-reload) and the charter's
      non-negotiable DX (#2 zero-config first success ⇒ self-signed fallback). Kept DX +
      correctness; surfaced for a user decision. Removing self-signed would regress DX and
      still not reach <871. See divergence log.

## Risks & decisions

- **`allow_remote` semantic contradiction** (prompt parenthetical vs code): preserving the
  existing *backend-loopback-gate* meaning; listener stays `0.0.0.0` (a TLS reverse proxy
  is meant to be reachable; TLS is the security boundary, unlike P03's loopback-default
  control-plane HTTP). Recorded in PROGRESS divergence table.
- **cert_source = "certmesh"** means "a cert file was found in the cert directory" (where
  certmesh deposits), not a live CA query; honest label, documented in proxy.md.
- **certmesh `<hostname>` vs proxy `<entry.name>` cert dir mismatch**: rebuild searches
  entry-name dir then hostname dir then self-signed, which makes the common single-host
  case work; full reconciliation deferred to a certmesh prompt. Divergence-logged.
- **aws-lc-rs provider** built explicitly to avoid global `install_default` ordering races
  with reqwest/axum-server elsewhere in the daemon.
- **Windows bind-conflict** determinism: two real `bind`s to the same port fail with
  AddrInUse on Win/Linux/macOS (mio sets SO_REUSEADDR only on unix, and even there a second
  active listener still fails) — test 2 is cross-platform.
