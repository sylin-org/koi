# P14 — MCP over Streamable HTTP — Plan

> Branch: `dev` (autonomous). Phase per commit; `cargo check` after each unit,
> full gate before each commit. Backed by a 5-subsystem code map (line numbers verified
> against current `dev`). Charter principles 8 (runtime tunables), 9 (API-first), 10
> (collaboration: their MCP format, no Koi knowledge required), 5 (secure path = easy path).

## Goal

In-process MCP server over **Streamable HTTP** at `/v1/mcp` on the existing axum adapter
(5641), backed by the live cores; MCP **resources** (snapshot-on-subscribe + deltas); LAN
discovery **without per-node flood** (one `_mcp._tcp` per host + in-zone TXT + well-known
card). stdio unchanged.

## Architecture (resolved)

- `KoiSource` trait + `Server<S>` + `streamable_http_service<S>()` live in **koi-mcp**
  (generic, no domain deps). `CoreSource(DaemonCores)` lives in the **binary**
  (`adapters/mcp_http.rs`). `ClientSource(KoiClient)` lives in koi-mcp (stdio).
- Resources delta seam: `KoiSource::change_stream() -> Option<broadcast::Receiver<ResourceChange>>`.
  `CoreSource` merges domain broadcasts (mirror `forward.rs`); `ClientSource` → `None`.
- Auth: `/v1/mcp` requires `x-koi-token` for **all** methods (carved OUT of GET-exemption);
  server-card GET is public.
- Status: `/v1/status` gains an `mcp_http` field (NOT an 8th `assemble_capabilities` rung).
- `/v1/mcp` is OpenAPI-exempt (like ACME) + negative test.

## File-by-file

### Phase 1 — KoiSource abstraction (koi-mcp; no behavior change)
- `crates/koi-mcp/src/source.rs` (NEW): `#[async_trait] trait KoiSource: Send+Sync+'static`
  with `is_available`, `browse(ty,window)->Vec<ServiceRecord>`, `resolve`, `register`,
  `unregister`, `heartbeat`, `unified_status`, `health_status`, `dns_list`, `dns_lookup`,
  `dns_add`, `dns_remove`, `runtime_instances` (typed, not `get_json`), and
  `fn change_stream(&self)->Option<broadcast::Receiver<ResourceChange>>` (default `None`).
  `enum SourceError`. `struct ClientSource(Arc<KoiClient>)` impl — wraps `client::call` +
  `tools::collect_browse`; `change_stream`→`None`. `enum ResourceChange { Inventory, Health,
  Dns, Mdns }`.
- `crates/koi-mcp/src/server.rs`: `Server<S: KoiSource>{ source: Arc<S>, registry: Registry }`;
  `impl<S: KoiSource> Server<S>` (tool_router) + `impl<S: KoiSource> ServerHandler for Server<S>`
  (tool_handler). Handlers L67–376: `call(&self.client,…)`→`self.source.*().await`;
  `require_daemon`→guard on `self.source.is_available().await`. `client_error_result`→over `SourceError`.
- `crates/koi-mcp/src/heartbeat.rs`: `Registry::track/shutdown/spawn_heartbeat` take a
  `source: Arc<S>` (or a heartbeat fn) and call `source.heartbeat`/`source.unregister`
  (drop the `&Arc<KoiClient>` coupling).
- `crates/koi-mcp/src/lib.rs`: `pub use source::{KoiSource, ClientSource, ResourceChange, SourceError}`;
  `pub type StdioServer = Server<ClientSource>`; `serve()` builds `Server::new(Arc::new(ClientSource(Arc::new(client))))`.
- `crates/koi/src/commands/mcp.rs`: unchanged call into `koi_mcp::serve` (still consumes KoiClient).
- `crates/koi-mcp/tests/stdio_session.rs`: `Server::new(...)` → `StdioServer`/`Server<ClientSource>`.
- Verify: 11 tool names + annotations identical.

### Phase 2 — Transport + CoreSource + tunable + auth + 503 + status
- root `Cargo.toml` L127: rmcp features += `transport-streamable-http-server` (verify exact name).
- `crates/koi-mcp/Cargo.toml`: inherit; (no axum, no domain deps).
- `crates/koi-mcp/src/lib.rs`: `pub type McpHttpService<S> = StreamableHttpService<Server<S>, LocalSessionManager>;`
  `pub fn streamable_http_service<S: KoiSource>(source: Arc<S>) -> McpHttpService<S>` —
  `StreamableHttpService::new(move || Ok(Server::new(source.clone())), Arc::new(LocalSessionManager::default()), cfg{ stateful_mode:true, .. })`. (Per-session Server ⇒ per-session Registry ⇒ session-scoped announce drain.)
- `crates/koi/src/adapters/mcp_http.rs` (NEW): `struct CoreSource{ cores: DaemonCores }` impl
  `koi_mcp::KoiSource` — async core calls (no spawn_blocking): browse→`MdnsCore::subscribe_type`
  collect over window; resolve→`MdnsCore::resolve`; register/unregister→`MdnsCore` (SYNC);
  health_status→`HealthRuntime.core().snapshot().await` serialized to the HTTP shape;
  unified_status→`assemble_capabilities`+fields (reuse dashboard/`prometheus_sd` snapshot code);
  dns_*→`DnsCore`; runtime_instances→`RuntimeCore::list_instances().await`;
  `change_stream`→merged domain broadcasts. `is_available`→true (per-capability → 503-shaped error if a needed core is None).
- `crates/koi/src/adapters/http.rs`: `paths::MCP="/v1/mcp"`, `paths::MCP_SERVER_CARD`;
  mount `.nest_service(paths::MCP, koi_mcp::streamable_http_service(Arc::new(CoreSource…)))`
  when enabled else `.nest(paths::MCP, disabled_fallback_router("mcp-http"))` (in `app` before
  Extension/auth/CORS); `dat_auth_middleware` L491-497 — carve `/v1/mcp` out of GET-exemption
  (`let is_mcp = path.starts_with("/v1/mcp"); if !is_mcp && (GET|HEAD|OPTIONS) {exempt}`);
  `AppState` += `mcp_http_enabled: bool`; `unified_status_handler` push `mcp_http` field;
  thread `mcp_http_enabled` (+ the service/cores) through `start`. CORS `allow_headers` +=
  `mcp-session-id`,`mcp-protocol-version` (browser clients).
- `crates/koi/src/cli.rs`: `no_mcp_http` (Cli L109, Config L610, from_cli L646,
  from_env(windows) ~L756/802, Default L832, require_capability "mcp-http"). + test fixture.
- `crates/koi/src/daemon.rs` L105 + `platform/windows.rs` L531: pass the new `start` arg.
- Tests: `get /v1/mcp no token → 401`; `post /v1/mcp token → !401`; disabled → 503;
  `!openapi.contains("/v1/mcp")`; require_capability("mcp-http") pair.

### Phase 3 — Resources
- `crates/koi-mcp/src/server.rs` get_info L407: `.enable_tools().enable_resources()` (subscribe=true).
- `crates/koi-mcp/src/resources.rs` (NEW): URI set + `list_resources`/`read_resource`/`subscribe`
  on `ServerHandler` (hand-written, not macro). read = `source.*` snapshot. subscribe = snapshot
  + spawn task draining `source.change_stream()` filtered to URI → `peer.notify_resource_updated`.
- Test: subscribe returns snapshot; a core state change yields `resources/updated`
  (CoreSource in-proc fixture).

### Phase 4 — Discovery descriptors
- `crates/koi/src/daemon.rs` (announce block ~L214, shutdown ~L276) + `platform/windows.rs`
  (~L598): `_mcp._tcp` `MdnsCore::register` (gated), capture `mcp_announce_id`; in-zone
  `DnsCore::add_txt("_mcp.<host>.<zone>", "transport=streamable-http;path=/v1/mcp")` when `cores.dns` Some.
- `crates/koi-compose/src/cores.rs` `ordered_shutdown` L349: add `mcp_announce_id: Option<String>`
  param + goodbye block (mirror L363-369); update both call sites.
- `crates/koi/src/adapters/http.rs` (or `adapters/mcp_card.rs`): `build_server_card(...)` pure fn +
  `mcp_server_card_handler` (public GET), `.route(paths::MCP_SERVER_CARD, get(...))`. Reuse
  `MCP_SERVICE_TYPE` + `to_mcp_endpoints` TXT vocab.
- Tests: pure `build_server_card`; one `_mcp._tcp` record when enabled, zero when disabled.

### Phase 5 — Docs + SURFACES + reference + catalog
- `docs/guides/mcp.md` (delete deferred bullets L133-138 + the L129 deferral; add HTTP/Resources/discovery).
- `docs/reference/http-api.md` (System table; auth-exception note for /v1/mcp; OpenAPI-exempt prose).
- `docs/reference/cli.md`, `.agentic/CONTEXT.md` tunables table, `.agentic/reference/api-endpoints.md`,
  `.agentic/reference/utilities.md` (path consts), `docs/reference/architecture.md` (koi-mcp row/edge).
- `docs/SURFACES.md`: rewrite the `mcp` row + 3 new rows (`/v1/mcp`, server-card, in-zone TXT,
  `_mcp._tcp`), 5 cells, date `2026-06-15`, guard = koi-mcp/koi tests (ci.yml). Run `lint-surfaces.sh`.
- `crates/koi/src/help/meta.rs`: `mcp serve` long_description prose (no new clap leaf).

## Test list (risk-first)
- koi-mcp: HTTP Streamable session (initialize→tools/list→read tool) over in-proc CoreSource mock;
  resources/list+read+subscribe snapshot; resources/updated on state change; stdio session unchanged.
- binary http.rs: /v1/mcp GET-no-token 401; POST-token ok; disabled 503; server-card 200 public;
  /v1/mcp not in openapi; require_capability mcp-http.
- daemon: exactly one `_mcp._tcp` when enabled, none when disabled; goodbye on shutdown.
- prometheus_sd-style pure tests for `build_server_card`.

## Risks / divergences (resolved, recorded here for the ledger)
1. **Map contradiction on auth direction** — resolved: `/v1/mcp` is AUTHENTICATED for all
   methods (not exempt like /certmesh/join). Matches the spec + the user's design.
2. **Status as field, not rung** — deliberate: MCP-HTTP is a transport (like `--no-http`),
   not a domain core; `assemble_capabilities` stays a 7-rung domain-pure ladder.
3. **rmcp HTTP feature name + per-session factory lifecycle** — verify against pinned rmcp
   1.7 source before Phase 2; confirm the factory runs per session (so per-session Registry
   drains announcements on session end) — if no teardown hook, the heartbeat-lease drains
   it naturally (defense in depth).
4. **ClientSource has no live deltas** — stdio resources are snapshot-only (`change_stream`
   None); documented, not a bug. Live deltas are an in-proc (CoreSource) capability.
5. **CoreSource must reproduce HTTP JSON shapes** for unified_status/health/dns/runtime —
   reuse the dashboard/prometheus_sd snapshot code paths as the source of truth.
6. **Windows parity** — every daemon.rs change mirrored in windows.rs + `Config::from_env`;
   the compile gate catches signature drift but the announce/goodbye logic is hand-duplicated.
