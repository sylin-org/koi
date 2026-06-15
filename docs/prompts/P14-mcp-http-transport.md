# P14 — MCP over Streamable HTTP: the in-process transport

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: L · Prereqs: P11 (koi-mcp stdio server), P03 (token UX) · Read `docs/prompts/CHARTER.md` first.
> This prompt was authored *after* a full prior-art research sweep and a 5-subsystem code
> map; the resolved design below is not a sketch — it is the decision. Verify the cited
> line numbers against current code (the repo has known drift) but do not relitigate the
> architecture without a stop-and-surface.

## Mission

P11 shipped `koi mcp serve` — an MCP server over **stdio** that a host spawns as a
subprocess. Its hard limit: a machine **without** Koi installed cannot reach a host
**with** Koi serving MCP. Close that gap.

Add an **in-process MCP server over Streamable HTTP** mounted at `/v1/mcp` on the
**existing** axum adapter (port 5641), running against the **live domain cores**, so a
Claude-Code-class client on any machine can reach a remote Koi host's MCP surface with one
config line. Expose Koi's live LAN state as **MCP resources** (snapshot-on-subscribe +
`resources/updated` deltas), and make MCP hosts **discoverable on the LAN without flooding
mDNS** — one record per host, never one per service.

stdio stays exactly as-is (the universal baseline). The HTTP transport is purely additive.

## Why this shape (the resolved decisions — do not relitigate)

- **Streamable HTTP, stateful, single endpoint.** rmcp 1.7 ships `StreamableHttpService`
  (a `tower::Service` over `http` 1.x — mounts into axum 0.8 via `.nest_service`). Use
  `StreamableHttpServerConfig.stateful_mode = true` + `LocalSessionManager` — the server→
  client SSE stream that `resources/updated` needs *requires* stateful mode. **Not** the
  deprecated HTTP+SSE two-endpoint transport.
- **One transport, two backings, via a `KoiSource` trait.** koi-mcp's tool handlers are
  refactored to call `self.source.<method>().await`. `Server<S: KoiSource>` is generic.
  `ClientSource` (wraps the blocking `KoiClient`, keeps `spawn_blocking`) backs **stdio**;
  `CoreSource` (calls the live cores directly, async, no `spawn_blocking`, no HTTP
  self-call) backs the **in-proc HTTP** path.
- **`CoreSource` lives in the binary crate, not koi-mcp.** koi-mcp may depend only on
  koi-client/koi-config/koi-common (CONTEXT.md rule 2/3 — domain crates never import each
  other; cross-domain wiring is binary-only). So koi-mcp defines the `KoiSource` trait +
  `Server<S>` + a public `streamable_http_service<S>(source)` factory; the **binary**
  implements `CoreSource(DaemonCores)` and mounts it. koi-mcp gains only the rmcp
  `transport-streamable-http-server` feature — **no domain-crate deps, no axum dep**
  (it returns the rmcp tower service; the binary `.nest_service`s it).
- **Resources express "snapshot then live."** MCP is client-driven: the client subscribes,
  the server returns the current snapshot immediately, then streams `resources/updated`.
  The delta seam is `KoiSource::change_stream() -> Option<broadcast::Receiver<ResourceChange>>`:
  `CoreSource` merges the domains' broadcast channels (mirroring
  `koi_dashboard::forward::spawn_event_forwarder`) into one `ResourceChange` stream;
  `ClientSource` returns `None` (stdio = snapshot-only; live deltas are an in-proc feature,
  documented honestly). The notification fan-out lives in koi-mcp (it holds the rmcp peer).
- **Authenticated, including the GET SSE stream.** `/v1/mcp` is carved **out** of the
  GET/HEAD/OPTIONS auth exemption — **every** method requires `x-koi-token` (the spec's
  "SHOULD authenticate all connections"; the SSE GET is a live channel, not a read).
  Claude Code's `--header` passes it: `--header "x-koi-token: <token>"`. (Optionally also
  accept `Authorization: Bearer <token>` as a synonym.) The `/.well-known/mcp/server-card.json`
  GET stays **public** (discovery metadata, no secrets). For cross-host, document fronting
  `/v1/mcp` with Koi's TLS proxy + a certmesh/ACME in-zone cert so it is real HTTPS with a
  verifiable Origin.
- **Discovery without flood — one record per host, gated on the transport.** When the HTTP
  transport is enabled, the daemon self-announces **exactly one** `_mcp._tcp` record (the
  daemon, not per service) with TXT `transport=streamable-http; path=/v1/mcp`, closing the
  loop with the existing `mcp_servers_on_lan` tool; plus one unicast in-zone
  `_mcp.<host>.<zone>` TXT (via `DnsCore::add_txt`, the ACME dns-01 plumbing); plus a
  public `GET /.well-known/mcp/server-card.json` (the Prometheus-SD "Door" pattern). All
  three turn off with the transport and emit a goodbye on shutdown. **Never** per-service
  announcement — that is the flood (IBM ContextForge's removal of mDNS auto-discovery,
  issue #1912, is the decisive external proof to reject it).
- **`--no-mcp-http` / `KOI_NO_MCP_HTTP`**, default enabled, 503 disabled-fallback — exactly
  the `--no-acme` pattern. Surfaced on `/v1/status` as a **field** (like
  `mdns_browse_active`), **not** an 8th rung on the 7-rung domain ladder (MCP-HTTP is a
  transport, not a domain; the `assemble_capabilities` golden test stays intact).
- **OpenAPI-exempt.** `/v1/mcp` is JSON-RPC, not utoipa pipeline shapes — exclude it from
  `/openapi.json` like ACME; add a negative assertion test + a prose section in
  `docs/reference/http-api.md`. The server-card may be documented in prose too.

## Load context first

1. `docs/prompts/CHARTER.md`; `.agentic/CONTEXT.md` (rules 2–5, 9); `.agentic/rules/mdns-boundary.md`.
2. koi-mcp: `crates/koi-mcp/src/{lib,server,tools,client,heartbeat}.rs`, `tests/stdio_session.rs`, `Cargo.toml`.
3. binary: `crates/koi/src/adapters/{http,prometheus_sd,dashboard}.rs`, `crates/koi/src/{daemon,cli,dispatch}.rs`, `crates/koi/src/platform/windows.rs`, `crates/koi/src/help/meta.rs`.
4. composition: `crates/koi-compose/src/{cores,status}.rs`, `crates/koi-dashboard/src/forward.rs`.
5. domains touched by `CoreSource`: `crates/koi-mdns/src/lib.rs` (register/unregister/subscribe/subscribe_type/resolve), `crates/koi-dns/src/resolver.rs` (add_txt/remove_txt/snapshot/subscribe), `crates/koi-health/`, `crates/koi-runtime/`, `koi-common::integration` (MdnsSnapshot/CertmeshSnapshot).
6. rmcp 1.7: verify the `transport-streamable-http-server` feature, `StreamableHttpService::new`, `StreamableHttpServerConfig`, `LocalSessionManager`, and the `ServerHandler` resource methods (`list_resources`/`read_resource`/`subscribe`/`unsubscribe`) + how a handler sends `notifications/resources/updated` (the peer/notification API). Do not guess the rmcp API — read the pinned source.

## Plan, then implement (phase per commit; gate green at each)

1. **`KoiSource` abstraction (koi-mcp only, no behavior change).** New `source.rs`: the
   async `KoiSource` trait (12 read/write methods mirroring the `KoiClient` surface +
   `is_available()` + `change_stream()`), a `SourceError`, and `ClientSource(Arc<KoiClient>)`
   moving the `call()`/`collect_browse` bridge into it. Make `Server<S: KoiSource>` generic
   (struct + both impl headers); rewrite the 11 handlers to `self.source.*`; make `Registry`
   source-aware (heartbeat/unregister via the trait). `lib.rs::serve` and `commands/mcp.rs`
   use `Server<ClientSource>` (add `pub type StdioServer = Server<ClientSource>`). Update
   `stdio_session.rs`. **All 11 tool names + annotations unchanged.** Commit.
2. **Streamable HTTP transport + `CoreSource` + tunable + auth + 503 + status field.**
   Add the rmcp feature; koi-mcp `pub fn streamable_http_service<S>(source) -> McpHttpService<S>`
   (stateful, LocalSessionManager). Binary `adapters/mcp_http.rs`: `CoreSource(DaemonCores)`
   impl `KoiSource` (cores direct, async; `is_available()=true`; reproduce the exact
   `/v1/status`,`/v1/health/status`,`/v1/dns/list`,`/v1/runtime/instances` JSON shapes).
   Mount `.nest_service(paths::MCP, …)` when enabled else `disabled_fallback_router("mcp-http")`,
   inside `app` before the auth/CORS layers. Carve `/v1/mcp` out of the GET-exemption in
   `dat_auth_middleware`. Add `--no-mcp-http`/`KOI_NO_MCP_HTTP` (Cli + Config + from_cli +
   from_env(windows) + Default + require_capability "mcp-http"). Surface `mcp_http` on
   `/v1/status`. Thread the new arg through `http::start` at **both** call sites
   (daemon.rs + windows.rs). Commit.
3. **MCP resources (snapshot-on-subscribe + deltas).** `enable_resources()` (subscribe);
   implement `list_resources`/`read_resource`/`subscribe` on `ServerHandler` for
   `koi://lan/inventory`, `koi://health`, `koi://dns/zone`, `koi://mdns/services`. read =
   `source.*` snapshot. subscribe = snapshot then a task draining `source.change_stream()`
   filtered to the subscribed URI → `notifications/resources/updated`. `CoreSource.change_stream`
   merges domain broadcasts → `ResourceChange` (mirror `forward.rs`). Keep the pull tools as
   the universal-client fallback. Commit.
4. **Discovery descriptors (gated on the transport, goodbye on shutdown).** In daemon.rs
   (+ windows.rs mirror): one `_mcp._tcp` `MdnsCore::register` (TXT
   `transport=streamable-http; path=/v1/mcp; v=mcp1; name=…`), gated on
   `!config.no_mcp_http && !config.no_http && cores.mdns.is_some()`, id retracted via
   `ordered_shutdown` (thread `mcp_announce_id`); one in-zone `_mcp.<host>.<zone>`
   `DnsCore::add_txt` when `cores.dns` is Some; `GET /.well-known/mcp/server-card.json` Door
   (pure `build_server_card` + thin handler, public GET). Reuse `MCP_SERVICE_TYPE` and the
   `to_mcp_endpoints` TXT vocabulary. Commit.
5. **Docs + SURFACES + reference + catalog.** Rewrite the deferred bits of
   `docs/guides/mcp.md` (HTTP face + Resources + discovery; delete the two "follow-up"
   bullets + the "self-announce deferred" paragraph). Add `/v1/mcp` + server-card rows and
   the auth-exception note to `docs/reference/http-api.md`; add the tunable to `cli.md` +
   `.agentic/CONTEXT.md` tunables table + `.agentic/reference/api-endpoints.md`; new
   constants to `.agentic/reference/utilities.md`; update `docs/reference/architecture.md`
   (koi-mcp row/edge). Four SURFACES.md rows (or rewrite the `mcp` row + 3 new), 5 cells,
   real dates, real guards. Update `help/meta.rs` prose (no new clap leaf → no conformance
   churn). Commit.

## Acceptance criteria

- [ ] `koi mcp serve` (stdio) is byte-for-byte unchanged in behavior: `stdio_session.rs`
      passes; 11 tool names + read-only/destructive annotations intact.
- [ ] With the daemon running and the transport enabled, an MCP client reaches
      `POST http://<host>:5641/v1/mcp` with `x-koi-token` and gets `initialize` →
      `tools/list` (the 11 tools) → a read tool result. Integration test: a scripted
      Streamable-HTTP session against an in-proc `CoreSource` (no external daemon needed).
- [ ] `GET /v1/mcp` **without** the token → 401 (the SSE GET is authenticated);
      `POST /v1/mcp` **with** the token → allowed. `GET /.well-known/mcp/server-card.json`
      → 200 unauthenticated, describing transport=streamable-http, path=/v1/mcp, auth header.
- [ ] `resources/list` returns the resource set; `resources/subscribe` returns the current
      snapshot immediately and emits `resources/updated` when the underlying state changes
      (test: drive a state change through a core, assert the notification). Tools remain the
      fallback for clients that don't subscribe.
- [ ] `--no-mcp-http` / `KOI_NO_MCP_HTTP` disables the transport → any `/v1/mcp` request is
      503 `capability_disabled`; the discovery descriptors are **not** published; `/v1/status`
      reports the transport state. Default (enabled) publishes exactly **one** `_mcp._tcp`
      record per host (test the count) and a goodbye fires on shutdown.
- [ ] `/v1/mcp` is **absent** from `/openapi.json` (negative test). `assemble_capabilities`
      still emits exactly 7 rungs (golden test untouched).
- [ ] Windows-service path (windows.rs + `Config::from_env`) wires the transport + descriptors
      + parses `KOI_NO_MCP_HTTP` identically (parity).
- [ ] Docs tell the truth: mcp.md's deferred bullets are gone; the auth exception, the
      tunable, and the new surfaces are documented. SURFACES lint passes. Workspace green
      (`cargo test --locked`, `clippy --locked -D warnings`, `fmt --check`, surfaces lint).

## Do NOT

- Per-service / per-node mDNS announcement (the flood). One `_mcp._tcp` record per **host**,
  gated on the transport. Never name or special-case a downstream consumer (STACK-0001 K2).
- The deprecated HTTP+SSE two-endpoint transport. Streamable HTTP only.
- An OAuth 2.1 authorization server. Reuse the DAT token (the spec mandates OAuth only for
  public servers; static bearer is correct for a LAN tool).
- Expose `/v1/mcp` unauthenticated, or on by default beyond loopback (`--http-bind` stays
  loopback-default; LAN reach is a deliberate operator choice with the existing warnings).
- Add an 8th rung to `assemble_capabilities` (breaks the domain-pure ladder + golden test).
- Import `mdns-sd` anywhere but `koi-mdns/src/daemon.rs`; leak mdns-sd types through
  `CoreSource` (use `MdnsCore`/`BrowseSubscription`).
- Make koi-mcp depend on domain crates. The trait is in koi-mcp; `CoreSource` is in the binary.
- Expose certmesh CA-admin operations as MCP tools, or put the token in any tool/resource output.
