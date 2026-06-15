# P11 — koi-mcp (LAN substrate for AI agents) — Plan

> Branch: `dev` (autonomous). Additive feature. Research (web-verified) archived in the run
> transcript: rmcp **1.7** API confirmed compiling, conventions, koi-client map.

## Crate

New `crates/koi-mcp` (testable; binary adds `koi mcp serve`). Deps: `rmcp = { version = "1.7",
features = ["server", "transport-io", "macros"] }`, koi-client, koi-config (breadcrumb), tokio,
serde, serde_json, anyhow, tracing. **schemars is re-exported by rmcp** (`rmcp::schemars`) — do
NOT add it. `rust-version = "1.92"`; rmcp is edition-2024 (needs ≥1.85) — **VERIFY the full dep
tree resolves under MSRV 1.92** before committing (the one real risk).

## rmcp API (verified shape)

`#[tool_router]` (no arg) on `impl Server` + a SEPARATE `#[tool_handler] impl ServerHandler`
(the `server_handler` macro arg conflicts with a custom `get_info` → E0119). `ServerInfo` is
`#[non_exhaustive]` → `ServerInfo::default()` then mutate. Tools: `#[tool(description="…",
annotations(read_only_hint=…, destructive_hint=…, idempotent_hint=…))]`, take
`Parameters(Req): Parameters<Req>` (Req: `serde::Deserialize + rmcp::schemars::JsonSchema`),
return `Result<CallToolResult, ErrorData>`; `CallToolResult::success(vec![Content::text(..)])`
or `::structured(serde_json::Value)`. Serve: `Server::new(..).serve(stdio()).await?.waiting().await?`.
**Read-only tools MUST set `read_only_hint=true`; additive writers set `destructive_hint=false`.**

## Server + daemon reach

Server holds `KoiClient` via `KoiClient::from_breadcrumb()` (breadcrumb endpoint+token), falling
back to `KOI_ENDPOINT`/`KOI_TOKEN` env. **koi-client is blocking ureq → wrap every call in
`tokio::task::spawn_blocking`.** No daemon → each tool returns an actionable error naming
`koi --daemon` (probe with `client.health()` 200ms). NEVER put the token in tool output.

## Tool surface v1 (names are the API)

| Tool | hints | koi-client |
|---|---|---|
| `lan_discover` {type?, timeout_secs≤10=5} | read, open-world | `browse_stream` collected within a time bound (spawn_blocking) |
| `lan_resolve` {instance} | read | `resolve` |
| `lan_announce` {name,type,port,txt?} | write, !destructive, idempotent | `register` (heartbeat lease) + auto-heartbeat + unregister-on-shutdown |
| `lan_unregister` {id} | write | `unregister` |
| `dns_lookup` {name,record_type?} / `dns_add` {name,ip?} / `dns_remove` {name} | read/write | `dns_lookup`/`dns_add`/`dns_remove` |
| `lan_inventory` {include?} | read | join `unified_status` + `health_status` + `dns_list` (+ admin_registrations) — ≥3 sources |
| `health_snapshot` | read | `health_status` |
| `runtime_instances` | read | `get_json("/v1/runtime/instances")` |
| `mcp_servers_on_lan` | read | browse `_mcp._tcp` (+ `_mcp._sub`); return connectable endpoints |

Tool descriptions per the agent-audience style (what + when + returns + side-effects); drafts in
the research. CA-admin ops (create/promote/destroy/unlock) are NOT exposed (charter Do-NOT).

## Lease auto-heartbeat lifecycle

Server keeps shared state `Arc<Mutex<HashMap<id, ()>>>` (or a registry handle). `lan_announce`
registers (heartbeat lease), spawns a background task that `heartbeat(id)` at ~⅓ `lease_secs`;
on server shutdown (Drop / the `.waiting()` returning), `unregister` all tracked ids. Test: an
agent crash ⇒ the entry drains per lease (the heartbeat task dies with the process).

## `_mcp._tcp`

No DNS-SD standard exists (two IETF drafts use unicast `_mcp.<domain>` TXT, not mDNS). `mcp_servers_on_lan`
browses `_mcp._tcp` as **Koi's convention** (documented as pending a standard; TXT vocab aligned
to the drafts: `v=mcp1, transport=, path=, name=`). **Daemon self-announce of its own stdio MCP
is DEFERRED** — a stdio server has no network endpoint to connect to; self-announce becomes
meaningful only with the HTTP transport follow-up. Note this in the guide (honest, not a gap).

## Sequence (per charter)

rmcp echo spike compiling under MSRV 1.92 → tool schemas + annotations → koi-client-backed
handlers (spawn_blocking) → lease auto-heartbeat → `koi mcp serve` subcommand + help/meta entry →
`mcp_servers_on_lan` → integration test (scripted stdio: initialize → tools/list → one read tool;
tools/list needs no daemon; a read tool can run against a test daemon or a mocked client) →
`docs/guides/mcp.md` (Claude Code/Desktop + generic configs + the worked agent session) + README
pointer + catalog.

## Acceptance (from the prompt)

`koi mcp serve` speaks MCP/stdio; tools/list = v1 surface w/ accurate schemas + annotations;
mutations need a daemon + breadcrumb token (actionable error without); lan_announce auto-heartbeats
+ unregisters on shutdown; lan_discover bounded; lan_inventory joins ≥3; integration test in
`cargo test`; docs/guides/mcp.md + README + catalog; workspace green.
