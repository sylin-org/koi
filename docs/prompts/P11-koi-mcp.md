# P11 — koi-mcp: the LAN Substrate for AI Agents

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: P03 (token UX) · Read `docs/prompts/CHARTER.md` first.
> Strategy basis: docs/assessment/research/trends-opportunities-2026.md §1 — local MCP
> discovery is an unsolved niche with one weak incumbent; this is Koi's highest-leverage
> strategic build.

## Mission

Give AI agents a first-class door into the local network: an **MCP server** exposing
Koi's discovery, naming, trust, and health as tools — so a coding agent can ask "what's
on this network," "give the app I just built a stable name and a trusted cert," and
"is it healthy" instead of port-scanning localhost. Koi should also *advertise* MCP
endpoints via DNS-SD (`_mcp._tcp`), positioning it as the thing that makes other local
MCP servers discoverable. Per the doctrine: Koi is the substrate agents discover
services *through* — not an agent framework, gateway, or registry.

## Load context first

1. `docs/prompts/CHARTER.md`
2. `docs/assessment/research/trends-opportunities-2026.md` §1 (evidence + anti-goals)
3. `crates/koi-client/src/lib.rs` (the blocking HTTP client — likely your backend),
   `crates/koi/src/adapters/http.rs` (endpoints + auth), domain protocol types
4. Research the current **rmcp** (official Rust MCP SDK) via its docs/crates.io — API
   has been moving; verify against the version you pin, and note its DNS-rebinding
   advisory (the spec requires Origin validation for HTTP transports)

## Research phase

- MCP transports: stdio (what Claude Desktop/Code, Cursor etc. spawn) vs streamable
  HTTP. **Ship stdio first** — `koi mcp serve` as a spawnable subcommand is zero-config
  and sidesteps the HTTP-auth design; evaluate HTTP as a documented follow-up only.
- Tool design: study 3–4 well-regarded MCP servers for naming/description conventions
  (tools must be self-describing for the *agent*, not for humans).
- How the MCP process reaches the daemon: breadcrumb + token (koi-client already does
  this); behavior when no daemon runs (fail with actionable guidance, or standalone
  mDNS-only mode? — decide in plan; recommend: require daemon, clear error).
- Annotation hygiene: which tools are read-only vs mutating (MCP `readOnlyHint` /
  destructive hints); lease defaults for agent-created announcements (heartbeat lease
  so agent crashes clean up — charter principle 7).

## Target experience (north star)

```jsonc
// claude_desktop_config.json / .mcp.json — the whole setup:
{ "mcpServers": { "koi": { "command": "koi", "args": ["mcp", "serve"] } } }
```

Tool surface v1 (names are the API — keep them; descriptions are sketches):

| Tool | Kind | Maps to |
|---|---|---|
| `lan_discover` | read | GET /v1/mdns/discover (bounded: collect for `timeout_secs`≤10, return array — SSE stays internal) |
| `lan_resolve` | read | GET /v1/mdns/resolve |
| `lan_announce` | write | POST /v1/mdns/announce (heartbeat lease; returns id + lease; MCP server auto-heartbeats while alive, unregisters on shutdown) |
| `lan_unregister` | write | DELETE /v1/mdns/unregister/{id} |
| `dns_lookup` / `dns_add` / `dns_remove` | read/write | /v1/dns/* |
| `lan_inventory` | read | the joined view: discovered services + DNS names + cert status + health + runtime instances (the "LAN inventory API" differentiator — one tool an agent calls to understand the network) |
| `health_snapshot` | read | GET /v1/health/status |
| `runtime_instances` | read | GET /v1/runtime/instances |
| `mcp_servers_on_lan` | read | discover `_mcp._tcp` + `_mcp._sub` types specifically; return endpoints agents can connect to |

Sample exchange the README must show:

```
agent: lan_announce {"name":"my-dev-app","type":"_http._tcp","port":3000}
koi:   {"registered":{"id":"a1b2c3d4","name":"my-dev-app","lease_secs":90}}
agent: dns_add {"name":"my-dev-app","ip":"<auto>"}        # ip auto = host lan ip
koi:   {"added":{"name":"my-dev-app.internal","ip":"192.168.1.42"}}
→ the agent's Playwright session opens http://my-dev-app.internal:3000 — a stable name.
```

Crate shape: new `crates/koi-mcp` (or a `koi mcp serve` module in the binary calling
into it — prefer the crate for testability; binary adds the subcommand). Daemon-side:
announce Koi's own `_koi-mcp._tcp` (or `_mcp._tcp` with TXT `name=koi`) when the
feature is active — research the emerging convention before choosing the type string,
note findings in the plan.

## Plan, then implement

Per charter: rmcp spike (echo server compiling against pinned version) → tool schemas
+ readonly/destructive annotations → koi-client-backed handlers (spawn_blocking around
the blocking client) → lease auto-heartbeat lifecycle → `koi mcp serve` subcommand +
catalog entry → `_mcp._tcp` discovery tool → docs (`docs/guides/mcp.md` with the
config-snippet quickstart + the worked agent session above).

## Acceptance criteria

- [ ] `koi mcp serve` speaks MCP over stdio; tools/list returns the v1 surface with
      accurate schemas and read-only/destructive annotations.
- [ ] Mutations require a reachable daemon and use the breadcrumb token; without a
      daemon every tool returns an actionable error naming `koi --daemon`.
- [ ] `lan_announce` registrations heartbeat automatically and unregister on MCP
      shutdown (test: kill the MCP process; entry drains per lease).
- [ ] `lan_discover` is bounded (no unbounded streams through MCP); `lan_inventory`
      joins ≥3 sources.
- [ ] Integration test: scripted stdio session (initialize → tools/list → one read
      tool against a test daemon) in `cargo test` (mark `#[ignore]` only if it needs
      live multicast; inventory/dns paths shouldn't).
- [ ] `docs/guides/mcp.md` exists with copy-paste configs for Claude Code/Desktop and
      one generic client; README gains a one-paragraph pointer; catalog updated.
- [ ] Workspace green per charter commands.

## Do NOT

- Build HTTP/SSE transport, OAuth, gateways, routing, or registry features (v1 is
  stdio; the anti-goals list in the research doc governs).
- Expose certmesh CA-admin operations (create/promote/destroy/unlock) as MCP tools —
  agents get service-level powers, not CA-root powers. Cert *provisioning* for a
  service may come later via P12's ACME; not here.
- Let any tool bypass DAT auth or embed the token in tool output.
