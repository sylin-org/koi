---
type: REF
domain: mcp
title: "MCP — an AI-agent door into your LAN"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.9.0
validation:
  date_last_tested: 2026-06-22
  status: verified
  scope: "integration (mcp_http::tests::mcp_client_over_tcp_through_auth_layer — a real rmcp client over TCP through the production DAT auth layer asserts the 11 v1 tools + resources list/read AND tokenless rejection; streamable_http_session_lists_and_reads_resources drives initialize→list→read; http-session auth tests mcp_get_without_token_is_rejected / mcp_options_preflight_is_not_blocked / non_mcp_get_stays_exempt / server_card_get_is_unauthenticated / mcp_http_disabled_fallback_is_503 / server_card_describes_streamable_http; koi-mcp unit tools::tests). The stdio `koi mcp serve` config recipe is code-reviewed against cli.rs + koi-mcp; not independently live-tested."
---

# MCP — an AI-agent door into your LAN

> One-screen map of Koi's MCP server: it hands the LAN substrate to an AI agent. Deeper walkthrough: [mcp.md](../../guides/mcp.md) · transport/auth shapes: [http-api.md](../http-api.md).

**What it does** — An AI agent reasons well but is blind to your network: it cannot see that `grafana` lives at `10.0.0.42:3000`, that a health check is red, or that another agent is already on the LAN. Koi already knows — it discovers (mDNS), names (DNS), monitors (health), and tracks runtime — and exposes that knowledge over the [Model Context Protocol](https://modelcontextprotocol.io). Two transports, **same surface**: `koi mcp serve` runs MCP over **stdio** (the host spawns it as a subprocess; it speaks to the local daemon via the breadcrumb / `KOI_ENDPOINT`+`KOI_TOKEN`), and the daemon **also** serves MCP over **Streamable HTTP** at `/v1/mcp` on its HTTP port (default 5641, backed by the live cores) so a host on a machine *without* Koi can reach a remote Koi node with one URL. CA administration is deliberately **not** exposed (`certmesh create/promote/destroy/unlock` stay on the human CLI).

## The one canonical pattern

Point your MCP host at Koi. Local host with Koi installed → stdio. Remote/Koi-less host → the HTTP URL.

```bash
# Local (stdio): the host spawns the subprocess; daemon found via breadcrumb.
claude mcp add koi -- koi mcp serve
#   → .mcp.json: {"command":"koi","args":["mcp","serve"]}

# Remote (Streamable HTTP): one URL, token on every request.
claude mcp add --transport http koi https://koi-host.internal/v1/mcp \
  --header "x-koi-token: $(koi token show)"
```

Then ask the agent to orient: it calls **`lan_inventory`** first (status + health + DNS joined), `lan_discover` to browse, `dns_add` to give a service a stable name, or `lan_announce` to publish its own endpoint (auto-heartbeated, auto-unregistered on shutdown).

## Commands & flags you'll use

| Command / flag / endpoint | What it does |
|---|---|
| `koi mcp serve` | Serve MCP over **stdio** against the local daemon (for an MCP host to spawn). |
| `GET/POST /v1/mcp` | In-process MCP over Streamable HTTP. **Token on every method** — incl. the server→client SSE **GET** (carved out of the GET exemption). |
| `--no-mcp-http` (`KOI_NO_MCP_HTTP`) | Disable the HTTP transport. Default **enabled**; disabled → `/v1/mcp` returns `503 capability_disabled`. Reported on `/v1/status` as `mcp_http`. |
| `koi token show` / `koi token write <path>` | Print the daemon token / write a `0600` file (containers). The token is **never** echoed in MCP output. |
| `GET /.well-known/mcp/server-card.json` | **Unauthenticated** discovery descriptor (the "Door"): `{name, version, mcp:{enabled, transport:"streamable-http", path:"/v1/mcp", auth:{scheme:"bearer", header}}}`. No secrets. |

**Tools (11):** `lan_inventory`, `lan_discover`, `lan_resolve`, `lan_announce`, `lan_unregister`, `mcp_servers_on_lan`, `dns_lookup`, `dns_add`, `dns_remove`, `health_snapshot`, `runtime_instances`. **Resources:** `koi://lan/inventory`, `koi://health`, `koi://dns/zone`, `koi://mdns/services` (read = snapshot on both transports; live `resources/updated` deltas are HTTP-only).

## The escape hatch / limits

`/v1/mcp` rides the daemon's `--http-bind` — **loopback by default**. For cross-host reach, front it with Koi's TLS proxy + a certmesh/ACME-issued in-zone cert so the token travels inside real HTTPS with a verifiable Origin. **LAN discovery is automatic:** the daemon advertises exactly one `_mcp._tcp` mDNS record per host (`transport=streamable-http;path=/v1/mcp`), an in-zone `_mcp.<host>.<zone>` DNS TXT when DNS serves the zone, and the public server-card above — so an agent can find a Koi MCP door without prior config. MCP-HTTP is a **transport, not a domain rung**, and is **not** in `/openapi.json`. Need only the baseline? stdio always works; the HTTP transport is purely additive.

## The proof it works

Integration: `mcp_http::tests::mcp_client_over_tcp_through_auth_layer` brings the service up behind the **production DAT auth middleware** on a real TCP listener and drives it with a real `rmcp` MCP client — asserting the **11** tools, the `koi://lan/inventory` resource, a `koi://health` read, **and** that a tokenless client is rejected at initialize. `streamable_http_session_lists_and_reads_resources` drives initialize → resources/list → resources/read against a mock source. The auth carve-out is pinned by `mcp_get_without_token_is_rejected`, `non_mcp_get_stays_exempt`, `mcp_options_preflight_is_not_blocked`, and `server_card_get_is_unauthenticated`; the gate by `mcp_http_disabled_fallback_is_503`; the Door shape by `server_card_describes_streamable_http`. koi-mcp's `tools::tests` cover the tool helpers (announce payload, record-type parse, endpoint projection). The stdio config recipe is code-reviewed against `crates/koi/src/cli.rs` (`McpSubcommand::Serve`) + `crates/koi-mcp`; not independently live-tested.
