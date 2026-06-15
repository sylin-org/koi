# MCP - The LAN as a substrate for AI agents

AI agents are good at reasoning and bad at knowing what is actually on your network. They cannot see that `grafana` lives at `10.0.0.42:3000`, that the database health check is red, or that another agent is already listening on the LAN. Koi already knows all of this — it discovers services (mDNS), names them (local DNS), monitors them (health), and tracks what is running (runtime). The MCP server hands that knowledge to an agent through the [Model Context Protocol](https://modelcontextprotocol.io), the same way Claude Code, Claude Desktop, and other MCP hosts consume any tool server.

`koi mcp serve` runs an MCP server over **stdio**. The MCP host launches it as a subprocess and speaks JSON-RPC over the pipe; you never run it interactively. Under the hood it is a thin adapter over the same daemon HTTP API the CLI uses — so the agent gets exactly the surface a script would, with descriptions and annotations written for a model audience.

**When to use it**: you want an agent to orient itself on a local network ("what is running here, and is it healthy?"), give a service a stable name, or publish its own endpoint so peers can find it.

**When not to**: certificate-authority administration. The MCP server intentionally does **not** expose `certmesh create/promote/destroy/unlock` — CA operations stay on the human-driven CLI.

---

## Quick start

The server needs a running Koi daemon to talk to (it discovers the daemon via the breadcrumb the daemon writes on startup, or `KOI_ENDPOINT`/`KOI_TOKEN`). Start one:

```bash
koi --daemon
```

Then point your MCP host at `koi mcp serve`.

### Claude Code / Claude Desktop

Add Koi to the host's MCP server configuration (Claude Desktop: `claude_desktop_config.json`; Claude Code: `.mcp.json` in the project, or `claude mcp add`):

```json
{
  "mcpServers": {
    "koi": {
      "command": "koi",
      "args": ["mcp", "serve"]
    }
  }
}
```

That is the whole config. `koi` must be on the host's `PATH` (or give an absolute path to the binary).

### Any generic MCP client

Any stdio-capable MCP client uses the same launch contract — spawn `koi mcp serve` and speak MCP over its stdin/stdout:

```json
{
  "command": "koi",
  "args": ["mcp", "serve"],
  "transport": "stdio"
}
```

To target a non-default daemon (e.g. a remote one), pass an endpoint and token through the environment — the server reads `KOI_ENDPOINT` and `KOI_TOKEN` when no local breadcrumb is found:

```json
{
  "command": "koi",
  "args": ["mcp", "serve"],
  "env": {
    "KOI_ENDPOINT": "http://10.0.0.10:5641",
    "KOI_TOKEN": "<daemon-access-token>"
  }
}
```

> **Security:** the daemon access token authorizes mutations. The MCP server reads it from the breadcrumb (local daemon) or the env var, but **never echoes it** in any tool output. For a remote daemon, hand the token in as `KOI_TOKEN` rather than embedding it in argv.

---

## Tools

All tools operate against the running daemon. Read tools are marked read-only; writers that only add are marked non-destructive; removers are marked destructive — so a host can apply its own confirmation policy.

| Tool | Kind | What it does |
| --- | --- | --- |
| `lan_inventory` | read | One consolidated view: capability status + health + the DNS name table. The agent's first orienting call. |
| `lan_discover` | read | Browse mDNS for a service type (or all types) for up to `timeout_secs` (default 5, max 10). Returns deduplicated service records. |
| `lan_resolve` | read | Resolve one instance name to host/IP/port/TXT. |
| `dns_lookup` | read | Resolve a name through Koi's local DNS resolver (A/AAAA/ANY). |
| `health_snapshot` | read | All health checks with up/down/unknown state. |
| `runtime_instances` | read | Container/service runtime instances Koi is tracking. |
| `mcp_servers_on_lan` | read | Find other MCP servers advertised on the LAN (browses `_mcp._tcp`). |
| `lan_announce` | write (additive) | Publish a service via mDNS with a heartbeat lease. Auto-heartbeated; auto-unregistered on shutdown. Returns the id + lease seconds. |
| `lan_unregister` | write (destructive) | Cancel a service announced with `lan_announce` and stop its heartbeat. |
| `dns_add` | write (additive) | Add/update a static DNS name → IP mapping. Omitting `ip` uses the host's address. |
| `dns_remove` | write (destructive) | Remove a static DNS record by name. |

### No daemon? An actionable error

If no daemon is reachable, every tool returns a clear text error instead of a cryptic transport failure:

> `no Koi daemon reachable — start one with `koi --daemon` (or set KOI_ENDPOINT/KOI_TOKEN)`

`tools/list` always works without a daemon — the schema is static — so a host can introspect the surface before anything is running.

---

## A worked agent session

The point of `lan_announce` + `dns_add` together is a **stable, discoverable name** for something the agent stands up. A typical flow:

1. **Orient.** The agent calls `lan_inventory` and sees the daemon is up, two services are healthy, and `app.lan` is not yet a known name.
2. **Announce its own endpoint.** The agent is serving an HTTP API on port 8080 and wants peers to find it:

   ```
   lan_announce { "name": "Planner Agent", "type": "_http._tcp", "port": 8080 }
   → { "id": "a1b2c3d4", "name": "Planner Agent", "type": "_http._tcp", "port": 8080, "lease_secs": 90 }
   ```

   Koi registers the service with a 90-second heartbeat lease and spins up a background heartbeat at ~⅓ of the lease. The agent does nothing further to keep it alive.
3. **Give it a name.** So peers can reach it as `planner.lan` rather than an IP:

   ```
   dns_add { "name": "planner.lan" }        # ip omitted → the host's address
   → { ... }
   ```
4. **Peers discover it.** Another agent calls `mcp_servers_on_lan` or `lan_discover { "type": "_http._tcp" }` and finds `Planner Agent`; `dns_lookup { "name": "planner.lan" }` resolves the address.
5. **Exit is clean.** When the MCP host closes the session (the agent finishes), `koi mcp serve` cancels the heartbeat and unregisters every service it announced. If the agent process simply **crashes**, the heartbeat task dies with it and the daemon drains the registration when the lease expires — leases over liveness guesses, so nothing is left stale.

`lan_unregister { "id": "a1b2c3d4" }` retracts the service immediately if the agent wants to take it down before exit.

---

## The `_mcp._tcp` convention

`mcp_servers_on_lan` browses the `_mcp._tcp` mDNS service type and returns connectable endpoints, reading TXT keys aligned to the in-flight MCP discovery drafts (`v=mcp1`, `transport=`, `path=`, `name=`).

**This is Koi's convention, not a standard.** There is no DNS-SD standard for MCP today — the two IETF drafts that exist describe *unicast* `_mcp.<domain>` TXT records, not multicast DNS. Koi uses `_mcp._tcp` on the LAN as a pragmatic stand-in until a discovery standard lands; expect this to track whatever the ecosystem settles on.

**Daemon self-announce is deferred.** A stdio MCP server has no network endpoint to advertise — there is nothing for a peer to connect to. Self-announcing Koi's own MCP server only becomes meaningful with an **HTTP transport**, which is a documented follow-up (along with daemon self-announce of that HTTP endpoint). For now, `mcp_servers_on_lan` finds *other* hosts that already advertise `_mcp._tcp`.

---

## Follow-ups (not yet implemented)

- **HTTP / Streamable-HTTP transport** for the MCP server, so remote hosts can connect without spawning a local subprocess.
- **Daemon self-announce** of that HTTP MCP endpoint over `_mcp._tcp`, closing the discovery loop with `mcp_servers_on_lan`.

These are deliberately out of v1; stdio is the transport every MCP host supports today.
