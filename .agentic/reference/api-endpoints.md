# Koi - API & Protocol Reference

Quick reference for all endpoints and wire protocol. For rules and patterns, see `.agentic/`.
For full request/response schemas, see `docs/reference/http-api.md`.

---

## HTTP Endpoints

Each domain crate owns its routes; the binary crate mounts them at `/v1/<domain>/`.
Interactive API docs: `GET /docs` (Scalar UI). OpenAPI spec: `GET /openapi.json`.

The HTTP adapter binds **loopback** (`127.0.0.1`) by default, so only local
processes reach it. Expose it to the LAN/containers with `--http-bind bridge` /
`--http-bind 0.0.0.0` / `--http-bind <ip>` (env `KOI_HTTP_BIND`); mutations always
require the `x-koi-token` header regardless of bind address.

### System

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/healthz` | Health check (200 "OK") |
| GET | `/v1/status` | Unified capability status (version, uptime, capabilities) |
| POST | `/v1/admin/shutdown` | Initiate graceful shutdown |
| GET | `/v1/host` | Host identity (hostname, FQDN, OS, arch, network interfaces) |
| GET | `/v1/sd/prometheus` | Prometheus HTTP service discovery (target groups) |
| GET/POST | `/v1/mcp` | MCP server over Streamable HTTP (JSON-RPC; token-authenticated) |
| GET | `/.well-known/mcp/server-card.json` | Public MCP discovery descriptor (unauthenticated) |
| GET | `/openapi.json` | OpenAPI specification |
| GET | `/docs` | Interactive API documentation (Scalar UI) |

`/v1/mcp` is MCP JSON-RPC over Streamable HTTP (in-process, against the live cores) —
like the ACME facade it is **NOT** in `/openapi.json`. Every method, including the GET
SSE stream, requires the `x-koi-token` header (carved out of the usual GET auth
exemption). It is a transport, not a domain capability rung: gated by `--no-mcp-http` /
`KOI_NO_MCP_HTTP` (default enabled; disabled → 503 `capability_disabled`) and reported on
`/v1/status` as an `mcp_http` boolean. It exposes MCP resources (`koi://lan/inventory`,
`koi://health`, `koi://dns/zone`, `koi://mdns/services`) with live `resources/updated`
deltas, and advertises a single `_mcp._tcp` mDNS record, an in-zone `_mcp.<host>.<zone>`
DNS TXT, and the public server-card above. Port is unchanged (5641, no new port).

### Dashboard & Browser

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/` | Embedded HTML dashboard |
| GET | `/v1/dashboard/snapshot` | System-level JSON snapshot for dashboard |
| GET | `/v1/dashboard/events` | Unified SSE activity feed |
| GET | `/mdns-browser` | mDNS network browser HTML page |
| GET | `/v1/mdns/browser/snapshot` | Network cache snapshot |
| GET | `/v1/mdns/browser/events` | Service discovery SSE feed |

### mDNS Service Operations (`/v1/mdns`)

Route handlers: `crates/koi-mdns/src/http.rs`

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/mdns/discover` | Browse for services (SSE stream) |
| POST | `/v1/mdns/announce` | Register a service |
| DELETE | `/v1/mdns/unregister/{id}` | Unregister a service |
| PUT | `/v1/mdns/heartbeat/{id}` | Renew heartbeat lease |
| GET | `/v1/mdns/resolve` | Resolve a service name |
| GET | `/v1/mdns/subscribe` | Subscribe to lifecycle events (SSE) |

### mDNS Admin Operations (`/v1/mdns/admin`)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/mdns/admin/status` | Daemon status overview |
| GET | `/v1/mdns/admin/ls` | List all registrations |
| GET | `/v1/mdns/admin/inspect/{id}` | Inspect single registration |
| DELETE | `/v1/mdns/admin/unregister/{id}` | Force-remove registration |
| POST | `/v1/mdns/admin/drain/{id}` | Begin grace period |
| POST | `/v1/mdns/admin/revive/{id}` | Cancel draining |

### Certmesh Operations (`/v1/certmesh`)

Route handlers: `crates/koi-certmesh/src/http.rs`

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/v1/certmesh/create` | Initialize CA (create key, cert, auth credential) |
| POST | `/v1/certmesh/join` | Join the certificate mesh (TOTP-authorized enrollment; the one mutation exempt from the `x-koi-token` requirement — a joining node can't know the CA host's local token) |
| POST | `/v1/certmesh/invite` | Mint a single-use, hostname-bound enrollment invite |
| POST | `/v1/certmesh/member-csr` | Generate this member's keypair + CSR |
| POST | `/v1/certmesh/member-cert` | Install a CA-signed cert next to the member key |
| GET | `/v1/certmesh/status` | Mesh status overview |
| GET | `/v1/certmesh/diagnose` | Trust-doctor report (posture, identity, integrity, revocation, CA-trust) |
| GET | `/v1/certmesh/trust-bundle` | Signed, monotonic mesh-truth bundle |
| POST | `/v1/certmesh/unlock` | Decrypt CA key with passphrase |
| PUT | `/v1/certmesh/set-hook` | Set reload hook for a member |
| POST | `/v1/certmesh/promote` | Promote standby (CA key transfer) |
| POST | `/v1/certmesh/renew` | Trigger certificate renewal |
| POST | `/v1/certmesh/revoke` | Revoke a member's certificate |
| POST | `/v1/certmesh/health` | Member health heartbeat (pinned CA fingerprint) |
| POST | `/v1/certmesh/rotate-auth` | Rotate enrollment auth credential |
| GET | `/v1/certmesh/log` | Read audit log entries (token-authenticated even on GET — like `/v1/mcp`, carved out of the GET exemption: the audit log narrates the full trust history) |
| POST | `/v1/certmesh/open-enrollment` | Open enrollment window |
| POST | `/v1/certmesh/close-enrollment` | Close enrollment window |
| POST | `/v1/certmesh/backup` | Create encrypted backup |
| POST | `/v1/certmesh/restore` | Restore from backup |
| POST | `/v1/certmesh/destroy` | Destroy all certmesh state (CA, certs, audit log) |

### DNS Operations (`/v1/dns`)

Route handlers: `crates/koi-dns/src/http.rs`

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/dns/status` | Resolver status (running, zone, port, record counts) |
| GET | `/v1/dns/lookup?name=grafana&type=A` | Resolve a local name |
| GET | `/v1/dns/list` | List all resolvable names |
| GET | `/v1/dns/zone?format=hosts\|dnsmasq\|json` | Export the resolvable zone (hosts / dnsmasq / json) |
| GET | `/v1/dns/entries` | List static entries with details |
| POST | `/v1/dns/add` | Add static entry (name, ip, optional ttl) |
| DELETE | `/v1/dns/remove/{name}` | Remove static entry |
| POST | `/v1/dns/serve` | Start the DNS resolver |
| POST | `/v1/dns/stop` | Stop the DNS resolver |

### Health Operations (`/v1/health`)

Route handlers: `crates/koi-health/src/http.rs`

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/health/status` | Snapshot of all checks with current state |
| GET | `/v1/health/list` | List registered check configurations |
| POST | `/v1/health/add` | Register a check (name, kind, target, interval, timeout) |
| DELETE | `/v1/health/remove/{name}` | Remove a check |

### Proxy Operations (`/v1/proxy`)

Route handlers: `crates/koi-proxy/src/http.rs`

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/proxy/status` | Active proxy status |
| GET | `/v1/proxy/list` | List proxy entries |
| POST | `/v1/proxy/add` | Add a proxy entry (name, listen_port, backend, allow_remote) |
| DELETE | `/v1/proxy/remove/{name}` | Remove a proxy entry |

### UDP Operations (`/v1/udp`)

Route handlers: `crates/koi-udp/src/http.rs`

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/v1/udp/bind` | Bind a host UDP socket |
| DELETE | `/v1/udp/bind/{id}` | Unbind (close) a binding |
| GET | `/v1/udp/recv/{id}` | Subscribe to incoming datagrams (SSE stream) |
| POST | `/v1/udp/send/{id}` | Send a datagram through a binding |
| GET | `/v1/udp/status` | List all active bindings |
| PUT | `/v1/udp/heartbeat/{id}` | Renew a binding's lease |

### Runtime Operations (`/v1/runtime`)

Route handlers: `crates/koi-runtime/src/http.rs`

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/runtime/status` | Runtime adapter status (active, backend, instance count) |
| GET | `/v1/runtime/instances` | List all tracked runtime instances |

### ACME Operations (`/acme`, separate TLS port 5643)

Route handlers: `crates/koi-certmesh/src/acme/router.rs`. **NOT** on the main HTTP adapter
and **not** in `/openapi.json` — RFC 8555 wire format (`application/jose+json` requests,
`application/problem+json` errors). Server-auth TLS listener (default 5643, `--acme-port`),
gated by `--no-acme` / `KOI_NO_ACME`; starts only when the CA is initialized + unlocked and
DNS is enabled. dns-01 only, EC/ES256 only, in-zone names only.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/acme/directory` | Directory (endpoint URLs + `meta.externalAccountRequired`) |
| HEAD/GET | `/acme/new-nonce` | Fresh `Replay-Nonce` (200/204) |
| POST | `/acme/new-account` | Register account (JWS + jwk; EAB in closed mode) |
| POST | `/acme/new-order` | Create order (in-zone identifiers only → else `rejectedIdentifier`) |
| POST | `/acme/authz/{id}` | Authorization (POST-as-GET) |
| POST | `/acme/chall/{id}` | Trigger dns-01 validation (in-process TXT check) |
| POST | `/acme/order/{id}/finalize` | Submit CSR → issue (every CSR SAN must be authorized) |
| POST | `/acme/cert/{id}` | Download leaf + CA chain (`application/pem-certificate-chain`) |
| POST | `/acme/revoke-cert` | Revoke an issued certificate |

---

## Query Parameters

**Discover / Subscribe** (`/v1/mdns/discover`, `/v1/mdns/subscribe`):
- `type` -- Service type (required for subscribe, optional for discover), e.g. `_http._tcp`
- `idle_for` -- SSE idle timeout in seconds:
  - Absent -> 5s default
  - `0` -> infinite (never auto-close)
  - `N` -> close after N seconds of no events

**Resolve** (`/v1/mdns/resolve`):
- `name` -- Service instance name to resolve (required)

**DNS Lookup** (`/v1/dns/lookup`):
- `name` -- Name to resolve (required)
- `type` -- Record type: `A`, `AAAA`, or `ANY` (default `A`)

---

## Pipe / CLI Protocol (NDJSON)

Used over Named Pipe (Windows), Unix Domain Socket, and piped stdin/stdout.

### Request Format (one JSON object per line)
```json
{"browse": "_http._tcp"}
{"register": {"name": "My App", "type": "_http._tcp", "port": 8080}}
{"unregister": "abc12345"}
{"heartbeat": "abc12345"}
```

### Response Format (one JSON object per line)
```json
{"found": {"name": "My App", "type": "_http._tcp", "port": 8080}}
{"registered": {"id": "abc12345", "name": "My App", "type": "_http._tcp", "port": 8080, "mode": "session"}}
{"renewed": {"id": "abc12345", "lease_secs": 90}}
{"unregistered": "abc12345"}
{"error": "not_found", "message": "Registration not found"}
```

### Response shape (streaming + non-streaming)
A response serializes as its body via `#[serde(flatten)]` — no envelope or wrapper
key. SSE/streaming responses use the same per-event body shape as the one-shot JSON
responses above. The happy path is just the data; an error is a flat
`{"error": <code>, "message": <msg>}`.

---

## Service Record Shape

```json
{
  "name": "My App",
  "type": "_http._tcp",
  "host": "server.local",
  "ip": "192.168.1.42",
  "port": 8080,
  "txt": {"version": "1.0"}
}
```

- `type` is renamed from `service_type` via serde
- `host`, `ip` are optional (may be absent in browse results)
- `txt` defaults to `{}`

---

## Registration Payload

```json
{
  "name": "My App",
  "type": "_http._tcp",
  "port": 8080,
  "txt": {"key": "value"},
  "lease_secs": 90
}
```

- `txt` optional (defaults to `{}`)
- `lease_secs` optional (adapter determines lease policy if absent)

---

## CLI Subcommands (v0.2 Moniker Structure)

| Command | Mode | Description |
|---------|------|-------------|
| `koi mdns discover [type]` | Standalone/Client | Browse for services |
| `koi mdns announce <args>` | Standalone/Client | Register a service |
| `koi mdns unregister <id>` | Standalone/Client | Remove a service |
| `koi mdns resolve <name>` | Standalone/Client | Resolve service |
| `koi mdns subscribe <type>` | Standalone/Client | Watch lifecycle events |
| `koi mdns admin status` | Client | Daemon status |
| `koi mdns admin ls` | Client | List registrations |
| `koi mdns admin inspect <id>` | Client | Registration details |
| `koi mdns admin unregister <id>` | Client | Force removal |
| `koi mdns admin drain <id>` | Client | Start draining |
| `koi mdns admin revive <id>` | Client | Cancel drain |
| `koi certmesh create` | Client | Initialize private CA |
| `koi certmesh join [endpoint]` | Client | Join existing mesh (mDNS CA discovery) |
| `koi certmesh invite <hostname>` | Client | Mint a single-use, hostname-bound invite |
| `koi certmesh status` | Client | Show mesh status |
| `koi certmesh unlock` | Client | Decrypt CA key |
| `koi certmesh log` | Client | Show audit log |
| `koi certmesh set-hook --reload CMD` | Client | Set reload hook |
| `koi certmesh promote [endpoint]` | Client | Promote standby CA |
| `koi certmesh open-enrollment` | Client | Open enrollment window |
| `koi certmesh close-enrollment` | Client | Close enrollment window |
| `koi certmesh rotate-auth` | Client | Rotate enrollment auth credential |
| `koi certmesh backup <path>` | Client | Create encrypted backup |
| `koi certmesh restore <path>` | Client | Restore from backup |
| `koi certmesh revoke <hostname>` | Client | Revoke a member |
| `koi certmesh destroy` | Client | Destroy all certmesh state |
| `koi certmesh acme enable` | Client | Show the ACME directory URL + client bootstrap recipe |
| `koi dns serve` | Client | Start DNS resolver |
| `koi dns stop` | Client | Stop DNS resolver |
| `koi dns status` | Client | DNS resolver status |
| `koi dns lookup <name>` | Client | Resolve a local name |
| `koi dns add <name> <ip>` | Client | Add static DNS entry |
| `koi dns remove <name>` | Client | Remove static DNS entry |
| `koi dns list` | Client | List all resolvable names |
| `koi health status` | Client | Show health status |
| `koi health watch` | Client | Live terminal watch |
| `koi health add <name>` | Client | Add a health check |
| `koi health remove <name>` | Client | Remove a health check |
| `koi health log` | Client | Health transition log |
| `koi proxy add <name>` | Client | Add/update a proxy entry |
| `koi proxy remove <name>` | Client | Remove a proxy entry |
| `koi proxy status` | Client | Proxy status |
| `koi proxy list` | Client | List configured proxies |
| `koi udp bind` | Client | Bind a host UDP port |
| `koi udp unbind <id>` | Client | Close a UDP binding |
| `koi udp send <id>` | Client | Send a datagram |
| `koi udp status` | Client | Show active bindings |
| `koi udp heartbeat <id>` | Client | Renew binding lease |
| `koi status` | Standalone/Client | Unified capability status |
| `koi trust install <pem>` | - | Install a CA certificate into the OS trust store |
| `koi trust list` | - | List the CA roots Koi installed |
| `koi trust remove <name>` | - | Remove a Koi-installed CA root |
| `koi trust export [--ca]` | - | Export a CA certificate (PEM) to stdout |
| `koi trust diagnose [--fix]` | - | Trust-doctor: posture, identity, integrity, revocation, CA-trust |
| `koi mcp serve` | - | Serve the MCP protocol over stdio (for AI agent hosts) |
| `koi token show` | - | Print the daemon access token (tty-guarded) |
| `koi token write <path>` | - | Write the token to a 0600 file for containers |
| `koi launch` | - | Open dashboard in browser |
| `koi install` | - | Install as OS service |
| `koi uninstall` | - | Uninstall OS service |
| `koi version` | - | Show version info |

---

## SSE Event Format

Browse and events endpoints return Server-Sent Events:

```
id: 019503a1-7c00-7def-8000-1a2b3c4d5e6f
data: {"found": {"name": "My App", ...}}

data: {"event": "resolved", "service": {...}}

data: {"error": "invalid_type", "message": "..."}
```
