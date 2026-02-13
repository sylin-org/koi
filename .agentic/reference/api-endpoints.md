# Koi - API & Protocol Reference

Quick reference for all endpoints and wire protocol. For rules and patterns, see `.agentic/`.

---

## HTTP Endpoints

All mDNS endpoints are mounted at `/v1/mdns/` by the binary crate.
Route handlers are defined in `crates/koi-mdns/src/http.rs`.

### Service Operations

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/mdns/browse?type=_http._tcp&idle_for=5` | Browse for services (SSE stream) |
| POST | `/v1/mdns/services` | Register a service |
| DELETE | `/v1/mdns/services/{id}` | Unregister a service |
| PUT | `/v1/mdns/services/{id}/heartbeat` | Renew heartbeat lease |
| GET | `/v1/mdns/resolve?name=My+Service` | Resolve a service name |
| GET | `/v1/mdns/events?type=_http._tcp&idle_for=0` | Subscribe to lifecycle events (SSE) |

### Admin Operations

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/mdns/admin/status` | Daemon status overview |
| GET | `/v1/mdns/admin/registrations` | List all registrations |
| GET | `/v1/mdns/admin/registrations/{id}` | Inspect single registration |
| DELETE | `/v1/mdns/admin/registrations/{id}` | Force-remove registration |
| POST | `/v1/mdns/admin/registrations/{id}/drain` | Begin grace period |
| POST | `/v1/mdns/admin/registrations/{id}/revive` | Cancel draining |

### Certmesh Operations

All certmesh endpoints are mounted at `/v1/certmesh/` by the binary crate.
Route handlers are defined in `crates/koi-certmesh/src/http.rs`.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/v1/certmesh/create` | Initialize CA (create key, cert, auth credential) |
| POST | `/v1/certmesh/join` | Join the certificate mesh (auth-verified enrollment) |
| GET | `/v1/certmesh/status` | Mesh status overview |
| POST | `/v1/certmesh/unlock` | Decrypt CA key with passphrase |
| PUT | `/v1/certmesh/hook` | Set reload hook for a member |
| POST | `/v1/certmesh/promote` | Promote standby (CA key transfer) |
| POST | `/v1/certmesh/renew` | Trigger certificate renewal |
| GET | `/v1/certmesh/roster` | Get signed roster manifest |
| POST | `/v1/certmesh/health` | Member health heartbeat |
| POST | `/v1/certmesh/rotate-auth` | Rotate enrollment auth credential |
| GET | `/v1/certmesh/log` | Read audit log entries |
| POST | `/v1/certmesh/enrollment/open` | Open enrollment window |
| POST | `/v1/certmesh/enrollment/close` | Close enrollment window |
| PUT | `/v1/certmesh/policy` | Set enrollment scope constraints |
| POST | `/v1/certmesh/destroy` | Destroy all certmesh state (CA, certs, audit log) |

### System

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/status` | Unified capability status (version, uptime, capabilities) |
| POST | `/v1/admin/shutdown` | Initiate graceful shutdown |
| GET | `/healthz` | Health check (200 "OK") |

---

## Query Parameters

**Browse / Events** (`/v1/mdns/browse`, `/v1/mdns/events`):
- `type` -- Service type (required), e.g. `_http._tcp`
- `idle_for` -- SSE idle timeout in seconds:
  - Absent -> 5s default
  - `0` -> infinite (never auto-close)
  - `N` -> close after N seconds of no events

**Resolve** (`/v1/mdns/resolve`):
- `name` -- Service instance name to resolve (required)

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

### Pipeline Responses (streaming)
Streaming responses include a `status` field:
```json
{"found": {...}, "status": "ongoing"}
{"found": {...}, "status": "finished"}
```
- `status` is absent on non-streaming responses (happy path = no extra fields)
- `warning` field appears only when relevant

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
| `koi certmesh status` | Client | Show mesh status |
| `koi certmesh unlock` | Client | Decrypt CA key |
| `koi certmesh log` | Client | Show audit log |
| `koi certmesh set-hook --reload CMD` | Client | Set reload hook |
| `koi certmesh promote [endpoint]` | Client | Promote standby CA |
| `koi certmesh open-enrollment` | Client | Open enrollment window |
| `koi certmesh close-enrollment` | Client | Close enrollment window |
| `koi certmesh set-policy` | Client | Set enrollment scope constraints |
| `koi certmesh rotate-auth` | Client | Rotate enrollment auth credential |
| `koi certmesh destroy` | Client | Destroy all certmesh state |
| `koi status` | Standalone/Client | Unified capability status |
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
