# Koi - API & Protocol Reference

Quick reference for all endpoints and wire protocol. For rules and patterns, see `.agentic/`.

---

## HTTP Endpoints (`src/adapters/http.rs`)

### Service Operations

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/browse?type=_http._tcp&idle_for=5` | Browse for services (SSE stream) |
| POST | `/v1/services` | Register a service |
| DELETE | `/v1/services/{id}` | Unregister a service |
| PUT | `/v1/services/{id}/heartbeat` | Renew heartbeat lease |
| GET | `/v1/resolve?name=My+Service` | Resolve a service name |
| GET | `/v1/events?type=_http._tcp&idle_for=0` | Subscribe to lifecycle events (SSE) |

### Admin Operations

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/v1/admin/status` | Daemon status overview |
| GET | `/v1/admin/registrations` | List all registrations |
| GET | `/v1/admin/registrations/{id}` | Inspect single registration |
| DELETE | `/v1/admin/registrations/{id}` | Force-remove registration |
| POST | `/v1/admin/registrations/{id}/drain` | Begin grace period |
| POST | `/v1/admin/registrations/{id}/revive` | Cancel draining |

### System

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/healthz` | Health check (200 OK) |

---

## Query Parameters

**Browse / Events** (`/v1/browse`, `/v1/events`):
- `type` — Service type (required), e.g. `_http._tcp`
- `idle_for` — SSE idle timeout in seconds:
  - Absent → 5s default
  - `0` → infinite (never auto-close)
  - `N` → close after N seconds of no events

**Resolve** (`/v1/resolve`):
- `name` — Service instance name to resolve (required)

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
{"registered": {"id": "abc12345", "lease": {"mode": "session"}}}
{"renewed": {"id": "abc12345", "expires_in_secs": 90}}
{"removed": "abc12345"}
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

## CLI Subcommands

| Command | Mode | Description |
|---------|------|-------------|
| `koi browse <type>` | Standalone/Client | Browse for services |
| `koi register <args>` | Standalone/Client | Register a service |
| `koi unregister <id>` | Standalone/Client | Remove a service |
| `koi resolve <name>` | Standalone/Client | Resolve service |
| `koi subscribe <type>` | Standalone/Client | Watch lifecycle events |
| `koi admin status` | Client | Daemon status |
| `koi admin list` | Client | List registrations |
| `koi admin inspect <id>` | Client | Registration details |
| `koi admin unregister <id>` | Client | Force removal |
| `koi admin drain <id>` | Client | Start draining |
| `koi admin revive <id>` | Client | Cancel drain |
| `koi install` | - | Install as OS service |
| `koi uninstall` | - | Uninstall OS service |

---

## SSE Event Format

Browse and events endpoints return Server-Sent Events:

```
data: {"found": {"name": "My App", ...}}

data: {"event": "resolved", "service": {...}}

data: {"error": "invalid_type", "message": "..."}
```
