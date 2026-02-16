# JSON Wire Protocol

Koi uses the same JSON protocol across HTTP, IPC (Named Pipe / Unix Domain Socket), and stdin/stdout. The top-level key is the verb — the JSON *is* the intent.

---

## Requests

The top-level key determines the operation:

```json
{ "browse": "_http._tcp" }
{ "register": { "name": "My App", "type": "_http._tcp", "port": 8080 } }
{ "unregister": "a1b2c3d4" }
{ "resolve": "My App._http._tcp.local." }
{ "subscribe": "_http._tcp" }
{ "heartbeat": "a1b2c3d4" }
```

## Responses

### Success

```json
{ "found": { "name": "Server A", "type": "_http._tcp", "host": "server.local", "ip": "192.168.1.42", "port": 8080, "txt": {} } }
{ "registered": { "id": "a1b2c3d4", "name": "My App", "type": "_http._tcp", "port": 8080, "mode": "heartbeat", "lease_secs": 90 } }
{ "unregistered": "a1b2c3d4" }
{ "resolved": { "name": "...", "type": "...", "host": "...", "ip": "...", "port": 8080, "txt": {} } }
{ "event": "found", "service": { "name": "...", "type": "...", ... } }
{ "renewed": { "id": "a1b2c3d4", "lease_secs": 90 } }
```

### Errors

```json
{ "error": "invalid_type", "message": "Service type must be _name._tcp or _name._udp" }
{ "error": "not_found", "message": "No registration with id 'xyz'" }
{ "error": "resolve_timeout", "message": "Could not resolve within 3s" }
```

---

## Service record schema

The canonical representation of a discovered or registered service:

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Human-readable instance name |
| `type` | string | yes | DNS-SD service type (`_name._tcp` or `_name._udp`) |
| `host` | string | no | Hostname (e.g., `server.local`). Present after discovery. |
| `ip` | string | no | IPv4 or IPv6 address. May be absent if unresolved. |
| `port` | integer | no | Service port. May be absent in early browse events. |
| `txt` | object | yes | TXT record key-value pairs. Empty `{}` if none. |

---

## Pipeline properties

Optional operational metadata attached as sibling keys via `#[serde(flatten)]`:

| Property | Values | Meaning |
|---|---|---|
| `status` | `"ongoing"` / `"finished"` | Whether more data is expected |
| `warning` | string | Operation succeeded with caveats |

Absence means clean success. Consumer logic:

```
if "error"   → something broke
if "status"  → "ongoing" means keep listening; "finished" means done
if "warning" → succeeded, but read this
if none      → clean result
```

---

## Event types

Lifecycle events from `subscribe`:

| Event | Meaning |
|---|---|
| `found` | Service instance discovered (may be partially resolved) |
| `resolved` | Fully resolved with IP, port, and TXT |
| `removed` | Service gone (goodbye packet or TTL expiry) |

---

## IPC transport

| Platform | Transport | Default path |
|---|---|---|
| Windows | Named Pipe | `\\.\pipe\koi` |
| Linux / macOS | Unix Domain Socket | `$XDG_RUNTIME_DIR/koi.sock` or `/var/run/koi.sock` |

Protocol: NDJSON (newline-delimited JSON). One JSON object per line. Streaming operations keep the connection open.

IPC registrations use **session-based leases**. The OS connection lifecycle is the liveness signal — when the connection drops, Koi starts a grace period.

---

## CLI transport

stdin/stdout with the same NDJSON protocol:

```bash
echo '{"browse":"_http._tcp"}' | koi
echo '{"register":{"name":"test","type":"_http._tcp","port":8080}}' | koi | jq '.registered.id'
```

Activates when Koi detects stdin is a pipe (not a terminal).

---

## Service type normalization

Koi normalizes input liberally and emits canonical output strictly:

| Input | Normalized to |
|---|---|
| `http` | `_http._tcp` |
| `_http` | `_http._tcp` |
| `_http._tcp` | `_http._tcp` |
| `_http._tcp.` | `_http._tcp` |
| `_http._tcp.local.` | `_http._tcp` |

Missing `_` prefix is added. Missing `._tcp` suffix is assumed. Trailing `.local.` is handled internally.
