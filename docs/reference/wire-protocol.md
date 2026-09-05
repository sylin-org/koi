# JSON Wire Protocol

Koi's mDNS commands use the same JSON vocabulary across HTTP and authenticated
local IPC (Named Pipe / Unix Domain Socket). The top-level key is the verb - the JSON _is_ the
intent. The authenticated local IPC transport additionally accepts the small,
versioned local-control contract documented below; those requests are not HTTP commands.

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
{ "error": "resolve_timeout", "message": "Could not resolve within 5s" }
```

---

## Service record schema

The canonical representation of a discovered or registered service:

| Field  | Type    | Required | Notes                                                     |
| ------ | ------- | -------- | --------------------------------------------------------- |
| `name` | string  | yes      | Human-readable instance name                              |
| `type` | string  | yes      | DNS-SD service type (`_name._tcp` or `_name._udp`)        |
| `host` | string  | no       | Hostname (e.g., `server.local`). Present after discovery. |
| `ip`   | string  | no       | IPv4 or IPv6 address. May be absent if unresolved.        |
| `port` | integer | no       | Service port. May be absent in early browse events.       |
| `txt`  | object  | yes      | TXT record key-value pairs. Empty `{}` if none.           |

---

## Response shape

A response serializes as its body via `#[serde(flatten)]` — no envelope, no
wrapper key. Consumer logic:

```
if "error" key present → something broke (carries a code + message)
otherwise              → clean result (the data is the top-level object)
```

---

## Event types

Lifecycle events from `subscribe`:

| Event      | Meaning                                                 |
| ---------- | ------------------------------------------------------- |
| `found`    | Service instance discovered (may be partially resolved) |
| `resolved` | Fully resolved with IP, port, and TXT                   |
| `removed`  | Service gone (goodbye packet or TTL expiry)             |

---

## IPC transport

| Platform      | Transport          | Default path                                       |
| ------------- | ------------------ | -------------------------------------------------- |
| Windows       | Named Pipe         | `\\.\pipe\koi`                                     |
| Linux / macOS | Unix Domain Socket | `$XDG_RUNTIME_DIR/koi.sock` or `/var/run/koi.sock` |

Protocol: NDJSON (newline-delimited JSON). One JSON object per line. Streaming operations keep the connection open.

IPC registrations use **session-based leases**. The OS connection lifecycle is the liveness signal - when the connection drops, Koi starts a grace period.

An installed machine service also uses this transport to hand facts to its recorded
interactive operator without making its breadcrumb world-readable. Version 1 accepts:

```json
{ "request": "access", "version": 1 }
{ "request": "info", "version": 1 }
```

`access` returns the running daemon's matching endpoint and token, plus its optional
resolved data root. It fails with `http_disabled` when the daemon has no HTTP adapter.
`info` returns the non-secret resolved data root and launch-selected configuration
path even when HTTP is disabled. The pipe/socket authenticates the peer before parsing
either request. Windows gives the pipe a protected DACL for SYSTEM, Administrators,
and the recorded operator, then returns bytes only when the connected process token
has the exact recorded operator SID. Unix admits root and the one recorded UID.
Neither response is exposed by Pond or public HTTP status.
Catalog snapshots, catalog subscriptions, and preference commands do not add another
IPC dialect. After `access`, local clients use the returned endpoint and DAT with the
schema-1 HTTP routes documented in [HTTP API Reference](http-api.md).

---

## Service type normalization

Koi normalizes input liberally and emits canonical output strictly:

| Input               | Normalized to |
| ------------------- | ------------- |
| `http`              | `_http._tcp`  |
| `_http`             | `_http._tcp`  |
| `_http._tcp`        | `_http._tcp`  |
| `_http._tcp.`       | `_http._tcp`  |
| `_http._tcp.local.` | `_http._tcp`  |

Missing `_` prefix is added. Missing `._tcp` suffix is assumed. Trailing `.local.` is handled internally.
