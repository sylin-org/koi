# mDNS — Service Discovery Guide

Koi's mDNS capability lets you find, advertise, and monitor services on your local network using mDNS/DNS-SD — the same protocol your printer and smart speaker use to announce themselves.

All CLI commands use the `koi mdns` moniker. All HTTP endpoints live under `/v1/mdns/`.

---

## Discovering services

Scan your local network for all advertised service types:

```
koi mdns discover
```

```
_http._tcp
_googlecast._tcp
_spotify-connect._tcp
_airplay._tcp
```

Find all HTTP servers:

```
koi mdns discover http
```

```
My NAS     _http._tcp    192.168.1.50:8080    nas.local.
Pi-hole    _http._tcp    192.168.1.10:80      pihole.local.
```

Columns are tab-separated: name, type, ip:port, hostname.

Koi accepts the type in any form. These are all equivalent:

```
koi mdns discover http
koi mdns discover _http._tcp
koi mdns discover _http._tcp.local.
```

### Controlling how long Koi listens

Discover and subscribe default to **5 seconds**. Override with `--timeout`:

```
koi mdns discover http --timeout 15       # 15 seconds
koi mdns discover http --timeout 0        # indefinite (Ctrl+C to stop)
```

---

## Resolving a specific instance

If you know the full name of a service instance:

```
koi mdns resolve "My NAS._http._tcp.local."
```

```
My NAS
  Type: _http._tcp
  Host: nas.local.
  IP:   192.168.1.50
  Port: 8080
  TXT:  path=/api version=2.1
```

Resolve is a one-shot operation — it waits up to 5 seconds for the instance to respond.

---

## Announcing a service

Advertise a service on the network:

```
koi mdns announce "My App" http 8080
```

This announces `_http._tcp` called "My App" on port 8080. The process stays alive to maintain the advertisement. Press Ctrl+C to unregister and exit.

Add TXT record metadata:

```
koi mdns announce "My App" http 8080 version=2.1 path=/api
```

Pin the A record to a specific IP (useful on multi-homed hosts or with Docker/WSL bridges):

```
koi mdns announce "My App" http 8080 --ip 192.168.1.42
```

Announce for a fixed duration:

```
koi mdns announce "My App" http 8080 --timeout 60
```

### Unregistering

If you know a registration's ID (shown when you announce, or via `koi mdns admin ls`):

```
koi mdns unregister a1b2c3d4
```

---

## Subscribing to lifecycle events

Subscribe tells you *what happened*, not just what's there:

```
koi mdns subscribe http
```

```
[found]     My NAS       _http._tcp    192.168.1.50:8080    nas.local.
[resolved]  My NAS       _http._tcp    192.168.1.50:8080    nas.local.
[removed]   My NAS       _http._tcp
```

The `[found]` → `[resolved]` → `[removed]` lifecycle is how mDNS works: a service is first *found* (it exists), then *resolved* (address known), and eventually *removed* (gone).

---

## JSON output

Every command supports `--json` for machine-readable NDJSON:

```
koi mdns discover http --json
```

```json
{"found":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{"version":"2.1"}}}
```

```
koi mdns announce "My App" http 8080 --json
```

```json
{"registered":{"id":"a1b2c3d4","name":"My App","type":"_http._tcp","port":8080}}
```

```
koi mdns resolve "My NAS._http._tcp.local." --json
```

```json
{"resolved":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{"version":"2.1"}}}
```

---

## Service type shorthand

Koi normalizes service types liberally:

| Input | Resolved to |
|---|---|
| `http` | `_http._tcp.local.` |
| `_http` | `_http._tcp.local.` |
| `_http._tcp` | `_http._tcp.local.` |
| `_http._tcp.` | `_http._tcp.local.` |
| `_http._tcp.local.` | `_http._tcp.local.` |
| `_dns._udp` | `_dns._udp.local.` |

If you omit the protocol, TCP is assumed. Service names must be 1–15 characters; protocol must be `tcp` or `udp`.

---

## HTTP API

All mDNS endpoints are mounted at `/v1/mdns/` on the daemon.

### Browse for services (SSE stream)

```
GET /v1/mdns/discover?type=_http._tcp
```

Returns a Server-Sent Events stream. Each event's `data` field contains JSON:

```
data: {"found":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
```

The stream closes after 5 seconds of no new events. Control with `idle_for`:

```
GET /v1/mdns/discover?type=_http._tcp&idle_for=0     # stream indefinitely
GET /v1/mdns/discover?type=_http._tcp&idle_for=15    # 15 seconds idle timeout
```

### Register a service

```
POST /v1/mdns/announce
Content-Type: application/json

{"name": "My App", "type": "_http._tcp", "port": 8080, "txt": {"version": "2.1"}}
```

Response:

```json
{"registered": {"id": "a1b2c3d4", "name": "My App", "type": "_http._tcp", "port": 8080, "mode": "heartbeat", "lease_secs": 90}}
```

Permanent registration (never expires):

```json
{"name": "My App", "type": "_http._tcp", "port": 8080, "lease_secs": 0}
```

Custom heartbeat interval:

```json
{"name": "My App", "type": "_http._tcp", "port": 8080, "lease_secs": 300}
```

### Unregister a service

```
DELETE /v1/mdns/unregister/a1b2c3d4
```

### Heartbeat (renew a lease)

```
PUT /v1/mdns/heartbeat/a1b2c3d4
```

```json
{"renewed": {"id": "a1b2c3d4", "lease_secs": 90}}
```

Send at half the `lease_secs` interval. A heartbeat revives a draining registration back to alive.

### Resolve an instance

```
GET /v1/mdns/resolve?name=My%20NAS._http._tcp.local.
```

### Subscribe to lifecycle events (SSE stream)

```
GET /v1/mdns/subscribe?type=_http._tcp
```

```
data: {"event":"found","service":{"name":"My NAS","type":"_http._tcp",...}}
data: {"event":"resolved","service":{...}}
data: {"event":"removed","service":{"name":"My NAS","type":"_http._tcp",...}}
```

Same `idle_for` parameter as browse.

### Error responses

Errors return JSON with the appropriate HTTP status:

```json
{"error": "invalid_type", "message": "Invalid service type: ..."}
```

| Error code | HTTP status | When |
|---|---|---|
| `invalid_type` | 400 | Bad service type format |
| `ambiguous_id` | 400 | ID prefix matches multiple registrations |
| `parse_error` | 400 | Malformed JSON body |
| `not_found` | 404 | Registration doesn't exist |
| `already_draining` | 409 | Drain on already-draining registration |
| `not_draining` | 409 | Revive on non-draining registration |
| `resolve_timeout` | 504 | mDNS resolve got no response in 5 seconds |
| `daemon_error` | 500 | mDNS engine error |
| `io_error` | 500 | I/O failure |

CORS is enabled for all origins.

---

## Admin commands

Admin commands manage daemon registrations. They always talk to the daemon and fail with a clear message if none is running.

### Status

```
koi mdns admin status
```

### List registrations

```
koi mdns admin ls
```

```
ID        NAME                 TYPE             PORT  STATE      MODE
a1b2c3d4  My App               _http._tcp       8080  alive      heartbeat
e5f6a7b8  My Service           _http._tcp       9090  alive      permanent
```

### Inspect a registration

```
koi mdns admin inspect a1b2
```

Full detail including lease timing, session info, and TXT records. Supports **prefix matching** — use any unambiguous prefix of the registration ID.

### Drain, revive, and force-unregister

```
koi mdns admin drain a1b2        # start grace timer (alive → draining)
koi mdns admin revive a1b2       # cancel drain (draining → alive)
koi mdns admin unregister a1b2   # remove immediately, send goodbye packets
```

### Admin HTTP endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/v1/mdns/admin/status` | Daemon mDNS status |
| GET | `/v1/mdns/admin/ls` | List all registrations |
| GET | `/v1/mdns/admin/inspect/{id}` | Inspect one registration |
| DELETE | `/v1/mdns/admin/unregister/{id}` | Force-remove |
| POST | `/v1/mdns/admin/drain/{id}` | Force-drain |
| POST | `/v1/mdns/admin/revive/{id}` | Force-revive |

All `{id}` parameters support prefix matching.

---

## Leases and heartbeats

Registrations have a **lease mode** that determines how they prove they're still alive. This prevents ghost services — if a process crashes, its services are automatically cleaned up.

| Mode | Mechanism | When it's used | Default timing |
|---|---|---|---|
| **Heartbeat** | Client sends periodic `PUT /v1/mdns/heartbeat/{id}` | HTTP API registrations | 90s lease, 30s grace |
| **Session** | Connection open = alive. Drop = grace starts. | IPC (pipe/socket) and piped stdin | 30s grace (IPC), 5s grace (CLI) |
| **Permanent** | Lives until explicit removal or daemon shutdown. | `lease_secs: 0` from any transport | No expiry |

The **adapter picks the default** automatically:
- HTTP → heartbeat mode (stateless)
- IPC → session mode (OS-level disconnect signal)
- Piped stdin → session mode (5s grace on EOF)

### What happens when liveness is lost

1. **Alive** → heartbeat missed or connection dropped
2. **Draining** → grace timer running. A heartbeat or reconnection during this window returns the registration to alive with no network-visible interruption.
3. **Expired** → grace elapsed. Koi sends mDNS goodbye packets and removes the registration.

A background reaper checks every 5 seconds.

### Session reconnection

If a new registration arrives (same name + type) while an existing entry is draining, Koi **reconnects** instead of creating a duplicate. The draining entry is revived with the new session, and the original registration ID is preserved. The network sees continuity.

---

## IPC (Named Pipe / Unix Socket)

The IPC interface uses the same NDJSON protocol as piped stdin, over a persistent connection:

- **Windows**: `\\.\pipe\koi`
- **Linux/macOS**: `$XDG_RUNTIME_DIR/koi.sock` (or `/var/run/koi.sock`)

Send one JSON command per line, receive one JSON response per line. Streaming commands send multiple response lines.

IPC connections use **session-based leases**: registrations are tied to the connection. When it drops, those registrations enter a 30-second grace period before removal.

This is the fastest interface — no HTTP overhead, no process spawn.
