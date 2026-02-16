# mDNS - Service Discovery

Every device on your local network already speaks mDNS. Your printer uses it. Your smart speaker uses it. AirPlay, Chromecast, Spotify Connect - they all use multicast DNS and DNS-SD to find each other without configuration servers or static IP tables.

The problem is that _your_ applications can't easily do the same. The OS-level APIs are platform-specific, poorly documented, and unusable from containers. Koi's mDNS module gives you this superpower through a uniform interface: CLI commands, an HTTP API, and IPC - all producing the same JSON.

**When to use mDNS**: You have services on a LAN that need to find each other without hardcoded addresses. A homelab where Grafana should discover Prometheus. A fleet of Raspberry Pis that need to know about each other. Containers on a Docker host that need to find a database on the LAN. If you're reaching for a service registry but your scope is "one network segment," mDNS is the right tool.

All CLI commands use the `koi mdns` prefix. All HTTP endpoints live under `/v1/mdns/`.

---

## Discovering what's on the network

The simplest thing you can do is listen:

```
koi mdns discover
```

This performs a multicast browse and streams back every service type it hears:

```
_http._tcp
_googlecast._tcp
_spotify-connect._tcp
_airplay._tcp
```

To narrow the search, specify a type:

```
koi mdns discover http
```

```
My NAS     _http._tcp    192.168.1.50:8080    nas.local.
Pi-hole    _http._tcp    192.168.1.10:80      pihole.local.
```

Koi is liberal about type formats. These are all equivalent:

| Input               | Resolved to         |
| ------------------- | ------------------- |
| `http`              | `_http._tcp.local.` |
| `_http`             | `_http._tcp.local.` |
| `_http._tcp`        | `_http._tcp.local.` |
| `_http._tcp.local.` | `_http._tcp.local.` |
| `_dns._udp`         | `_dns._udp.local.`  |

If you omit the protocol, TCP is assumed. Service names must be 1–15 characters; protocol must be `tcp` or `udp`.

### How long to listen

Discovery is inherently a streaming operation - services arrive over time as they respond to the multicast query. By default Koi listens for **5 seconds**, which is usually enough for a populated network. Override with `--timeout`:

```
koi mdns discover http --timeout 15       # 15 seconds
koi mdns discover http --timeout 0        # indefinite (Ctrl+C to stop)
```

For automation, the indefinite mode is powerful: pipe the output to a script that reacts as services appear.

---

## Resolving a specific instance

If you know the full instance name and just need its address:

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

Resolve is a one-shot query - it waits up to 5 seconds for the instance to respond. Use this when you know _what_ you want and just need the _where_.

---

## Announcing a service

Discovery is only half the story. The other half is making your services visible:

```
koi mdns announce "My App" http 8080
```

This advertises `_http._tcp` called "My App" on port 8080. The process stays alive to maintain the advertisement - because that's how mDNS works. An announcement is a promise: "I'm here, and I'll keep saying so." Press Ctrl+C to send goodbye packets and unregister.

### Metadata with TXT records

TXT records let you attach key-value metadata to your service. Other tools can read these to know _what_ your service offers without connecting to it:

```
koi mdns announce "My App" http 8080 version=2.1 path=/api
```

### Pinning the IP address

On multi-homed hosts (multiple network interfaces), Docker hosts, or WSL, the auto-detected IP might not be the one you want. Pin it explicitly:

```
koi mdns announce "My App" http 8080 --ip 192.168.1.42
```

### Fixed-duration announcements

For CI/CD or test environments where you want timed visibility:

```
koi mdns announce "My App" http 8080 --timeout 60
```

---

## Subscribing to lifecycle events

Where `discover` shows you what currently exists, `subscribe` tells you _what changed_:

```
koi mdns subscribe http
```

```
[found]     My NAS       _http._tcp    192.168.1.50:8080    nas.local.
[resolved]  My NAS       _http._tcp    192.168.1.50:8080    nas.local.
[removed]   My NAS       _http._tcp
```

The three lifecycle states - **found** (it exists), **resolved** (address known), **removed** (gone) - reflect how mDNS actually works under the hood. Subscribe is what you want when building reactive systems: a load balancer that updates its pool, a dashboard that tracks fleet membership, or a deploy script that waits for a service to appear.

---

## JSON output

Every command supports `--json` for machine-readable NDJSON (one JSON object per line). This is the format scripts should consume:

```
koi mdns discover http --json
```

```json
{
  "found": {
    "name": "My NAS",
    "type": "_http._tcp",
    "host": "nas.local.",
    "ip": "192.168.1.50",
    "port": 8080,
    "txt": { "version": "2.1" }
  }
}
```

```
koi mdns announce "My App" http 8080 --json
```

```json
{
  "registered": {
    "id": "a1b2c3d4",
    "name": "My App",
    "type": "_http._tcp",
    "port": 8080
  }
}
```

```
koi mdns resolve "My NAS._http._tcp.local." --json
```

```json
{
  "resolved": {
    "name": "My NAS",
    "type": "_http._tcp",
    "host": "nas.local.",
    "ip": "192.168.1.50",
    "port": 8080,
    "txt": { "version": "2.1" }
  }
}
```

---

## HTTP API

The HTTP API is the primary interface for applications. Any language with an HTTP client can use it - from a container, a script, a microservice, or a browser.

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
{
  "registered": {
    "id": "a1b2c3d4",
    "name": "My App",
    "type": "_http._tcp",
    "port": 8080,
    "mode": "heartbeat",
    "lease_secs": 90
  }
}
```

The registration ID is your handle for renewals and unregistration.

For a permanent registration (never expires, lives until explicit removal):

```json
{ "name": "My App", "type": "_http._tcp", "port": 8080, "lease_secs": 0 }
```

For a custom heartbeat interval:

```json
{ "name": "My App", "type": "_http._tcp", "port": 8080, "lease_secs": 300 }
```

### Heartbeat (renew a lease)

```
PUT /v1/mdns/heartbeat/a1b2c3d4
```

```json
{ "renewed": { "id": "a1b2c3d4", "lease_secs": 90 } }
```

Send at half the `lease_secs` interval. A heartbeat also revives a draining registration back to alive - useful for brief network glitches.

### Unregister a service

```
DELETE /v1/mdns/unregister/a1b2c3d4
```

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

| Error code         | HTTP status | Meaning                                  |
| ------------------ | ----------- | ---------------------------------------- |
| `invalid_type`     | 400         | Bad service type format                  |
| `ambiguous_id`     | 400         | ID prefix matches multiple registrations |
| `parse_error`      | 400         | Malformed JSON body                      |
| `not_found`        | 404         | Registration doesn't exist               |
| `already_draining` | 409         | Drain on already-draining registration   |
| `not_draining`     | 409         | Revive on non-draining registration      |
| `resolve_timeout`  | 504         | No mDNS response within 5 seconds        |
| `daemon_error`     | 500         | mDNS engine error                        |
| `io_error`         | 500         | I/O failure                              |

CORS is enabled for all origins, so browser-based dashboards can call the API directly.

---

## Leases and liveness

This is the most important conceptual piece to understand. mDNS services should disappear when their owner dies - otherwise your network fills with ghost entries. Koi enforces this through a **lease system** that varies by transport.

| Mode          | Mechanism                                       | When it's used                     | Default timing                  |
| ------------- | ----------------------------------------------- | ---------------------------------- | ------------------------------- |
| **Heartbeat** | Client sends periodic `PUT /heartbeat/{id}`     | HTTP API registrations             | 90s lease, 30s grace            |
| **Session**   | Connection open = alive. Drop = grace starts.   | IPC (pipe/socket) and piped stdin  | 30s grace (IPC), 5s grace (CLI) |
| **Permanent** | Lives until explicit removal or daemon shutdown | `lease_secs: 0` from any transport | No expiry                       |

The choice is automatic - the adapter picks the right mode for the transport. HTTP is stateless, so it uses heartbeats. IPC has a persistent connection, so it uses session awareness. You only need to think about this if you want to override the defaults.

### The lifecycle of a registration

1. **Alive** - actively advertised on the network. Clients can discover it.
2. **Draining** - the lease expired or the session dropped. A grace timer is running. The service is still advertised (to prevent flapping during brief interruptions), but if no heartbeat or reconnection arrives before the grace period ends...
3. **Expired** - gone. Koi sends mDNS goodbye packets and removes the registration.

A background reaper checks every 5 seconds.

### Session reconnection

Here's a subtlety that matters for reliability: if a new registration arrives (same name + type) while an existing entry is draining, Koi **reconnects** rather than creating a duplicate. The draining entry is revived with the new session, the original registration ID is preserved, and the network sees uninterrupted continuity. This is what makes restarting an application transparent to its consumers.

---

## Admin commands

Admin commands give you visibility and control over the daemon's registrations. They're for operators, not applications - think of them as the management plane.

```
koi mdns admin status         # is the mDNS engine running? how many registrations?
koi mdns admin ls             # list all registrations with state and mode
koi mdns admin inspect a1b2   # full detail on one registration (prefix match)
koi mdns admin drain a1b2     # start grace timer (alive → draining)
koi mdns admin revive a1b2    # cancel drain (draining → alive)
koi mdns admin unregister a1b2  # remove immediately, send goodbye packets
```

All `{id}` parameters support **prefix matching** - use any unambiguous prefix of the registration ID. This is a small convenience that matters when you're debugging at 2 AM.

### Admin HTTP endpoints

| Method   | Path                             | Purpose                  |
| -------- | -------------------------------- | ------------------------ |
| `GET`    | `/v1/mdns/admin/status`          | Daemon mDNS status       |
| `GET`    | `/v1/mdns/admin/ls`              | List all registrations   |
| `GET`    | `/v1/mdns/admin/inspect/{id}`    | Inspect one registration |
| `DELETE` | `/v1/mdns/admin/unregister/{id}` | Force-remove             |
| `POST`   | `/v1/mdns/admin/drain/{id}`      | Force-drain              |
| `POST`   | `/v1/mdns/admin/revive/{id}`     | Force-revive             |

---

## IPC (Named Pipe / Unix Socket)

The IPC interface is the fastest path to the daemon - no HTTP overhead, no process spawn. It uses the same NDJSON protocol as piped stdin, over a persistent connection:

- **Windows**: `\\.\pipe\koi`
- **Linux/macOS**: `$XDG_RUNTIME_DIR/koi.sock` (or `/var/run/koi.sock`)

Send one JSON command per line, receive one JSON response per line. Streaming commands send multiple response lines.

IPC connections use **session-based leases**: registrations are tied to the connection lifetime. When the connection drops, those registrations enter the grace period. This is the interface the CLI uses internally, and it's what you should use if you're building a long-lived process that needs to maintain registrations without heartbeat overhead.
