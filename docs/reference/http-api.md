# HTTP API Reference

Base URL: `http://localhost:5641` (configurable via `--port` or `KOI_PORT`)

All responses are JSON unless noted. Disabled capabilities return `503` with `{"error": "capability_disabled", "message": "..."}`. Error responses follow `{"error": "error_code", "message": "description"}`.

## Authentication & Security

The HTTP API is **loopback-only** by default (`127.0.0.1:5641`). To reach it from
containers or other hosts, start the daemon with `--http-bind bridge` / `<ip>` /
`0.0.0.0` (env `KOI_HTTP_BIND`); the chosen address appears in `GET /v1/status`
(`http_bind`). Exposure does not relax the token requirement below. See the
[security model](security-model.md) for the bind modes and `koi token`.

**CORS policy:** Browser requests are accepted only from `http://localhost` / `http://127.0.0.1` origins (any port). The API is not open to arbitrary web origins.

**Daemon Access Token (DAT):**
At startup, the daemon generates a fresh random token and writes it to the breadcrumb file (`koi.endpoint`) with owner-only permissions.
- **GET / HEAD / OPTIONS** requests are normally unauthenticated — **except `/v1/mcp` and `/v1/events`** (live channels), **`/v1/certmesh/{posture,log}`** (live posture and trust history), **`/v1/pond`** (operator desire), and the **`/v1/udp/*`** surface (binding enumeration + datagram streams), which require the token on every resource-bearing method and every peer. CORS `OPTIONS` preflight remains body-free and token-free.
- **Peer-gated reads:** `/v1/inventory`, `/v1/certmesh/{status,diagnose}`, `/v1/dns/{list,zone,entries}`, and `/v1/dashboard/{snapshot,events}` are GET-exempt for a **loopback** peer (local CLI / dashboard) but require the token from a **non-loopback** peer; when the peer address is unknown they fail closed. The aggregate projections carry the same health and DNS detail as the protected domain reads.
- **Public certmesh protocol reads:** `/v1/certmesh/bootstrap` and `/v1/certmesh/trust-bundle` stay open on every peer. A joiner uses the minimal bootstrap projection to pin the CA before it holds a credential; members pull the ES256-signed, self-verifying trust bundle over plain HTTP. Full `/v1/certmesh/status` is not the bootstrap surface.
- **All mutations (POST, PUT, DELETE)** require the token to be sent in the `x-koi-token` header (except `/v1/certmesh/join`, which uses standard TOTP credentials during bootstrap).
- **Server-Sent Events (SSE)** endpoints are `GET`, so they follow the same policy: `/v1/mcp`, `/v1/events`, and `/v1/udp/recv/{id}` require the token on every peer, while `/v1/dashboard/events` requires it from remote or unknown peers.

The header value is the **bare token** — the breadcrumb file stores it with a `dat:` line prefix, but that prefix is **not** part of the header value (clients strip it):
```http
x-koi-token: 8a31…base64url…
```
See the [API authentication guide](../guides/api-authentication.md) for the per-OS recipe to read the token and make an authenticated write.

Interactive API docs are available at `GET /docs` (Scalar UI).


---

## System

| Method | Path                 | Description                                |
| ------ | -------------------- | ------------------------------------------ |
| GET    | `/healthz`           | Health check - returns `"OK"` (plain text) |
| GET    | `/v1/status`         | Revisioned composition-owned capability status |
| GET    | `/v1/inventory`      | Capability, health, and DNS views from one product revision |
| POST   | `/v1/admin/shutdown` | Initiate graceful shutdown                 |
| GET    | `/v1/host`           | Host identity and network interfaces       |
| GET    | `/v1/sd/prometheus`  | Prometheus HTTP service discovery (target groups) |
| GET/POST | `/v1/mcp`          | MCP server (Streamable HTTP / JSON-RPC) — token-required on all methods; **not** in `/openapi.json` (see below) |
| GET    | `/.well-known/mcp/server-card.json` | Public MCP discovery descriptor (unauthenticated) |
| GET    | `/openapi.json`      | OpenAPI specification                      |
| GET    | `/docs`              | Interactive API documentation              |

### Pond operator control and public projection

The full operator adapter exposes DAT-gated `PUT|DELETE /v1/ui` (publish the exact
five-file browser bundle or clear its current selection) and `GET|PUT|DELETE /v1/pond` (inspect, desire, and
stop the adapter). `PUT /v1/pond` returns the observed `url` only after a real
bind, interface observation, and supported firewall assessment settle. Its returned
`PondStatus` includes a process-local `revision` that advances when desired or observed
state changes and a listener `generation` that fences observations from a superseded task.
Its additive `accepting_commands` field becomes false before terminal daemon shutdown rejects
a lifecycle command; that rejection is HTTP 503 with the same typed status body.
If an intent or UI pointer replacement is visible but crash durability cannot be confirmed,
the authoritative status advances to that visible state while the mutating request returns
HTTP 500 with `pond_intent_durability_uncertain` or `pond_ui_durability_uncertain`. Retrying the
same request reflushes the visible selection or desire instead of treating it as a no-op.
The `ui` member identifies whether a complete bundle is available and its content-addressed
revision. `PUT /v1/ui` validates all five assets, durably writes the immutable generation,
atomically advances a separate durable current pointer, and returns only after that revision
is selected in the authoritative `PondStatus` and therefore becomes the serving truth. The
DAT-gated `DELETE /v1/ui` atomically changes that pointer to no selection, publishes the
unavailable UI status, and emits the semantic clear event before replying. It is a no-op when
already clear and never removes immutable generations; `GET /` returns the typed unpublished
response while every retained generation URL remains addressable across clear and restart.
The generation store retains bytes but owns no second mutable current selection. A rejected or failed publish keeps the preceding complete
generation current. Accepted generations remain addressable after later publishes and daemon
restarts. At startup, valid preceding single-bundle or exact five-loose-file storage migrates
to this repository; incomplete, corrupt, hash-incoherent, or dangling pointer state fails
initialization rather than being treated as an absent UI. Corruption of any retained
generation also fails closed, and a missing migration marker cannot erase accepted or unknown
repository state.
The first status already reflects persisted desire; malformed intent is surfaced as an
initialization failure rather than being reported as disabled. `running` reports actual
socket liveness; `state = running` additionally means Pond has a LAN endpoint with no known
supported-firewall block, while `state = waiting` may retain `running = true` when a bound
socket is blocked by interface or firewall conditions. UI storage does not introduce another
lifecycle value: `state` remains `disabled`, `reconciling`, `running`, `waiting`, or `error`.
All listener and UI status/event publications pass through one serialized, instance-scoped
gate: committed truth precedes status, status precedes its event, and the command reply comes
last. Each transition preserves the other concern's already-accepted projection.

Pond itself is a different, read-only router on `http_port + 3` (normally
5644). `GET /` reads the current status selection once and returns a no-store `307 Temporary
Redirect` to `/_koi/ui/<64-lowercase-hex>/`. The generation root serves its stored
`index.html` unchanged, and its relative `styles.css`, `sentences.js`, `app.js`, and
`koi.png` references resolve within that same retained immutable generation. Generation
assets are immutable; a later UI publish cannot change their bytes. The flat `/app.js`,
`/styles.css`, `/sentences.js`, and `/koi.png` routes do not exist.

Root-absolute reads made by the browser bundle remain live Pond endpoints: `/healthz`,
`/v1/status`, `/v1/mdns/browser/snapshot`, and `/v1/dns/entries`. They are never rewritten
under the generation prefix. Unknown generations and assets do not fall back to the current
bundle. Generation HTML uses `script-src 'self'` so its two external scripts can load, while
retaining `style-src 'self' 'unsafe-inline'`, `connect-src 'self'`, and `base-uri 'none'`.

`GET /v1/status` returns the explicit `PondPublicStatus` allowlist below. It is projected from
one accepted product snapshot, not formed by serializing internal status and deleting known
secrets:

```json
{
  "version": "1.0.0-dev.0",
  "platform": "linux",
  "uptime_secs": 3600,
  "revision": 18,
  "daemon": true,
  "surface": "pond",
  "capabilities": [
    { "name": "mdns", "enabled": true, "healthy": true }
  ]
}
```

Only known capability names and the three shown capability fields cross this unauthenticated
LAN boundary. Capability summaries, exact domain snapshots, listener addresses, filesystem
paths, reasons, firewall details, and error text are not part of this DTO. Pond does not mount
the full router, mutation routes, OpenAPI, audit history, or the DAT.

### MCP over Streamable HTTP (not in OpenAPI)

`/v1/mcp` speaks the Model Context Protocol over the **Streamable HTTP** transport (JSON-RPC 2.0, single endpoint, optional SSE upgrade) — it is **not** part of the utoipa-generated `/openapi.json`, the same way the ACME facade is documented separately. POST carries JSON-RPC requests; a bare GET opens the server→client SSE stream. Both require the `x-koi-token` header (the GET is carved out of the usual GET-exemption — it is a live channel, not a read). Enabled by default; disable with `--no-mcp-http` / `KOI_NO_MCP_HTTP` (then `/v1/mcp` returns `503 capability_disabled`), and `/v1/status` reports the state as the `mcp_http` field. The endpoint exposes the same tools as `koi mcp serve` plus MCP **resources** (`koi://lan/inventory`, `koi://health`, `koi://dns/zone`, `koi://mdns/services`). See [the MCP guide](../guides/mcp.md).

### Dashboard & Browser

| Method | Path                        | Description                                |
| ------ | --------------------------- | ------------------------------------------ |
| GET    | `/`                         | Embedded HTML dashboard (Lantern/Vellum)   |
| GET    | `/v1/dashboard/snapshot`    | System-level JSON snapshot (all capabilities; token required remotely) |
| GET    | `/v1/dashboard/events`      | Unified SSE activity feed (token required remotely) |
| GET    | `/mdns-browser`             | mDNS network browser HTML page             |
| GET    | `/v1/mdns/browser/snapshot` | Network cache snapshot                     |
| GET    | `/v1/mdns/browser/events`   | Service discovery SSE feed                 |

### GET /v1/host

```json
{
  "hostname": "node-azure-pool",
  "hostname_fqdn": "node-azure-pool.local",
  "os": "windows",
  "arch": "x86_64",
  "interfaces": {
    "lan": [
      { "name": "Ethernet", "ip": "192.168.1.42" }
    ]
  }
}
```

LAN interfaces exclude loopback and link-local addresses.

### GET /v1/sd/prometheus

Prometheus [HTTP service discovery](https://prometheus.io/docs/prometheus/latest/http_sd/)
endpoint. Returns **200** with `Content-Type: application/json` and a JSON array of
target groups; the full list is returned on every poll (Prometheus does not diff),
and an empty result is `[]`. Unauthenticated like `/healthz` (it is a `GET`).

Query: `?include=discovered` also emits LAN-discovered mDNS `_http._tcp` services.
By default only **Koi-managed** targets are returned (health checks + runtime
instances with a published port).

```json
[
  {
    "targets": ["10.0.0.5:3000"],
    "labels": {
      "__meta_koi_name": "grafana",
      "__meta_koi_source": "health",
      "__meta_koi_health": "up",
      "__meta_koi_cert_expiry_days": "30"
    }
  }
]
```

See [`docs/guides/integrations.md`](../guides/integrations.md#prometheus) for the
`prometheus.yml` snippet and the full label table. `__meta_koi_cert_expiry_days`
is unique to Koi — no other LAN SD source exposes certificate expiry.

### GET /v1/status

```json
{
  "version": "1.0.0-dev.0",
  "platform": "windows",
  "uptime_secs": 3600,
  "daemon": true,
  "http_bind": "127.0.0.1",
  "revision": 18,
  "capabilities": [
    { "name": "mdns", "summary": "3 registrations", "healthy": true }
  ]
}
```

`revision` is the process-local revision of the composition-owned `KoiStatus`. It advances
when a domain feed or explicit adapter/composition fact changes the projected capability
ladder; it is not comparable across daemon restarts or hosts.

### GET /v1/inventory

Returns the MCP automation inventory (`status`, `health`, and `dns`) projected from one
immutable `KoiStatus` revision. The daemon captures the aggregate once; it never joins
independently timed domain endpoint reads. Missing or disabled domain projections are `null`.
The `status` object includes the bounded `mdns` and `dns` runtime snapshots from that same
revision, while the top-level `dns` member remains the DNS catalog projection.
The route is token-free for a loopback peer and requires `x-koi-token` from a non-loopback
peer; an unknown peer identity fails closed.

---

## mDNS (`/v1/mdns`)

### GET /v1/mdns/snapshot

Return the authoritative, revisioned discovery projection currently accepted by the mDNS
domain. This is the recovery/read-model endpoint for late or lagged stream consumers.

```json
{
  "revision": 12,
  "service_types": ["_http._tcp.local."],
  "records": [
    {"name":"My NAS","type":"_http._tcp.local.","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}
  ],
  "sources": [
    {"query":"_http._tcp.local.","provider":"avahi","generation":7,"available":true}
  ],
  "observations": [
    {"source":{"query":"_http._tcp.local.","provider":"avahi","generation":7,"available":true},"kind":"service_record","record":{"name":"My NAS","type":"_http._tcp.local.","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
  ]
}
```

`service_types` and `records` are compatibility projections. `sources` reports every
currently demanded canonical browse query, including an empty or temporarily
unavailable query. `observations` retains the query, concrete provider, route
generation and availability beside each accepted fact. For subtype browsing the
source query remains `_printer._sub._http._tcp.local.`, while the returned record's
`type` is the base instance namespace `_http._tcp.local.`. Unknown but valid DNS-SD
service types are preserved. A provider becoming unavailable does not mean an empty
network; retained observations are marked unavailable until the generation is
retired or matching removals arrive.

### GET /v1/mdns/discover

Browse for services via mDNS. Returns an SSE stream.

| Parameter  | Type  | Default                         | Description                                    |
| ---------- | ----- | ------------------------------- | ---------------------------------------------- |
| `type`     | query | `_services._dns-sd._udp.local.` | Base service type or DNS-SD subtype to browse  |
| `idle_for` | query | `5`                             | Seconds of quiet before closing (0 = infinite) |

Each SSE event includes an `id:` field (UUIDv7) for deduplication.

```
data: {"found":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
```

If the bounded event receiver lags, the stream emits `event: resync` with a
`{"snapshot": ...}` frame. Replace the local projection with that full snapshot; do not
append it or infer the missing events. The snapshot has already been committed before the
notification is emitted.

### POST /v1/mdns/announce

Register a service on the network.

```json
{
  "name": "My App",
  "type": "_http._tcp",
  "port": 8080,
  "ip": "192.168.1.42", // optional - pin to specific address
  "lease_secs": 90, // optional - null=heartbeat 90s, 0=permanent
  "txt": { "version": "1.0" } // optional
}
```

Response (`201 Created`):

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

Lease modes:

- `null` or omitted → `heartbeat` (90s default, requires periodic `PUT /heartbeat/{id}`)
- `0` → `permanent` (lives until delete or daemon restart)
- `N` → `heartbeat` with N-second lease

### PUT /v1/mdns/heartbeat/{id}

Renew a heartbeat-mode registration.

```json
{ "renewed": { "id": "a1b2c3d4", "lease_secs": 90 } }
```

### DELETE /v1/mdns/unregister/{id}

Remove a registration. Sends mDNS goodbye packets.

```json
{ "unregistered": "a1b2c3d4" }
```

### GET /v1/mdns/resolve

Resolve a specific service instance.

| Parameter | Type  | Required | Description                                           |
| --------- | ----- | -------- | ----------------------------------------------------- |
| `name`    | query | yes      | Full instance name (e.g., `My NAS._http._tcp.local.`) |

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

### GET /v1/mdns/subscribe

Stream lifecycle events for a service type. Returns SSE.

| Parameter  | Type  | Required | Description                                               |
| ---------- | ----- | -------- | --------------------------------------------------------- |
| `type`     | query | yes      | Service type to watch                                     |
| `idle_for` | query | no       | Seconds of quiet before closing (default 5, 0 = infinite) |

Events: `found`, `resolved`, `removed`.

```
data: {"event":"found","service":{"name":"...","type":"...","host":"...","ip":"...","port":8080,"txt":{}}}
data: {"event":"removed","service":{"name":"...","type":"..."}}
```

This stream uses the same `event: resync` + `{"snapshot": ...}` recovery frame as
`/discover` when delivery lags.

### Admin endpoints (`/v1/mdns/admin`)

| Method | Path                             | Description                                          |
| ------ | -------------------------------- | ---------------------------------------------------- |
| GET    | `/v1/mdns/admin/status`          | Daemon/registration status plus revisioned provider control-plane state |
| GET    | `/v1/mdns/admin/ls`              | List all registrations with lifecycle details        |
| GET    | `/v1/mdns/admin/inspect/{id}`    | Detailed view of one registration (prefix match)     |
| DELETE | `/v1/mdns/admin/unregister/{id}` | Force-remove a registration                          |
| POST   | `/v1/mdns/admin/drain/{id}`      | Start grace timer                                    |
| POST   | `/v1/mdns/admin/revive/{id}`     | Cancel drain, restore to alive                       |

---

## Certmesh (`/v1/certmesh`)

### Core operations

| Method | Path                         | Description                                          |
| ------ | ---------------------------- | ---------------------------------------------------- |
| POST   | `/v1/certmesh/create`        | Create a new CA                                      |
| POST   | `/v1/certmesh/join`          | Enroll into existing mesh                            |
| POST   | `/v1/certmesh/invite`        | Mint a single-use, hostname-bound enrollment invite |
| POST   | `/v1/certmesh/member-csr`    | Generate this member's keypair + CSR                 |
| POST   | `/v1/certmesh/member-cert`   | Install a CA-signed cert next to the member key      |
| POST   | `/v1/certmesh/unlock`        | Unlock a locked CA                                   |
| GET    | `/v1/certmesh/bootstrap`     | Minimal public CA/enrollment preflight               |
| GET    | `/v1/certmesh/status`        | Full authoritative mesh status (**token required remotely**) |
| GET    | `/v1/certmesh/diagnose`      | Trust-doctor report (posture, identity, integrity)  |
| GET    | `/v1/certmesh/trust-bundle`  | Signed, monotonic mesh-truth bundle                 |
| GET    | `/v1/certmesh/log`           | Audit log (**token-authenticated** even on GET — carved out of the GET exemption, like `/v1/mcp`) |

### Enrollment management

| Method | Path                            | Description                        |
| ------ | ------------------------------- | ---------------------------------- |
| POST   | `/v1/certmesh/open-enrollment`  | Open enrollment window             |
| POST   | `/v1/certmesh/close-enrollment` | Close enrollment                   |
| POST   | `/v1/certmesh/rotate-auth`      | Rotate enrollment auth credential  |

### Lifecycle

| Method | Path                    | Description                   |
| ------ | ----------------------- | ----------------------------- |
| POST   | `/v1/certmesh/renew`    | Renew a member's certificate  |
| POST   | `/v1/certmesh/revoke`   | Revoke a member's certificate |
| PUT    | `/v1/certmesh/set-hook` | Set renewal hook command      |
| POST   | `/v1/certmesh/promote`  | Promote a member to standby CA |
| POST   | `/v1/certmesh/health`   | CA fingerprint health check   |

### Backup/restore

| Method | Path                   | Description                                                               |
| ------ | ---------------------- | ------------------------------------------------------------------------- |
| POST   | `/v1/certmesh/backup`  | Create encrypted backup (`ca_passphrase`, `backup_passphrase`)            |
| POST   | `/v1/certmesh/restore` | Restore from backup (`backup_hex`, `backup_passphrase`, `new_passphrase`) |
| POST   | `/v1/certmesh/destroy` | Destroy all certmesh state                                                |

### POST /v1/certmesh/join

```json
{
  "hostname": "workstation-01",
  "auth": { "method": "totp", "code": "123456" },
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "sans": ["workstation-01.internal"]
}
```

Response:

```json
{
  "hostname": "workstation-01",
  "ca_cert": "-----BEGIN CERTIFICATE-----...",
  "service_cert": "-----BEGIN CERTIFICATE-----...",
  "ca_fingerprint": "AB:CD:...",
  "policy": { "leaf_lifetime_days": 7, "renew_threshold_days": 3, "grace_days": 1 }
}
```

The joining member creates and retains the private key; the CA requires the CSR and never
returns `service_key` or a CA-local `cert_path` in the normal remote flow.

### GET /v1/certmesh/status

This is the full operator read model. It is token-free on loopback but requires
`x-koi-token` from a non-loopback peer (and fails closed when peer identity is unknown).
`role` is the durable relationship to the mesh; `posture` and `identity.condition` describe
what the local identity can safely do now. A joined member with damaged identity remains
`role: "member"` with open posture and an `invalid` condition rather than failing open.

```json
{
  "revision": 12,
  "role": "authority",
  "posture": { "signed": true, "encrypted": false },
  "identity": {
    "condition": "healthy",
    "info": {
      "hostname": "ca-host",
      "ca_fingerprint": "abcdef0123456789",
      "renewal": {
        "expires_at": "2026-09-10T12:00:00Z",
        "next_renewal_at": "2026-09-07T12:00:00Z",
        "expires_in_days": 6,
        "renew_overdue": false,
        "expired": false
      }
    }
  },
  "diagnosis": {
    "posture": { "signed": true, "encrypted": false },
    "overall": "healthy",
    "checks": [
      { "name": "posture", "status": "ok", "detail": "Authenticated" },
      { "name": "identity", "status": "ok", "detail": "ca-host (abcdef0123456789)" },
      {
        "name": "identity_integrity",
        "status": "ok",
        "detail": "on-disk leaf parses and chains to its CA"
      },
      { "name": "self_revocation", "status": "ok", "detail": "not revoked" },
      { "name": "renewal", "status": "ok", "detail": "leaf healthy (expires in 6 days)" },
      {
        "name": "clock",
        "status": "ok",
        "detail": "envelopes accept ±300s skew (run NTP if peers reject for skew)"
      }
    ]
  },
  "authority": {
    "locked": false,
    "ca_fingerprint": "abcdef0123456789",
    "auth_method": "totp",
    "enrollment_open": true,
    "requires_approval": false,
    "enrollment_state": "open",
    "member_count": 1,
    "seq": 4,
    "policy": {
      "leaf_lifetime_days": 7,
      "renew_threshold_days": 3,
      "grace_days": 1
    },
    "members": [
      {
        "hostname": "ca-host",
        "role": "primary",
        "status": "active",
        "cert_fingerprint": "0123456789abcdef",
        "cert_expires": "2026-09-10T12:00:00Z",
        "cert_sans": ["ca-host.internal"],
        "last_seen": "2026-09-03T12:00:00Z",
        "proxy_entries": []
      }
    ]
  },
  "renewal": { "consecutive_failures": 0 }
}
```

`revision` is monotonic only for this running Certmesh instance. It is a refresh/convergence
hint, not the durable roster `seq` and not a cross-node ordering token. `renewal` is the
process-local execution health of automatic renewal: `consecutive_failures` resets after a
successful renewal, and `last_error` is present while failures remain. A visible Certmesh
generation whose crash durability cannot be confirmed is returned with a RED
`repository_durability` diagnosis; the mutating request is not acknowledged as success.

### GET /v1/certmesh/bootstrap

This token-free endpoint is the intentionally small pre-credential projection used for
enrollment discovery and CA pinning:

```json
{
  "revision": 12,
  "authority_available": true,
  "ca_fingerprint": "abcdef0123456789",
  "enrollment_open": true,
  "requires_approval": false
}
```

It never includes local identity diagnosis, renewal state, policy, roster members, or audit
history. The joining client still compares `ca_fingerprint` with the fingerprint received
out of band before it sends a CSR.

---

## DNS (`/v1/dns`)

| Method | Path                                 | Description                                          |
| ------ | ------------------------------------ | ---------------------------------------------------- |
| GET    | `/v1/dns/status`                     | Revisioned listener state, configuration, and record counts |
| GET    | `/v1/dns/lookup?name=grafana&type=A` | Resolve a local name                                 |
| GET    | `/v1/dns/list`                       | List all resolvable names                            |
| GET    | `/v1/dns/entries`                    | List static entries with details                     |
| GET    | `/v1/dns/zone?format=hosts\|dnsmasq\|json` | Export the resolvable zone for an incumbent resolver |
| POST   | `/v1/dns/add`                        | Add static entry (`name`, `ip`, optional `ttl`)      |
| DELETE | `/v1/dns/remove/{name}`              | Remove static entry                                  |
| POST   | `/v1/dns/serve`                      | Start the DNS resolver                               |
| POST   | `/v1/dns/stop`                       | Stop the DNS resolver                                |

### GET /v1/dns/status

This is the DNS domain's cheap authoritative status: listener desire and observed
state, immutable configuration identity, and bounded counts for each effective
record source. Full records remain on the list/entries/zone query surfaces.

```json
{
  "revision": 3,
  "running": true,
  "desired": true,
  "state": "running",
  "endpoints": ["0.0.0.0:53"],
  "zone": "internal",
  "port": 53,
  "records": {
    "static_entries": 3,
    "certmesh_entries": 2,
    "mdns_entries": 4,
    "txt_names": 0
  }
}
```

### GET /v1/dns/lookup

| Parameter | Type  | Default  | Description                        |
| --------- | ----- | -------- | ---------------------------------- |
| `name`    | query | required | Name to resolve                    |
| `type`    | query | `A`      | Record type: `A`, `AAAA`, or `ANY` |

### GET /v1/dns/zone

Export the full resolvable zone (static + certmesh + mDNS-derived records) so an
*incumbent* resolver can conditionally forward to or import from Koi. The `format`
query param selects the shape:

| `format`  | Content-Type | Body |
| --------- | ------------ | ---- |
| `hosts`   | `text/plain` | `<ip> <name>` lines (trailing dot stripped) |
| `dnsmasq` | `text/plain` | `address=/<name>/<ip>` lines (trailing dot stripped) |
| `json` (default) | `application/json` | `{ static_entries, certmesh_entries, mdns_entries }`, each a map of FQDN → IPs |

See [`docs/guides/dns-coexistence.md`](../guides/dns-coexistence.md) for the
conditional-forwarding recipes (AdGuard Home, Pi-hole, dnsmasq, Unbound,
Technitium) that let Koi sit alongside your existing resolver.

```json
{ "name": "grafana.internal.", "ips": ["192.168.1.42"], "source": "static" }
```

Sources: `static`, `certmesh`, `mdns`.

---

## Health (`/v1/health`)

| Method | Path                       | Description                               |
| ------ | -------------------------- | ----------------------------------------- |
| GET    | `/v1/health/status`        | Snapshot of all checks with current state |
| GET    | `/v1/health/list`          | List registered check configurations      |
| POST   | `/v1/health/add`           | Register a check                          |
| DELETE | `/v1/health/remove/{name}` | Remove a check                            |

`GET /v1/health/status` returns the authoritative `HealthSnapshot` with `revision`,
`running`, `machines`, and `services`. Completed check batches publish the snapshot before
their semantic transition events, so a lagged consumer can recover from this endpoint.

### POST /v1/health/add

```json
{
  "name": "api",
  "kind": "http",
  "target": "https://localhost:3000/health",
  "interval_secs": 30,
  "timeout_secs": 5
}
```

`kind`: `"http"` or `"tcp"`. Interval and timeout are optional with sensible defaults.

---

## Proxy (`/v1/proxy`)

A TLS-terminating **TCP passthrough**: it binds the listen port, terminates TLS, and
pipes raw bytes to the backend (so WebSockets and any bidirectional protocol work). It
does **not** do path routing, header injection, or rewrites — point it at Caddy/Traefik
for L7 features.

| Method | Path                      | Description          |
| ------ | ------------------------- | -------------------- |
| GET    | `/v1/proxy/status`        | Active proxy status  |
| GET    | `/v1/proxy/list`          | List proxy entries   |
| POST   | `/v1/proxy/add`           | Add a proxy entry    |
| DELETE | `/v1/proxy/remove/{name}` | Remove a proxy entry |

### POST /v1/proxy/add

`backend` is a TCP endpoint as `host:port`. A URL (`http://127.0.0.1:8080`) is also
accepted — only its `host:port` is used; the path is irrelevant to a byte passthrough.
A non-loopback backend requires `allow_remote: true` (the proxy→backend hop is plaintext).

```json
{
  "name": "web",
  "listen_port": 8443,
  "backend": "127.0.0.1:8080",
  "allow_remote": false
}
```

### GET /v1/proxy/status

`state` reflects each listener's real liveness; `error` is present only when a listener
failed (e.g. the port was already in use). `cert_source` is `override` for a usable
Proxy-owned file pair, `certmesh` for the current identity supplied through the composed
Certmesh port, or `self-signed` for the generated zero-config fallback. `cert_revision`
advances whenever the selected certificate bytes or provenance changes.

```json
{
  "revision": 7,
  "proxies": [
    {
      "name": "web",
      "listen_port": 8443,
      "backend": "127.0.0.1:8080",
      "allow_remote": false,
      "cert_source": "certmesh",
      "cert_revision": 2,
      "state": "running"
    },
    {
      "name": "old-app",
      "listen_port": 9443,
      "backend": "127.0.0.1:9000",
      "allow_remote": false,
      "cert_source": "self-signed",
      "cert_revision": 0,
      "state": "error",
      "error": "address in use"
    }
  ]
}
```

---

## UDP (`/v1/udp`)

| Method | Path                     | Description                                  |
| ------ | ------------------------ | -------------------------------------------- |
| POST   | `/v1/udp/bind`           | Bind a host UDP socket                       |
| DELETE | `/v1/udp/bind/{id}`      | Unbind (close) a binding                     |
| GET    | `/v1/udp/recv/{id}`      | Subscribe to incoming datagrams (SSE stream) |
| POST   | `/v1/udp/send/{id}`      | Send a datagram through a binding            |
| GET    | `/v1/udp/status`         | List all active bindings                     |
| PUT    | `/v1/udp/heartbeat/{id}` | Renew a binding's lease                      |

### POST /v1/udp/bind

Open a host-side UDP socket. Returns a binding ID used for all subsequent operations.

```json
{
  "port": 9999,
  "addr": "127.0.0.1",
  "lease_secs": 300,
  "allow_remote": false
}
```

`addr` defaults to `127.0.0.1` (loopback). Binding a non-loopback address — and
sending to non-loopback destinations through the binding — requires
`"allow_remote": true`; the default keeps a binding loopback-only so a token
holder cannot use it as an SSRF / egress relay.

Response (`201 Created`):

```json
{
  "id": "a1b2c3d4",
  "local_addr": "127.0.0.1:9999",
  "created_at": "2026-06-13T02:09:30Z",
  "last_heartbeat": "2026-06-13T02:09:30Z",
  "lease_secs": 300,
  "allow_remote": false
}
```

### DELETE /v1/udp/bind/{id}

Close a binding and release the socket. Returns `200` with `{"unbound": "a1b2c3d4"}` or `404` if the binding does not exist.

### GET /v1/udp/recv/{id}

Subscribe to incoming datagrams on a binding. Returns an SSE stream. Each event carries a base64-encoded payload and the sender address:

```
data: {"binding_id":"a1b2c3d4","src":"192.168.1.10:54321","payload":"aGVsbG8=","received_at":"2026-06-13T02:09:30Z"}
```

Returns `404` if the binding does not exist.

### POST /v1/udp/send/{id}

Send a datagram through an existing binding.

```json
{
  "payload": "aGVsbG8=",
  "dest": "192.168.1.10:9998"
}
```

`payload` is base64-encoded (RFC 4648 standard). Response: `200 OK` with `{"sent": <bytes>}`.

### GET /v1/udp/status

List all active bindings with lease information.

```json
{
  "revision": 4,
  "running": true,
  "bindings": [
    {
      "id": "a1b2c3d4",
      "local_addr": "127.0.0.1:9999",
      "created_at": "2026-06-13T02:09:30Z",
      "last_heartbeat": "2026-06-13T02:09:30Z",
      "lease_secs": 300,
      "allow_remote": false
    }
  ]
}
```

### PUT /v1/udp/heartbeat/{id}

Renew a binding's lease. Bindings expire after `lease_secs` (default 300) without a heartbeat.

Response: `200 OK` with `{"renewed": "a1b2c3d4"}` or `404` if the binding does not exist.

---

## Runtime adapter (`/v1/runtime`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/runtime/status` | Adapter status (active, backend, instance count) |
| GET | `/v1/runtime/instances` | List all tracked instances |

### GET /v1/runtime/status

Returns the adapter's connection state and complete normalized inventory. `revision`
advances for backend or inventory changes; `backend_error` is omitted when the latest
connection is healthy.

```json
{
  "revision": 9,
  "active": true,
  "backend": "docker",
  "instance_count": 0,
  "instances": []
}
```

### GET /v1/runtime/instances

Returns all instances currently tracked by the adapter. Each includes resolved port mappings, parsed `koi.*` labels, IPs, and image info.

```json
[
  {
    "id": "a1b2c3d4e5f6...",
    "name": "grafana",
    "ports": [
      {"host_port": 3000, "container_port": 3000, "protocol": "tcp", "host_ip": "0.0.0.0"}
    ],
    "ips": ["172.17.0.2"],
    "metadata": {
      "service_type": "_http._tcp",
      "dns_name": "grafana",
      "health_path": "/api/health"
    },
    "backend": "docker",
    "state": "running",
    "discovered_at": "2026-03-26T10:00:00Z",
    "image": "grafana/grafana:latest"
  }
]
```

---

## ACME (RFC 8555) — separate TLS port

The ACME facade is **not** part of the main HTTP adapter or its OpenAPI spec. It runs on a
dedicated server-auth TLS listener (default port **5643**, `--acme-port` / `KOI_ACME_PORT`),
gated by `--no-acme` / `KOI_NO_ACME`, and only when the certmesh CA is initialized + unlocked
and the DNS capability is enabled. Endpoints follow the RFC 8555 wire format
(`application/jose+json` requests, `application/problem+json` errors) — a different content
model from the Koi pipeline shapes, which is why they are documented here rather than in the
utoipa-generated `/openapi.json`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/acme/directory` | Directory: endpoint URLs + `meta.externalAccountRequired` |
| HEAD/GET | `/acme/new-nonce` | Fresh `Replay-Nonce` (200/204) |
| POST | `/acme/new-account` | Register account (JWS + embedded jwk; EAB in closed mode) |
| POST | `/acme/new-order` | Create an order (identifiers must be in the DNS zone) |
| POST | `/acme/authz/{id}` | Authorization object (POST-as-GET) |
| POST | `/acme/chall/{id}` | Trigger dns-01 validation (in-process TXT check) |
| POST | `/acme/order/{id}/finalize` | Submit CSR → issue (SAN-authorization enforced) |
| POST | `/acme/cert/{id}` | Download leaf + CA chain (`application/pem-certificate-chain`) |
| POST | `/acme/revoke-cert` | Revoke an issued certificate |

Scope: dns-01 only, EC/ES256 only, in-zone names only. Errors use the ACME problem registry
(`urn:ietf:params:acme:error:*`). Every response carries a fresh `Replay-Nonce`. See
[guides/acme.md](../guides/acme.md) for client recipes and the security model.

---

## Response shape

`#[serde(flatten)]` emits a response as its body at the top level — there is no
envelope or wrapper key. The happy path is just the data:

```json
{ "found": { "name": "Server A", ... } }
```

An error is a flat body carrying an `error` code and a `message`:

```json
{ "error": "not_found", "message": "Registration not found" }
```
