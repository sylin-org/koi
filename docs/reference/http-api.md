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
- **GET / HEAD / OPTIONS** requests are unauthenticated (exempt from token checks) — **except `/v1/mcp`**, which requires the token on *every* method (including its server→client SSE GET); see the MCP note below.
- **All mutations (POST, PUT, DELETE)** require the token to be sent in the `x-koi-token` header (except `/v1/certmesh/join`, which uses standard TOTP credentials during bootstrap).
- **Server-Sent Events (SSE)** endpoints are `GET`, so they are unauthenticated on the open methods above — except `/v1/mcp`'s server→client SSE stream, which (like the rest of `/v1/mcp`) requires the `x-koi-token` header.

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
| GET    | `/v1/status`         | Unified capability status                  |
| POST   | `/v1/admin/shutdown` | Initiate graceful shutdown                 |
| GET    | `/v1/host`           | Host identity and network interfaces       |
| GET    | `/v1/sd/prometheus`  | Prometheus HTTP service discovery (target groups) |
| GET/POST | `/v1/mcp`          | MCP server (Streamable HTTP / JSON-RPC) — token-required on all methods; **not** in `/openapi.json` (see below) |
| GET    | `/.well-known/mcp/server-card.json` | Public MCP discovery descriptor (unauthenticated) |
| GET    | `/openapi.json`      | OpenAPI specification                      |
| GET    | `/docs`              | Interactive API documentation              |

### MCP over Streamable HTTP (not in OpenAPI)

`/v1/mcp` speaks the Model Context Protocol over the **Streamable HTTP** transport (JSON-RPC 2.0, single endpoint, optional SSE upgrade) — it is **not** part of the utoipa-generated `/openapi.json`, the same way the ACME facade is documented separately. POST carries JSON-RPC requests; a bare GET opens the server→client SSE stream. Both require the `x-koi-token` header (the GET is carved out of the usual GET-exemption — it is a live channel, not a read). Enabled by default; disable with `--no-mcp-http` / `KOI_NO_MCP_HTTP` (then `/v1/mcp` returns `503 capability_disabled`), and `/v1/status` reports the state as the `mcp_http` field. The endpoint exposes the same tools as `koi mcp serve` plus MCP **resources** (`koi://lan/inventory`, `koi://health`, `koi://dns/zone`, `koi://mdns/services`). See [the MCP guide](../guides/mcp.md).

### Dashboard & Browser

| Method | Path                        | Description                                |
| ------ | --------------------------- | ------------------------------------------ |
| GET    | `/`                         | Embedded HTML dashboard (Lantern/Vellum)   |
| GET    | `/v1/dashboard/snapshot`    | System-level JSON snapshot (all capabilities) |
| GET    | `/v1/dashboard/events`      | Unified SSE activity feed                  |
| GET    | `/mdns-browser`             | mDNS network browser HTML page             |
| GET    | `/v1/mdns/browser/snapshot` | Network cache snapshot                     |
| GET    | `/v1/mdns/browser/events`   | Service discovery SSE feed                 |

### GET /v1/host

```json
{
  "hostname": "stone-azure-pool",
  "hostname_fqdn": "stone-azure-pool.local",
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
  "version": "0.4.2",
  "platform": "windows",
  "uptime_secs": 3600,
  "daemon": true,
  "http_bind": "127.0.0.1",
  "capabilities": [
    { "name": "mdns", "summary": "3 registrations", "healthy": true }
  ]
}
```

---

## mDNS (`/v1/mdns`)

### GET /v1/mdns/discover

Browse for services via mDNS. Returns an SSE stream.

| Parameter  | Type  | Default                         | Description                                    |
| ---------- | ----- | ------------------------------- | ---------------------------------------------- |
| `type`     | query | `_services._dns-sd._udp.local.` | Service type to browse                         |
| `idle_for` | query | `5`                             | Seconds of quiet before closing (0 = infinite) |

Each SSE event includes an `id:` field (UUIDv7) for deduplication.

```
data: {"found":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
```

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

### Admin endpoints (`/v1/mdns/admin`)

| Method | Path                             | Description                                          |
| ------ | -------------------------------- | ---------------------------------------------------- |
| GET    | `/v1/mdns/admin/status`          | Daemon status (version, uptime, registration counts) |
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
| GET    | `/v1/certmesh/status`        | Mesh status                                          |
| GET    | `/v1/certmesh/diagnose`      | Trust-doctor report (posture, identity, integrity)  |
| GET    | `/v1/certmesh/trust-bundle`  | Signed, monotonic mesh-truth bundle                 |
| GET    | `/v1/certmesh/log`           | Audit log                                            |

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
  "sans": ["workstation-01.lan"]
}
```

Response:

```json
{
  "hostname": "workstation-01",
  "ca_cert": "-----BEGIN CERTIFICATE-----...",
  "service_cert": "-----BEGIN CERTIFICATE-----...",
  "service_key": "-----BEGIN PRIVATE KEY-----...",
  "ca_fingerprint": "AB:CD:...",
  "cert_path": "/path/to/certs"
}
```

### GET /v1/certmesh/status

```json
{
  "ca_initialized": true,
  "ca_locked": false,
  "ca_fingerprint": "AB:CD:...",
  "auth_method": "totp",
  "enrollment_open": true,
  "requires_approval": false,
  "enrollment_state": "open",
  "member_count": 3,
  "members": [
    {
      "hostname": "server-01",
      "role": "primary",
      "fingerprint": "...",
      "expires": "..."
    }
  ]
}
```

---

## DNS (`/v1/dns`)

| Method | Path                                 | Description                                          |
| ------ | ------------------------------------ | ---------------------------------------------------- |
| GET    | `/v1/dns/status`                     | Resolver status (running, zone, port, record counts) |
| GET    | `/v1/dns/lookup?name=grafana&type=A` | Resolve a local name                                 |
| GET    | `/v1/dns/list`                       | List all resolvable names                            |
| GET    | `/v1/dns/entries`                    | List static entries with details                     |
| GET    | `/v1/dns/zone?format=hosts\|dnsmasq\|json` | Export the resolvable zone for an incumbent resolver |
| POST   | `/v1/dns/add`                        | Add static entry (`name`, `ip`, optional `ttl`)      |
| DELETE | `/v1/dns/remove/{name}`              | Remove static entry                                  |
| POST   | `/v1/dns/serve`                      | Start the DNS resolver                               |
| POST   | `/v1/dns/stop`                       | Stop the DNS resolver                                |

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
{ "name": "grafana.lan.", "ips": ["192.168.1.42"], "source": "static" }
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
failed (e.g. the port was already in use). `cert_source` is `certmesh` when a cert file
was found on disk (where certmesh deposits certs) or `self-signed` for the generated
zero-config fallback.

```json
{
  "proxies": [
    {
      "name": "web",
      "listen_port": 8443,
      "backend": "127.0.0.1:8080",
      "allow_remote": false,
      "cert_source": "certmesh",
      "state": "running"
    },
    {
      "name": "old-app",
      "listen_port": 9443,
      "backend": "127.0.0.1:9000",
      "allow_remote": false,
      "cert_source": "self-signed",
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
  "addr": "0.0.0.0",
  "lease_secs": 300
}
```

Response (`201 Created`):

```json
{
  "id": "a1b2c3d4",
  "local_addr": "0.0.0.0:9999",
  "created_at": "2026-06-13T02:09:30Z",
  "last_heartbeat": "2026-06-13T02:09:30Z",
  "lease_secs": 300
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
  "bindings": [
    {
      "id": "a1b2c3d4",
      "local_addr": "0.0.0.0:9999",
      "created_at": "2026-06-13T02:09:30Z",
      "last_heartbeat": "2026-06-13T02:09:30Z",
      "lease_secs": 300
    }
  ]
}
```

### PUT /v1/udp/heartbeat/{id}

Renew a binding's lease. Bindings expire after 30 seconds without a heartbeat.

Response: `200 OK` with `{"renewed": "a1b2c3d4"}` or `404` if the binding does not exist.

---

## Runtime adapter (`/v1/runtime`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/runtime/status` | Adapter status (active, backend, instance count) |
| GET | `/v1/runtime/instances` | List all tracked instances |

### GET /v1/runtime/status

Returns the adapter's connection state.

```json
{
  "active": true,
  "backend": "docker",
  "instance_count": 3
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

## Pipeline properties

Status, warnings, and errors are operational metadata attached alongside responses. Their absence is the happy path.

| Property  | Values                     | Meaning                          |
| --------- | -------------------------- | -------------------------------- |
| `status`  | `"ongoing"` / `"finished"` | Whether more data is expected    |
| `warning` | Free-form string           | Operation succeeded with caveats |

Clean response (no extra keys):

```json
{ "found": { "name": "Server A", ... } }
```

With pipeline metadata:

```json
{ "found": { "name": "Server B", ... }, "status": "ongoing" }
```
