# HTTP API Reference

Base URL: `http://localhost:5641` (configurable via `--port` or `KOI_PORT`)

All responses are JSON unless noted. Disabled capabilities return `503` with `{"error": "capability_disabled", "message": "..."}`. Error responses follow `{"error": "error_code", "message": "description"}`.

CORS is enabled by default. Interactive API docs are available at `GET /docs` (Scalar UI).

---

## System

| Method | Path                 | Description                                |
| ------ | -------------------- | ------------------------------------------ |
| GET    | `/healthz`           | Health check - returns `"OK"` (plain text) |
| GET    | `/v1/status`         | Unified capability status                  |
| POST   | `/v1/admin/shutdown` | Initiate graceful shutdown                 |
| GET    | `/openapi.json`      | OpenAPI specification                      |
| GET    | `/docs`              | Interactive API documentation              |

### GET /v1/status

```json
{
  "version": "0.2.x",
  "platform": "windows",
  "uptime_secs": 3600,
  "daemon": true,
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

| Method | Path                      | Description               |
| ------ | ------------------------- | ------------------------- |
| POST   | `/v1/certmesh/create`     | Create a new CA           |
| POST   | `/v1/certmesh/join`       | Enroll into existing mesh |
| POST   | `/v1/certmesh/unlock`     | Unlock a locked CA        |
| GET    | `/v1/certmesh/status`     | Mesh status               |
| GET    | `/v1/certmesh/log`        | Audit log                 |
| GET    | `/v1/certmesh/compliance` | Compliance summary        |

### Enrollment management

| Method | Path                            | Description                                                |
| ------ | ------------------------------- | ---------------------------------------------------------- |
| POST   | `/v1/certmesh/open-enrollment`  | Open enrollment window (optional `deadline` field)         |
| POST   | `/v1/certmesh/close-enrollment` | Close enrollment                                           |
| PUT    | `/v1/certmesh/set-policy`       | Set enrollment policy (`allowed_domain`, `allowed_subnet`) |
| POST   | `/v1/certmesh/rotate-auth`      | Rotate enrollment auth credential                          |

### Lifecycle

| Method | Path                    | Description                   |
| ------ | ----------------------- | ----------------------------- |
| POST   | `/v1/certmesh/renew`    | Renew a member's certificate  |
| POST   | `/v1/certmesh/revoke`   | Revoke a member's certificate |
| PUT    | `/v1/certmesh/set-hook` | Set renewal hook command      |
| POST   | `/v1/certmesh/promote`  | Promote standby to primary CA |
| GET    | `/v1/certmesh/roster`   | Signed roster manifest        |
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
  "profile": "just_me",
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
| POST   | `/v1/dns/add`                        | Add static entry (`name`, `ip`, optional `ttl`)      |
| DELETE | `/v1/dns/remove/{name}`              | Remove static entry                                  |
| POST   | `/v1/dns/serve`                      | Start the DNS resolver                               |
| POST   | `/v1/dns/stop`                       | Stop the DNS resolver                                |

### GET /v1/dns/lookup

| Parameter | Type  | Default  | Description                        |
| --------- | ----- | -------- | ---------------------------------- |
| `name`    | query | required | Name to resolve                    |
| `type`    | query | `A`      | Record type: `A`, `AAAA`, or `ANY` |

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

| Method | Path                      | Description          |
| ------ | ------------------------- | -------------------- |
| GET    | `/v1/proxy/status`        | Active proxy status  |
| GET    | `/v1/proxy/list`          | List proxy entries   |
| POST   | `/v1/proxy/add`           | Add a proxy entry    |
| DELETE | `/v1/proxy/remove/{name}` | Remove a proxy entry |

### POST /v1/proxy/add

```json
{
  "name": "web",
  "listen_port": 8443,
  "backend": "http://127.0.0.1:8080",
  "allow_remote": false
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
  "addr": "0.0.0.0:9999"
}
```

Response (`200 OK`):

```json
{
  "id": "a1b2c3d4",
  "addr": "0.0.0.0:9999"
}
```

### DELETE /v1/udp/bind/{id}

Close a binding and release the socket. Returns `200` with `{"unbound": "a1b2c3d4"}` or `404` if the binding does not exist.

### GET /v1/udp/recv/{id}

Subscribe to incoming datagrams on a binding. Returns an SSE stream. Each event carries a base64-encoded payload and the sender address:

```
data: {"payload":"aGVsbG8=","from":"192.168.1.10:54321"}
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
  "bindings": [{ "id": "a1b2c3d4", "addr": "0.0.0.0:9999" }]
}
```

### PUT /v1/udp/heartbeat/{id}

Renew a binding's lease. Bindings expire after 30 seconds without a heartbeat.

Response: `200 OK` with `{"renewed": "a1b2c3d4"}` or `404` if the binding does not exist.

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
