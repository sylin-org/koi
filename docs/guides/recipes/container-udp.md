# Recipe: UDP bridging from inside a container

**Goal:** a process inside a bridge-networked Docker container binds a host UDP port through Koi and receives datagrams from the LAN — without `--network=host`, without multicast forwarding, without any UDP socket of its own.

Bridge networking gives a container no path to raw UDP, multicast, or broadcast. Koi binds the real socket on the host and relays datagrams to the container over plain HTTP and SSE. The container only needs an HTTP client. This recipe walks the whole loop: reach the host daemon, source the token, then `bind` → `recv` → `send` → `heartbeat`.

If you want the *why* behind UDP bridging and its design limits (control-plane traffic only, base64 overhead, not for media or game servers), read the [UDP guide](../udp.md) first. This recipe is the container-specific walkthrough that guide doesn't cover.

---

## Prerequisites

- Koi running on the host, reachable from the container (see [Reach the host daemon](#1-reach-the-host-daemon)).
- The UDP capability enabled — it is on by default; `--no-udp` / `KOI_NO_UDP=1` turns it off.
- An HTTP client with SSE support inside the container. `curl` is enough; any language with an HTTP client works.

---

## 1. Reach the host daemon

Koi's HTTP API binds to `127.0.0.1:5641` by default. How the container reaches it depends on the platform:

| Platform | Address | What it takes |
| -------- | ------- | ------------- |
| Docker Desktop (Windows/macOS) | `host.docker.internal:5641` | Works as-is — Desktop proxies into the host loopback |
| Native Linux | `172.17.0.1:5641` (default bridge gateway), or `host.docker.internal:5641` with `extra_hosts: ["host.docker.internal:host-gateway"]` | Bridge-networked containers **cannot** reach a loopback bind — start Koi with `--http-bind bridge` (binds the bridge IP, e.g. `172.17.0.1`) or `--http-bind 0.0.0.0` |

```bash
# On native Linux, expose the daemon to the bridge:
koi --daemon --http-bind bridge
```

`--http-bind` accepts `loopback` (default), `bridge`, an explicit `<ip>`, or `0.0.0.0`; the env var `KOI_HTTP_BIND` mirrors it. Exposing the port does **not** relax auth — mutations still need the token. For the full bind policy see the [security model](../../reference/security-model.md) and the [container guide](../../../CONTAINERS.md).

Inside the container we use `$KOI_HOST` as a placeholder for whichever address fits:

```bash
export KOI_HOST=host.docker.internal   # Docker Desktop
export KOI_HOST=172.17.0.1             # native Linux default bridge
```

Confirm reachability (no token needed for `GET /healthz`):

```bash
curl -s "http://$KOI_HOST:5641/healthz"   # → OK
```

---

## 2. Source the token

Every `/v1/udp/*` endpoint — including the `GET` status and recv streams — requires the daemon access token in the `x-koi-token` header, or it returns `401`. (These endpoints enumerate binding ids and stream other token-holders' inbound datagrams, so they are not read-safe to leave open.) The daemon mints a fresh token on every start; read it from a mounted file rather than baking it into the image.

On the host, write a 0600 token file and mount it as a Compose secret:

```bash
# On the host — owner-only file
sudo koi token write /run/koi/token
```

Inside the container, the secret lands at `/run/secrets/koi_token`:

```bash
TOKEN=$(cat /run/secrets/koi_token)
```

`koi token show` prints the token to a terminal for quick experiments (it refuses to pipe without `--force`). For how the token is generated, stored, and read straight from the breadcrumb, see the [security model](../../reference/security-model.md).

---

## 3. Bind a host UDP port

```bash
curl -s -X POST -H "x-koi-token: $TOKEN" \
  -H 'Content-Type: application/json' \
  "http://$KOI_HOST:5641/v1/udp/bind" \
  -d '{"port": 7184, "addr": "0.0.0.0", "allow_remote": true, "lease_secs": 300}'
```

Response (`201 Created`):

```json
{
  "id": "01958f2a-...",
  "local_addr": "0.0.0.0:7184",
  "created_at": "2026-06-13T12:00:00Z",
  "last_heartbeat": "2026-06-13T12:00:00Z",
  "lease_secs": 300,
  "allow_remote": true
}
```

Keep the `id` — every subsequent call references it. Use `"port": 0` for an OS-assigned ephemeral port. `addr` defaults to `127.0.0.1` (loopback); binding `0.0.0.0` so containers on the bridge can reach it requires `"allow_remote": true`. `lease_secs` defaults to `300` (max `86400`).

---

## 4. Receive datagrams (SSE)

Subscribe to the binding's SSE stream. Like the rest of `/v1/udp/*`, this requires the token even though it is a `GET`:

```bash
curl -sN -H "x-koi-token: $TOKEN" "http://$KOI_HOST:5641/v1/udp/recv/01958f2a-..."
```

Each incoming datagram arrives as a `datagram` event:

```
event: datagram
data: {"binding_id":"01958f2a-...","src":"192.168.1.42:7184","payload":"aGVsbG8=","received_at":"2026-06-13T12:00:05Z"}
```

`payload` is standard base64 (RFC 4648) — decode it for the raw bytes. `src` is the sender's `host:port`. The UDP recv stream stays open indefinitely by default (unlike the mDNS streams, which idle out after 5s); pass `?idle_for=N` to close it after N seconds of silence.

---

## 5. Send a datagram

```bash
curl -s -X POST -H "x-koi-token: $TOKEN" \
  -H 'Content-Type: application/json' \
  "http://$KOI_HOST:5641/v1/udp/send/01958f2a-..." \
  -d '{"dest": "192.168.1.255:9", "payload": "//8AAAAAAA..."}'
```

Response:

```json
{ "sent": 102 }
```

`payload` is base64-encoded; the datagram leaves from the bound socket, so the source address on the wire is the binding's `local_addr`. URL-safe base64 (`-_`) will fail to decode — use the standard alphabet.

---

## 6. Heartbeat to keep the binding alive

Bindings are lease-based. The default lease is 300s; a reaper sweeps every 30s and closes any socket whose last heartbeat is older than its lease. Renew at roughly half the lease interval. Note this is a **`PUT`** (needs the token):

```bash
curl -s -X PUT -H "x-koi-token: $TOKEN" \
  "http://$KOI_HOST:5641/v1/udp/heartbeat/01958f2a-..."
```

Response:

```json
{ "renewed": "01958f2a-..." }
```

If your container dies without unbinding, the lease expires and Koi reclaims the socket — no orphaned ports. To release it explicitly:

```bash
curl -s -X DELETE -H "x-koi-token: $TOKEN" \
  "http://$KOI_HOST:5641/v1/udp/bind/01958f2a-..."
# → {"unbound": "01958f2a-..."}
```

---

## Putting it together: an entrypoint

A container that binds on start, runs a background recv + heartbeat loop, and unbinds on exit:

```bash
#!/bin/sh
# entrypoint.sh
KOI_URL="http://${KOI_HOST:-host.docker.internal}:5641"
TOKEN=$(cat /run/secrets/koi_token)

until curl -sf "$KOI_URL/healthz" >/dev/null 2>&1; do sleep 2; done

# Bind a host UDP port (0.0.0.0 so LAN devices can reach it → needs allow_remote)
BIND=$(curl -sf -X POST -H "x-koi-token: $TOKEN" \
  -H 'Content-Type: application/json' \
  "$KOI_URL/v1/udp/bind" \
  -d '{"port": 7184, "addr": "0.0.0.0", "allow_remote": true, "lease_secs": 300}')
ID=$(echo "$BIND" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
echo "bound: $ID"

# Receive datagrams (GET — needs the token, like all /v1/udp/*)
curl -sN -H "x-koi-token: $TOKEN" "$KOI_URL/v1/udp/recv/$ID" &
RECV_PID=$!

# Heartbeat at ~half the lease (PUT — token)
( while true; do
    sleep 150
    curl -sf -X PUT -H "x-koi-token: $TOKEN" \
      "$KOI_URL/v1/udp/heartbeat/$ID" >/dev/null 2>&1 || break
  done ) &
HB_PID=$!

cleanup() {
  kill "$RECV_PID" "$HB_PID" 2>/dev/null
  curl -sf -X DELETE -H "x-koi-token: $TOKEN" \
    "$KOI_URL/v1/udp/bind/$ID" >/dev/null 2>&1
}
trap cleanup EXIT TERM INT

exec "$@"
```

---

## docker-compose

```yaml
# docker-compose.yml
services:
  udp-app:
    image: my-udp-app:latest
    # Native Linux: map host.docker.internal to the host gateway.
    # On Docker Desktop the name resolves automatically and this is a no-op.
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - KOI_HOST=host.docker.internal
    secrets:
      - koi_token

secrets:
  koi_token:
    file: /run/koi/token   # created on the host: `sudo koi token write /run/koi/token`
```

Start (and expose) Koi on the host, write the token, then bring the container up:

```bash
# On the host — add --http-bind bridge on native Linux
koi --daemon --http-bind bridge
sudo koi token write /run/koi/token

docker compose up -d
```

---

## Endpoint reference

All UDP endpoints live under `/v1/udp/` and **every** one carries `x-koi-token` — including the `GET` recv and status streams, which expose other token-holders' bindings.

| Method | Path | Auth | Returns |
| ------ | ---- | ---- | ------- |
| `POST` | `/v1/udp/bind` | token | `201` + binding info |
| `GET` | `/v1/udp/recv/{id}` | token | SSE stream of `datagram` events |
| `POST` | `/v1/udp/send/{id}` | token | `{"sent": <bytes>}` |
| `PUT` | `/v1/udp/heartbeat/{id}` | token | `{"renewed": "<id>"}` |
| `DELETE` | `/v1/udp/bind/{id}` | token | `{"unbound": "<id>"}` |
| `GET` | `/v1/udp/status` | token | `{"bindings": [...]}` |

Full request/response schemas: [http-api.md](../../reference/http-api.md). The capability concepts, lease model, and design scope: the [UDP guide](../udp.md). General container patterns (reaching the host, distributing the token, the runtime adapter): the [container guide](../../../CONTAINERS.md).

---

## Troubleshooting

**`401 unauthorized` on bind/send/heartbeat.** The `x-koi-token` header is missing or wrong. Confirm the secret is mounted (`cat /run/secrets/koi_token`) and that the daemon hasn't restarted since you wrote the file — a restart mints a new token, so re-run `koi token write`.

**Container can't reach the daemon.** On native Linux a loopback bind is invisible to bridge containers. Restart Koi with `--http-bind bridge` (or `0.0.0.0`) and reach it at the bridge gateway or `host.docker.internal` (with the `extra_hosts` mapping). Verify with `curl -s "http://$KOI_HOST:5641/healthz"`.

**Bind fails with a `400` io error.** The host port is already in use. Stop the conflicting process or bind `"port": 0` for an OS-assigned one.

**Binding vanished.** The lease expired — the reaper closes any socket idle past its `lease_secs`. Run a heartbeat loop at ~half the interval, or raise `lease_secs` (max `86400`).

**Nothing arrives on the recv stream.** Confirm traffic is actually hitting the bound host port, and that you subscribed to the right `id` (each binding has its own stream). The payload is base64 — decode before comparing bytes.
