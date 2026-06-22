---
type: REF
domain: udp
title: "UDP bridge for containers — capability card"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.5.0
validation:
  date_last_tested: 2026-06-22
  status: verified
  scope: "integration (koi-embedded/tests/udp.rs — full bind → recv(SSE) → send → heartbeat → unbind lifecycle over both the in-process facade and the live HTTP adapter, base64 round-trip, SSE idle-close, multi-subscriber fan-out) + unit (koi-udp validate_dest_* / bind_rejects_non_loopback_without_allow_remote; koi-serve udp_get_surface_requires_token / non_udp_sibling_get_stays_exempt)"
---

# UDP bridge for containers — capability card

> One-screen map of relaying real host UDP into a bridge-networked container over HTTP+SSE. Concepts + design limits: [udp.md](../../guides/udp.md) · the container walkthrough: [container-udp.md](../../guides/recipes/container-udp.md) · wire shapes: [http-api.md](../http-api.md).

**What it does** — A bridge-networked container has no path to raw UDP, multicast, or broadcast. Koi binds the **real** UDP socket on the host and relays datagrams to the container over plain HTTP + SSE, so the container needs only an HTTP client — no `--network=host`, no multicast forwarding, no socket of its own. A binding is **lease-based**: bound sockets expire after `lease_secs` without a heartbeat, and a reaper sweeps every 30s and reclaims them, so a dead container never orphans a host port. Bindings and destinations are **loopback-only by default** (`addr` defaults to `127.0.0.1`); a non-loopback bind or send requires an explicit `allow_remote=true` opt-in, and an SSRF guard always rejects the unspecified / multicast / broadcast addresses so a token holder cannot launder LAN/internet egress through the host's identity. UDP is for control-plane traffic — base64 framing makes it the wrong tool for media or game servers ([udp.md](../../guides/udp.md)).

## The one canonical pattern

The lease loop is `bind → recv → send → heartbeat → unbind`. Every `/v1/udp/*` call — **including the `GET` recv and status streams** — carries `x-koi-token` or returns `401`.

```bash
TOKEN=$(cat /run/secrets/koi_token)          # mounted; minted fresh each daemon start
KOI=http://$KOI_HOST:5641

# 1. Bind a host UDP port (0.0.0.0 for LAN ingress ⇒ allow_remote; loopback otherwise)
BIND=$(curl -s -X POST -H "x-koi-token: $TOKEN" -H 'Content-Type: application/json' \
  "$KOI/v1/udp/bind" -d '{"port":7184,"addr":"0.0.0.0","allow_remote":true,"lease_secs":300}')
ID=$(echo "$BIND" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)

# 2. Receive datagrams (GET SSE — stays open indefinitely; ?idle_for=N to auto-close)
curl -sN -H "x-koi-token: $TOKEN" "$KOI/v1/udp/recv/$ID" &
#   event: datagram
#   data: {"binding_id":"…","src":"192.168.1.42:7184","payload":"aGVsbG8=","received_at":"…"}

# 3. Send a datagram (payload is standard base64; leaves from the bound local_addr)
curl -s -X POST -H "x-koi-token: $TOKEN" -H 'Content-Type: application/json' \
  "$KOI/v1/udp/send/$ID" -d '{"dest":"192.168.1.255:9","payload":"//8AAA=="}'   # {"sent":4}

# 4. Heartbeat at ~half the lease, or the reaper reclaims the socket (PUT)
curl -s -X PUT -H "x-koi-token: $TOKEN" "$KOI/v1/udp/heartbeat/$ID"             # {"renewed":"…"}

# 5. Release explicitly (or let the lease expire)
curl -s -X DELETE -H "x-koi-token: $TOKEN" "$KOI/v1/udp/bind/$ID"               # {"unbound":"…"}
```

The CLI mirrors the same flow against a running daemon (no standalone mode — UDP needs a live socket): `koi udp bind`, `udp status`, `udp send`, `udp heartbeat`, `udp unbind`.

## Commands & flags you'll use

| Command / flag | What it does |
|---|---|
| `koi udp bind --port <n> --addr <ip> --lease <s> [--allow-remote]` | Bind a host socket. **Defaults: `--port 0` (OS-assigned), `--addr 127.0.0.1`, `--lease 300`** (max `86400`). `--allow-remote` is required for any non-loopback `addr`. |
| `koi udp send <id> --dest <host:port> <payload>` | Send through a binding. Non-loopback `dest` needs the binding's `allow_remote`; payload is base64-framed on the wire. |
| `koi udp heartbeat <id>` / `koi udp unbind <id>` | Renew the lease / close the binding. |
| `koi udp status` | List active bindings (id, `local_addr`, lease). |
| `GET /v1/udp/recv/{id}?idle_for=<n>` | SSE `datagram` stream. **Absent or `0` = open indefinitely** (UDP streams are long-lived); `N` = close after N s of silence. |
| `--no-udp` (`KOI_NO_UDP=1`) | Disable the capability (returns 503). On by default. |

## The escape hatch / limits

`allow_remote` is the single opt-in that lifts the loopback default — set it on the binding (CLI `--allow-remote`, HTTP `"allow_remote": true`) for genuine cross-host datagram bridging, e.g. binding `0.0.0.0` so LAN devices reach the host port. Even with it, the SSRF guard **always** refuses the unspecified (`0.0.0.0`), multicast, and IPv4 broadcast destinations — they are never valid unicast targets. On native Linux a loopback HTTP bind is invisible to bridge containers, so start the daemon with `--http-bind bridge` (or `0.0.0.0`); exposing the port does **not** relax auth. The whole `/v1/udp/` surface is carved out of the usual GET exemption — `status` enumerates every binding's id and `recv` streams another token-holder's datagrams — so reads need the token too.

## The proof it works

Integration: `crates/koi-embedded/tests/udp.rs` drives the full lease loop end to end over **both** the in-process facade and the live HTTP adapter — `udp_bind_and_status`, `udp_send_and_recv` (base64 round-trip), `udp_send_through_binding` (source is the bound `local_addr`), `udp_heartbeat_extends_lease`, `udp_with_http_adapter`, `udp_sse_recv_datagrams` / `udp_sse_idle_timeout_closes_stream` / `udp_sse_multiple_subscribers` (SSE fan-out + idle-close). The token carve-out is guarded by `udp_get_surface_requires_token` + `non_udp_sibling_get_stays_exempt` in `crates/koi-serve/src/http.rs`; the SSRF / loopback-default invariants by `validate_dest_*` and `bind_rejects_non_loopback_without_allow_remote` in `crates/koi-udp/src/lib.rs`. The operator path is the [container-udp recipe](../../guides/recipes/container-udp.md).
