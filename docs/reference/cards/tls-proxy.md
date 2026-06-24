---
type: REF
domain: proxy
title: "TLS proxy — a certmesh endpoint in front of any backend"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.8.0
validation:
  date_last_tested: 2026-06-22
  status: verified
  scope: "integration (crates/koi-proxy/src/data_plane_tests.rs: https_request_round_trips_to_backend, bidirectional_full_duplex_round_trips, listener_reaches_running_without_panic, bind_conflict_reports_error_state, cert_change_on_disk_is_served_without_restart) + unit (safety::tests loopback/--backend-remote gate). These drive the real tokio-rustls listener; the koi proxy add CLI surface itself is code-reviewed against cli.rs/http.rs, not independently live-tested."
---

# TLS proxy — a certmesh endpoint in front of any backend

> One-screen map of Koi's TLS-terminating passthrough. Full setup + reload-hook flow: [proxy.md](../../guides/proxy.md) · endpoints + request shapes: [http-api.md](../http-api.md) · the cert it serves: [certmesh-invite.md](certmesh-invite.md).

**What it does** — You have a service on `127.0.0.1:3000` and want it reachable over TLS with a cert the LAN already trusts. The proxy binds a TLS listener, **terminates** the handshake with a certmesh-issued member cert, and pipes the decrypted bytes straight to the backend over plain TCP with `copy_bidirectional`. Because forwarding is byte-level — there is **no HTTP layer in the path** — WebSockets, gRPC, and HTTP/2 pass through by construction. The cert is resolved in priority order: an **explicit per-entry** cert (`certs/<name>/`) → the **local certmesh member** cert (`certs/<hostname>/`) → a **generated self-signed** fallback (zero-config). When the cert file changes on disk it is served on the **next handshake with no restart** (a `notify` watcher swaps the `rustls` resolver). Status reflects the listener's **real liveness** (bind/accept outcome), never a hardcoded `running: true`.

## The one canonical pattern

Add an entry; the listener comes up on the listen port and serves your certmesh cert in front of the plaintext backend.

```bash
# Loopback backend (default — no extra flag):
koi proxy add web --listen 443 --backend 127.0.0.1:3000
koi proxy status            # web  443  127.0.0.1:3000  cert: certmesh  state: running

# Non-loopback backend must be opted into explicitly (the proxy→backend hop is plaintext):
koi proxy add api --listen 8443 --backend 10.0.0.5:9000 --backend-remote
```

The cert served is whatever certmesh deposited at `certs/<hostname>/{fullchain.pem,key.pem}` — so `https://web.internal` is browser-trusted on any host that trusts the certmesh root ([certmesh-invite.md](certmesh-invite.md)). Drop a renewed cert in place and the next TLS handshake picks it up.

## Commands & flags you'll use

| Command / flag | What it does |
|---|---|
| `koi proxy add <name> --listen <port> --backend <host:port>` | Add/update a listener. `<name>` also selects the per-entry cert dir (`certs/<name>/`). |
| `--backend <host:port \| url>` | Backend TCP endpoint. A URL's `host:port` is used (path ignored — it's a byte proxy). |
| `--backend-remote` | Allow a **non-loopback** backend. Required for anything but `127.0.0.0/8` / `localhost`; logs an unencrypted-hop warning. |
| `koi proxy status` | Per-listener real state (`starting`/`running`/`error`/`stopped`), `cert_source`, and bind-error detail. |
| `koi proxy list` / `koi proxy remove <name>` | List configured entries / remove one (the listener is torn down on reload). |

HTTP equivalents (loopback, mutations need `x-koi-token`): `GET /v1/proxy/status`, `GET /v1/proxy/list`, `POST /v1/proxy/add`, `DELETE /v1/proxy/remove/{name}`.

## The escape hatch / limits

The listener binds **all interfaces** (`0.0.0.0`) on `--listen`, so the LAN reaches it directly — front-door exposure is intentional. The proxy→backend hop is **plaintext**: keep the backend on loopback, or accept the unencrypted hop with `--backend-remote`; a non-loopback backend without the flag is **rejected** at add time. No cert on disk for the name → the listener still comes up on a **generated self-signed** cert (`cert_source: self-signed`), so a missing certmesh cert degrades, it doesn't crash. A bind conflict (port in use) surfaces as `state: error` with detail, not a silent failure.

## The proof it works

`crates/koi-proxy/src/data_plane_tests.rs` drives the real `tokio-rustls` listener against a stub backend: `https_request_round_trips_to_backend` (HTTPS body returns through the proxy), `bidirectional_full_duplex_round_trips` (server-initiated + echoed bytes — the WebSocket-equivalence case), `listener_reaches_running_without_panic`, `bind_conflict_reports_error_state` (real `Error` state, not `running:true`), and `cert_change_on_disk_is_served_without_restart` (hot reload). The loopback gate is unit-tested in `safety::tests`. Guard + ledger row: `koi-proxy data_plane_tests` in [SURFACES.md](../../SURFACES.md) (proxy row, last exercised 2026-06-22; CI job `koi-proxy tests`).
