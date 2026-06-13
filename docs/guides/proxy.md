# Proxy - TLS Passthrough Endpoint

Here's the problem: you have a service running on `127.0.0.1:3000`, and you want clients to reach it over TLS using a certificate the rest of your network already trusts. Setting that up by hand means managing certificates, wiring reload hooks, and maintaining yet another config file.

Koi's proxy collapses that into a single command. It binds a TLS listener, terminates the connection with a certmesh-issued certificate (or a generated self-signed one when no cert is present), and pipes the decrypted bytes straight to your backend over plain TCP. When the certificate changes on disk, the proxy serves the new one on the next handshake — no restart.

It is a **passthrough**, not an application proxy. Once TLS is terminated, Koi copies bytes in both directions and never looks at them. That has a deliberate consequence: **WebSockets and any other bidirectional or upgraded protocol just work** — and equally, Koi does **not** do path routing, header injection, or request rewriting. It is the pre-wired TLS endpoint for certmesh certs, not a Caddy/Traefik replacement.

**When to use the proxy**: you have a local TCP service that doesn't speak TLS natively and you want clients to reach it over HTTPS with a trusted cert. A homelab service that should open in a browser without certificate warnings. A backend that needs to present a valid cert to other certmesh members.

**When to reach for something else**: if you need path-based routing (`/api` → one service, `/` → another), header rewriting, redirects, or ACME — run [Caddy](https://caddyserver.com/) or [Traefik](https://traefik.io/) and point Koi's proxy (or a certmesh cert) at it. Koi is the substrate; it's meant to sit under the tools you already use, not replace them.

All CLI commands use the `koi proxy` prefix. All HTTP endpoints live under `/v1/proxy/`. Proxy commands require a running daemon - use `koi install` or `koi --daemon` first.

---

## How it works

1. You `proxy add` a named entry with a listen port and a backend `host:port`.
2. Koi binds a TLS listener on the listen port.
3. Koi resolves a certificate (see [Certificates](#certificates) below) and terminates TLS with it.
4. For each accepted connection, Koi opens a plain `TcpStream` to the backend and pumps bytes both ways until either side closes.
5. When the certificate files change on disk, the next handshake serves the new certificate — no restart, no dropped connections.

Because step 4 is a byte-level copy, the proxy is protocol-agnostic above TLS: HTTP/1.1, HTTP/2 (h2c is not negotiated, but HTTP/2-over-TLS to an h2 backend passes through), WebSockets, gRPC, and raw TCP all work.

---

## Certificates

The proxy resolves its certificate in priority order:

1. `<data-dir>/certs/<entry-name>/{fullchain.pem,key.pem}` — an explicit per-entry cert you (or an external tool) placed there.
2. `<data-dir>/certs/<hostname>/{fullchain.pem,key.pem}` — the **local certmesh member certificate**. This is where `koi certmesh join` writes your machine's cert, so on a mesh member the proxy picks it up automatically.
3. A **generated self-signed certificate** — the zero-config fallback so a proxy always starts and serves TLS, even with no certmesh at all.

`koi proxy status` reports which one is in use as the `TLS` column: `certmesh` when a cert file was found on disk, `self-signed` when Koi generated one.

> The certmesh integration is the point. When the proxy serves the certmesh member cert, it presents a certificate that every other certmesh member already trusts — no manual distribution, no per-client trust store fiddling. A self-signed cert is fine for local development (you just need TLS to be *present*), but external clients will see a warning until they trust it.

Certificate renewal is transparent: when certmesh rotates the member cert on disk, the proxy's cert watcher reloads it and the next handshake uses the new cert.

---

## Getting started

Expose a local dev server over TLS:

```
koi proxy add devserver --listen 9443 --backend 127.0.0.1:3000
```

Now clients can connect to `https://localhost:9443`. On a certmesh member, the certificate is the mesh cert — fully trusted by other members, no warnings.

`--backend` takes a `host:port`. A URL is also accepted for convenience (`--backend http://127.0.0.1:3000`), but only its `host:port` is used — the path is meaningless to a byte passthrough.

By default the backend must be loopback, because the proxy→backend hop is **unencrypted**. To forward to a backend on another host, opt in explicitly:

```
koi proxy add remote-svc --listen 8443 --backend 10.0.0.20:8080 --backend-remote
```

Check what's running, with real state:

```
koi proxy status
```

```console
NAME      LISTEN  BACKEND          TLS          STATE
devserver :9443   127.0.0.1:3000   certmesh     running
old-app   :8443   127.0.0.1:9000   self-signed  error: address in use
```

The `STATE` column is real — it reflects the listener task's actual liveness. If a port is already in use, the entry shows `error: address in use` instead of pretending to run, and the rest of the daemon is unaffected.

See all configured entries (independent of whether they're currently running):

```
koi proxy list
```

Remove one (the listener stops and the port is released immediately):

```
koi proxy remove devserver
```

---

## CLI commands

```
koi proxy add NAME --listen PORT --backend HOST:PORT [--backend-remote]
koi proxy remove NAME      # Remove and stop a proxy
koi proxy status           # Listeners with real state (running / error)
koi proxy list             # Configured entries
```

Adding a proxy with an existing name updates it in place — the listener restarts with the new configuration.

The distinction between `status` and `list` is intentional: `status` shows runtime state (is the listener actually bound? which cert? did it fail?), while `list` shows configuration (what's defined, regardless of whether it's running).

---

## HTTP API

When the daemon is running, proxy endpoints live under `/v1/proxy/`:

| Method   | Path                      | Purpose                       |
| -------- | ------------------------- | ----------------------------- |
| `GET`    | `/v1/proxy/status`        | Runtime status of all proxies |
| `GET`    | `/v1/proxy/list`          | Configured proxy entries      |
| `POST`   | `/v1/proxy/add`           | Add or update a proxy         |
| `DELETE` | `/v1/proxy/remove/{name}` | Remove a proxy                |

### Add example

```
POST /v1/proxy/add
Content-Type: application/json

{"name": "web", "listen_port": 8443, "backend": "127.0.0.1:8080"}
```

Mutating endpoints require the daemon access token (`x-koi-token`) — see the security model. `status`/`list` are read-only and unauthenticated by default.

---

## The certmesh connection

The proxy is most powerful combined with certmesh:

1. You create a certmesh (`koi certmesh create`).
2. Other machines join (`koi certmesh join`) — each receives a cert at `certs/<hostname>/`.
3. You add a proxy on any member (`koi proxy add web --listen 8443 --backend 127.0.0.1:8080`).
4. The proxy serves that member's certmesh cert.
5. Every other mesh member already trusts the mesh CA.
6. Result: genuinely trusted TLS between any two machines on the LAN, with no certificate distribution.

Without certmesh the proxy still works — it serves a generated self-signed cert. That's enough when you just need TLS to be present (testing secure cookies, CORS, HTTP/2), but non-member clients will see a certificate warning until they trust it.

---

## Troubleshooting

### Port already in use

`koi proxy status` will show the entry in the `error` state with `address in use`. Another process is holding the listen port. Find it:

```powershell
# Windows
netstat -ano | findstr :8443

# Linux/macOS
lsof -i :8443
```

Either stop the conflicting process or `proxy add` the entry again with a different `--listen` port.

### Certificate not trusted by clients

The `TLS` column shows `self-signed`, or the client isn't a certmesh member. Members trust the mesh CA automatically; non-members (external browsers, API clients) need the CA in their trust store. Install Koi's CA via `koi certmesh` on that machine, or import the CA certificate from the data directory's `certs/` tree and trust it (`curl --cacert <ca>.pem`, system store, etc.).

### Proxy shows `self-signed` despite certmesh

Either the CA is locked after a daemon restart, or the member cert hasn't been issued yet. Unlock the CA:

```
koi certmesh unlock
```

Once the member cert lands in `certs/<hostname>/`, the proxy's cert watcher picks it up and the next handshake serves it — no restart needed. (If you placed a per-entry cert at `certs/<entry-name>/`, that one takes priority.)

### A backend on another host is refused

By default only loopback backends are allowed, because the proxy→backend hop is unencrypted. Re-add the entry with `--backend-remote` to opt in, and be aware that traffic between the proxy and that backend is plaintext on the wire.
