# Proxy - TLS Reverse Proxy

Here's the problem: you have a service running on `http://127.0.0.1:8080`, and you want clients to reach it over TLS. In production, you'd put nginx or Caddy in front of it. But on a LAN, setting up a reverse proxy means managing certificates, configuring reload hooks, and maintaining yet another config file.

Koi's proxy capability collapses that entire workflow into a single command. It binds a TLS listener, terminates the connection using a certmesh-issued certificate (when available), and forwards plaintext HTTP to your backend. When the certificate renews, the proxy hot-reloads it. No restarts, no cron jobs, no config templates.

**When to use the proxy**: You have a local service that doesn't speak TLS natively, and you need clients to connect over HTTPS. A development server you want to test with real TLS. A homelab service that should be reachable from browsers without certificate warnings. An API backend that needs to present a valid cert to other services in the certmesh.

All CLI commands use the `koi proxy` prefix. All HTTP endpoints live under `/v1/proxy/`. Proxy commands require a running daemon - use `koi install` or `koi --daemon` first.

---

## How it works

The proxy's lifecycle is straightforward:

1. You `proxy add` a named proxy with a listen port and a backend URL.
2. Koi binds a TLS listener on the specified port.
3. If a certmesh CA is running, Koi requests a certificate for the proxy automatically. If no CA is available, it falls back to a self-signed certificate.
4. Incoming TLS connections are terminated and forwarded as plaintext HTTP to the backend.
5. When certmesh renews the certificate, the proxy picks up the new cert without restarting.

The certmesh integration is the important part. It means the proxy presents a certificate that every other certmesh member already trusts. No manual certificate distribution, no trust store configuration - it's all handled by the same CA infrastructure that secures the rest of your network.

---

## Getting started

Expose a local dev server over TLS:

```
koi proxy add devserver --listen 9443 --backend http://127.0.0.1:3000
```

Now clients can connect to `https://localhost:9443`. If they trust the Koi CA (which certmesh installs automatically), the certificate is fully valid - no browser warnings, no `--insecure` flags.

Check what's running:

```
koi proxy status
```

See all configured proxies:

```
koi proxy list
```

Remove one:

```
koi proxy remove devserver
```

The distinction between `status` and `list` is intentional: `status` shows runtime details (active connections, certificate info, uptime), while `list` shows the configuration (what's defined, regardless of whether it's currently running).

---

## CLI commands

```
koi proxy add NAME --listen PORT --backend URL   # Add or update a proxy
koi proxy remove NAME                            # Remove and stop a proxy
koi proxy status                                 # Runtime details
koi proxy list                                   # Configured entries
```

Adding a proxy with an existing name updates it in place - the listener restarts with the new configuration. Removing a proxy stops the listener immediately and releases the port.

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

{"name": "web", "listen": 8443, "backend": "http://127.0.0.1:8080"}
```

---

## The certmesh connection

The proxy is most powerful when combined with certmesh. Here's the full picture:

1. You create a certmesh (`koi certmesh create`)
2. Other machines join (`koi certmesh join`)
3. You add a proxy on any member (`koi proxy add web --listen 8443 --backend http://127.0.0.1:8080`)
4. The proxy gets a real certificate from the mesh CA
5. Every other mesh member already trusts that CA
6. Result: genuine trusted TLS between any two machines on the LAN

Without certmesh, the proxy still works - it generates a self-signed certificate. This is useful for local development where you just need TLS to be present (testing CORS, secure cookies, etc.), but clients will see certificate warnings unless you manually trust the cert.

---

## Troubleshooting

### Port already in use

Another process is holding the listen port. Find it:

```powershell
# Windows
netstat -ano | findstr :8443

# Linux/macOS
lsof -i :8443
```

Either stop the conflicting process or choose a different listen port.

### Certificate not trusted by clients

This means the client doesn't have the Koi CA in its trust store. If you're using certmesh, the CA is installed automatically on mesh members - but external clients (browsers on non-member machines, API clients, etc.) need it manually:

```
koi certmesh export-ca > koi-ca.pem
```

Then install `koi-ca.pem` in the client's trust store. The exact steps vary by OS and application - most browsers use the system store, while tools like `curl` may need `--cacert koi-ca.pem`.

### Proxy shows self-signed certificate despite certmesh

The certmesh CA might be locked (after a daemon restart). Unlock it first:

```
koi certmesh unlock
```

The proxy will automatically request a proper certificate once the CA is available.
