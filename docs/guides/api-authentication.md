# Authenticate to the HTTP API

You want a script, a container, or a non-Rust client to make a *write* to the Koi
daemon — register a service, add a DNS entry, add a proxy — and you keep getting
`401 {"error": "unauthorized", "message": "Missing or invalid x-koi-token header"}`.
This guide gets you from that 401 to a successful authenticated `POST` in both bash
and PowerShell.

If you use the `koi` CLI, you never see any of this: it reads the token and attaches
it for you. This guide is for everything that *isn't* the CLI — `curl`, `Invoke-RestMethod`,
a language SDK, a CI job, a sidecar container.

---

## The model: reads are open, writes need a token

The daemon's HTTP API listens on `127.0.0.1:5641` (loopback) by default, so only
processes on the same machine can reach it. Within that boundary:

- **`GET` / `HEAD` / `OPTIONS` are unauthenticated.** Any local process can read
  status, discovered services, DNS entries, certmesh status, the roster, and the
  audit log without a token. (The one exception is `/v1/mcp`, which requires the
  token on every method, including its `GET` SSE stream — see the [MCP guide](./mcp.md).)
- **`POST` / `PUT` / `DELETE` require the daemon access token.** Send it in the
  `x-koi-token` HTTP header. Without it you get a `401`. Comparison is constant-time.

Each daemon start generates a **fresh random token** — it is not persisted across
restarts, so a script that caches the token must re-read it after the daemon
restarts.

> Exposing the API beyond loopback (`--http-bind bridge | <ip> | 0.0.0.0`) does **not**
> relax this — mutations still require the token. See the
> [security model](../reference/security-model.md) for bind modes and the full threat model.

### The certmesh bootstrap exception

Enrolling a new node into a certificate mesh — `POST /v1/certmesh/join` — is the one
mutation that authorizes the caller with an **enrollment credential in the request body**
(a single-use invite code, or a mesh TOTP code) rather than the daemon token, because a
fresh node joining a *remote* CA host has no way to know that host's local token. That
flow is owned end-to-end by `koi certmesh join`; you should not hand-roll it. Everything
else in this guide is about the ordinary token-authenticated writes. See the
[certmesh guide](./certmesh.md).

> `koi certmesh join`/`promote` route their key-custody calls to the **local** daemon
> (via the breadcrumb) and reach the CA at the positional `<ca-endpoint>` argument (or
> mDNS) — the global `--endpoint`/`--token` below do **not** point them at the CA, they
> apply to the other certmesh client commands (`status`, `invite`, `revoke`, …).

---

## Read the token

The daemon writes its current token to a **breadcrumb file** at startup, with
owner-only permissions. Two lines: the endpoint URL, then the token prefixed with
`dat:`.

```
http://localhost:5641
dat:8a31…base64url…
```

The breadcrumb path depends on the OS:

| Platform | Breadcrumb path |
| -------- | --------------- |
| Windows | `%ProgramData%\koi\koi.endpoint` |
| Linux / macOS | `$XDG_RUNTIME_DIR/koi.endpoint`, falling back to `/var/run/koi.endpoint` when `XDG_RUNTIME_DIR` is unset |

The token value you send in the header is the part **after** `dat:` — the `dat:` is
just the breadcrumb's line prefix, not part of the token. The examples below strip it.

### Option A — parse the breadcrumb (local, zero dependencies)

This is what the CLI does internally. Good for a script running on the same machine
as the daemon, as a user who can read the file.

```bash
# Linux / macOS
BC="${XDG_RUNTIME_DIR:-/var/run}/koi.endpoint"
TOKEN=$(sed -n 's/^dat://p' "$BC")
```

```powershell
# Windows
$token = (Get-Content "$env:ProgramData\koi\koi.endpoint")[1] -replace '^dat:', ''
```

### Option B — `koi token` (containers, services, anything off-box)

When the consumer isn't a plain local script — a container that can't see the
breadcrumb, a service running as a different user — use the `koi token` subcommands
instead of parsing the file by hand.

```bash
koi token show                 # print the token to the terminal
koi token show --force         # print even when stdout is not a TTY (piping)
koi token write /run/koi/token # write the token to a 0600 file
```

`koi token show` deliberately **refuses to print to a non-TTY** unless you pass
`--force` — this stops the secret from being silently captured in logs or scrollback
when you pipe it somewhere. Its confirmation/usage text goes to stderr, so stdout
stays clean for capture:

```bash
TOKEN=$(koi token show --force)
```

`koi token write <path>` writes the bare token (no `dat:` prefix, trailing newline)
to a file with owner-only permissions (`0600` on Unix; ACL-restricted to
SYSTEM/Administrators/you on Windows). Mount that file as a secret into a container
or hand its path to a service:

```bash
koi token write /run/koi/token
# then, inside the consumer:
TOKEN=$(cat /run/koi/token)
```

Both commands read the token from the breadcrumb, so they require a running daemon;
if none is running they exit with a clear error.

---

## Make an authenticated write

A worked example end to end: add a static DNS entry via `POST /v1/dns/add`. The
request body is `{"name": ..., "ip": ..., "ttl"?: ...}`; a successful write returns
the updated list of static entries.

### bash (curl)

```bash
BC="${XDG_RUNTIME_DIR:-/var/run}/koi.endpoint"
TOKEN=$(sed -n 's/^dat://p' "$BC")

curl -X POST http://localhost:5641/v1/dns/add \
  -H "x-koi-token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "grafana", "ip": "192.168.1.42"}'
```

A read needs no token — leave the header off:

```bash
curl "http://localhost:5641/v1/dns/list"
```

### PowerShell (Invoke-RestMethod)

```powershell
$token = (Get-Content "$env:ProgramData\koi\koi.endpoint")[1] -replace '^dat:', ''

Invoke-RestMethod -Method Post -Uri http://localhost:5641/v1/dns/add `
  -Headers @{ 'x-koi-token' = $token } `
  -ContentType 'application/json' `
  -Body '{"name":"grafana","ip":"192.168.1.42"}'
```

If the header is missing or wrong, the daemon replies `401` with
`{"error": "unauthorized", "message": "Missing or invalid x-koi-token header"}`.
The same header works for every mutating endpoint — swap the path and body for
`/v1/mdns/announce`, `/v1/proxy/add`, `/v1/udp/bind`, and the rest.

---

## Remote and explicit endpoints

The breadcrumb token belongs to the **local** daemon only. The moment you point a
client at a different host, the local token is meaningless — and Koi never sends it
to a remote address, because doing so would leak your local daemon's secret to
another machine.

So when you target a daemon by an explicit endpoint, you must supply that daemon's
token yourself:

- With the `koi` CLI: pass `--endpoint <url>` together with `--token <value>`
  (or set `KOI_TOKEN` in the environment). With an explicit `--endpoint` and no
  token, the CLI sends the request **tokenless** — fine for reads, a `401` for writes.
- With a raw HTTP client: read that remote daemon's token on *that* machine
  (its own breadcrumb or `koi token`), transport it to your client over a channel
  you trust, and put it in the `x-koi-token` header exactly as above.

```bash
# CLI against a remote daemon, with its token
koi --endpoint http://stone-01:5641 --token "$REMOTE_TOKEN" dns list
```

There are no per-client accounts or scopes: one token per daemon authorizes all
writes to that daemon. Treat it as a machine-wide secret. For the rest of the model —
CORS, what `GET` does *not* protect, certificate revocation, and the LAN threat model —
see the [security model](../reference/security-model.md). For the full endpoint
catalog, see the [HTTP API reference](../reference/http-api.md), and to browse and try
calls interactively, open `GET /docs` on a running daemon. Back to the
[guides index](../index.md).
