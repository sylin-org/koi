# Troubleshooting & FAQ

Most first-run trouble with Koi is one of a handful of things: a port that something
else already owns, multicast that the network silently drops, or a request that's
missing the daemon token. This guide is a symptom-first lookup table — find the line
that matches what you're seeing, read the cause, apply the fix.

Each section is `symptom → cause → fix`. The headings are written the way the problem
actually shows up, so you can scan for yours.

When in doubt, start by asking the daemon what it thinks is going on:

```
koi status
```

That single command shows every capability's state (running / disabled / inactive) and
the bind address. If `koi status` itself can't reach a daemon, jump straight to
[The CLI says "No daemon endpoint found"](#the-cli-says-no-daemon-endpoint-found).

---

## The daemon won't start / "address in use" on port 5641

**Symptom.** `koi --daemon` exits immediately, or the installed service flaps. The log
shows a bind error on `127.0.0.1:5641` ("address in use", "Os error 98"/"10048", or
"only one usage of each socket address").

**Cause.** Koi binds its HTTP API to `127.0.0.1:5641` at startup. If anything already
holds that port — usually a second Koi (a foreground `koi --daemon` *and* the installed
service), or an unrelated app — the bind fails and the daemon can't start.

**Fix.** First find the conflicting process:

```powershell
# Windows
netstat -ano | findstr :5641
```

```sh
# Linux/macOS
lsof -i :5641
```

If it's a stray Koi, stop it (close the foreground terminal, or stop the service) and
start once. If it's another app you can't move, run Koi on a different port — the port
flag must come **before** the subcommand because it's a daemon-level flag:

```
koi --port 5642 --daemon          # foreground
koi --port 5642 install           # bake the port into the installed service
```

Clients then need to know the new port. The breadcrumb the daemon writes records the
real endpoint, so local `koi …` commands follow automatically; remote callers set
`KOI_ENDPOINT` (see [the client section](#the-cli-says-no-daemon-endpoint-found)).

> The same pattern applies to other listeners that can collide: the certmesh mTLS plane
> (`--mtls-port`, default 5642 — note it overlaps the example above, so pick a third
> port if you move the HTTP port there) and the ACME listener (`--acme-port`, default
> 5643). See [the certmesh guide](./certmesh.md#network-architecture) for what each port
> does.

---

## DNS won't bind: port 53 needs privileges (and systemd-resolved already holds it)

**Symptom.** `koi dns serve` fails, or the daemon logs a DNS bind error on `0.0.0.0:53`
("permission denied" / "address in use"). `koi dns status` reports the resolver as not
running.

**Cause.** Two separate things conspire on the default DNS port:

1. **Port 53 is privileged.** On Unix, binding any port below 1024 requires root (or the
   `CAP_NET_BIND_SERVICE` capability). On Windows it needs an elevated/Administrator
   context. The installed service runs with enough privilege; a plain foreground
   `koi --daemon` from your user shell usually does not.
2. **On Linux, `systemd-resolved` already owns :53.** Many distros run a stub resolver
   on `127.0.0.53:53`, and depending on configuration it can hold the port broadly —
   so even as root Koi may find :53 taken.

**Fix.** For development and testing, just move Koi's resolver to a high port — no
privileges needed:

```
koi --dns-port 15353 --daemon
```

Then point your test query at that port directly:

```sh
dig @127.0.0.1 -p 15353 grafana.lan
```

For production, run Koi as the installed service (`koi install`) so it has the privilege
to bind :53. If `systemd-resolved` is in the way, either keep Koi on an alternate port
and have your real resolver conditionally forward the Koi zone to it (the recommended,
non-invasive pattern — see [DNS coexistence](./dns-coexistence.md)), or disable
`systemd-resolved` if you intend Koi to own :53 outright. This matches the DNS guide's
[port 53 troubleshooting](./dns.md#troubleshooting); don't run both resolvers on :53 at
once.

> `--dns-port` and `--dns-zone` are daemon-level flags — put them before the subcommand
> (`koi --dns-port 15353 --daemon`), not after `dns serve`.

---

## `koi mdns discover` finds nothing

**Symptom.** `koi mdns discover` (or `discover http`) returns no services even though you
know things are on the LAN, or your announcements never show up on other machines.

**Cause.** mDNS is multicast UDP (group `224.0.0.251`, port 5353), and multicast is the
first thing networks drop. The usual culprits, roughly in order:

- **The network blocks multicast.** Managed switches, "client isolation" / "AP
  isolation" on guest and many corporate Wi-Fi networks, and most VPN tunnels do not
  carry mDNS between clients. This is by far the most common cause and is not something
  Koi can work around — multicast simply doesn't reach the other host.
- **A host firewall blocks UDP 5353.** Inbound multicast is dropped before Koi sees it.
- **Different subnets / broadcast domains.** mDNS does not cross routers. Two machines on
  different VLANs or subnets won't discover each other.
- **A VPN owns the default route.** With a full-tunnel VPN active, the multicast query
  may leave on the wrong interface.

**Fix.** Confirm the basics first — that you're discovering at all and that announcing
works locally:

```
koi mdns discover --timeout 15      # listen longer; some stacks respond slowly
```

On the announcing host, register a service and check it appears on *that same machine*
to prove Koi's mDNS engine is alive:

```
koi mdns announce "Test" http 8080    # leave running; Ctrl+C to stop
koi mdns discover http                # from another terminal on the SAME host
```

If local discovery works but cross-machine doesn't, the problem is the network path, not
Koi:

- Put both machines on the **same subnet / VLAN** and the same physical or Wi-Fi segment.
- On Wi-Fi, turn off **client/AP isolation** for that SSID.
- Disconnect the **VPN** (or split-tunnel the LAN range) and retry.
- Open **UDP 5353** inbound on the host firewall.

When multicast genuinely can't be fixed (guest Wi-Fi, segmented corporate LAN), don't
fight it — name services with the [DNS resolver](./dns.md) instead, which works over
plain unicast, or pin addresses explicitly. On multi-homed hosts, Docker hosts, and WSL,
also pin the advertised IP so peers learn the right one:

```
koi mdns announce "My App" http 8080 --ip 192.168.1.42
```

---

## HTTP API returns `401 Unauthorized`

**Symptom.** A `POST`/`PUT`/`DELETE` to the API comes back with
`401 {"error": "unauthorized", ...}`. `GET`s to the same daemon work fine.

**Cause.** Every daemon start generates a fresh random **daemon access token (DAT)**.
All non-`GET` HTTP requests must carry it in the `x-koi-token` header; reads
(`GET`/`HEAD`/`OPTIONS`) do not. A 401 means the header is missing, or the token is stale
(the daemon restarted and minted a new one). Exposing the API with `--http-bind` does
**not** relax this — the token is required regardless of bind address.

**Fix.** Read the current token and attach it. The token lives on the second line of the
breadcrumb file, prefixed with `dat:`:

```sh
# Linux/macOS
BC="${XDG_RUNTIME_DIR:-/var/run}/koi.endpoint"
TOKEN=$(sed -n 's/^dat://p' "$BC")

curl -X POST -H "x-koi-token: $TOKEN" \
  http://localhost:5641/v1/dns/add \
  -d '{"name": "grafana", "ip": "10.0.0.42"}'
```

```powershell
# Windows
$token = (Get-Content "$env:ProgramData\koi\koi.endpoint")[1] -replace '^dat:', ''
Invoke-RestMethod -Method Post -Uri http://localhost:5641/v1/dns/add `
  -Headers @{ 'x-koi-token' = $token } `
  -Body '{"name":"grafana","ip":"10.0.0.42"}'
```

Rather than parse the breadcrumb by hand — especially for a container or another process —
use the helper:

```
koi token show                 # print the token (TTY only; add --force to pipe it)
koi token write /run/koi/token # write a 0600 file to mount as a container secret
```

`koi token show` refuses to print to a non-TTY (so a secret doesn't land in scrollback or
a captured log) unless you pass `--force`. If `koi token show` reports *no token found*,
the daemon isn't running — start it first.

The full recipe, the breadcrumb format, and what is and isn't protected are in the
[security model](../reference/security-model.md). (The `koi` CLI does all of this for you
automatically — you only need the token when calling the raw HTTP API yourself.)

---

## The CLI says "No daemon endpoint found"

**Symptom.** A client/admin command (e.g. `koi mdns admin ls`, `koi dns status`) prints
`No daemon endpoint found. Is the daemon running? Use --endpoint to specify.` — or a
command silently runs in standalone mode when you expected it to talk to the daemon.

**Cause.** The CLI finds the daemon through the **breadcrumb file** the daemon writes on
startup. It contains the endpoint URL and the token. The breadcrumb is missing or stale
when:

- the daemon isn't actually running;
- it was killed ungracefully (power loss, `kill -9`, `taskkill /F`) and the breadcrumb
  points at a dead endpoint; or
- the daemon runs in a different context whose breadcrumb your shell can't read — most
  often a daemon under a different `XDG_RUNTIME_DIR`, or one bound to a custom `--port`.

Breadcrumb locations:

| Platform | Breadcrumb path |
| -------- | --------------- |
| Windows | `%ProgramData%\koi\koi.endpoint` |
| Linux/macOS | `$XDG_RUNTIME_DIR/koi.endpoint`, fallback `/var/run/koi.endpoint` |

**Fix.** Confirm the daemon is up and reachable:

```sh
curl http://localhost:5641/healthz     # expect: 200 "OK"
```

If that fails, start the daemon (`koi install` for a persistent service, or
`koi --daemon` to run in the foreground). If the daemon *is* running but the CLI still
can't find it — a custom port, a remote daemon, or a missing breadcrumb — point at it
explicitly. `--endpoint` (env `KOI_ENDPOINT`) is a global flag, and for a non-loopback or
explicit endpoint you also supply the token via `--token` (env `KOI_TOKEN`), since the
CLI deliberately won't reuse the local breadcrumb token for a remote endpoint:

```
koi --endpoint http://localhost:5642 dns status
koi --endpoint http://other-host:5641 --token "$TOKEN" mdns admin ls
```

A stale breadcrumb from an ungraceful kill is cleared by simply starting the daemon
again — it rewrites the file with a live endpoint and a fresh token.

---

## Reading the logs and turning up the volume

When a symptom isn't obvious, the daemon's own logs almost always say why. Koi always
logs to **stderr**; the installed service additionally writes to a file (see below).

**Raise verbosity.** Two global flags, plus an environment variable:

| Want | Use |
| ---- | --- |
| More detail, quickly | `-v` (debug) or `-vv` (trace) — global, works on any command |
| A specific level | `--log-level debug` (env `KOI_LOG`; one of `error`, `warn`, `info`, `debug`, `trace`; default `info`) |
| Logs in a file too | `--log-file /path/koi.log` (env `KOI_LOG_FILE`) — appends, in addition to stderr |

```
koi -vv --daemon                                  # foreground, trace-level on stderr
koi --log-level debug --log-file ./koi.log --daemon
```

`-v`/`-vv` win over `--log-level` when both are given (`-v` forces debug, `-vv` forces
trace). For the installed service, set the level with the `KOI_LOG` environment variable
in the service definition.

**Where the installed-service logs land:**

| Platform | Log location |
| -------- | ------------ |
| Windows | `%ProgramData%\koi\logs\koi.log` (the service writes here). Service start/stop failures also surface in **Event Viewer → Windows Logs → System**. |
| Linux | `journalctl -u koi` (systemd captures stderr) |
| macOS | `/var/log/koi.log` (stdout) and `/var/log/koi.err` (stderr), per the launchd plist |

```powershell
# Windows — tail the service log
Get-Content "$env:ProgramData\koi\logs\koi.log" -Tail 40 -Wait
```

```sh
# Linux
journalctl -u koi --no-pager -n 50

# macOS
tail -n 50 /var/log/koi.err
```

The daemon's data directory (where `logs/` lives on Windows) is `%ProgramData%\koi\` on
Windows, `/var/lib/koi/` on Linux, and `/Library/Application Support/koi/` on macOS.
`KOI_DATA_DIR` overrides it.

---

## Certmesh: every enrollment gets `503 CA locked`

**Symptom.** `koi certmesh join` (or any issuance/enrollment call) fails with
`503 ca_locked` / "CA locked". `koi certmesh status` shows `CA locked: true`.

**Cause.** The CA private key is encrypted at rest, always. When the daemon starts or
restarts, it loads the roster but leaves the CA **locked** — it can answer status queries
but cannot issue or enroll until the key is decrypted. This is deliberate: a reboot
shouldn't silently restore certificate-issuing power.

**Fix.** Unlock it:

```
koi certmesh unlock
```

The unlock ceremony detects which methods the mesh has and prompts accordingly —
passphrase, a TOTP code, or nothing at all if **auto-unlock** is enabled (the *Just Me*
and *My Team* presets enable auto-unlock, so those meshes unlock themselves on daemon
start and you should rarely see this state). If you expected auto-unlock but the CA is
still locked, the mesh was likely created with a manual unlock method (the *My
Organization* preset), so an operator must run `unlock` after each restart. Once
unlocked, retry the join. Full details are in
[the certmesh guide](./certmesh.md#unlocking-the-ca).

> A *related-but-different* symptom: the [proxy](./proxy.md) serving a `self-signed`
> certificate instead of the mesh cert often means the CA is locked too — unlocking it
> lets the member cert get issued, and the proxy's watcher picks it up on the next
> handshake.

---

## Still stuck?

- For anything authentication- or exposure-related, the
  [security model](../reference/security-model.md) is the precise, ships-today reference.
- For per-capability behavior, each guide has its own troubleshooting section:
  [DNS](./dns.md#troubleshooting), [certmesh](./certmesh.md), [proxy](./proxy.md#troubleshooting),
  and [system / service lifecycle](./system.md#when-things-go-wrong).
- The full flag and environment-variable list is in the [CLI reference](../reference/cli.md);
  every endpoint and its auth requirements are in the [HTTP API reference](../reference/http-api.md).
- When something is genuinely broken beyond repair, `koi factory-reset` wipes the data
  directory and starts clean — it is irreversible and destroys CA keys and every issued
  certificate, so treat it as the last resort (see [system](./system.md#factory-reset)).

Back to the [documentation index](../index.md).
