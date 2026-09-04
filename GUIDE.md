# Koi User Guide

**Let everything local find, trust, and talk.** Koi bridges containers,
applications, and devices so they can discover, trust, and communicate with one
another across a private network. This guide takes you from the first command to
daily usage; each implementation capability then has its own deep-dive.

**Find:**

- **[mDNS — Service Discovery](docs/guides/mdns.md)** — find, advertise, and monitor services, with a real lease lifecycle
- **[DNS — Local Resolver](docs/guides/dns.md)** — friendly names from three sources: static entries, discovery, certificates
- **[Runtime — Container Lifecycle](docs/guides/runtime.md)** — label a container; Koi announces, names, and watches it

**Trust:**

- **[Certmesh — Certificate Mesh](docs/guides/certmesh.md)** — private CA, guided enrollment, renewal, and membership
- **[Trust — OS Integration](docs/guides/trust.md)** — install, inspect, export, and diagnose the local trust root
- **[ACME — Standard Certificate Issuance](docs/guides/acme.md)** — let existing proxies obtain and renew in-zone certificates

**Connect:**

- **[Proxy — TLS Endpoint](docs/guides/proxy.md)** — zero-config TLS termination for certmesh certificates
- **[UDP — Datagram Bridging](docs/guides/udp.md)** — host UDP sockets for bridge-networked containers
- **[Containers — Network Participation](CONTAINERS.md)** — let isolated workloads announce, discover, and communicate
- **[Embedded — Rust In-Process](docs/guides/embedded.md)** — use Koi as a library

**Operate and observe:**

- **[Health — Endpoint Monitoring](docs/guides/health.md)** — HTTP and TCP checks feeding status and the dashboard
- **[System — Daemon Lifecycle](docs/guides/system.md)** — install, manage, uninstall

References: [CLI](docs/reference/cli.md) ·
[HTTP API](docs/reference/http-api.md) ·
[Security model](docs/reference/security-model.md)

---

## Quick start

Open a terminal:

```
koi --standalone mdns discover
```

Koi scans your local network and lists every service type it can find. After five
seconds it stops. You might see:

```
_http._tcp
_googlecast._tcp
_spotify-connect._tcp
```

That's an intentional one-process mDNS session — no configuration or central
server. `--standalone` is explicit so Koi never starts a second responder beside
an installed service.

To advertise a service:

```
koi --standalone mdns announce "My App" _http._tcp 8080
```

Other devices running any mDNS browser will see it. Press Ctrl+C to stop — and
because announcements are *leased*, stopping actually removes it from the network.
No ghosts.

---

## Finding your way around

Koi's CLI is built to be explored — three levels of help, no manual required:

```
koi                      # live daemon status + the full command catalog
koi dns                  # one domain's commands, with curated examples
koi mdns announce?       # any command + '?' → detail page with examples
                         # and the equivalent HTTP call
```

Commands follow one shape throughout: `koi <domain> <verb> [args]`. Every command
accepts `--json` for machine-readable output, `--timeout`, and `-v`/`-vv` for
diagnostics.

---

## The daemon

One-off commands can use explicit `--standalone`, but composed services — DNS, certificates,
the dashboard, and container integration — live in the daemon:

```
koi --daemon             # foreground (Ctrl+C to stop)
koi install              # or install as a system service (see below)
```

The daemon exposes:

- **HTTP API** on `127.0.0.1:5641` — loopback only; see the
  [security model](docs/reference/security-model.md) for the bind and auth details
- **Web dashboard** at `http://localhost:5641/` and an **mDNS network browser**
  at `/mdns-browser` (`koi launch` opens it)
- **Interactive API docs** at `/docs` (OpenAPI/Scalar)
- **IPC** via Named Pipe (`\\.\pipe\koi` on Windows) or Unix socket
  (`$XDG_RUNTIME_DIR/koi.sock`) — mDNS operations over NDJSON

Bare `koi` (no flags, no subcommand) does **not** start a daemon — it shows status
and the command catalog. The daemon starts only with `--daemon` or as an installed
service.

### Writes require the daemon token

`GET` endpoints are open on loopback. Everything else needs the `x-koi-token`
header. The CLI handles this automatically; for raw HTTP, read the token from the
breadcrumb file — the two-line recipe per OS is in the
[security model](docs/reference/security-model.md).

---

## Capabilities and `koi status`

Capabilities are independent domains, all enabled by default, each toggleable at
runtime (`--no-dns`, `--no-certmesh`, … or `KOI_NO_DNS=1`, …). Disabled
capabilities answer with a clear message naming the flag that re-enables them.

```
koi status
```

```
Koi v0.x
  Platform:  windows
  Daemon:    running
  [+] mdns:      3 registrations
  [+] certmesh:  Just Me (1 member)
  [+] dns:       8 local names
  [+] health:    5 checks (4 healthy, 1 unhealthy)
  [+] proxy:     2 listeners
  [+] udp:       1 binding
```

---

## How commands pick their mode

You normally never think about this — but here is the rule:

1. **Subcommand present** (`koi mdns discover`, `koi dns add`, …):
   - `--standalone` → run an intentional local composition, only when the local service is stopped
   - `--endpoint URL` → talk to that daemon explicitly
   - otherwise → use the healthy authenticated local service; if none is available, fail with startup guidance
2. **`koi --daemon`** → start the daemon
3. **No subcommand** → status + catalog

Client mode is what makes `koi mdns announce` pleasant: the CLI auto-heartbeats the
lease while running and unregisters cleanly on Ctrl+C.

---

## JSON output

Commands support `--json` for machine-readable output:

```
koi mdns discover _http._tcp --json
koi status --json
```

Redirecting stdin never starts a local responder. For long-lived integrations,
use the authenticated HTTP or local IPC boundary. `koi mcp serve` is the one
explicit stdio surface and remains a client of the installed service.

---

## Local DNS in five minutes

Koi's resolver serves one local zone (default: `.internal`) populated from three
sources — static entries you add, certmesh certificate names, and mDNS-derived
aliases — and forwards everything else upstream.

```
koi dns serve                      # start the resolver (or run inside the daemon)
koi dns add grafana 10.0.0.42      # static entry → grafana.internal
koi dns lookup grafana             # resolve through Koi
koi dns list                       # everything currently resolvable
```

**Keeping your existing DNS:** you don't have to point machines at Koi. Delegate
just the Koi zone from the resolver you already run — Pi-hole, AdGuard Home, and
dnsmasq all support per-domain conditional forwarding (e.g. forward `*.internal` to
Koi's port). Same pattern works for a Tailscale split-DNS rule, which lets remote
tailnet devices resolve your LAN names. See the [DNS guide](docs/guides/dns.md).

---

## Configuration

All daemon settings are CLI flags with environment-variable mirrors:

```bash
koi --daemon --port 8053 -v              # custom port, debug logging
koi --daemon -vv --log-file koi.log      # trace-level with log file
koi --daemon --no-certmesh --no-dns      # disable capabilities
KOI_PORT=9090 KOI_LOG=trace koi --daemon # same, via environment
```

Full table: [CLI Reference](docs/reference/cli.md).

---

## System service

```
koi install       # install and start
koi uninstall     # stop and remove
```

| Platform | Mechanism | Service name |
| -------- | --------- | ------------ |
| Windows | Service Control Manager | `koi` |
| Linux | systemd unit | `koi.service` |
| macOS | launchd plist | `org.sylin.koi` |

On Windows, manage with `sc stop koi` / `sc start koi`; on Linux, `systemctl`.

---

## What's next

- **[Documentation hub](docs/index.md)** — the goal-keyed map of every guide and
  reference; start here when you're not sure where to look
- **[Trusted HTTPS in ~10 minutes](docs/tutorials/trusted-https.md)** — the headline
  end-to-end journey: a private CA to a green browser across two machines
- **[Container Guide](CONTAINERS.md)** — the host-daemon pattern, label-driven
  runtime adapter, and current limitations
- **[Certmesh guide](docs/guides/certmesh.md)** · **[ACME guide](docs/guides/acme.md)** —
  TLS on your LAN without browser warnings; issue certs to Caddy/Traefik/lego
- **[MCP guide](docs/guides/mcp.md)** — expose the LAN to AI agents
- **[DNS coexistence](docs/guides/dns-coexistence.md)** — run alongside Pi-hole / AdGuard /
  dnsmasq / Unbound
- **[Security model](docs/reference/security-model.md)** — exactly what listens
  where, and what the token protects
