# Koi User Guide

Koi is a local infrastructure toolkit. It handles service discovery (mDNS/DNS-SD) and certificate management (private CA with TOTP enrollment) — the two things every LAN needs but nobody wants to set up manually.

This guide covers the basics. Each capability has a detailed reference:

- **[mDNS — Service Discovery](docs/guide-mdns.md)** — find, advertise, and monitor services on your network
- **[Certmesh — Certificate Mesh](docs/guide-certmesh.md)** — private CA, TOTP enrollment, mutual TLS trust
- **[DNS — Local Resolver](docs/guide-dns.md)** — map friendly hostnames to local IPs

---

## Quick start

Open a terminal:

```
koi mdns discover
```

Koi scans your local network and lists every service type it can find. After five seconds it stops. You might see:

```
_http._tcp
_googlecast._tcp
_spotify-connect._tcp
```

That's mDNS discovery — no configuration, no server. Just devices talking to each other.

To advertise a service:

```
koi mdns announce "My App" http 8080
```

Other devices running any mDNS browser will see it. Press Ctrl+C to stop.

---

## Capabilities

Koi is organized into **capabilities** — independent domains that can be enabled or disabled individually.

| Capability | What it does | CLI moniker |
|---|---|---|
| **mdns** | mDNS/DNS-SD service discovery | `koi mdns ...` |
| **certmesh** | Private CA, certificate enrollment | `koi certmesh ...` |
| **dns** | Local DNS resolver for `.lan` names | `koi dns ...` |

Check the status of all capabilities:

```
koi status
```

```
Koi v0.2.x
  Platform:  windows
  Daemon:    running
  [+] mdns:      mdns-sd (3 registrations)
  [+] certmesh:  Just Me (1 member)
```

---

## Daemon mode

When you run Koi without a subcommand, it starts as a persistent daemon:

```
koi
```

The daemon exposes:
- **HTTP API** on port 5641 (all interfaces)
- **IPC** via Named Pipe (`\\.\pipe\koi` on Windows) or Unix socket (`$XDG_RUNTIME_DIR/koi.sock`)

All CLI commands automatically detect a running daemon and delegate to it. When no daemon is running, commands like `koi mdns discover` spin up a temporary mDNS engine and run standalone.

### Health check

```
GET /healthz → "OK"
```

### Unified status

```
GET /v1/status
```

Returns version, uptime, platform, and the status of each capability.

### Admin shutdown

```
POST /v1/admin/shutdown
```

Requests a graceful daemon shutdown.

---

## Client mode

When a daemon is running, verb commands (`discover`, `announce`, `resolve`, etc.) automatically connect to it instead of creating a standalone engine. Detection is fast (<1ms when no daemon exists) — Koi reads a breadcrumb file written on startup.

```
koi mdns discover http --endpoint http://localhost:5641   # force specific daemon
koi mdns discover http --standalone                       # force standalone mode
```

---

## JSON output

Every command supports `--json` for machine-readable NDJSON output:

```
koi mdns discover http --json
koi certmesh status --json
koi status --json
```

The flag can appear before or after the subcommand.

---

## Piped JSON mode

When stdin is a pipe, Koi reads NDJSON commands and writes NDJSON responses:

```bash
echo '{"browse":"_http._tcp"}' | koi
```

| Operation | Request JSON |
|---|---|
| Browse | `{"browse": "_http._tcp"}` |
| Register | `{"register": {"name": "My App", "type": "_http._tcp", "port": 8080}}` |
| Unregister | `{"unregister": "a1b2c3d4"}` |
| Resolve | `{"resolve": "My NAS._http._tcp.local."}` |
| Subscribe | `{"subscribe": "_http._tcp"}` |
| Heartbeat | `{"heartbeat": "a1b2c3d4"}` |

---

## Configuration

All daemon settings can be set via CLI flags or environment variables:

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--port` | `KOI_PORT` | `5641` | HTTP API port |
| `--pipe` | `KOI_PIPE` | platform-specific | IPC socket/pipe path |
| `--log-level` | `KOI_LOG` | `info` | Log level (error/warn/info/debug/trace) |
| `-v`, `--verbose` | | off | Increase verbosity (`-v` = debug, `-vv` = trace) |
| `--log-file` | `KOI_LOG_FILE` | _(none)_ | Write logs to file (in addition to stderr) |
| `--no-http` | `KOI_NO_HTTP` | `false` | Disable the HTTP adapter |
| `--no-ipc` | `KOI_NO_IPC` | `false` | Disable the IPC adapter |
| `--no-mdns` | `KOI_NO_MDNS` | `false` | Disable the mDNS capability |
| `--no-certmesh` | `KOI_NO_CERTMESH` | `false` | Disable the certmesh capability |
| `--no-dns` | `KOI_NO_DNS` | `false` | Disable the DNS capability |
| `--dns-port` | `KOI_DNS_PORT` | `53` | DNS server port |
| `--dns-zone` | `KOI_DNS_ZONE` | `lan` | Local DNS zone suffix |
| `--dns-public` | `KOI_DNS_PUBLIC` | `false` | Allow queries from non-private clients |

When `-v` is used, it takes precedence over `--log-level`.

Examples:

```bash
koi --port 8053 -v                       # custom port, debug logging
koi -vv --log-file /var/log/koi.log      # trace-level with log file
koi --no-http                            # IPC only
koi --no-certmesh                        # disable certmesh capability
koi --no-dns                             # disable DNS capability
KOI_DNS_PORT=15353 koi                   # run DNS on a high port
KOI_PORT=9090 KOI_LOG=trace koi          # all via environment
```

---

## System service

Koi can run as a system service on all major platforms:

```
koi install       # install and start
koi uninstall     # stop and remove
```

| Platform | Mechanism | Service name |
|---|---|---|
| Windows | Service Control Manager | `koi` |
| Linux | systemd unit | `koi.service` |
| macOS | launchd plist | `org.sylin.koi` |

On Windows, manage with `sc stop koi` / `sc start koi`. On Linux, use `systemctl`.

---

## DNS usage

Koi can act as a lightweight resolver for a local zone (default: `.lan`).
It combines static entries, certmesh SANs, and mDNS aliases, and forwards
non-local queries upstream.

### Start the resolver

Standalone (foreground):

```
koi dns serve
```

Daemon (background):

```
koi dns serve --endpoint http://localhost:5641
```

### Add static entries

```
koi dns add grafana 10.0.0.42
koi dns add grafana.lan 10.0.0.42
koi dns remove grafana
```

### Query and list

```
koi dns lookup grafana
koi dns lookup grafana --record-type AAAA
koi dns list
```

### Stop (daemon mode)

```
koi dns stop --endpoint http://localhost:5641
```

## How modes are chosen

1. **Subcommand present** (`koi mdns discover`, `koi certmesh status`, etc.):
   - **`mdns admin` subcommand** — always talks to the daemon.
   - **`--standalone`** — runs a local mDNS engine, no daemon needed.
   - **`--endpoint URL`** — connects to the specified daemon.
   - **Otherwise** — checks for a running daemon. If found, uses client mode. If not, standalone.
2. **Stdin is a pipe** (`echo '...' | koi`) — reads NDJSON from stdin, writes to stdout.
3. **No subcommand, no pipe** — starts daemon mode (HTTP + IPC adapters).
4. **Windows, no arguments, launched by SCM** — runs as a Windows Service.

---

## Quick reference

```
# Service discovery (mDNS)
koi mdns discover [TYPE]                         # browse for services (5s default)
koi mdns announce NAME TYPE PORT [KEY=VALUE ...] # advertise a service
koi mdns unregister ID                           # stop advertising
koi mdns resolve INSTANCE                        # look up a specific instance
koi mdns subscribe TYPE                          # stream lifecycle events

koi mdns admin status                            # daemon mDNS status
koi mdns admin ls                                # list all registrations
koi mdns admin inspect ID                        # detailed view (prefix matching)
koi mdns admin drain ID                          # start grace timer
koi mdns admin revive ID                         # cancel drain
koi mdns admin unregister ID                     # force-remove

# Certificate mesh
koi certmesh create [--profile just-me|team|organization] [--operator NAME]
koi certmesh status                              # show mesh status
koi certmesh join [ENDPOINT]                     # join existing mesh (discovers CA via mDNS)
koi certmesh unlock                              # decrypt CA key
koi certmesh log                                 # show audit log
koi certmesh set-hook --reload "COMMAND"         # set renewal hook
koi certmesh promote [ENDPOINT]                  # promote standby CA
koi certmesh open-enrollment [--until DURATION]  # open enrollment window
koi certmesh close-enrollment                    # close enrollment window
koi certmesh set-policy [--domain ...] [--subnet ...] [--clear]
koi certmesh rotate-totp                         # rotate TOTP secret
koi certmesh destroy                             # destroy all certmesh state

# DNS
koi dns serve                                    # start resolver
koi dns stop                                     # stop resolver (daemon mode)
koi dns status                                   # resolver status
koi dns lookup NAME [--record-type A|AAAA|ANY]   # query a name
koi dns add NAME IP [--ttl SECS]                 # static entry
koi dns remove NAME                              # remove static entry
koi dns list                                     # list all resolvable names

# Global
koi status                                       # unified capability status
koi install                                      # install system service
koi uninstall                                    # remove system service
koi version                                      # show version

# Flags (work with any subcommand)
  --json              JSON output
  --timeout SECONDS   auto-exit (0 = run forever)
  --endpoint URL      connect to a specific daemon
  --standalone        skip daemon detection
  -v, -vv             increase verbosity
  --log-file PATH     write logs to file
```
