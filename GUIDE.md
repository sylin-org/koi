# Koi User Guide

Koi is a local infrastructure toolkit. It handles service discovery (mDNS/DNS-SD) and certificate management (private CA with pluggable enrollment auth) - the two things every LAN needs but nobody wants to set up manually.

This guide covers the basics. Each capability has a detailed walkthrough:

- **[mDNS - Service Discovery](docs/guides/mdns.md)** - find, advertise, and monitor services on your network
- **[Certmesh - Certificate Mesh](docs/guides/certmesh.md)** - private CA, TOTP/FIDO2 enrollment, mutual TLS trust
- **[DNS - Local Resolver](docs/guides/dns.md)** - map friendly hostnames to local IPs
- **[Health - Endpoint Monitoring](docs/guides/health.md)** - HTTP and TCP health checks
- **[Proxy - TLS Termination](docs/guides/proxy.md)** - local TLS-terminating reverse proxy
- **[UDP - Datagram Bridging](docs/guides/udp.md)** - relay host UDP sockets to containers over HTTP/SSE
- **[System - Daemon Lifecycle](docs/guides/system.md)** - install, manage, uninstall
- **[Embedded - Rust In-Process](docs/guides/embedded.md)** - use Koi as a library in Rust apps

For full CLI flags and configuration, see the [CLI Reference](docs/reference/cli.md). For the HTTP API, see the [HTTP API Reference](docs/reference/http-api.md).

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

That's mDNS discovery - no configuration, no server. Just devices talking to each other.

To advertise a service:

```
koi mdns announce "My App" http 8080
```

Other devices running any mDNS browser will see it. Press Ctrl+C to stop.

---

## Capabilities

Koi is organized into **capabilities** - independent domains that can be enabled or disabled individually. Each capability can be turned off with `--no-<capability>` (e.g., `--no-dns`). Check the status of all capabilities:

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

When a daemon is running, verb commands (`discover`, `announce`, `resolve`, etc.) automatically connect to it instead of creating a standalone engine. Detection is fast (<1ms when no daemon exists) - Koi reads a breadcrumb file written on startup.

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

| Operation  | Request JSON                                                           |
| ---------- | ---------------------------------------------------------------------- |
| Browse     | `{"browse": "_http._tcp"}`                                             |
| Register   | `{"register": {"name": "My App", "type": "_http._tcp", "port": 8080}}` |
| Unregister | `{"unregister": "a1b2c3d4"}`                                           |
| Resolve    | `{"resolve": "My NAS._http._tcp.local."}`                              |
| Subscribe  | `{"subscribe": "_http._tcp"}`                                          |
| Heartbeat  | `{"heartbeat": "a1b2c3d4"}`                                            |

---

## Configuration

All daemon settings can be set via CLI flags or environment variables. A few common examples:

```bash
koi --port 8053 -v                       # custom port, debug logging
koi -vv --log-file /var/log/koi.log      # trace-level with log file
koi --no-http                            # IPC only, no HTTP adapter
koi --no-certmesh --no-dns               # disable specific capabilities
KOI_PORT=9090 KOI_LOG=trace koi          # all via environment
```

For the full configuration table (all flags, env vars, and defaults), see the [CLI Reference](docs/reference/cli.md).

---

## System service

Koi can run as a system service on all major platforms:

```
koi install       # install and start
koi uninstall     # stop and remove
```

| Platform | Mechanism               | Service name    |
| -------- | ----------------------- | --------------- |
| Windows  | Service Control Manager | `koi`           |
| Linux    | systemd unit            | `koi.service`   |
| macOS    | launchd plist           | `org.sylin.koi` |

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
   - **`mdns admin` subcommand** - always talks to the daemon.
   - **`--standalone`** - runs a local mDNS engine, no daemon needed.
   - **`--endpoint URL`** - connects to the specified daemon.
   - **Otherwise** - checks for a running daemon. If found, uses client mode. If not, standalone.
2. **Stdin is a pipe** (`echo '...' | koi`) - reads NDJSON from stdin, writes to stdout.
3. **No subcommand, no pipe** - starts daemon mode (HTTP + IPC adapters).
4. **Windows, no arguments, launched by SCM** - runs as a Windows Service.

---

## What's next

- **[CLI Reference](docs/reference/cli.md)** - complete list of every command, flag, and environment variable
- **[HTTP API Reference](docs/reference/http-api.md)** - all 43 HTTP endpoints with request/response shapes
- **[Architecture](docs/reference/architecture.md)** - how the crates fit together
- **[Architecture Decision Records](docs/adr/)** - why Koi is built the way it is
