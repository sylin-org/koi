# 🐟 Koi

**Local service discovery for everyone.**

Koi is a cross-platform mDNS/DNS-SD daemon that exposes local network service discovery through a simple JSON API. It wraps the battle-tested [mdns-sd](https://github.com/keepsimple1/mdns-sd) library in a single binary with HTTP, IPC, and CLI interfaces — making mDNS accessible from any language, any container, any script.

Think of it as **Avahi for everywhere** — without the D-Bus dependency, without the Linux-only limitation, without the configuration files.

```bash
# Browse for services
curl http://localhost:5353/v1/browse?type=_http._tcp

# Register a service
curl -X POST http://localhost:5353/v1/services \
  -d '{"name": "My App", "type": "_http._tcp", "port": 8080}'

# Stream events in real time
curl http://localhost:5353/v1/events?type=_http._tcp
```

Or from the command line:

```bash
echo '{"browse": "_http._tcp"}' | koi
echo '{"register": {"name": "My App", "type": "_http._tcp", "port": 8080}}' | koi
```

## Why Koi exists

mDNS is the invisible backbone of local networking. Printers, smart speakers, AirPlay, Chromecast, IoT devices — everything uses it. But **using** mDNS programmatically is surprisingly painful:

- **Windows** has native mDNS since Windows 10, but the Win32 APIs are poorly documented, 64-bit only, and don't expose full DNS-SD. The alternative — Apple's Bonjour — has redistribution-prohibiting licensing and a 13-year-old installer.
- **Linux** has Avahi, which is excellent but Linux-only and deeply coupled to D-Bus and systemd.
- **Containers** can't do mDNS at all. Docker's bridge network doesn't forward multicast traffic. Every workaround (`--network=host`, macvlan, mDNS reflectors) sacrifices isolation or adds fragility.
- **Cross-platform** libraries exist, but they're libraries — you need to write code in a specific language to use them.

Koi fills the gap: a single daemon that speaks mDNS on the network side and JSON over HTTP/IPC/stdio on the application side. Any language with an HTTP client or the ability to spawn a process can discover and advertise services on the local network.

**For containers, this changes everything.** When Koi runs as a service on the host, any container can reach it via the Docker host gateway (`http://172.17.0.1:5353`) or a mounted socket (`/var/run/koi.sock`). No `--network=host`. No macvlan. No mDNS reflectors. The container makes a plain HTTP call; Koi speaks multicast on the physical network. Containers gain full mDNS capabilities — browse, register, resolve, subscribe — without ever touching a multicast socket.

## Containers get mDNS

When Koi runs as a service on the host, every container on that machine gains mDNS capabilities through Koi's HTTP API — no network mode changes, no multicast forwarding, no reflectors.

```bash
# From inside any Docker container:
curl http://host.docker.internal:5353/v1/browse?type=_http._tcp
curl http://172.17.0.1:5353/v1/browse?type=_ipp._tcp
```

The container doesn't need mDNS libraries, multicast socket access, or `--network=host`. It makes a plain HTTP request to the host, and Koi translates that into multicast mDNS on the physical network. Browse, register, resolve — all of it works from inside the most minimal scratch container.

This is the Docker-mDNS problem solved at the infrastructure level, not patched per-container.

## Features

- **Browse** — discover services by type, with real-time streaming as new services appear
- **Register** — advertise services on the local network via mDNS
- **Unregister** — remove service advertisements with goodbye packets
- **Resolve** — get full details (IP, port, TXT records) for a specific service instance
- **Subscribe** — stream service lifecycle events (found, resolved, removed)

## Platform support

| Platform | mDNS engine | Service integration |
|---|---|---|
| Windows | Pure Rust (no Bonjour needed) | Windows Service (SCM) |
| Linux | Pure Rust (no Avahi needed) | systemd unit |
| macOS | Pure Rust (no Bonjour needed) | launchd (planned) |

Zero OS dependencies. No Bonjour, no Avahi, no system mDNS service required. Koi manages its own multicast sockets directly via the [mdns-sd](https://github.com/keepsimple1/mdns-sd) crate.

## Interfaces

Koi exposes the same JSON protocol over three transports:

| Interface | Transport | Best for |
|---|---|---|
| **HTTP + SSE** | TCP (default: port 5353) | Containers, remote access, polyglot environments |
| **Named Pipe / UDS** | Local IPC | Same-host services, zero network overhead |
| **CLI** | stdin/stdout | Scripting, testing, shell pipelines |

All three speak identical JSON. A request looks the same whether it arrives over HTTP, gets read from a pipe, or comes in on stdin.

## JSON protocol

The protocol is verb-oriented. The top-level key is the intent — no envelopes, no indirection.

**Browse** — discover services of a given type:
```json
→ { "browse": "_http._tcp" }
← { "found": { "name": "My Web Server", "type": "_http._tcp", "host": "server.local", "ip": "192.168.1.42", "port": 8080, "txt": { "path": "/api" }}}
← { "found": { "name": "Office Printer", "type": "_http._tcp", "host": "printer.local", "ip": "192.168.1.50", "port": 80, "txt": {} }}
```

**Register** — advertise a service:
```json
→ { "register": { "name": "My App", "type": "_http._tcp", "port": 8080, "txt": { "version": "1.0" }}}
← { "registered": { "id": "a1b2c3", "name": "My App", "type": "_http._tcp", "port": 8080 }}
```

**Resolve** — look up a specific service instance:
```json
→ { "resolve": "My Web Server._http._tcp.local." }
← { "resolved": { "name": "My Web Server", "type": "_http._tcp", "host": "server.local", "ip": "192.168.1.42", "port": 8080, "txt": { "path": "/api" }}}
```

**Unregister** — remove a service:
```json
→ { "unregister": "a1b2c3" }
← { "unregistered": "a1b2c3" }
```

**Subscribe** — stream lifecycle events:
```json
→ { "subscribe": "_http._tcp" }
← { "event": "found",    "service": { "name": "...", "type": "...", ... }}
← { "event": "resolved", "service": { "name": "...", "type": "...", ... }}
← { "event": "removed",  "service": { "name": "...", "type": "..." }}
```

Responses may include optional pipeline properties when the situation calls for it:

| Property | Meaning |
|---|---|
| `"status": "ongoing"` | More data is expected for this result |
| `"status": "finished"` | This result is complete |
| `"warning": "..."` | Succeeded, but something is noteworthy |
| `"error": "..."` | Operation failed |

Their absence is the happy path — a clean response with no extra keys means everything went perfectly.

## Installation

### Prebuilt binaries

Download the latest release from [GitHub Releases](https://github.com/sylin-org/koi/releases). Extract and place `koi` (or `koi.exe`) on your `PATH`.

### Build from source

Requires [Rust](https://rustup.rs/) 1.75 or later.

```bash
git clone https://github.com/sylin-org/koi.git
cd koi
cargo build --release
# Binary is at target/release/koi (or koi.exe on Windows)
```

Or install directly from crates.io:

```bash
cargo install koi-mdns
```

## Usage

### Daemon mode

Start Koi as a foreground daemon with HTTP and IPC adapters:

```bash
koi --daemon
```

This starts the HTTP API on port 5353 and the IPC adapter (Named Pipe on Windows, Unix socket on Linux/macOS).

### CLI mode

Koi provides human-friendly verb subcommands for all operations:

```bash
# Browse for HTTP services on the local network
koi browse http

# Register a service (keeps advertising until Ctrl+C)
koi register "My App" http 8080 version=1.0

# Resolve a specific service instance
koi resolve "My Server._http._tcp.local."

# Subscribe to lifecycle events
koi subscribe http

# Output JSON instead of human-readable text
koi browse http --json
```

When stdin is piped, Koi reads NDJSON commands and writes NDJSON responses:

```bash
echo '{"browse": "_http._tcp"}' | koi
echo '{"register": {"name": "My App", "type": "_http._tcp", "port": 8080}}' | koi
```

### Windows Service

```powershell
# Install (run as Administrator)
koi.exe install

# Start/stop via Service Control Manager
sc start koi
sc stop koi

# Uninstall
koi.exe uninstall
```

### Configuration

| Setting | Flag | Env var | Default |
|---|---|---|---|
| HTTP port | `--port` | `KOI_PORT` | `5353` |
| Pipe/socket path | `--pipe` | `KOI_PIPE` | `\\.\pipe\koi` (Windows) / `/var/run/koi.sock` (Linux) |
| Log level | `--log-level` | `KOI_LOG` | `info` |
| Disable HTTP | `--no-http` | `KOI_NO_HTTP` | — |
| Disable IPC | `--no-ipc` | `KOI_NO_IPC` | — |
| JSON output | `--json` | — | off (human-readable) |

### HTTP API

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/browse?type=_http._tcp` | SSE stream of discovered services |
| `POST` | `/v1/services` | Register a service |
| `DELETE` | `/v1/services/{id}` | Unregister a service |
| `GET` | `/v1/resolve?name={instance}` | Resolve a specific service instance |
| `GET` | `/v1/events?type=_http._tcp` | SSE stream of lifecycle events |
| `GET` | `/healthz` | Health check (`{"ok": true}`) |

## Use cases

**Docker containers** — The core use case. Koi on the host gives every container full mDNS access via HTTP. No `--network=host`, no macvlan, no mDNS reflectors, no Avahi-in-a-container. A scratch image with `curl` can discover printers, Chromecast devices, Home Assistant, or any service advertising on the local network. Containers can also register services that appear on the LAN — something that's otherwise impossible from behind Docker's NAT bridge.

**Windows development** — Full mDNS/DNS-SD without installing Bonjour, configuring the registry, or fighting the firewall.

**Home automation** — Discover Home Assistant devices, printers, Chromecast, AirPlay speakers from scripts or tools that don't have native mDNS support.

**IoT and LAN games** — Any application that needs peer discovery on a local network gets it through a simple HTTP call.

**Polyglot environments** — Python, Node, .NET, Go, Java, PowerShell, bash — if it can make an HTTP request or spawn a process, it can use mDNS.

## Standards compliance

Koi implements [RFC 6762](https://tools.ietf.org/html/rfc6762) (mDNS) and [RFC 6763](https://tools.ietf.org/html/rfc6763) (DNS-SD) via the mdns-sd library, which supports probing, conflict resolution, known-answer suppression, goodbye packets, and cache flushing. See [TECHNICAL.md](TECHNICAL.md) for details.

## Name

Koi (鯉) are the fish that live in garden ponds. They're visible — they surface, they announce themselves by simply existing. You look into the pond and see what's there. That's service discovery: the network is the pond, the services are the koi. You peer in and see what's swimming.

## License

Dual licensed under Apache-2.0 and MIT. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).

## Contributing

Contributions welcome. Please open an issue to discuss before submitting large changes.
