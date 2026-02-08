# Koi

**Local service discovery for everyone.**

Koi is a cross-platform mDNS/DNS-SD daemon that exposes local network service discovery through a simple JSON API. It wraps the battle-tested [mdns-sd](https://github.com/keepsimple1/mdns-sd) library in a single binary with HTTP, IPC, and CLI interfaces — making mDNS accessible from any language, any container, any script.

Think of it as **Avahi for everywhere** — without the D-Bus dependency, without the Linux-only limitation, without the configuration files.

```bash
# What's on my network?
koi browse

# Find all HTTP servers
koi browse http

# Register a service
koi register "My App" http 8080 version=1.0

# Resolve a specific instance
koi resolve "My Server._http._tcp.local."
```

Or over HTTP — from any language, any container, any script:

```bash
curl http://localhost:5641/v1/browse?type=_http._tcp
curl -X POST http://localhost:5641/v1/services \
  -d '{"name": "My App", "type": "_http._tcp", "port": 8080}'
```

## Quick start

Install Koi as a system service (recommended):

```powershell
# Windows (run as Administrator)
koi install
```

```bash
# Linux
sudo systemctl enable --now koi
```

That's it. Koi is now running on port 5641, ready for HTTP, IPC, and CLI clients.

For temporary or interactive use, run in the foreground instead:

```bash
koi --daemon
```

## Why Koi exists

mDNS is the invisible backbone of local networking. Printers, smart speakers, AirPlay, Chromecast, IoT devices — everything uses it. But **using** mDNS programmatically is surprisingly painful:

- **Windows** has native mDNS since Windows 10, but the Win32 APIs are poorly documented, 64-bit only, and don't expose full DNS-SD. The alternative — Apple's Bonjour — has redistribution-prohibiting licensing and a 13-year-old installer.
- **Linux** has Avahi, which is excellent but Linux-only and deeply coupled to D-Bus and systemd.
- **Containers** can't do mDNS at all. Docker's bridge network doesn't forward multicast traffic. Every workaround (`--network=host`, macvlan, mDNS reflectors) sacrifices isolation or adds fragility.
- **Cross-platform** libraries exist, but they're libraries — you need to write code in a specific language to use them.

Koi fills the gap: a single daemon that speaks mDNS on the network side and JSON over HTTP/IPC/stdio on the application side. Any language with an HTTP client or the ability to spawn a process can discover and advertise services on the local network.

## Containers get mDNS

When Koi runs on the host, every container gains full mDNS capabilities through plain HTTP — no `--network=host`, no macvlan, no mDNS reflectors.

```bash
# From inside any Docker container:
curl http://host.docker.internal:5641/v1/browse?type=_http._tcp
```

The container makes a plain HTTP request; Koi speaks multicast on the physical network. Browse, register, resolve — all of it works from inside the most minimal scratch container. See [CONTAINERS.md](CONTAINERS.md) for Docker Compose examples, startup patterns, and Kubernetes DaemonSet configuration.

## Features

- **Browse** — discover services by type, with real-time streaming
- **Register** — advertise services on the local network via mDNS
- **Unregister** — remove service advertisements with goodbye packets
- **Resolve** — get full details (IP, port, TXT records) for a specific instance
- **Subscribe** — stream lifecycle events (found, resolved, removed)

## Platform support

| Platform | mDNS engine | Service integration |
|---|---|---|
| Windows | Pure Rust (no Bonjour needed) | Windows Service (SCM) |
| Linux | Pure Rust (no Avahi needed) | systemd unit |
| macOS | Pure Rust (no Bonjour needed) | launchd (planned) |

Zero OS dependencies. No Bonjour, no Avahi, no system mDNS service required.

## HTTP API

Koi's HTTP API uses SSE (Server-Sent Events) for streaming and JSON for everything else.

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/browse?type=_http._tcp` | SSE stream of discovered services |
| `POST` | `/v1/services` | Register a service |
| `DELETE` | `/v1/services/{id}` | Unregister a service |
| `GET` | `/v1/resolve?name={instance}` | Resolve a specific service instance |
| `GET` | `/v1/events?type=_http._tcp` | SSE stream of lifecycle events |
| `GET` | `/healthz` | Health check |

SSE streams close after 5 seconds of quiet by default. Set `idle_for=0` for infinite streaming, or `idle_for=15` to wait longer on slow networks.

## CLI

```bash
koi browse http                              # discover HTTP services
koi browse                                   # discover all service types
koi register "My App" http 8080 version=1.0  # advertise a service
koi resolve "My Server._http._tcp.local."    # resolve an instance
koi subscribe http                           # stream lifecycle events
koi browse http --json                       # output as NDJSON
```

When stdin is piped, Koi reads NDJSON commands directly:

```bash
echo '{"browse": "_http._tcp"}' | koi
```

## Configuration

| Setting | Flag | Env var | Default |
|---|---|---|---|
| HTTP port | `--port` | `KOI_PORT` | `5641` |
| Pipe/socket path | `--pipe` | `KOI_PIPE` | `\\.\pipe\koi` / `/var/run/koi.sock` |
| Log level | `--log-level` | `KOI_LOG` | `info` |
| Disable HTTP | `--no-http` | `KOI_NO_HTTP` | — |
| Disable IPC | `--no-ipc` | `KOI_NO_IPC` | — |
| JSON output | `--json` | — | off |

## Installation

### Prebuilt binaries

Download the latest release from [GitHub Releases](https://github.com/sylin-org/koi/releases). Extract and place `koi` (or `koi.exe`) on your `PATH`.

### Build from source

Requires [Rust](https://rustup.rs/) 1.75 or later.

```bash
git clone https://github.com/sylin-org/koi.git
cd koi
cargo build --release
```

Or install directly from crates.io:

```bash
cargo install koi-mdns
```

## Documentation

- [**User Guide**](GUIDE.md) — step-by-step walkthrough from first command to advanced usage
- [**Container Guide**](CONTAINERS.md) — Docker, Compose, and Kubernetes integration
- [**Technical Details**](TECHNICAL.md) — protocol spec, wire format, standards compliance

## Name

Koi (鯉) are the fish that live in garden ponds. They're visible — they surface, they announce themselves by simply existing. You look into the pond and see what's there. That's service discovery: the network is the pond, the services are the koi. You peer in and see what's swimming.

## Acknowledgments

Koi is an orchestration wrapper — the heavy lifting happens in [mdns-sd](https://github.com/keepsimple1/mdns-sd), a pure-Rust mDNS/DNS-SD implementation by [@keepsimple1](https://github.com/keepsimple1). Their library handles probing, conflict resolution, known-answer suppression, goodbye packets, cache flushing, and all the multicast plumbing that makes service discovery actually work. Koi just gives it a friendly front door.

## License

Dual licensed under Apache-2.0 and MIT. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).

## Contributing

Contributions welcome. Please open an issue to discuss before submitting large changes.
