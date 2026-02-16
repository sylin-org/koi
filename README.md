# Koi 𓆝

**Local network toolkit.**

Koi is a cross-platform local network toolkit. It bundles service discovery (mDNS/DNS-SD), a local DNS resolver for friendly names, and a private certificate mesh for LAN TLS. It ships as a single binary with HTTP, IPC, and CLI interfaces, so any language or container can use it.

Think of it as **the missing LAN toolbox**: discover services, name them, and secure them without installing a stack of OS-specific daemons.

```bash
# Discover what's on the network
koi mdns discover

# Resolve a friendly local name
koi dns lookup grafana

# Add a static DNS entry
koi dns add grafana 10.0.0.42

# Check unified status
koi status
```

Or over HTTP - from any language, any container, any script:

```bash
curl http://localhost:5641/v1/mdns/discover?type=_http._tcp
curl -X POST http://localhost:5641/v1/mdns/announce \
  -d '{"name": "My App", "type": "_http._tcp", "port": 8080, "ip": "192.168.1.42"}'
```

## Quick start

Install Koi as a system service (recommended):

```powershell
# Windows (run as Administrator)
koi install
```

```bash
# Linux / macOS
sudo koi install
```

Koi is now running on port 5641, ready for HTTP, IPC, and CLI clients.

For temporary or interactive use, run in the foreground instead:

```bash
koi --daemon
```

## Why Koi exists

mDNS is the invisible backbone of local networking. Printers, smart speakers, AirPlay, Chromecast, IoT devices - everything uses it. But **using** mDNS programmatically is surprisingly painful:

- **Windows** has native mDNS since Windows 10, but the Win32 APIs are poorly documented, 64-bit only, and don't expose full DNS-SD. The alternative - Apple's Bonjour - has redistribution-prohibiting licensing and a 13-year-old installer.
- **Linux** has Avahi, which is excellent but Linux-only and deeply coupled to D-Bus and systemd.
- **Containers** can't do mDNS at all. Docker's bridge network doesn't forward multicast traffic. Every workaround (`--network=host`, macvlan, mDNS reflectors) sacrifices isolation or adds fragility.
- **Cross-platform** libraries exist, but they're libraries - you need to write code in a specific language to use them.

Koi fills the gap: a single daemon that speaks mDNS on the network side and JSON over HTTP/IPC/stdio on the application side. Any language with an HTTP client or the ability to spawn a process can discover, name, and secure services on the local network.

## Containers

When Koi runs on the host, every container gains LAN capabilities through plain HTTP - no `--network=host`, no macvlan, no mDNS reflectors.

```bash
# From inside any Docker container:
curl http://host.docker.internal:5641/v1/mdns/discover?type=_http._tcp
curl http://host.docker.internal:5641/v1/dns/lookup?name=grafana
```

See [CONTAINERS.md](CONTAINERS.md) for Docker Compose examples, startup patterns, and Kubernetes DaemonSet configuration.

## Capabilities

| Capability   | What it does                        | CLI                | Guide                                     |
| ------------ | ----------------------------------- | ------------------ | ----------------------------------------- |
| **mDNS**     | Service discovery (DNS-SD)          | `koi mdns ...`     | [mDNS guide](docs/guides/mdns.md)         |
| **DNS**      | Local resolver for friendly names   | `koi dns ...`      | [DNS guide](docs/guides/dns.md)           |
| **Certmesh** | Private CA + enrollment for LAN TLS | `koi certmesh ...` | [Certmesh guide](docs/guides/certmesh.md) |
| **Health**   | Machine/service health monitoring   | `koi health ...`   | [Health guide](docs/guides/health.md)     |
| **Proxy**    | TLS-terminating local reverse proxy | `koi proxy ...`    | [Proxy guide](docs/guides/proxy.md)       |
| **UDP**      | Datagram bridging for containers    | HTTP API           | [UDP guide](docs/guides/udp.md)           |

## Platform support

| Platform | mDNS engine                   | Service integration   |
| -------- | ----------------------------- | --------------------- |
| Windows  | Pure Rust (no Bonjour needed) | Windows Service (SCM) |
| Linux    | Pure Rust (no Avahi needed)   | systemd unit          |
| macOS    | Pure Rust (no Bonjour needed) | launchd plist         |

Zero OS dependencies. No Bonjour, no Avahi, no system mDNS service required.

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

Or install from [crates.io](https://crates.io/crates/koi-net):

```bash
cargo install koi-net
```

## Documentation

**Using Koi:**

- [**User Guide**](GUIDE.md) - from first command to advanced usage
- [**Container Guide**](CONTAINERS.md) - Docker Compose, startup patterns, Kubernetes

**Capability deep-dives:**

- [mDNS - Service Discovery](docs/guides/mdns.md)
- [Certmesh - Certificate Mesh](docs/guides/certmesh.md)
- [DNS - Local Resolver](docs/guides/dns.md)
- [Health - Endpoint Monitoring](docs/guides/health.md)
- [Proxy - TLS Termination](docs/guides/proxy.md)
- [UDP - Datagram Bridging](docs/guides/udp.md)
- [System - Daemon Lifecycle](docs/guides/system.md)
- [Embedded - Rust In-Process](docs/guides/embedded.md)

**Reference:**

- [Architecture](docs/reference/architecture.md) - crate structure, boundaries, design
- [HTTP API](docs/reference/http-api.md) - all 49 endpoints
- [CLI Reference](docs/reference/cli.md) - every command and flag
- [Wire Protocol](docs/reference/wire-protocol.md) - JSON protocol spec
- [Ceremony Protocol](docs/reference/ceremony-protocol.md) - interactive flow engine
- [Envelope Encryption](docs/reference/envelope-encryption.md) - CA key protection

**Decisions:**

- [Architecture Decision Records](docs/adr/) - why things are the way they are

## Name

Koi (鯉) are the fish that live in garden ponds. They're visible - they surface, they announce themselves by simply existing. You look into the pond and see what's there. That's service discovery: the network is the pond, the services are the koi. You peer in and see what's swimming.

The binary is `koi`. The crates.io package is published as `koi-net` because `koi` was already taken.

## Acknowledgments

Koi is an orchestration wrapper - the heavy lifting happens in [mdns-sd](https://github.com/keepsimple1/mdns-sd), a pure-Rust mDNS/DNS-SD implementation by [@keepsimple1](https://github.com/keepsimple1). Their library handles probing, conflict resolution, known-answer suppression, goodbye packets, cache flushing, and all the multicast plumbing that makes service discovery actually work. Koi just gives it a friendly front door.

## License

Dual licensed under Apache-2.0 and MIT. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).

Free to use, embed, bundle, and redistribute, commercially or otherwise. Just link back to this project somewhere reasonable (a README, an about page, a comment in your manifest). That's it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and contribution guidelines.
