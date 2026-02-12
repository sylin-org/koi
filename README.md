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

Or over HTTP — from any language, any container, any script:

```bash
curl http://localhost:5641/v1/mdns/browse?type=_http._tcp
curl -X POST http://localhost:5641/v1/mdns/services \
  -d '{"name": "My App", "type": "_http._tcp", "port": 8080, "ip": "192.168.1.42"}'
```

## Quick start

Install Koi as a system service (recommended):

```powershell
# Windows (run as Administrator)
koi install
```

```bash
# Linux
sudo koi install

# macOS
sudo koi install
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

Koi fills the gap: a single daemon that speaks mDNS on the network side and JSON over HTTP/IPC/stdio on the application side. Any language with an HTTP client or the ability to spawn a process can discover, name, and secure services on the local network.

## Containers get LAN tooling

When Koi runs on the host, every container gains LAN capabilities through plain HTTP — no `--network=host`, no macvlan, no mDNS reflectors.

```bash
# From inside any Docker container:
curl http://host.docker.internal:5641/v1/mdns/browse?type=_http._tcp
curl http://host.docker.internal:5641/v1/dns/lookup?name=grafana
```

The container makes a plain HTTP request; Koi speaks multicast on the physical network. Browse, register, resolve — all of it works from inside the most minimal scratch container. See [CONTAINERS.md](CONTAINERS.md) for Docker Compose examples, startup patterns, and Kubernetes DaemonSet configuration.

## Capabilities

| Capability | What it does | CLI moniker |
| --- | --- | --- |
| **mDNS** | Service discovery (DNS-SD) | `koi mdns ...` |
| **DNS** | Local resolver for friendly names | `koi dns ...` |
| **Certmesh** | Private CA + enrollment for LAN TLS | `koi certmesh ...` |
| **Health** | Machine/service health view | `koi health ...` |
| **Proxy** | TLS-terminating local reverse proxy | `koi proxy ...` |

## Features

- **Service discovery** — browse, resolve, subscribe to mDNS events
- **Local DNS** — static entries, mDNS aliases, certmesh SANs
- **LAN TLS** — private CA, TOTP enrollment, automatic renewals
- **Health view** — machine synthesis + opt-in HTTP/TCP checks
- **Local TLS proxy** — terminate TLS with certmesh-managed certs
- **Single binary** — HTTP, IPC, and CLI in one daemon

## Platform support

| Platform | mDNS engine                   | Service integration   |
| -------- | ----------------------------- | --------------------- |
| Windows  | Pure Rust (no Bonjour needed) | Windows Service (SCM) |
| Linux    | Pure Rust (no Avahi needed)   | systemd unit          |
| macOS    | Pure Rust (no Bonjour needed) | launchd plist         |

Zero OS dependencies. No Bonjour, no Avahi, no system mDNS service required.

## HTTP API

Koi's HTTP API uses SSE (Server-Sent Events) for streaming and JSON for everything else.

| Method   | Path                               | Description                         |
| -------- | ---------------------------------- | ----------------------------------- |
| `GET`    | `/v1/mdns/browse?type=_http._tcp`  | SSE stream of discovered services   |
| `POST`   | `/v1/mdns/services`                | Register a service                  |
| `DELETE` | `/v1/mdns/services/{id}`           | Unregister a service                |
| `PUT`    | `/v1/mdns/services/{id}/heartbeat` | Renew heartbeat lease               |
| `GET`    | `/v1/mdns/resolve?name={instance}` | Resolve a specific service instance |
| `GET`    | `/v1/mdns/events?type=_http._tcp`  | SSE stream of lifecycle events      |
| `GET`    | `/v1/dns/status`                   | DNS resolver status                 |
| `GET`    | `/v1/dns/lookup?name=grafana`      | Resolve a local name                |
| `GET`    | `/v1/health/status`                | Health snapshot                     |
| `GET`    | `/v1/status`                       | Unified capability status           |
| `POST`   | `/v1/admin/shutdown`               | Initiate graceful shutdown          |
| `GET`    | `/healthz`                         | Health check                        |

SSE streams close after 5 seconds of quiet by default. Set `idle_for=0` for infinite streaming, or `idle_for=15` to wait longer on slow networks.

## CLI

```bash
koi mdns discover http                              # discover HTTP services
koi mdns announce "My App" http 8080 version=1.0    # advertise a service
koi mdns resolve "My Server._http._tcp.local."      # resolve an instance
koi dns add grafana 10.0.0.42                        # add DNS entry
koi dns lookup grafana                               # resolve local name
koi certmesh status                                  # private CA status
koi health status                                    # health snapshot
koi status                                           # unified capability status
```

When stdin is piped, Koi reads NDJSON commands directly:

```bash
echo '{"browse": "_http._tcp"}' | koi
```

## Configuration

| Setting            | Flag           | Env var          | Default                              |
| ------------------ | -------------- | ---------------- | ------------------------------------ |
| HTTP port          | `--port`       | `KOI_PORT`       | `5641`                               |
| Pipe/socket path   | `--pipe`       | `KOI_PIPE`       | `\\.\pipe\koi` / `/var/run/koi.sock` |
| Log level          | `--log-level`  | `KOI_LOG`        | `info`                               |
| Verbosity          | `-v`, `-vv`    | —                | off                                  |
| Log file           | `--log-file`   | `KOI_LOG_FILE`   | —                                    |
| Disable HTTP       | `--no-http`    | `KOI_NO_HTTP`    | —                                    |
| Disable IPC        | `--no-ipc`     | `KOI_NO_IPC`     | —                                    |
| Disable mDNS       | `--no-mdns`    | `KOI_NO_MDNS`    | —                                    |
| Disable Certmesh   | `--no-certmesh`| `KOI_NO_CERTMESH`| —                                    |
| Disable DNS        | `--no-dns`     | `KOI_NO_DNS`     | —                                    |
| Disable Health     | `--no-health`  | `KOI_NO_HEALTH`  | —                                    |
| Disable Proxy      | `--no-proxy`   | `KOI_NO_PROXY`   | —                                    |
| DNS port           | `--dns-port`   | `KOI_DNS_PORT`   | `53`                                 |
| DNS zone           | `--dns-zone`   | `KOI_DNS_ZONE`   | `lan`                                |
| DNS public         | `--dns-public` | `KOI_DNS_PUBLIC` | off                                  |
| JSON output        | `--json`       | —                | off                                  |

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

Or build and install locally:

```bash
cargo install --path crates/koi
```

## Documentation

- [**User Guide**](GUIDE.md) — step-by-step walkthrough from first command to advanced usage
- [**Embedded Integration Guide**](docs/embedded-integration-guide.md) — embed Koi in Rust apps and validate full adapter surfaces
- [**DNS Guide**](docs/guide-dns.md) — local resolver usage and HTTP endpoints
- [**Container Guide**](CONTAINERS.md) — Docker, Compose, and Kubernetes integration
- [**Technical Details**](TECHNICAL.md) — protocol spec, wire format, standards compliance

## Name

Koi (鯉) are the fish that live in garden ponds. They're visible — they surface, they announce themselves by simply existing. You look into the pond and see what's there. That's service discovery: the network is the pond, the services are the koi. You peer in and see what's swimming.

The binary is `koi`. The crates.io package is published as `koi-net` because `koi` was already taken.

## Acknowledgments

Koi is an orchestration wrapper — the heavy lifting happens in [mdns-sd](https://github.com/keepsimple1/mdns-sd), a pure-Rust mDNS/DNS-SD implementation by [@keepsimple1](https://github.com/keepsimple1). Their library handles probing, conflict resolution, known-answer suppression, goodbye packets, cache flushing, and all the multicast plumbing that makes service discovery actually work. Koi just gives it a friendly front door.

## License

Dual licensed under Apache-2.0 and MIT. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).

Free to use, embed, bundle, and redistribute, commercially or otherwise. Just link back to this project somewhere reasonable (a README, an about page, a comment in your manifest). That's it.

## Contributing

Contributions welcome. Please open an issue to discuss before submitting large changes.
