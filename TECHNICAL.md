# Koi Technical Specification

**Version:** 0.2.0
**Status:** Implemented

## Table of Contents

1. [Architecture](#architecture)
2. [Core API](#core-api)
3. [JSON Wire Protocol](#json-wire-protocol)
4. [HTTP Adapter](#http-adapter)
5. [Named Pipe / Unix Domain Socket Adapter](#named-pipe--unix-domain-socket-adapter)
6. [CLI Adapter](#cli-adapter)
7. [Pipeline Properties](#pipeline-properties)
8. [Service Record Schema](#service-record-schema)
9. [Platform Integration](#platform-integration)
10. [Project Structure](#project-structure)
11. [Dependencies](#dependencies)
12. [RFC Compliance](#rfc-compliance)
13. [Design Decisions](#design-decisions)

---

## Architecture

Koi is a single binary with three layers: adapters, core, and the mDNS engine. Adapters are thin transport translations. The core owns all domain logic. The engine is the `mdns-sd` crate.

```
┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐
│  HTTP Adapter   │  │ Named Pipe / UDS │  │  CLI Adapter    │
│  (Axum + SSE)   │  │ Adapter          │  │  (stdin/stdout) │
└────────┬────────┘  └────────┬─────────┘  └────────┬────────┘
         │                    │                      │
         ▼                    ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│                      Core API Layer                         │
│                                                             │
│  browse() / register() / unregister() / resolve()           │
│  subscribe() → event stream                                 │
│  Service registry (in-memory, owns lifecycle)               │
│  Event fan-out (broadcast to all subscribers)               │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    mdns-sd daemon                            │
│  Single ServiceDaemon / flume channels / UDP 5353           │
└─────────────────────────────────────────────────────────────┘
```

Key architectural principles:

- **Single shared `ServiceDaemon`.** Multiple callers browsing the same service type don't each create their own multicast listeners. The core multiplexes browse subscriptions through one daemon — avoiding the "multiple mDNS stacks" problem that plagues systems where each application runs its own resolver.

- **Adapters are pure translation.** An adapter maps a transport (HTTP, pipe, stdio) to core API calls. Each adapter is roughly 150 lines. They don't contain domain logic, validation, or state management.

- **Core owns the registry.** All registered services, active browse handles, and subscription fan-out live in the core. If an adapter disconnects, the core cleans up its registrations.

- **Rust visibility enforces boundaries.** `core::daemon` internals are `pub(crate)` — invisible to `adapters`. Adapters receive `Arc<MdnsCore>` and nothing else.

---

## Core API

The core exposes a Rust API that all adapters program against.

```rust
pub struct MdnsCore {
    // Owns: ServiceDaemon, in-memory registry, broadcast event bus
}

impl MdnsCore {
    /// Start browsing for services of the given type.
    /// Returns a handle that yields ServiceEvent values.
    pub fn browse(&self, service_type: &str) -> Result<BrowseHandle>

    /// Register a service on the local network via mDNS.
    /// Returns registration details and lease metadata.
    pub fn register(&self, payload: RegisterPayload) -> Result<RegistrationResult>

    /// Unregister a previously registered service.
    /// Sends mDNS goodbye packets.
    pub fn unregister(&self, id: &str) -> Result<()>

    /// Resolve a specific service instance by its full name.
    pub fn resolve(&self, instance: &str) -> Result<ServiceRecord>

    /// Subscribe to all service events across all active browses.
    /// Returns a broadcast receiver for fan-out.
    pub fn subscribe(&self) -> broadcast::Receiver<MdnsEvent>
}
```

### Domain types

```rust
/// Canonical service representation used across browse/resolve/events.
pub struct ServiceRecord {
  pub name: String,
  pub service_type: String,   // "_http._tcp"
  pub host: Option<String>,   // "server-01.local"
  pub ip: Option<String>,     // "192.168.1.42"
  pub port: Option<u16>,
  pub txt: HashMap<String, String>,
}

/// Request to register a new service.
pub struct RegisterPayload {
  pub name: String,           // "My Web Server"
  pub service_type: String,   // "_http._tcp"
  pub port: u16,              // 8080
  pub ip: Option<String>,
  pub lease_secs: Option<u64>,
  pub txt: HashMap<String, String>,
}

/// Result of a successful registration.
pub struct RegistrationResult {
  pub id: String,
  pub name: String,
  pub service_type: String,
  pub port: u16,
  pub mode: LeaseMode,
  pub lease_secs: Option<u64>,
}

/// Result of a successful lease renewal (heartbeat).
pub struct RenewalResult {
  pub id: String,
  pub lease_secs: u64,
}

/// How a registration stays alive (wire representation).
pub enum LeaseMode {
  Session,
  Heartbeat,
  Permanent,
}

/// Events emitted by browse and subscribe operations.
pub enum EventKind {
  Found,
  Resolved,
  Removed,
}
```

---

## JSON Wire Protocol

All three adapters share the same JSON protocol. The top-level key is the verb — no envelopes, no `{"action": "...", "params": {...}}` indirection. The JSON _is_ the intent.

### Browse

Discover services of a given type. Browse is a stream — results arrive as they're discovered on the network. The stream stays open until the caller disconnects.

```json
→ { "browse": "_http._tcp" }

← { "found": {
     "name": "My Web Server",
     "type": "_http._tcp",
     "host": "server-01.local",
     "ip": "192.168.1.42",
     "port": 8080,
     "txt": { "path": "/api", "version": "2.1" }
   }}

← { "found": {
     "name": "Office Printer",
     "type": "_http._tcp",
     "host": "printer.local",
     "ip": "192.168.1.50",
     "port": 80,
     "txt": {}
   }}
```

### Register

Advertise a service on the local network. Returns an opaque `id` for lifecycle management.

The optional `ip` field pins the mDNS A record to a specific address. When omitted, all machine IPs are advertised (auto-detect).

```json
→ { "register": {
     "name": "My App",
     "type": "_http._tcp",
     "port": 8080,
     "ip": "192.168.1.42",
     "txt": { "version": "1.0", "env": "prod" }
   }}

← { "registered": {
     "id": "a1b2c3",
     "name": "My App",
     "type": "_http._tcp",
     "port": 8080
   }}
```

### Unregister

Remove a previously registered service. Triggers mDNS goodbye packets.

```json
→ { "unregister": "a1b2c3" }

← { "unregistered": "a1b2c3" }
```

### Resolve

Look up full details for a specific service instance by its DNS-SD instance name.

```json
→ { "resolve": "My Web Server._http._tcp.local." }

← { "resolved": {
     "name": "My Web Server",
     "type": "_http._tcp",
     "host": "server-01.local",
     "ip": "192.168.1.42",
     "port": 8080,
     "txt": { "path": "/api", "version": "2.1" }
   }}
```

### Subscribe

Stream all lifecycle events for a service type. Unlike browse, subscribe includes removal events.

```json
→ { "subscribe": "_http._tcp" }

← { "event": "found",    "service": { "name": "...", "type": "...", ... }}
← { "event": "resolved", "service": { "name": "...", "type": "...", ... }}
← { "event": "removed",  "service": { "name": "...", "type": "..." }}
```

Event names map to `mdns-sd`'s `ServiceEvent` variants:

| Event | Meaning |
|---|---|
| `found` | Service instance discovered (may be partially resolved) |
| `resolved` | Service fully resolved with IP, port, and TXT records |
| `removed` | Service is no longer available (goodbye packet or TTL expiry) |

### Errors

Consistent shape across all operations:

```json
← { "error": "invalid_type", "message": "Service type must be _name._tcp or _name._udp" }
← { "error": "not_found", "message": "No registration with id 'xyz'" }
← { "error": "resolve_timeout", "message": "Could not resolve My Web Server._http._tcp.local. within 3s" }
```

---

## Pipeline Properties

Pipeline properties are operational metadata attached to responses by the adapter pipeline. They are **not** part of the core domain objects — the core returns pure service records. The pipeline decorates with status, warnings, and errors only when there is something to communicate.

**Their absence is the happy path.** A response with no pipeline properties means everything succeeded cleanly.

### Properties

| Property | Values | Meaning |
|---|---|---|
| `status` | `"ongoing"` / `"finished"` | Whether more data is expected for this result |
| `warning` | Free-form string | Operation succeeded but something is noteworthy |
| `error` | Error code string | Operation failed |
| `message` | Free-form string | Human-readable description (accompanies `error`) |

### Examples

**Clean result — no pipeline properties needed:**

```json
← { "found": { "name": "Server A", "type": "_http._tcp",
               "host": "server.local", "ip": "192.168.1.42",
               "port": 8080, "txt": { "version": "2.1" }}}
```

**Partially resolved — more data coming:**

```json
← { "found": { "name": "Server B", "type": "_http._tcp",
               "host": "server.local", "port": 8080 },
    "status": "ongoing" }

← { "found": { "name": "Server B", "type": "_http._tcp",
               "host": "server.local", "ip": "192.168.1.42",
               "port": 8080, "txt": { "version": "2.1" }},
    "status": "finished" }
```

**Succeeded with warning:**

```json
← { "found": { "name": "Flaky Printer", "type": "_ipp._tcp",
               "host": "printer.local", "port": 631 },
    "status": "finished",
    "warning": "TXT records empty" }
```

**Failed:**

```json
← { "error": "resolve_timeout",
    "message": "Could not resolve My Web Server._http._tcp.local. within 3s" }
```

### Consumer logic

```
if "error"   → something broke
if "status"  → "ongoing" means keep listening; "finished" means done
if "warning" → succeeded, but read this
if none      → clean result, move on
```

---

## HTTP Adapter

The HTTP adapter translates REST semantics to core API calls using Axum.

### Endpoints

| Method | Path | Core operation | Response |
|---|---|---|---|
| `GET` | `/v1/mdns/browse?type=_http._tcp` | `browse()` | SSE stream of `found` events |
| `POST` | `/v1/mdns/services` | `register()` | JSON `registered` response |
| `DELETE` | `/v1/mdns/services/{id}` | `unregister()` | JSON `unregistered` response |
| `PUT` | `/v1/mdns/services/{id}/heartbeat` | `heartbeat()` | JSON `renewed` response |
| `GET` | `/v1/mdns/resolve?name={instance}` | `resolve()` | JSON `resolved` response |
| `GET` | `/v1/mdns/events?type=_http._tcp` | `subscribe()` | SSE stream of lifecycle events |
| `GET` | `/v1/status` | — | Unified capability status |
| `POST` | `/v1/admin/shutdown` | — | Initiate graceful shutdown |
| `GET` | `/healthz` | — | `"OK"` |

### SSE streaming

Browse and subscribe endpoints use [Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events). Each event is a JSON line:

```
GET /v1/mdns/browse?type=_http._tcp
Accept: text/event-stream

data: {"found": {"name": "Server A", "type": "_http._tcp", ...}}

data: {"found": {"name": "Server B", "type": "_http._tcp", ...}, "status": "ongoing"}

data: {"found": {"name": "Server B", "type": "_http._tcp", ...}, "status": "finished"}
```

Each SSE event includes an `id` field (UUID v7) to support client resume tracking.

### Default port

Koi's HTTP adapter defaults to port **5641** (configurable via `--port` or `KOI_PORT`). The port number spells "KOI" on a phone keypad (K=5, O=6, I=4).

### CORS

CORS is enabled by default for browser-based consumers.

---

## Named Pipe / Unix Domain Socket Adapter

The IPC adapter provides zero-network-overhead local access using the platform's native IPC mechanism.

| Platform | Transport | Path |
|---|---|---|
| Windows | Named Pipe | `\\.\pipe\koi` |
| Linux / macOS | Unix Domain Socket | `/var/run/koi.sock` or `$XDG_RUNTIME_DIR/koi.sock` |

### Protocol

Newline-delimited JSON (NDJSON). Each message is a single JSON object terminated by `\n`. The same request/response shapes as the wire protocol:

```
→ {"browse": "_http._tcp"}\n
← {"found": {"name": "Server A", ...}}\n
← {"found": {"name": "Server B", ...}}\n
```

Streaming operations (browse, subscribe) keep the pipe open and write events as they arrive. Request-response operations (register, unregister, resolve) write one response and the caller can send the next request.

---

## CLI Adapter

The CLI adapter reads JSON from stdin and writes JSON to stdout. It's the same NDJSON protocol as the pipe adapter, but over standard streams.

```bash
# Browse (streams until interrupted)
echo '{"browse": "_http._tcp"}' | koi

# Register
echo '{"register": {"name": "My App", "type": "_http._tcp", "port": 8080}}' | koi

# Resolve
echo '{"resolve": "My App._http._tcp.local."}' | koi

# Pipe through jq for pretty output
echo '{"browse": "_http._tcp"}' | koi | jq '.found.name'
```

The CLI adapter activates when Koi detects stdin is a pipe (not a terminal). When stdin is a terminal and no `--daemon` flag is set, Koi starts in daemon mode with the HTTP and IPC adapters.

---

## Service Record Schema

The canonical representation of a discovered or registered service:

```json
{
  "name": "My Web Server",
  "type": "_http._tcp",
  "host": "server-01.local",
  "ip": "192.168.1.42",
  "port": 8080,
  "txt": {
    "path": "/api",
    "version": "2.1"
  }
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Human-readable instance name |
| `type` | string | yes | DNS-SD service type (`_name._tcp` or `_name._udp`) |
| `host` | string | no | Hostname (e.g. `server.local`). Present after discovery. |
| `ip` | string | no | IPv4 or IPv6 address. May be absent if unresolved. |
| `port` | integer | no | Service port number. May be absent in browse events. |
| `txt` | object | yes | TXT record key-value pairs. Empty object `{}` if none. |

*`host` is typically present in browse/resolve responses but is not required in register requests (Koi uses the machine's hostname).

---

## Container Access Pattern

The primary deployment model for Koi is as a host service that containers reach via HTTP. This solves the fundamental Docker-mDNS incompatibility at the infrastructure level.

### The problem

Docker's default bridge network does not forward UDP multicast. Containers on `docker0` never see mDNS traffic from the physical LAN, and their multicast announcements never leave the bridge. This isn't a bug — Docker's bridge is a Layer 3 NAT construct, not a true Layer 2 bridge.

Existing workarounds all sacrifice something:

| Workaround | Sacrifice |
|---|---|
| `--network=host` | Loses container network isolation entirely |
| `macvlan` | Linux-only, no host↔container connectivity, no Docker Desktop support |
| mDNS reflectors | Fragile, require `--privileged`, add moving parts |
| Avahi inside container | Heavy images, D-Bus socket mounting, per-container setup |

### The Koi solution

Koi runs on the host as a system service. It participates in mDNS on the physical network via multicast UDP. It exposes that capability as an HTTP API on a TCP port. Containers reach the host via the standard Docker gateway:

```
┌─────────────────────────────────────────────────────────┐
│  Host                                                   │
│                                                         │
│  ┌──────────┐    multicast     ┌──────────────────┐     │
│  │   Koi    │◄────UDP 5353────►│  Physical LAN    │     │
│  │  daemon  │                  │  (printers, IoT, │     │
│  │          │    TCP 5641      │   other hosts)   │     │
│  │  HTTP API│◄──────┐         └──────────────────┘     │
│  └──────────┘       │                                   │
│                     │ http://172.17.0.1:5641             │
│  ┌──────────────────┴──────────────────────────────┐    │
│  │  Docker bridge (docker0)                        │    │
│  │                                                  │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐   │    │
│  │  │ Container │  │ Container │  │ Container │   │    │
│  │  │     A     │  │     B     │  │     C     │   │    │
│  │  └───────────┘  └───────────┘  └───────────┘   │    │
│  └──────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Container access methods

| Docker environment | HTTP access | IPC access (zero network overhead) |
|---|---|---|
| Docker Desktop (Mac/Windows) | `host.docker.internal:5641` | Named pipe mount (Windows) |
| Docker Engine (Linux) | `172.17.0.1:5641` (default gateway) | `-v /var/run/koi.sock:/var/run/koi.sock` |
| Docker Compose | `host.docker.internal` with `extra_hosts` | Volume mount the socket |
| Kubernetes (host network pods) | `localhost:5641` | `hostPath` volume |

The socket mount option is significant — it gives containers mDNS access with zero TCP overhead and no exposed ports. The container writes JSON to the socket; Koi speaks multicast on the physical network. The container never needs network access to the host at all.

### What containers can do through Koi

**Browse** — Discover services on the physical LAN that the container cannot reach via multicast:
```bash
# Inside a container: find all printers on the office network
curl http://172.17.0.1:5641/v1/mdns/browse?type=_ipp._tcp
```

**Register** — Advertise a containerized service on the LAN so non-container devices can find it:
```bash
# Inside a container: announce a web service to the LAN
curl -X POST http://172.17.0.1:5641/v1/mdns/services \
  -d '{"name": "My App", "type": "_http._tcp", "port": 8080}'
```

This makes the containerized service visible to mDNS browsers on the physical network — phones, desktops, IoT devices — without any Docker networking workarounds.

**Subscribe** — Stream real-time service events for dynamic service mesh behavior:
```bash
# Inside a container: watch for new services appearing on the LAN
curl http://172.17.0.1:5641/v1/mdns/events?type=_http._tcp
```

### Docker Compose examples

**Via HTTP (simplest):**
```yaml
services:
  my-app:
    image: my-app:latest
    environment:
      KOI_ENDPOINT: "http://host.docker.internal:5641"
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

**Via socket mount (zero network overhead):**
```yaml
services:
  my-app:
    image: my-app:latest
    environment:
      KOI_SOCKET: "/var/run/koi.sock"
    volumes:
      - /var/run/koi.sock:/var/run/koi.sock
```

The socket approach is ideal for high-frequency discovery or latency-sensitive applications. The HTTP approach requires no volume mounts and works identically across Docker Desktop and Docker Engine.

---

## Platform Integration

### Windows Service

Koi registers as a Windows service via the `windows-service` crate, integrating with the Service Control Manager (SCM).

```
Service Name: koi
Display Name: Koi mDNS Service
Startup Type: Automatic
```

Install/uninstall:

```powershell
koi.exe install
koi.exe uninstall
```

### systemd (Linux)

```ini
[Unit]
Description=Koi mDNS Service
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/koi --daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Configuration

Koi is configured via CLI flags and environment variables. CLI flags take precedence.

| Setting | Flag | Env var | Default |
|---|---|---|---|
| HTTP port | `--port` | `KOI_PORT` | `5641` |
| Pipe/socket path | `--pipe` | `KOI_PIPE` | Platform default |
| Log level | `--log-level` | `KOI_LOG` | `info` |
| Verbosity | `-v`, `-vv` | — | off |
| Log file | `--log-file` | `KOI_LOG_FILE` | — |
| Disable HTTP | `--no-http` | `KOI_NO_HTTP` | `false` |
| Disable IPC | `--no-ipc` | `KOI_NO_IPC` | `false` |
| Disable mDNS | `--no-mdns` | `KOI_NO_MDNS` | `false` |
| Disable Certmesh | `--no-certmesh` | `KOI_NO_CERTMESH` | `false` |
| Disable DNS | `--no-dns` | `KOI_NO_DNS` | `false` |
| Disable Health | `--no-health` | `KOI_NO_HEALTH` | `false` |
| Disable Proxy | `--no-proxy` | `KOI_NO_PROXY` | `false` |
| DNS port | `--dns-port` | `KOI_DNS_PORT` | `53` |
| DNS zone | `--dns-zone` | `KOI_DNS_ZONE` | `lan` |
| DNS public | `--dns-public` | `KOI_DNS_PUBLIC` | `false` |

`config.toml` is created in the Koi data directory for proxy entries, but there is no global `--config` flag yet.

---

## Project Structure

Koi v0.2 is a multi-crate Cargo workspace:

```
crates/
├── koi/                # Binary crate — CLI entry, wiring, adapters
│   └── src/
│       ├── main.rs           # Orchestrator: CLI parse, routing, daemon wiring, shutdown
│       ├── cli.rs            # clap definitions (Cli, Command, Config)
│       ├── client.rs         # KoiClient (ureq HTTP client for client/admin mode)
│       ├── format.rs         # All human-readable CLI output
│       ├── admin.rs          # Admin command execution
│       ├── commands/
│       │   ├── mod.rs        # Shared helpers (detect_mode, run_streaming, etc.)
│       │   ├── mdns.rs       # mDNS commands (discover, announce, etc.)
│       │   ├── certmesh.rs   # Certmesh commands (create, join, etc.)
│       │   └── status.rs     # Unified status command
│       ├── adapters/
│       │   ├── http.rs       # HTTP server (Axum router, health, status)
│       │   ├── pipe.rs       # Named pipe (Windows) / UDS (Unix) adapter
│       │   ├── cli.rs        # stdin/stdout NDJSON adapter
│       │   └── dispatch.rs   # Shared NDJSON dispatch logic
│       └── platform/
│           ├── windows.rs    # Windows Service (SCM), firewall, paths
│           ├── unix.rs       # systemd, paths
│           └── macos.rs      # launchd, paths
├── koi-common/         # Shared kernel — types, errors, pipeline, id
├── koi-mdns/           # mDNS domain — core, daemon, registry, protocol, http
├── koi-config/         # Config & state — breadcrumb discovery
├── koi-certmesh/       # Certificate mesh — CA, enrollment, roster
├── koi-crypto/         # Cryptographic primitives — key gen, TOTP
└── koi-truststore/     # Trust store — platform cert installation
```

The `platform/` module is the only location with `#[cfg(target_os)]` conditional compilation. Everything else is pure cross-platform Rust. Domain crates depend on `koi-common` but never on each other.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `mdns-sd` | mDNS/DNS-SD engine (pure Rust, no OS dependencies) |
| `axum` | HTTP server |
| `tokio` | Async runtime |
| `serde` / `serde_json` | JSON serialization |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |
| `windows-service` | Windows SCM integration (Windows only) |
| `flume` | Channels (transitive via mdns-sd) |

The total dependency footprint is deliberately minimal. No protobuf, no D-Bus, no OpenSSL.

---

## RFC Compliance

Koi delegates mDNS protocol handling to the `mdns-sd` crate, which implements:

| Feature | RFC | Status |
|---|---|---|
| Multicast DNS | [RFC 6762](https://tools.ietf.org/html/rfc6762) | ✅ |
| DNS-Based Service Discovery | [RFC 6763](https://tools.ietf.org/html/rfc6763) | ✅ |
| DNS wire format | [RFC 1035](https://tools.ietf.org/html/rfc1035) | ✅ |
| Known-Answer Suppression | RFC 6762 §7.1 | ✅ |
| Probing and announcing | RFC 6762 §8.1 | ✅ |
| Conflict resolution | RFC 6762 §9 | ✅ |
| Goodbye packets | RFC 6762 §10.1 | ✅ |
| Cache-flush bit | RFC 6762 §10.2 | ✅ |
| Unicast responses | RFC 6762 §5.4 | ❌ Not supported |

The unicast limitation is irrelevant for Koi's use case — all discovery is multicast-based.

---

## Design Decisions

### Host service as the container mDNS bridge

Koi's primary deployment model is as a system service on the host. This is not incidental — it's the architectural answer to Docker's multicast blindness. Docker's bridge network is a Layer 3 NAT construct that doesn't forward UDP multicast. No amount of container-side configuration fixes this without sacrificing isolation. By running Koi on the host where multicast works natively, and exposing its capabilities over HTTP (TCP) and Unix domain sockets, containers gain full mDNS access through transports that Docker handles perfectly. The host service is the bridge between the multicast world of the LAN and the unicast world inside Docker's network namespace.

### Single shared daemon, not per-browse instances

Multiple callers browsing `_http._tcp` share one multicast listener. This mirrors the architecture of Apple's `mDNSResponder` — a single system daemon that multiplexes for all applications — without requiring a system service. The core manages subscription fan-out internally.

### Verb-oriented JSON, not envelope-based

Request and response types are identified by their top-level key (`browse`, `found`, `register`, `registered`), not by a wrapper like `{"action": "browse", "params": {...}}`. This makes messages self-describing and parseable at a glance.

### Pipeline properties as optional metadata

Status, warnings, and errors are operational concerns added by the pipeline, not part of the core domain model. The core returns pure service records. The pipeline decorates only when necessary. Absence means success.

### Adapters share protocol, not code

The HTTP, IPC, and CLI adapters all speak the same JSON shapes but don't share adapter code. Each is a thin, independent module (~150 lines) that maps its transport to core API calls. This keeps each adapter simple enough to read in one sitting.

### Port 5641 — "KOI" on a phone keypad

Koi's HTTP adapter defaults to TCP port 5641 (K=5, O=6, I=4, plus a `1` suffix). The port is IANA-unassigned, sits comfortably in the registered range (1024–49151), and is easy to remember.

### Explicitly deferred

The following were considered and deliberately excluded from v1:

- **gRPC** — Heavy dependency, target audience doesn't want stub generation for simple discovery
- **WebSocket** — SSE already covers server-push; bidirectional not needed
- **D-Bus** — Linux-only, the whole point is cross-platform simplicity
- **mDNS reflection/proxying** — Scope creep; Koi translates mDNS to API, not mDNS to mDNS
- **Wide Area Bonjour** — Unicast DNS integration deferred
- **Plugin system** — Keep it razor-thin

---

**Document Status:** Current
**Last Updated:** 2026-02-11
