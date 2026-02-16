# Architecture

Koi is a single binary with a layered architecture. Three adapter layers sit on top of domain cores, which sit on top of engines. Adapters are thin transport translations. Cores own all domain logic. Engines are implementation details that cores wrap.

```
┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐
│  HTTP Adapter   │  │ Named Pipe / UDS │  │  CLI Adapter    │
│  (Axum + SSE)   │  │ Adapter          │  │  (stdin/stdout) │
└────────┬────────┘  └────────┬─────────┘  └────────┬────────┘
         │                    │                      │
         ▼                    ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Domain Core Layer                        │
│                                                             │
│  koi-mdns    koi-certmesh    koi-dns    koi-health    koi-proxy
│  MdnsCore    CertmeshCore    DnsCore    HealthCore    ProxyRuntime
│                                                       koi-udp
│                                                       UdpRuntime
└─────────────────────────┬───────────────────────────────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
         mdns-sd     koi-crypto   hickory-server
         (mDNS)      (ring,       (DNS)
                      rcgen)
```

---

## Crate inventory

| Crate                     | Package name      | Role                                                               | Lines  |
| ------------------------- | ----------------- | ------------------------------------------------------------------ | ------ |
| `crates/koi/`             | `koi-net`         | Binary - CLI entry, adapters, wiring                               | ~3,500 |
| `crates/koi-common/`      | `koi-common`      | Shared kernel - types, errors, pipeline, ceremony engine           | ~2,000 |
| `crates/koi-mdns/`        | `koi-mdns`        | mDNS domain - daemon, registry, protocol, HTTP routes              | ~2,500 |
| `crates/koi-certmesh/`    | `koi-certmesh`    | Certificate mesh - CA, enrollment, roster, failover                | ~4,500 |
| `crates/koi-crypto/`      | `koi-crypto`      | Crypto primitives - keys, TOTP, FIDO2, auth adapters, unlock slots | ~2,500 |
| `crates/koi-truststore/`  | `koi-truststore`  | Platform trust store installation                                  | ~400   |
| `crates/koi-config/`      | `koi-config`      | Config, state, breadcrumb discovery                                | ~600   |
| `crates/koi-dns/`         | `koi-dns`         | Local DNS resolver - zone, resolution, rate limiting               | ~1,500 |
| `crates/koi-health/`      | `koi-health`      | Health monitoring - HTTP/TCP checks, transitions                   | ~1,000 |
| `crates/koi-proxy/`       | `koi-proxy`       | TLS-terminating reverse proxy - cert reload, forwarding            | ~800   |
| `crates/koi-client/`      | `koi-client`      | Blocking HTTP client for daemon communication (ureq)               | ~650   |
| `crates/koi-embedded/`    | `koi-embedded`    | In-process facade - builder, handles, events                       | ~1,300 |
| `crates/koi-udp/`         | `koi-udp`         | UDP datagram bridging - bind, relay, lease reaper, HTTP routes     | ~500   |
| `crates/command-surface/` | `command-surface` | Glyph-based command rendering, semantic metadata                   | ~500   |

---

## Dependency graph

```
koi (bin)
├── koi-common
├── koi-mdns        → koi-common, mdns-sd, axum, tokio
├── koi-certmesh    → koi-common, koi-crypto, koi-truststore, axum, tokio
├── koi-crypto      → ring, rcgen, totp-rs, p256
├── koi-truststore  → platform cert APIs
├── koi-config      → koi-common
├── koi-dns         → koi-common, koi-config, hickory-server, hickory-resolver, axum, tokio
├── koi-health      → koi-common, koi-config, axum, tokio
├── koi-proxy       → koi-common, koi-config, axum-server, rustls, reqwest, tokio
├── koi-udp         → koi-common, axum, tokio
├── koi-client      → koi-common, ureq (blocking)
├── koi-embedded    → koi-common, koi-mdns, koi-certmesh, koi-dns, koi-health, koi-proxy, koi-udp, koi-config, tokio
└── command-surface → crossterm
```

Domain crates depend on `koi-common` but **never on each other**. Cross-domain wiring happens exclusively in the binary crate.

---

## Boundary rules

**Adapters are pure translation.** An adapter maps a transport to core API calls. Each adapter is roughly 150 lines. They don't contain domain logic, validation, or state management.

**Core owns the registry.** All registered services, active browse handles, and subscription fan-out live in the core. If an adapter disconnects, the core cleans up.

**Rust visibility enforces boundaries.** Domain internals are `pub(crate)` - invisible to adapters. Adapters receive `Arc<DomainCore>` and nothing else.

**The mdns-sd boundary.** `crates/koi-mdns/src/daemon.rs` is the only file that imports `mdns_sd`. Nowhere else. The conversion from `mdns_sd::ServiceInfo` to `ServiceRecord` lives in one place.

---

## Execution modes

| Mode           | Detection                         | Core owner       | Transport           |
| -------------- | --------------------------------- | ---------------- | ------------------- |
| **Daemon**     | No subcommand                     | Shared cores     | HTTP + Pipe/UDS     |
| **Standalone** | `koi mdns <cmd>` + no daemon      | Local core       | Direct              |
| **Client**     | `koi mdns <cmd>` + daemon running | KoiClient → HTTP | HTTP to daemon      |
| **Piped**      | stdin is piped                    | Local core       | NDJSON stdin/stdout |

---

## Binary crate layout

```
crates/koi/src/
├── main.rs          # Pure orchestrator - CLI parse, routing, daemon wiring, shutdown
├── cli.rs           # clap definitions (Cli, Command, Config)
├── client.rs        # KoiClient (ureq HTTP client for client mode)
├── format.rs        # All human-readable CLI output
├── admin.rs         # Admin command execution
├── openapi.rs       # OpenAPI spec generation
├── surface.rs       # Command manifest population
├── commands/
│   ├── mod.rs       # Shared helpers (detect_mode, run_streaming, print_json)
│   ├── mdns.rs      # mDNS commands
│   ├── certmesh.rs  # Certmesh commands
│   ├── ceremony_cli.rs  # Generic ceremony render loop
│   ├── dns.rs       # DNS commands
│   ├── health.rs    # Health commands
│   ├── proxy.rs     # Proxy commands
│   └── status.rs    # Unified status command
├── adapters/
│   ├── http.rs      # HTTP server (Axum router, health, status)
│   ├── pipe.rs      # Named Pipe (Windows) / UDS (Unix)
│   ├── cli.rs       # stdin/stdout NDJSON
│   └── dispatch.rs  # Shared NDJSON dispatch logic
└── platform/
    ├── windows.rs   # SCM, firewall, service paths
    ├── unix.rs      # systemd, service paths
    └── macos.rs     # launchd, service paths
```

Platform-conditional compilation (`#[cfg(target_os)]`) lives exclusively in `platform/`. Everything else is pure cross-platform Rust.

---

## Design principles

**One model.** There is one `ServiceRecord` type. Not a `CoreService` and an `ApiService` and an `HttpService`. This type flows everywhere - the core produces it, adapters serialize it, events carry it.

**Adapters share protocol, not code.** The HTTP, IPC, and CLI adapters all speak the same JSON shapes but are independent modules (~150 lines each). The pipe and CLI adapters share NDJSON dispatch logic via `adapters::dispatch`.

**Runtime capability control.** All domain capabilities are compiled into one binary. Enable/disable at runtime with `--no-mdns`, `--no-certmesh`, etc. No `#[cfg(feature)]` for domain capabilities.

**Domain facade pattern.** Every domain crate exposes an opaque facade (`MdnsCore`, `CertmeshCore`, etc.) with internal state hidden behind `pub(crate)`. HTTP handlers delegate to facade methods - no lock management in handlers.
