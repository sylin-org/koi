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
│                                                       koi-udp    koi-runtime
│                                                       UdpRuntime RuntimeCore
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
| `crates/koi/`             | `koi-net`         | Binary - CLI entry, command dispatch, platform/service, wiring (serving moved to koi-serve) | ~12,400|
| `crates/koi-common/`      | `koi-common`      | Types-only kernel - types, errors, pipeline, ceremony engine       | ~3,122 |
| `crates/koi-compose/`     | `koi-compose`     | Composition root - `build_cores`, `Cores`/`DaemonCores`, `ordered_shutdown`, orchestrator, capability ladder, certmesh background loops, self-announce, integration bridges | ~1,900 |
| `crates/koi-serve/`       | `koi-serve`       | Serving layer - the one HTTP/OpenAPI router (`HttpConfig` + `start`), `serve()`, IPC pipe + piped stdio (NDJSON), in-process MCP HTTP, inter-node mTLS + ACME listeners, Prometheus SD, dashboard wiring, posture-reactive trust plane | ~3,600 |
| `crates/koi-dashboard/`   | `koi-dashboard`   | Presentation - dashboard + mDNS browser (HTML, SSE, forwarder, lazy meta-browse) | ~1,345 |
| `crates/koi-mdns/`        | `koi-mdns`        | mDNS domain - daemon, registry, protocol, HTTP routes              | ~3,662 |
| `crates/koi-certmesh/`    | `koi-certmesh`    | Certificate mesh - CA, enrollment, roster, failover                | ~12,162|
| `crates/koi-crypto/`      | `koi-crypto`      | Crypto primitives - keys, TOTP, auth adapters, unlock slots        | ~3,162 |
| `crates/koi-config/`      | `koi-config`      | Config, state, breadcrumb discovery                                | ~574   |
| `crates/koi-dns/`         | `koi-dns`         | Local DNS resolver - zone, resolution, rate limiting               | ~1,931 |
| `crates/koi-health/`      | `koi-health`      | Health monitoring - HTTP/TCP checks, transitions                   | ~1,041 |
| `crates/koi-proxy/`       | `koi-proxy`       | TLS-terminating reverse proxy - cert reload, forwarding            | ~1,656 |
| `crates/koi-client/`      | `koi-client`      | Blocking HTTP client for daemon communication (ureq)               | ~754   |
| `crates/koi-embedded/`    | `koi-embedded`    | In-process facade - builder, handles, events                       | ~3,221 |
| `crates/koi-udp/`         | `koi-udp`         | UDP datagram bridging - bind, relay, lease reaper, HTTP routes     | ~689   |
| `crates/koi-runtime/`     | `koi-runtime`     | Container/service runtime adapter - Docker/Podman lifecycle events | ~1,964 |
| `crates/koi-mcp/`         | `koi-mcp`         | MCP server (stdio + in-process Streamable HTTP) - exposes the LAN substrate to AI agents | ~1,452 |

---

## Dependency graph

```
koi (bin)        → koi-serve, koi-compose, koi-common, koi-mcp, koi-client (+ axum, clap, tokio)
koi-embedded     → koi-serve, koi-compose, koi-common, koi-client (+ axum, reqwest, tokio)
└── koi-serve    → koi-compose, koi-dashboard, koi-mcp, koi-common, koi-config,
    │              koi-mdns, koi-certmesh, koi-dns, koi-health, koi-proxy, koi-udp, koi-runtime
    │             (the serving layer: the one HTTP/OpenAPI router + serve(), IPC/stdio NDJSON,
    │              in-process MCP HTTP, inter-node mTLS + ACME listeners, Prometheus SD,
    │              dashboard wiring, the posture-reactive trust plane)
    └── koi-compose  → koi-common, koi-config, koi-crypto, koi-dashboard, koi-client,
        │             koi-mdns, koi-certmesh, koi-dns, koi-health, koi-proxy, koi-udp, koi-runtime
        │            (the composition root: build_cores, Cores/DaemonCores, ordered_shutdown,
        │             orchestrator, capability ladder, certmesh loops, self-announce, bridges)
        ├── koi-common
        ├── koi-mdns        → koi-common, mdns-sd, axum, tokio
        ├── koi-certmesh    → koi-common, koi-crypto, os-truststore (external, crates.io), axum, tokio
        ├── koi-crypto      → ring, rcgen, totp-rs, p256
        ├── koi-config      → koi-common
        ├── koi-dns         → koi-common, koi-config, hickory-server, hickory-resolver, axum, tokio
        ├── koi-health      → koi-common, koi-config, axum, tokio
        ├── koi-proxy       → koi-common, koi-config, axum, tokio-rustls, rustls, rcgen, tokio
        ├── koi-udp         → koi-common, axum, tokio
        ├── koi-runtime     → koi-common, bollard, axum, utoipa, tokio, chrono
        ├── koi-client      → koi-common, ureq (blocking)
        └── koi-dashboard   → koi-common, koi-mdns, koi-certmesh, koi-dns, koi-health, koi-proxy, koi-runtime, axum, tokio

koi-mcp          → koi-common, koi-client, koi-config, rmcp (+ transport-streamable-http-server), thiserror, async-trait, tokio
```

Terminal-profile-aware help rendering lives in the binary's `crates/koi/src/help/`
module, not a separate workspace crate.

`koi-mcp` still depends on **no domain crate** — the in-process Streamable HTTP transport
serves MCP resources against the live cores via a `CoreSource` bridge that lives in
`koi-serve` (`koi_serve::mcp_http`), not in `koi-mcp` itself.

**Domain** crates depend on `koi-common` but **never on each other**. Cross-domain wiring
happens in `koi-compose` — the **composition root** that constructs the cores
(`build_cores` → `Cores`, re-exported by the binary as `DaemonCores`), installs the
integration bridges, runs the orchestrator + certmesh background loops, assembles the
capability ladder, and tears everything down via `ordered_shutdown`. Above it, **`koi-serve`**
is the **serving layer**: it owns every transport (the one HTTP/OpenAPI router + `serve()`,
IPC and piped-stdio NDJSON, the in-process MCP HTTP transport, the inter-node mTLS + ACME
listeners, Prometheus SD, and the dashboard wiring) plus the posture-reactive trust plane.
`serve(cores, ServeConfig, cancel, tasks)` spawns the whole stack into a shared task set;
each consumer owns only its lifecycle edge (the daemon blocks on a signal, the Windows
service reports SCM status, `koi-embedded` returns a non-blocking handle). Building the
composition once is what keeps the `koi` daemon, the Windows service, and `koi-embedded` at
parity by construction. `koi-dashboard` is a **presentation** crate (not a domain): it
depends on the event-bearing domain crates so the event forwarder + mDNS browse adapter
exist once, shared by the composition layer's consumers. Because nothing depends on
`koi-compose` or `koi-dashboard` except the top-level consumers (`koi`, `koi-embedded`),
the kernel and domain closures stay clean.
`koi-common` is **types-only** — the dashboard/browser presentation deps (`tokio`,
`tokio-stream`, `tokio-util`, `async-stream`, `hostname`) moved to `koi-dashboard` in P06.

---

## Boundary rules

**Adapters are pure translation.** An adapter maps a transport to core API calls. Each adapter is roughly 150 lines. They don't contain domain logic, validation, or state management.

**Core owns the registry.** All registered services, the per-type browse hub (one real mDNS browse per type, reference-counted broadcast fan-out to N subscriptions), and subscription fan-out live in the core. If an adapter disconnects, the core cleans up.

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
├── main.rs          # CLI entry point and top-level execution routing
├── cli.rs           # clap definitions (Cli, Command, Config)
├── daemon.rs        # Daemon-mode bring-up: pre-serve setup + koi_serve::serve + the lifecycle edge
├── dispatch.rs      # Top-level command dispatch (subcommand → handler routing)
├── infra.rs         # Infrastructure wiring (logging, signals, runtime setup)
├── integrations.rs  # Re-export shim for koi-compose's integration bridges (live in koi-compose)
├── client.rs        # client utility wrappers
├── format.rs        # All human-readable CLI output
├── admin.rs         # Admin command execution
├── commands/
│   ├── mod.rs            # Shared helpers (detect_mode, run_streaming, print_json)
│   ├── mdns.rs          # mDNS commands
│   ├── certmesh.rs      # Certmesh commands
│   ├── ceremony_cli.rs  # Generic ceremony render loop
│   ├── dns.rs           # DNS commands
│   ├── health.rs        # Health commands
│   ├── proxy.rs         # Proxy commands
│   ├── udp.rs           # UDP commands
│   ├── trust.rs         # `koi trust` (OS trust store install/list/remove/export/diagnose)
│   ├── mcp.rs           # `koi mcp serve` (stdio MCP server launch)
│   ├── token.rs         # `koi token` (daemon access token show/write)
│   ├── factory_reset.rs # `koi factory-reset` (destroy all Koi data)
│   └── status.rs        # Unified status command
│                        # (transport adapters + the trust plane moved to the koi-serve
│                        #  crate; the binary calls koi_serve::serve — see daemon.rs)
├── help/                # Terminal-profile-aware help rendering + command/API metadata
└── platform/
    ├── windows.rs   # Windows Service (SCM), firewall rules, registry access
    ├── unix.rs      # systemd integration, Unix service paths
    └── macos.rs     # launchd integration, macOS service paths
```

> Note: The transport adapters (the HTTP router, IPC pipe, piped stdio, MCP HTTP, mTLS,
> ACME, Prometheus SD, dashboard wiring) and the posture-reactive trust plane now live in
> the **`koi-serve`** crate. The binary calls `koi_serve::serve(..)` (see `daemon.rs` and
> `platform/windows.rs`) and keeps only CLI dispatch, the piped standalone mode, help,
> install/uninstall, and the platform/service shells.
>
> Note: The single-file, zero-build HTML for the **Web dashboard** (`dashboard.html`) and
> the **mDNS browser** (`mdns-browser.html`) live as static assets in
> `crates/koi-dashboard/assets/` and are embedded into the binary at compile time. The
> mDNS browser renders dynamic (LAN-attacker-controlled) data via DOM construction
> (`createElement` + `textContent`/`dataset`) and restricts launch links to an
> `http`/`https` scheme allowlist — closing the XSS class structurally (P06).
```

Platform-conditional compilation (`#[cfg(target_os)]`) lives exclusively in `platform/`. Everything else is pure cross-platform Rust.

---

## Design principles

**One model.** There is one `ServiceRecord` type. Not a `CoreService` and an `ApiService` and an `HttpService`. This type flows everywhere - the core produces it, adapters serialize it, events carry it.

**Adapters share protocol, not code.** The HTTP, IPC, and piped-stdio adapters all speak the same JSON shapes but are independent modules in the `koi-serve` crate. The pipe and stdio adapters share NDJSON dispatch logic via `koi_serve::dispatch`.

**Runtime capability control.** All domain capabilities are compiled into one binary. Enable/disable at runtime with `--no-mdns`, `--no-certmesh`, `--no-runtime`, etc. No `#[cfg(feature)]` for domain capabilities.

**Domain facade pattern.** Every domain crate exposes an opaque facade (`MdnsCore`, `CertmeshCore`, `RuntimeCore`, etc.) with internal state hidden behind `pub(crate)`. HTTP handlers delegate to facade methods - no lock management in handlers.
