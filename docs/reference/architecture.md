# Architecture

Koi is a DDD-aligned modular monolith. Thin boundary adapters sit above domain
facades, which own their state, events, and invariants. Engines and platform APIs
stay behind provider ports. The composition root selects providers, wires
cross-domain reactions, and owns the one process lifecycle.

```
┌────────────────────────┐       ┌────────────────────────┐
│ HTTP / SSE / MCP       │       │ Authenticated IPC     │
│ boundary adapters      │       │ Named Pipe / UDS      │
└────────────┬───────────┘       └────────────┬───────────┘
             │                                │
             └────────────────┬───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Domain Core Layer                        │
│                                                             │
│  koi-mdns    koi-certmesh    koi-trust  koi-dns    koi-health    koi-proxy
│  MdnsCore    CertmeshCore    TrustCore  DnsCore    HealthCore    ProxyRuntime
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
| `crates/koi-common/`      | `koi-common`      | Dependency-light kernel - types, errors, status/event/runtime primitives, pipeline, ceremony engine | ~3,122 |
| `crates/koi-compose/`     | `koi-compose`     | Composition root - `build_cores`, inert `Cores` views, non-cloneable `RunningCores` lifecycle ownership, reactive `KoiStatus`, `ordered_shutdown`, orchestrator, certmesh background loops, self-announce, integration bridges | ~1,900 |
| `crates/koi-serve/`       | `koi-serve`       | Serving layer - the one HTTP/OpenAPI router, authenticated local IPC, in-process MCP HTTP, inter-node mTLS + ACME listeners, Prometheus SD, dashboard wiring, posture-reactive trust plane | ~3,600 |
| `crates/koi-dashboard/`   | `koi-dashboard`   | Presentation - dashboard + mDNS browser (HTML, SSE, forwarder, lazy meta-browse) | ~1,345 |
| `crates/koi-mdns/`        | `koi-mdns`        | mDNS domain - registry, discovery hub, provider control plane, HTTP routes | ~5,500 |
| `crates/koi-certmesh/`    | `koi-certmesh`    | Certificate mesh - CA, enrollment, roster, failover                | ~12,162|
| `crates/koi-trust/`       | `koi-trust`       | Managed OS roots - journal, platform adapter, status, events       | —      |
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
    │              koi-mdns, koi-certmesh, koi-trust, koi-dns, koi-health, koi-proxy, koi-udp, koi-runtime
    │             (the serving layer: the one HTTP/OpenAPI router + serve(), local IPC NDJSON,
    │              in-process MCP HTTP, inter-node mTLS + ACME listeners, Prometheus SD,
    │              dashboard wiring, the posture-reactive trust plane)
    └── koi-compose  → koi-common, koi-config, koi-crypto, koi-dashboard, koi-client,
        │             koi-mdns, koi-certmesh, koi-trust, koi-dns, koi-health, koi-proxy, koi-udp, koi-runtime
        │            (the composition root: build_cores, Cores/RunningCores, KoiStatusRuntime,
        │             ordered_shutdown, orchestrator, certmesh loops, self-announce, bridges)
        ├── koi-common
        ├── koi-mdns        → koi-common, mdns-sd, zbus, axum, tokio
        ├── koi-certmesh    → koi-common, koi-crypto, axum, tokio
        ├── koi-trust       → koi-common, os-truststore (external, crates.io), tokio
        ├── koi-crypto      → ring, rcgen, totp-rs, p256
        ├── koi-config      → koi-common
        ├── koi-dns         → koi-common, koi-config, hickory-server, hickory-resolver, axum, tokio
        ├── koi-health      → koi-common, koi-config, axum, tokio
        ├── koi-proxy       → koi-common, koi-config, axum, tokio-rustls, rustls, rcgen, tokio
        ├── koi-udp         → koi-common, axum, tokio
        ├── koi-runtime     → koi-common, bollard, axum, utoipa, tokio, chrono
        ├── koi-client      → koi-common, ureq (blocking)
        └── koi-dashboard   → koi-common, koi-mdns, koi-certmesh, koi-trust, koi-dns, koi-health, koi-proxy, koi-udp, koi-runtime, axum, tokio

koi-mcp          → koi-common, koi-client, koi-config, rmcp (+ transport-streamable-http-server), thiserror, async-trait, tokio
```

Terminal-profile-aware help rendering lives in the binary's `crates/koi/src/help/`
module, not a separate workspace crate.

`koi-mcp` still depends on **no domain crate** — the in-process Streamable HTTP transport
serves MCP resources against the live cores via a `CoreSource` bridge that lives in
`koi-serve` (`koi_serve::mcp_http`), not in `koi-mcp` itself.

**Domain** crates depend on `koi-common` but **never on each other**. Cross-domain wiring
happens in `koi-compose` — the **composition root** that constructs the cores
(`build_cores` → `RunningCores`, with cloneable `Cores` only as an inert domain view), installs the
integration bridges, runs the orchestrator + certmesh background loops, assembles the
reactive `KoiStatus` and its capability projection, and tears everything down via
`ordered_shutdown`. Above it, **`koi-serve`** is the **serving layer**: it owns every
transport (the one HTTP/OpenAPI router + `serve()`, authenticated local IPC, the
in-process MCP HTTP transport, and the inter-node mTLS + ACME
listeners, Prometheus SD, and the dashboard wiring) plus the posture-reactive trust plane.
`serve(&running_cores, ServeConfig, cancel)` transfers each spawned task immediately into that
one lifecycle owner; there is no caller-maintained task vector that can be dropped during
partial setup. Each consumer owns only its terminal lifecycle edge (the daemon blocks on a
signal, the Windows service reports SCM status, `koi-embedded` returns a non-blocking handle).
Building the
composition once is what keeps the `koi` daemon, the Windows service, and `koi-embedded` at
parity by construction. `koi-dashboard` is a **presentation** crate (not a domain): it
depends on the event-bearing domain crates so the event forwarder + mDNS browse adapter
exist once, shared by the composition layer's consumers. Because nothing depends on
`koi-compose` or `koi-dashboard` except the top-level consumers (`koi`, `koi-embedded`),
the kernel and domain closures stay clean.
`koi-common` is the **dependency-light kernel**. It owns shared vocabulary and small
coordination primitives (`StatusFeed` and typed event-channel construction),
but no domain model or presentation. The dashboard/browser presentation deps
(`tokio-stream`, `tokio-util`, `async-stream`, `hostname`) moved to `koi-dashboard` in P06.

---

## Boundary rules

**Adapters are pure translation.** An adapter maps a transport to core API calls. Each adapter is roughly 150 lines. They don't contain domain logic, validation, or state management.

**Domain ownership is singular.** `RegistrationRegistry` owns desired service
intent and leases. `DiscoveryHub` owns per-type browse demand, cache, and fan-out.
`MdnsControlPlane` owns route policy and synchronization. Provider sessions own
their native handles, recovery, and acknowledged teardown. `MdnsCore` coordinates
transactions across those owners without duplicating their state.

**Rust visibility enforces boundaries.** Domain internals are `pub(crate)` - invisible to adapters. Adapters receive `Arc<DomainCore>` and nothing else.

**The provider boundary.** `crates/koi-mdns/src/native.rs` is the only file that
imports `mdns_sd`; Avahi and systemd-resolved own their respective D-Bus types in
their adapter modules. Provider-native values never cross the session port.

Runtime follows the same rule: built-in Docker/Podman adapters and custom embedded
providers implement `RuntimeBackend`. `RuntimeCore::start_with_backend` admits the
provider into the normal connect, initial-snapshot, lossless observation,
reconciliation, and owned-shutdown lifecycle. Production callers cannot inject
aggregate events directly.

**The OS trust boundary.** `koi-trust` is the only domain that imports
`os-truststore`. It owns Koi-managed root intent, recovery, platform presence,
status, and events. Certmesh owns only its CA anchor; `koi-compose` reacts to that
typed desired-state projection through idempotent Trust commands.

**Persistent roots are composition inputs.** `CoreSpec.data_dir` is resolved once,
then becomes an immutable `PersistencePaths` value. Each domain receives only its
exact repository path or small path value. Domain code never rediscovers a global
state directory, so two differently rooted compositions remain isolated inside one
process.

**Readiness follows resource acquisition.** HTTP, authenticated IPC, mTLS, and ACME
listeners are acquired before their adapters report ready. Breadcrumbs, Windows SCM
state, and mDNS presence publish only after those fences and use the exact bound
endpoints. Partial acquisition rolls back as one generation; late adapter exit is an
owned lifecycle transition, not a detached task failure.

### Observable domain boundary

Every domain facade has three explicit, typed faces. They share one owner but have different
delivery guarantees:

```text
consumer ── command ──▶ domain facade ──▶ private mutable/durable model
consumer ◀─ Arc<S> ── status() / watch_status() ◀─ private StatusFeed<S>
consumer ◀─ event ── subscribe() ◀─────── typed broadcast channel
```

- **Commands** validate and mutate through facade methods.
- **Status** is a domain-owned structured snapshot. `status()` is a constant-time `Arc`
  clone; `watch_status()` immediately contains that value and then coalesces to the latest
  revision. Reads perform no I/O and expose no locks.
- **Events** report occurrences. Their typed broadcast channels are best effort, not a state
  store or durable history. A late or lagged receiver rereads status.

For persistent commands, the causal order is durable commit, status publication, semantic
event, then success response. This guarantees that an event consumer's immediate status read
contains the event's result or something newer. Each domain status has a monotonic,
process-local revision; equal/no-op projections do not advance it. See
[ADR-043](../adr/043-observable-domain-boundaries.md).

`StatusFeed<S>` centralizes only the `Arc`/Tokio `watch` mechanics. It is private inside each
facade and is not a global state service. Domain types remain in domain crates, events remain
on domain channels, and cross-domain queries/commands remain narrow `koi-common` integration
traits wired explicitly in `koi-compose`. Pond's data-only status vocabulary is placed in
`koi-common` because its behavior lives in the higher `koi-serve` layer while the lower
composition layer must retain the exact status; Pond's runtime and events remain in
`koi-serve`.

### Composition and presentation status

`koi-compose` owns `KoiStatusRuntime`, which subscribes to enabled domain statuses and
publishes the reactive `KoiStatus` aggregate. It accepts explicit, instance-scoped facts only
composition can know, such as an absent/disabled capability; there is no process-global
capability-note or override registry. `Cores` updates those private inputs directly. Pond
continues to own its desired/observed `PondStatus` feed, and `koi-serve` explicitly projects
the exact snapshot through `Cores::publish_pond_status`; `KoiStatus.domains.pond` retains it
and composition derives the Pond capability card from it. The HTTP API, CLI, dashboard, MCP,
embedded facade, and Pond derive their views from the aggregate.
`CapabilityStatus` is the small human-facing projection of authoritative structured state,
not an input to domain logic.

`RunningCores` is deliberately non-cloneable and owns all composition and presentation task
handles. Tasks may retain only an inert `Cores` clone; they cannot retain the owner that
retains their handle. Startup remains guarded until every admitted resource transfers into
that owner, and terminal shutdown is one retained transaction whose waiter may be abandoned
without detaching release work.

The aggregate may retain a domain's specialized exact projection where its bounded status is
intentionally insufficient for a product surface. `KoiStatus.domains.mdns_discovery`, for
example, carries the mDNS-owned resolved-record snapshot, while `certmesh_roster` carries the
Certmesh-owned active-member projection and `dns_catalog` carries DNS's sorted effective names
plus operator-managed entries without exposing resolver internals. Domains publish these
specialized values before their primary status, which is the causal fence composition observes.
The Prometheus SD adapter and both MCP inventory transports capture one `Arc<KoiStatus>` and
project their details from that revision. In-process MCP calls the projector directly; its
HTTP-backed source performs one authenticated `GET /v1/inventory` rather than joining domain
reads. MCP change notifications diff the same coalescing aggregate watch. These adapters have
no separate core or bridge reads and do not reinterpret membership.

Presentation-specific redaction remains an adapter responsibility. In particular, the
standalone daemon treats full certmesh status as a local/operator view protected from remote
peers, while the unauthenticated `/v1/certmesh/bootstrap` route is a minimal domain-derived
projection for enrollment. An embedded host that mounts the raw domain router owns its
transport authentication, as documented by the embedded contract. A public adapter never
keeps a second copy of either state.

---

## Execution modes

| Mode           | Selection                                      | Core owner       | Transport       |
| -------------- | ---------------------------------------------- | ---------------- | --------------- |
| **Daemon**     | Installed service or explicit `koi --daemon`   | Shared cores     | HTTP + Pipe/UDS |
| **Client**     | Capability command, local service or endpoint  | KoiClient        | HTTP to daemon  |
| **Standalone** | Explicit `--standalone`, no live local service | This invocation  | Direct          |

Capability commands never infer permission to create a second owner from a
missing or stale daemon. Without `--standalone`, they require a healthy local
service or an explicit endpoint. Explicit standalone mode is refused while the
local service is alive. With no subcommand, Koi reports status and renders its
catalog; it does not start a service implicitly.

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

> Note: The transport adapters (the HTTP router, authenticated local IPC, MCP HTTP, mTLS,
> ACME, Prometheus SD, dashboard wiring) and the posture-reactive trust plane now live in
> the **`koi-serve`** crate. The binary calls `koi_serve::serve(..)` (see `daemon.rs` and
> `platform/windows.rs`) and keeps only CLI dispatch, help, install/uninstall, and the
> platform/service shells.
>
> Note: The single-file, zero-build HTML for the **Web dashboard** (`dashboard.html`) and
> the **mDNS browser** (`mdns-browser.html`) live as static assets in
> `crates/koi-dashboard/assets/` and are embedded into the binary at compile time. The
> mDNS browser renders dynamic (LAN-attacker-controlled) data via DOM construction
> (`createElement` + `textContent`/`dataset`) and restricts launch links to an
> `http`/`https` scheme allowlist — closing the XSS class structurally (P06).

Platform-conditional compilation (`#[cfg(target_os)]`) lives exclusively in `platform/`. Everything else is pure cross-platform Rust.

---

## Design principles

**One model.** There is one `ServiceRecord` type. Not a `CoreService` and an `ApiService` and an `HttpService`. This type flows everywhere - the core produces it, adapters serialize it, events carry it.

**Adapters translate; domains decide.** HTTP and IPC use the same domain request and
response vocabulary. Transport parsing and authentication stay in their adapters;
state transitions and policy stay behind domain facades. The explicit `koi mcp
serve` process is a client of the authoritative service, not another composition.

**Failures do not become values.** Boundary decoding and host observation return
errors when required facts are unavailable. Adapters never replace a failure with an
empty collection, `false`, zero, `None`, or a guessed label that a consumer could
mistake for authoritative domain state.

**Runtime capability control.** All domain capabilities are compiled into one binary. Enable/disable at runtime with `--no-mdns`, `--no-certmesh`, `--no-runtime`, etc. No `#[cfg(feature)]` for domain capabilities.

**Domain facade pattern.** Every domain crate exposes an opaque facade (`MdnsCore`, `CertmeshCore`, `RuntimeCore`, etc.) with internal state hidden behind `pub(crate)`. HTTP handlers delegate to facade methods - no lock management in handlers.
