# Koi - Agentic Context

> **Tool-agnostic AI context.** Claude, Cursor, Copilot, and other AI assistants bootstrap from here.

---

## Before Writing Code

**Check reference docs**: `docs/reference/`

- [architecture.md](../docs/reference/architecture.md) - crate inventory, boundaries, dependency graph
- [http-api.md](../docs/reference/http-api.md) - all HTTP endpoints with request/response shapes
- [wire-protocol.md](../docs/reference/wire-protocol.md) - JSON protocol, serde patterns, service records
- [cli.md](../docs/reference/cli.md) - every command, flag, and environment variable
- [ceremony-protocol.md](../docs/reference/ceremony-protocol.md) - ceremony engine, input types, session flow
- [envelope-encryption.md](../docs/reference/envelope-encryption.md) - CA key protection, slot types
- [domain-template.md](../docs/reference/domain-template.md) - **adding a new domain crate**: crate layout, the shared `koi-common` primitives to use (`DomainRuntime`, async `Capability`, `event_channel`, `http::error_response`, `integration` traits), the per-crate conventions that stay, and the binary-side touchpoints

**Check design decisions**: `docs/adr/`

- Architecture Decision Records documenting why things are built the way they are
- **Stack canon (cross-repo)**: [../docs/adr/STACK-0001-sylin-stack-canon.md](../docs/adr/STACK-0001-sylin-stack-canon.md) — Koi is the **base layer** of the Sylin stack (Koi → Zen Garden → Koan). STACK-0001 is canon: Koi may not name, special-case, or document its consumers (the K2 vocabulary leakage), the HKDF domain-separation byte strings are **frozen** (K3, never renamed), and the contract surface is mdns/dns/certmesh/udp/truststore (the TLS proxy is excluded until tested). Do not contradict it without an upstream architect decision.

**Surface ledger (cross-repo)**: [../docs/SURFACES.md](../docs/SURFACES.md) — records which surfaces are exercised by what, when last, and what guard protects them. Its top is the **rotation contract** (binding): before a lane leaves a surface, leave a tripwire and update that surface's row (`Last exercised` → today, `Guard` → the tripwire). The `surfaces` job in `.github/workflows/ci.yml` lints that the ledger parses. Honesty rule: unknown exercise status is written `unknown since <date>`, never a guessed "works" — the proxy row reads guard `none` (truth).

---

## Critical Rules

### 1. Cargo Workspace Architecture

Koi v0.2 is a multi-crate Cargo workspace. Each domain has its own crate.

```
crates/
├── koi/              # Binary crate - CLI entry, wiring, adapters
├── koi-common/       # Shared kernel - types, errors, pipeline, id, paths, ceremony
├── koi-mdns/         # mDNS domain - core, daemon, registry, protocol, http routes
├── koi-config/       # Config & state - breadcrumb discovery
├── koi-certmesh/     # Certificate mesh domain - CA, enrollment, roster
├── koi-crypto/       # Cryptographic primitives - key gen, signing, TOTP, FIDO2, auth adapters
├── koi-dns/          # Local DNS resolver - zone management, resolution, rate limiting
├── koi-health/       # Machine & service health monitoring - HTTP/TCP checks, transitions
├── koi-proxy/        # TLS-terminating reverse proxy - cert reload, forwarding
├── koi-udp/          # UDP datagram bridging - HTTP/SSE tunneling, binding lifecycle
├── koi-runtime/      # Container/service runtime adapter - Docker, Podman lifecycle events
├── koi-client/       # HTTP client for daemon communication (blocking ureq)
├── koi-dashboard/    # Presentation - dashboard + mDNS browser (HTML, SSE, event forwarder, lazy meta-browse)
└── koi-embedded/     # Embed Koi in Rust applications - builder, handles, events
```

> Terminal-profile-aware help rendering (the former standalone `command-surface` crate)
> was folded into the binary's `crates/koi/src/help/` module in P09.

### 2. Domain Boundary Model

Each domain crate exposes three faces:

```
              ┌─────────────────────────┐
  Commands →  │        Domain           │  → Events (broadcast)
              │  (internal state machine │
  State    ←  │   hidden from outside)  │
              └─────────────────────────┘
```

- **Commands**: Methods that drive domain actions. Sync if cheap, async if needed.
- **State**: Read-only snapshots of current domain state.
- **Events**: `tokio::sync::broadcast` channel for subscribers.
- **Routes**: Each domain owns its HTTP handlers via `fn routes(state) -> axum::Router`.
- Cross-domain wiring happens in the **binary crate only**. Domain crates never import each other.

### 3. Crate Dependency Graph

```
koi (bin) → koi-common, koi-dashboard, koi-mdns, koi-certmesh, koi-crypto, koi-config, koi-dns, koi-health, koi-proxy, koi-udp, koi-runtime, koi-client, koi-embedded, os-truststore (external)
koi-mdns      → koi-common, mdns-sd, axum, utoipa, tokio
koi-certmesh  → koi-common, koi-crypto, os-truststore (external), axum, utoipa, tokio
koi-crypto    → (standalone: ring/rcgen/totp-rs/p256)
# os-truststore: platform trust-store install — spun out to the os-tools repo (ADR-019);
# consumed via a git dependency, not a workspace member.
koi-config    → koi-common
koi-dns       → koi-common, koi-config, hickory-server, hickory-resolver, axum, utoipa, tokio
koi-health    → koi-common, koi-config, axum, utoipa, tokio
koi-proxy     → koi-common, koi-config, tokio-rustls, rustls, rcgen, axum, utoipa, tokio
koi-udp       → koi-common, axum, utoipa, tokio
koi-runtime   → koi-common, bollard, axum, utoipa, tokio, chrono, async-trait
koi-client    → koi-common, ureq (blocking)
koi-dashboard → koi-common, koi-mdns, koi-certmesh, koi-dns, koi-health, koi-proxy, koi-runtime, axum, tokio
koi-embedded  → koi-common, koi-dashboard, koi-crypto, koi-mdns, koi-certmesh, koi-dns, koi-health, koi-proxy, koi-udp, koi-runtime, koi-config, koi-client, tokio
```

**Domain** crates depend on `koi-common` but **never** on each other.
`koi-dashboard` is a **composition/presentation** crate (a peer of the binary's
adapters, not a domain): it depends on the event-bearing domain crates so it can host a
single event forwarder + mDNS browse adapter. Nothing depends on it except the two
top-level consumers (`koi`, `koi-embedded`), so the kernel and domain closures stay
clean. `koi-common` is a **types-only kernel** — it carries no presentation deps
(`tokio`/`tokio-stream`/`tokio-util`/`async-stream`/`hostname` left with the dashboard in
P06); the dashboard/browser HTML, SSE, and browse cache live in `koi-dashboard`.

### 4. mdns-sd Isolation (CRITICAL)

- `crates/koi-mdns/src/daemon.rs` is the **only** file that imports `mdns-sd`
- `MdnsDaemon` wraps all mdns-sd operations behind a clean Rust API
- mdns-sd runs on a dedicated worker thread (`koi-mdns-ops`)
- Never use mdns-sd types outside `daemon.rs`

### 5. Constants Convention

- `SCREAMING_SNAKE_CASE`, co-located with the module that uses them
- Module path provides the namespace: `koi_common::id::SHORT_ID_LEN`, `http::DEFAULT_HEARTBEAT_LEASE`
- Do NOT create a centralized constants module

### 6. Error Handling

```rust
// Domain: thiserror enum (MdnsError in koi-mdns)
#[derive(Debug, thiserror::Error)]
pub enum MdnsError { ... }

// Shared: ErrorCode enum → HTTP status mapping (koi-common)
ErrorCode::NotFound → StatusCode::NOT_FOUND

// Wire: error_to_pipeline() converts domain error → pipeline response
```

### 7. Serde Patterns (CRITICAL)

```rust
// Response has custom Serialize impl - two JSON shapes:
// Wrapped: {"found": {...}}  (externally tagged)
// Flat:    {"error": "not_found", "message": "..."}  (struct fields at top level)

// PipelineResponse<B> uses #[serde(flatten)] on body
// skip_serializing_if = "Option::is_none" for pipeline properties
```

### 8. Platform-Conditional Compilation

```rust
// Windows-only: Named Pipes, SCM, firewall
#[cfg(windows)]

// Unix-only: Unix domain sockets, systemd
#[cfg(unix)]

// macOS-only: LaunchDaemon (system-wide, /Library/LaunchDaemons)
#[cfg(target_os = "macos")]
```

### 9. Runtime Capability Tunables

All domain capabilities are compiled into a **single binary**. Enable/disable at runtime:

| Flag            | Env Var             | Effect                       |
| --------------- | ------------------- | ---------------------------- |
| `--no-mdns`     | `KOI_NO_MDNS=1`     | Disable mDNS capability      |
| `--no-certmesh` | `KOI_NO_CERTMESH=1` | Disable certmesh capability  |
| `--no-dns`      | `KOI_NO_DNS=1`      | Disable DNS capability       |
| `--no-health`   | `KOI_NO_HEALTH=1`   | Disable health capability    |
| `--no-proxy`    | `KOI_NO_PROXY=1`    | Disable proxy capability     |
| `--no-udp`      | `KOI_NO_UDP=1`      | Disable UDP bridging         |
| `--no-runtime`  | `KOI_NO_RUNTIME=1`  | Disable runtime adapter      |
| `--no-http`     | `KOI_NO_HTTP=1`     | Disable the HTTP adapter     |
| `--no-ipc`      | `KOI_NO_IPC=1`      | Disable the IPC adapter      |
| `--no-mcp-http` | `KOI_NO_MCP_HTTP=1` | Disable the in-process MCP HTTP transport (`/v1/mcp`) |

Additional runtime adapter flags:

| Flag                  | Env Var          | Effect                                          |
| --------------------- | ---------------- | ----------------------------------------------- |
| `--runtime <backend>` | `KOI_RUNTIME`    | Select backend: auto, docker, podman (default: auto) |

All capabilities are **enabled by default**.

The binary crate checks `Config.no_<capability>` at three layers:

- **CLI dispatch**: `config.require_capability("mdns")?` before running any domain command
- **HTTP routes**: disabled capabilities return 503 via a fallback router
- **Daemon mode**: disabled capabilities skip core creation entirely

Domain crates are **never aware** of this mechanism - the binary crate is the sole orchestrator.

Do NOT use `#[cfg(feature = "...")]` for domain capabilities. Platform-conditional compilation (`#[cfg(windows)]`, `#[cfg(unix)]`, `#[cfg(target_os)]`) remains appropriate for genuinely platform-specific code.

---

## Verification Commands

After making changes, run:

```bash
cargo check
cargo test
cargo clippy -- -D warnings
```

---

## Execution Modes

Koi operates in four modes - understand which one your change affects:

| Mode           | Detection                            | Core Owner          | Transport           |
| -------------- | ------------------------------------ | ------------------- | ------------------- |
| **Daemon**     | No subcommand                        | All cores (shared)  | HTTP + Pipe/UDS     |
| **Standalone** | `koi mdns <cmd>` + no daemon         | MdnsCore (local)    | Direct              |
| **Client**     | `koi <domain> <cmd>` + daemon running | KoiClient → HTTP   | HTTP to daemon      |
| **Piped**      | stdin is piped                       | MdnsCore (local)    | NDJSON stdin/stdout |

Daemon mode also serves an embedded dashboard (`GET /`) and mDNS browser (`GET /mdns-browser`).

---

## CLI Moniker Structure

v0.2 uses domain monikers: `koi <domain> <command>`

```
koi mdns discover [type]         # Browse for services
koi mdns announce <args>         # Register a service
koi mdns unregister <id>         # Remove a service
koi mdns resolve <name>          # Resolve service
koi mdns subscribe <type>        # Watch lifecycle events
koi mdns admin <cmd>             # Admin operations (status, ls, inspect, drain, revive)
koi certmesh create              # Initialize private CA
koi certmesh join [endpoint]     # Join existing mesh
koi certmesh status              # Mesh status
koi certmesh unlock              # Decrypt CA key
koi certmesh log                 # Audit log
koi certmesh set-hook            # Set reload hook
koi certmesh promote [endpoint]  # Promote standby CA
koi certmesh open-enrollment     # Open enrollment window
koi certmesh close-enrollment    # Close enrollment window
koi certmesh rotate-auth         # Rotate enrollment auth
koi certmesh backup <path>       # Create encrypted backup
koi certmesh restore <path>      # Restore from backup
koi certmesh revoke <hostname>   # Revoke a member
koi certmesh destroy             # Destroy all certmesh state
koi dns serve                    # Start the DNS resolver
koi dns stop                     # Stop the DNS resolver
koi dns status                   # DNS resolver status
koi dns lookup <name>            # Resolve a local name
koi dns add <name> <ip>          # Add static DNS entry
koi dns remove <name>            # Remove static DNS entry
koi dns list                     # List all resolvable names
koi health status                # Show health status
koi health watch                 # Live terminal watch
koi health add <name>            # Add a health check
koi health remove <name>         # Remove a health check
koi health log                   # Health transition log
koi proxy add <name>             # Add/update a proxy entry
koi proxy remove <name>          # Remove a proxy entry
koi proxy status                 # Proxy status
koi proxy list                   # List configured proxies
koi udp bind                     # Bind a host UDP port
koi udp unbind <id>              # Close a UDP binding
koi udp send <id>                # Send a datagram
koi udp status                   # Show active bindings
koi udp heartbeat <id>           # Renew binding lease
koi status                       # Unified capability status
koi launch                       # Open dashboard in browser
koi install                      # Install as OS service
koi uninstall                    # Uninstall OS service
koi version                      # Show version
```

---

## Never Do

- Import `mdns-sd` outside of `crates/koi-mdns/src/daemon.rs`
- Create a centralized constants module
- Have domain crates import each other
- Use `unwrap()` in production code (use `?`, `unwrap_or_else`, or graceful fallbacks)
- Use `.expect()` in production code (treat as `unwrap()` - both panic)
- Use `unreachable!()` in match arms reachable through API evolution (use `anyhow::bail!`)
- Use blocking I/O in async context (except `ureq` which is intentionally blocking)
- Duplicate types between `koi-common` and domain crates
- Use `#[cfg(feature = "...")]` for domain capabilities (use runtime tunables instead)
- Expose domain internal state as `pub` (use opaque facade pattern - see "Domain Facade Pattern" below)
- Duplicate session ID generation (use `koi_common::id::generate_short_id()`)
- Duplicate the streaming `select! { stream, ctrl_c, timeout }` skeleton (use `commands::run_streaming()`)
- Define the same constant in multiple files (make `pub(crate)` and import)

## Always Do

- Check reference/utilities.md before creating constants
- Propagate errors with `thiserror` or `.context()`
- Use `tracing::*` for logging (never `eprintln!` for diagnostic output)
- Keep mdns-sd isolated behind `MdnsDaemon`
- Test serde round-trips for new protocol types
- Check `config.require_capability()` before dispatching domain commands
- Use `commands::print_json()` for CLI JSON output (handles serialization errors gracefully)
- Use shared helpers (`build_register_payload`, `print_register_success`, `run_streaming`) instead of duplicating
- Re-export domain error types at crate root (e.g., `pub use error::CertmeshError`)

---

## Lessons Learned

### Domain Facade Pattern

Every domain crate must follow the opaque facade pattern established by `koi-mdns`:

1. **Internal state is `pub(crate)` or private** - never expose `Mutex<T>`, internal types, or lock handles
2. **Domain core is the single entry point** - `MdnsCore` / `CertmeshCore` exposes commands as methods
3. **HTTP handlers delegate to domain methods** - no lock management in HTTP handlers where possible
4. **Status logic lives in one place** - shared `build_status()` helpers prevent duplication between facade and HTTP
5. **Constructor hides complexity** - callers pass high-level types, not internal state components

Bad:

```rust
pub struct InternalState { pub mutex_field: Mutex<T> }  // Leaks internals
handler(state.mutex_field.lock().await)                  // Lock in handler
```

Good:

```rust
pub(crate) struct InternalState { ... }
pub struct DomainCore { state: Arc<InternalState> }
impl DomainCore { pub async fn do_thing(&self) -> Result<T> { ... } }
```

### Adapter Dispatch Dedup

The pipe and CLI adapters share identical NDJSON request dispatch logic. This is factored into `adapters::dispatch`:

- `new_session_id()` - uses `koi_common::id::generate_short_id()`
- `handle_line()` - parses request, dispatches to MdnsCore, writes responses
- `write_response()` - serializes with graceful error handling (no `.unwrap()`)

Each adapter only keeps its own session grace period and transport setup.

### Binary Crate Module Structure

The binary crate (`crates/koi/src/`) is organized by responsibility:

```
main.rs            - Pure orchestrator: CLI parse, routing, daemon wiring, shutdown
cli.rs             - clap definitions (Cli, Command, Config)
client.rs          - Re-exports koi-client (HTTP client for client mode)
format.rs          - ALL human-readable CLI output (single source of truth)
admin.rs           - Admin command execution (delegates to KoiClient)
openapi.rs         - Manifest-driven OpenAPI spec builder (utoipa)
help/              - Terminal-profile-aware help rendering + command/API metadata
                     (folded in from the former command-surface crate in P09)
commands/
  mod.rs           - Shared helpers (detect_mode, run_streaming, print_json, etc.)
  mdns.rs          - mDNS commands + admin routing (discover, announce, etc.)
  certmesh.rs      - Certmesh commands (create, join, status, etc.)
  dns.rs           - DNS commands (serve, stop, lookup, add, remove, list)
  health.rs        - Health commands (status, watch, add, remove, log)
  proxy.rs         - Proxy commands (add, remove, status, list)
  udp.rs           - UDP commands (bind, unbind, send, status, heartbeat)
  ceremony_cli.rs  - Ceremony protocol CLI handling
  status.rs        - Unified status command
adapters/
  mod.rs
  http.rs          - HTTP server (AppState, routes, health, status, OpenAPI/Scalar)
  pipe.rs          - Named Pipe / UDS adapter
  cli.rs           - Piped stdin/stdout adapter
  dispatch.rs      - Shared NDJSON dispatch logic
  dashboard.rs     - Dashboard wiring (snapshot builder + DashboardState); HTML/SSE/forwarder live in koi-dashboard
platform/
  mod.rs           - Platform abstraction
  windows.rs       - SCM, firewall, service paths
  unix.rs          - systemd, service paths
  macos.rs         - launchd, service paths
```

Key design rules:

- `main.rs` contains zero business logic - only routing and wiring
- `format.rs` is the only file with `println!`-based presentation
- Platform paths live in their respective `platform/` modules, not in `cli.rs`
- Commands are organized by domain (`commands/mdns.rs`, `commands/certmesh.rs`, `commands/dns.rs`, etc.)
- Dashboard and browser HTML/SSE/routes/cache live in the `koi-dashboard` crate (a
  composition crate); the binary keeps only its snapshot builder + `DashboardState`
  wiring in `adapters/dashboard.rs`. The single event forwarder
  (`koi_dashboard::forward`) and mDNS browse adapter (`koi_dashboard::browse_source`) are
  shared by both the binary and `koi-embedded`. The LAN-wide meta-browse is lazy
  (`koi_dashboard::meta_browse`): it starts on the first browser request and idles out —
  `koi status` reports `Browse: active|idle`.

### Serialization Safety

Never `unwrap()` on `serde_json::to_string()`. While it rarely fails for well-formed types, production code must handle it:

- CLI output: use `commands::print_json()` helper
- Adapter output: use `adapters::dispatch::write_response()` with fallback JSON
- HTTP handlers: match on `serde_json::to_value()` result
