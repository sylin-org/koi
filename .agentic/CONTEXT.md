# Koi - Agentic Context

> **Tool-agnostic AI context.** Claude, Cursor, Copilot, and other AI assistants bootstrap from here.

---

## Before Writing Code

**Check reference docs**: `docs/reference/`
- [architecture.md](../docs/reference/architecture.md) — crate inventory, boundaries, dependency graph
- [http-api.md](../docs/reference/http-api.md) — all 43 HTTP endpoints with request/response shapes
- [wire-protocol.md](../docs/reference/wire-protocol.md) — JSON protocol, serde patterns, service records
- [cli.md](../docs/reference/cli.md) — every command, flag, and environment variable
- [ceremony-protocol.md](../docs/reference/ceremony-protocol.md) — ceremony engine, input types, session flow
- [envelope-encryption.md](../docs/reference/envelope-encryption.md) — CA key protection, slot types

**Check design decisions**: `docs/adr/`
- 10 Architecture Decision Records documenting why things are built the way they are

---

## Critical Rules

### 1. Cargo Workspace Architecture

Koi v0.2 is a multi-crate Cargo workspace. Each domain has its own crate.

```
crates/
├── koi/              # Binary crate — CLI entry, wiring, adapters
├── koi-common/       # Shared kernel — types, errors, pipeline, id, paths
├── koi-mdns/         # mDNS domain — core, daemon, registry, protocol, http routes
├── koi-config/       # Config & state — breadcrumb discovery
├── koi-certmesh/     # Certificate mesh domain — CA, enrollment, roster
├── koi-crypto/       # Cryptographic primitives — key gen, signing, TOTP, FIDO2, auth adapters
├── koi-truststore/   # Trust store — platform cert installation
├── koi-dns/          # Local DNS resolver — zone management, resolution, rate limiting
├── koi-health/       # Machine & service health monitoring — HTTP/TCP checks, transitions
├── koi-proxy/        # TLS-terminating reverse proxy — cert reload, forwarding
├── koi-client/       # HTTP client for daemon communication (blocking ureq)
├── koi-embedded/     # Embed Koi in Rust applications — builder, handles, events
└── command-surface/  # Glyph-based command rendering — semantic metadata, profiles
```

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
koi (bin) → koi-common, koi-mdns, koi-certmesh, koi-crypto, koi-truststore, koi-config, koi-dns, koi-health, koi-proxy, koi-client, koi-embedded, command-surface
koi-mdns      → koi-common, mdns-sd, axum, tokio
koi-certmesh  → koi-common, koi-crypto, koi-truststore, axum, tokio
koi-crypto    → (standalone: ring/rcgen/totp-rs/p256)
koi-truststore → (standalone: platform cert APIs)
koi-config    → koi-common
koi-dns       → koi-common, koi-config, hickory-server, hickory-resolver, axum, tokio
koi-health    → koi-common, koi-config, axum, tokio
koi-proxy     → koi-common, koi-config, axum-server, rustls, reqwest, tokio
koi-client    → koi-common, ureq (blocking)
koi-embedded  → koi-common, koi-mdns, koi-certmesh, koi-dns, koi-health, koi-proxy, koi-config, tokio
command-surface → (standalone: crossterm)
```

Domain crates depend on `koi-common` but **never** on each other.

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
// Response has custom Serialize impl — two JSON shapes:
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

// macOS-only: LaunchAgent
#[cfg(target_os = "macos")]
```

### 9. Runtime Capability Tunables

All domain capabilities are compiled into a **single binary**. Enable/disable at runtime:

| Flag | Env Var | Effect |
|------|---------|--------|
| `--no-mdns` | `KOI_NO_MDNS=1` | Disable mDNS capability |
| `--no-certmesh` | `KOI_NO_CERTMESH=1` | Disable certmesh capability |
| `--no-dns` | `KOI_NO_DNS=1` | Disable DNS capability |
| `--no-health` | `KOI_NO_HEALTH=1` | Disable health capability |
| `--no-proxy` | `KOI_NO_PROXY=1` | Disable proxy capability |

All capabilities are **enabled by default**.

The binary crate checks `Config.no_<capability>` at three layers:
- **CLI dispatch**: `config.require_capability("mdns")?` before running any domain command
- **HTTP routes**: disabled capabilities return 503 via a fallback router
- **Daemon mode**: disabled capabilities skip core creation entirely

Domain crates are **never aware** of this mechanism — the binary crate is the sole orchestrator.

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

Koi operates in four modes — understand which one your change affects:

| Mode | Detection | Core Owner | Transport |
|------|-----------|------------|-----------|
| **Daemon** | No subcommand | MdnsCore (shared) | HTTP + Pipe/UDS |
| **Standalone** | `koi mdns <cmd>` + no daemon | MdnsCore (local) | Direct |
| **Client** | `koi mdns <cmd>` + daemon running | KoiClient → HTTP | HTTP to daemon |
| **Piped** | stdin is piped | MdnsCore (local) | NDJSON stdin/stdout |

---

## CLI Moniker Structure

v0.2 uses domain monikers: `koi <domain> <command>`

```
koi mdns discover [type]     # Browse for services
koi mdns announce <args>     # Register a service
koi mdns unregister <id>     # Remove a service
koi mdns resolve <name>      # Resolve service
koi mdns subscribe <type>    # Watch lifecycle events
koi mdns admin <cmd>         # Admin operations
koi certmesh create          # Initialize private CA
koi certmesh join [endpoint] # Join existing mesh
koi certmesh status          # Mesh status
koi certmesh unlock          # Decrypt CA key
koi certmesh log             # Audit log
koi certmesh set-hook        # Set reload hook
koi status                   # Unified capability status
koi install                  # Install as OS service
koi uninstall                # Uninstall OS service
koi version                  # Show version
```

---

## Never Do

- Import `mdns-sd` outside of `crates/koi-mdns/src/daemon.rs`
- Create a centralized constants module
- Have domain crates import each other
- Use `unwrap()` in production code (use `?`, `unwrap_or_else`, or graceful fallbacks)
- Use `.expect()` in production code (treat as `unwrap()` — both panic)
- Use `unreachable!()` in match arms reachable through API evolution (use `anyhow::bail!`)
- Use blocking I/O in async context (except `ureq` which is intentionally blocking)
- Duplicate types between `koi-common` and domain crates
- Use `#[cfg(feature = "...")]` for domain capabilities (use runtime tunables instead)
- Expose domain internal state as `pub` (use opaque facade pattern — see "Domain Facade Pattern" below)
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

1. **Internal state is `pub(crate)` or private** — never expose `Mutex<T>`, internal types, or lock handles
2. **Domain core is the single entry point** — `MdnsCore` / `CertmeshCore` exposes commands as methods
3. **HTTP handlers delegate to domain methods** — no lock management in HTTP handlers where possible
4. **Status logic lives in one place** — shared `build_status()` helpers prevent duplication between facade and HTTP
5. **Constructor hides complexity** — callers pass high-level types, not internal state components

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
- `new_session_id()` — uses `koi_common::id::generate_short_id()`
- `handle_line()` — parses request, dispatches to MdnsCore, writes responses
- `write_response()` — serializes with graceful error handling (no `.unwrap()`)

Each adapter only keeps its own session grace period and transport setup.

### Binary Crate Module Structure

The binary crate (`crates/koi/src/`) is organized by responsibility:

```
main.rs          — Pure orchestrator: CLI parse, routing, daemon wiring, shutdown
cli.rs           — clap definitions (Cli, Command, Config)
client.rs        — KoiClient (ureq HTTP client for client mode)
format.rs        — ALL human-readable CLI output (single source of truth)
admin.rs         — Admin command execution (delegates to KoiClient)
commands/
  mod.rs         — Shared helpers (detect_mode, run_streaming, print_json, etc.)
  mdns.rs        — mDNS commands + admin routing (discover, announce, etc.)
  certmesh.rs    — Certmesh commands (create, join, status, etc.)
  status.rs      — Unified status command
adapters/
  mod.rs
  http.rs        — HTTP server (AppState, routes, health, status handler)
  pipe.rs        — Named Pipe / UDS adapter
  cli.rs         — Piped stdin/stdout adapter
  dispatch.rs    — Shared NDJSON dispatch logic
platform/
  mod.rs         — Platform abstraction
  windows.rs     — SCM, firewall, service paths
  unix.rs        — systemd, service paths
  macos.rs       — launchd, service paths
```

Key design rules:
- `main.rs` contains zero business logic — only routing and wiring
- `format.rs` is the only file with `println!`-based presentation
- Platform paths live in their respective `platform/` modules, not in `cli.rs`
- Commands are organized by domain (`commands/mdns.rs`, `commands/certmesh.rs`)

### Serialization Safety

Never `unwrap()` on `serde_json::to_string()`. While it rarely fails for well-formed types, production code must handle it:
- CLI output: use `commands::print_json()` helper
- Adapter output: use `adapters::dispatch::write_response()` with fallback JSON
- HTTP handlers: match on `serde_json::to_value()` result
