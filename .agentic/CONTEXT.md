# Koi - Agentic Context

> **Tool-agnostic AI context.** Claude, Cursor, Copilot, and other AI assistants bootstrap from here.

---

## Before Writing Code

**Check existing constants & types**: [reference/utilities.md](reference/utilities.md)
- Constants, wire protocol types, serde patterns

**Check API & protocol**: [reference/api-endpoints.md](reference/api-endpoints.md)
- HTTP endpoints, pipe/CLI protocol, request/response shapes

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
├── koi-crypto/       # Cryptographic primitives — key gen, signing, TOTP
├── koi-truststore/   # Trust store — platform cert installation
├── koi-dns/          # Placeholder (Phase 6)
├── koi-health/       # Placeholder (Phase 7)
└── koi-proxy/        # Placeholder (Phase 8)
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
koi (bin) → koi-common, koi-mdns, koi-certmesh, koi-crypto, koi-truststore, koi-config
koi-mdns      → koi-common, mdns-sd, axum, tokio
koi-certmesh  → koi-common, koi-crypto, koi-truststore, axum, tokio
koi-crypto    → (standalone: ring/rcgen/totp-rs)
koi-truststore → (standalone: platform cert APIs)
koi-config    → koi-common
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
- Duplicate adapter dispatch logic (use `adapters::dispatch` module)
- Define the same constant in multiple files (make `pub(crate)` and import)

## Always Do

- Check reference/utilities.md before creating constants
- Propagate errors with `thiserror` or `.context()`
- Use `tracing::*` for logging (never `eprintln!` for diagnostic output)
- Keep mdns-sd isolated behind `MdnsDaemon`
- Test serde round-trips for new protocol types
- Check `config.require_capability()` before dispatching domain commands
- Use `commands::print_json()` for CLI JSON output (handles serialization errors gracefully)
- Use shared helpers (`build_register_payload`, `print_register_success`, `wait_for_signal_or_timeout`) instead of duplicating
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

### Serialization Safety

Never `unwrap()` on `serde_json::to_string()`. While it rarely fails for well-formed types, production code must handle it:
- CLI output: use `commands::print_json()` helper
- Adapter output: use `adapters::dispatch::write_response()` with fallback JSON
- HTTP handlers: match on `serde_json::to_value()` result
