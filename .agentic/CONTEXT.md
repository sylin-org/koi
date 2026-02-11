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
├── koi-certmesh/     # Placeholder (Phase 2)
├── koi-crypto/       # Placeholder (Phase 2)
├── koi-truststore/   # Placeholder (Phase 2)
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
koi (bin) → koi-common, koi-mdns, koi-config
koi-mdns  → koi-common, mdns-sd, axum, tokio
koi-config → koi-common
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

### 9. Feature-Gated Domains
```toml
# crates/koi/Cargo.toml
[features]
default = ["mdns"]
mdns = ["dep:koi-mdns"]
```
All domain references in the binary crate are behind `#[cfg(feature = "...")]`.

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
- Use `unwrap()` in production code
- Use blocking I/O in async context (except `ureq` which is intentionally blocking)
- Duplicate types between `koi-common` and domain crates

## Always Do

- Check reference/utilities.md before creating constants
- Propagate errors with `thiserror` or `.context()`
- Use `tracing::*` for logging
- Keep mdns-sd isolated behind `MdnsDaemon`
- Test serde round-trips for new protocol types
- Gate domain features in the binary crate with `#[cfg(feature = "...")]`
