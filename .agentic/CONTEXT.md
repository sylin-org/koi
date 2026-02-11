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

### 1. Three-Layer Architecture
```
Adapters (HTTP, Pipe, CLI)  →  Core (MdnsCore, Registry)  →  mdns-sd engine (MdnsDaemon)
```
- **Adapters** (`src/adapters/`): Transport layer — HTTP, Named Pipe/UDS, stdin/stdout
- **Core** (`src/core/`): Business logic — browse, register, lease lifecycle, registry
- **Protocol** (`src/protocol/`): Wire format — request/response types, error codes, serde
- **Rule**: Only `core/daemon.rs` imports `mdns-sd`. Everything else goes through `MdnsCore`.

### 2. Single Crate Structure
Koi is a single binary crate (`koi-mdns`). There is no workspace, no `common/` crate.
```
src/
├── main.rs           # Entry point, mode detection, shutdown
├── adapters/         # Transport adapters (http, pipe, cli)
├── core/             # Business logic (MdnsCore, registry, daemon, events)
├── protocol/         # Wire types (request, response, error, data types)
├── commands/         # CLI command handlers (standalone, client)
├── platform/         # OS service integration (windows, unix, macos)
├── client.rs         # KoiClient (ureq HTTP client for client mode)
├── admin.rs          # Admin CLI commands (status, list, inspect, drain)
├── config.rs         # CLI args (clap), breadcrumb, daemon config
└── format.rs         # Human-readable output formatting
```

### 3. mdns-sd Isolation (CRITICAL)
- `core/daemon.rs` is the **only** file that imports `mdns-sd`
- `MdnsDaemon` wraps all mdns-sd operations behind a clean Rust API
- mdns-sd runs on a dedicated worker thread (`koi-mdns-ops`)
- Never use mdns-sd types in adapters, protocol, or commands

### 4. Constants Convention
- `SCREAMING_SNAKE_CASE`, co-located with the module that uses them
- Module path provides the namespace: `core::SHORT_ID_LEN`, `adapters::http::DEFAULT_HEARTBEAT_LEASE`
- Do NOT create a centralized constants module

### 5. Error Handling
```rust
// Core: thiserror enum (KoiError)
#[derive(Debug, thiserror::Error)]
pub enum KoiError { ... }

// Protocol: ErrorCode enum → HTTP status mapping
ErrorCode::NotFound → StatusCode::NOT_FOUND

// Adapters: Convert KoiError → Response::error()
```

### 6. Serde Patterns (CRITICAL)
```rust
// Response has custom Serialize impl — two JSON shapes:
// Wrapped: {"found": {...}}  (externally tagged)
// Flat:    {"error": "not_found", "message": "..."}  (struct fields at top level)

// PipelineResponse uses #[serde(flatten)] on body
// skip_serializing_if = "Option::is_none" for pipeline properties
```

### 7. Platform-Conditional Compilation
```rust
// Windows-only: Named Pipes, SCM, firewall
#[cfg(windows)]

// Unix-only: Unix domain sockets, systemd
#[cfg(unix)]

// macOS-only: LaunchAgent
#[cfg(target_os = "macos")]
```

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
| **Standalone** | Subcommand + no daemon | MdnsCore (local) | Direct |
| **Client** | Subcommand + daemon running | KoiClient → HTTP | HTTP to daemon |
| **Piped** | stdin is piped | MdnsCore (local) | NDJSON stdin/stdout |

---

## Never Do

- Import `mdns-sd` outside of `core/daemon.rs`
- Create a centralized constants module
- Use `unwrap()` in production code
- Use blocking I/O in async context (except `ureq` which is intentionally blocking)
- Duplicate types between protocol/ and core/

## Always Do

- Check reference/utilities.md before creating constants
- Propagate errors with `thiserror` or `.context()`
- Use `tracing::*` for logging
- Keep mdns-sd isolated behind `MdnsDaemon`
- Test serde round-trips for new protocol types
