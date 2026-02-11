# Koi - Constants & Types Reference

Existing constants and types - don't reinvent these.

---

## Constants (Co-located, Not Centralized)

### Core (`src/core/mod.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `SHORT_ID_LEN` | 8 | UUID prefix for registration IDs |
| `BROADCAST_CHANNEL_CAPACITY` | 256 | Event subscriber channel size |
| `REAPER_INTERVAL` | 5s | Lease expiry sweep frequency |
| `SERVICE_NAME_MAX_LEN` | 15 | RFC 6763 service name limit |

### Core Daemon (`src/core/daemon.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `RESOLVE_TIMEOUT` | 5s | mDNS resolve wait duration |

### HTTP Adapter (`src/adapters/http.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `DEFAULT_HEARTBEAT_LEASE` | 90s | HTTP service lease duration |
| `DEFAULT_HEARTBEAT_GRACE` | 30s | Grace period after expiry |
| `DEFAULT_SSE_IDLE` | 5s | SSE stream idle timeout |

### Pipe Adapter (`src/adapters/pipe.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `SESSION_GRACE` | 30s | IPC session grace period |

### CLI Adapter (`src/adapters/cli.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `SESSION_GRACE` | 5s | Piped stdin grace period |

### Main (`src/main.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `SHUTDOWN_TIMEOUT` | 20s | Hard shutdown limit |
| `SHUTDOWN_DRAIN` | 500ms | In-flight request grace |

### Config (`src/config.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `DEFAULT_HTTP_PORT` | 5641 | Default daemon port ("KOI" keypad) |

### Client (`src/client.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `HEALTH_TIMEOUT` | 200ms | Quick daemon health probe |

### Commands (`src/commands/mod.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `DEFAULT_TIMEOUT` | 5s | CLI command timeout |

---

## Wire Protocol Types (`src/protocol/`)

### Data Types (`src/protocol/mod.rs`)

| Type | Purpose |
|------|---------|
| `ServiceRecord` | Core service data (name, type, host, ip, port, txt) |
| `RegisterPayload` | Registration request body |
| `RegistrationResult` | Registration response (id, lease info) |
| `RenewalResult` | Heartbeat renewal response |
| `LeaseMode` | Session / Heartbeat / Permanent |
| `LeaseState` | Alive / Draining |
| `AdminRegistration` | Full lifecycle view for admin commands |
| `DaemonStatus` | Daemon overview (id, uptime, registrations) |
| `RegistrationCounts` | Counts by state (alive, draining) |

### Request (`src/protocol/request.rs`)

| Variant | JSON Shape |
|---------|------------|
| `Browse(String)` | `{"browse": "_http._tcp"}` |
| `Register(RegisterPayload)` | `{"register": {...}}` |
| `Unregister(String)` | `{"unregister": "id"}` |
| `Heartbeat(String)` | `{"heartbeat": "id"}` |

### Response (`src/protocol/response.rs`)

| Variant | JSON Shape |
|---------|------------|
| `Found(ServiceRecord)` | `{"found": {...}}` |
| `Registered(RegistrationResult)` | `{"registered": {...}}` |
| `Renewed(RenewalResult)` | `{"renewed": {...}}` |
| `Removed(String)` | `{"removed": "id"}` |
| `Error(ErrorCode, String)` | `{"error": "code", "message": "..."}` |
| `Event(...)` | `{"event": "type", "service": {...}}` |

### Error Codes (`src/protocol/error.rs`)

| Code | HTTP Status | Meaning |
|------|-------------|---------|
| `invalid_type` | 400 | Bad service type format |
| `invalid_name` | 400 | Bad service name |
| `invalid_payload` | 400 | Malformed request body |
| `not_found` | 404 | Registration not found |
| `conflict` | 409 | Duplicate registration |
| `session_mismatch` | 403 | Wrong session for operation |
| `shutting_down` | 503 | Daemon is shutting down |
| `internal` | 500 | Internal error |

---

## Core Types (`src/core/`)

| Type | Location | Purpose |
|------|----------|---------|
| `MdnsCore` | `core/mod.rs` | Main facade for all mDNS operations |
| `MdnsDaemon` | `core/daemon.rs` | mdns-sd wrapper (worker thread) |
| `Registry` | `core/registry.rs` | Thread-safe registration store |
| `Registration` | `core/registry.rs` | Single registration (payload + metadata) |
| `SessionId` | `core/registry.rs` | Session identifier type |
| `LeasePolicy` | `core/mod.rs` | Session / Heartbeat(dur, grace) / Permanent |
| `ServiceType` | `core/mod.rs` | Parsed `_name._proto` type |
| `BrowseHandle` | `core/mod.rs` | RAII browse cleanup (closure on drop) |
| `KoiError` | `core/mod.rs` | Error enum (thiserror) |

---

## Client (`src/client.rs`)

| Type | Purpose |
|------|---------|
| `KoiClient` | Blocking HTTP client (ureq) for client mode & admin |

---

## Config (`src/config.rs`)

| Type | Purpose |
|------|---------|
| `Cli` | Top-level clap parser |
| `Command` | Subcommand enum (Browse, Register, etc.) |
| `AdminCommand` | Admin subcommand enum (Status, List, etc.) |
| `Config` | Daemon configuration |

---

## Breadcrumb Discovery

Daemon writes endpoint to breadcrumb file for client auto-discovery:

| Platform | Path |
|----------|------|
| Windows | `%LOCALAPPDATA%\koi\koi.endpoint` |
| Unix | `$XDG_RUNTIME_DIR/koi.endpoint` |

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `mdns-sd` | 0.17 | mDNS/DNS-SD engine |
| `axum` | 0.8 | HTTP framework |
| `tokio` | 1 (full) | Async runtime |
| `serde` / `serde_json` | - | Serialization |
| `clap` | 4 (derive) | CLI parsing |
| `tracing` | - | Structured logging |
| `tower-http` | - | CORS middleware |
| `thiserror` | - | Error derive macros |
| `ureq` | 2 | Blocking HTTP client |
| `uuid` | 1 (v4) | ID generation |
| `tokio-util` | - | CancellationToken |
| `windows-service` | 0.8 | Windows SCM (Windows only) |
