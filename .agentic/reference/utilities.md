# Koi - Constants & Types Reference

Existing constants and types - don't reinvent these.

---

## Constants (Co-located, Not Centralized)

### koi-common (`crates/koi-common/src/id.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `SHORT_ID_LEN` | 8 | UUID prefix for registration IDs |

### koi-mdns -- Core (`crates/koi-mdns/src/lib.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `BROADCAST_CHANNEL_CAPACITY` | 256 | Event subscriber channel size |
| `REAPER_INTERVAL` | 5s | Lease expiry sweep frequency |

### koi-mdns -- Daemon (`crates/koi-mdns/src/daemon.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `RESOLVE_TIMEOUT` | 5s | mDNS resolve wait duration |

### koi-mdns -- HTTP (`crates/koi-mdns/src/http.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `DEFAULT_HEARTBEAT_LEASE` | 90s | HTTP service lease duration |
| `DEFAULT_HEARTBEAT_GRACE` | 30s | Grace period after expiry |
| `DEFAULT_SSE_IDLE` | 5s | SSE stream idle timeout |

### koi -- Pipe Adapter (`crates/koi/src/adapters/pipe.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `SESSION_GRACE` | 30s | IPC session grace period |

### koi -- CLI Adapter (`crates/koi/src/adapters/cli.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `SESSION_GRACE` | 5s | Piped stdin grace period |

### koi -- Main (`crates/koi/src/main.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `SHUTDOWN_TIMEOUT` | 20s | Hard shutdown limit |
| `SHUTDOWN_DRAIN` | 500ms | In-flight request grace |

### koi -- CLI (`crates/koi/src/cli.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `DEFAULT_HTTP_PORT` | 5641 | Default daemon port ("KOI" keypad) |

### koi -- Client (`crates/koi/src/client.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `HEALTH_TIMEOUT` | 200ms | Quick daemon health probe |

### koi -- Commands (`crates/koi/src/commands/mod.rs`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `DEFAULT_TIMEOUT` | 5s | CLI command timeout |

---

## Shared Types (`koi-common`)

### `koi_common::types`

| Type | Purpose |
|------|---------|
| `ServiceRecord` | Core service data (name, type, host, ip, port, txt) |
| `ServiceType` | Parsed `_name._proto` type with validation |
| `EventKind` | Found / Resolved / Removed |
| `SessionId` | Session identifier newtype |
| `META_QUERY` | `"_services._dns-sd._udp.local."` constant |

### `koi_common::error`

| Type | Purpose |
|------|---------|
| `ErrorCode` | Wire error codes with `http_status()` mapping |

### `koi_common::pipeline`

| Type | Purpose |
|------|---------|
| `PipelineResponse<B>` | Generic pipeline wrapper with status/warning |
| `PipelineStatus` | Ongoing / Finished |

### `koi_common::id`

| Function | Purpose |
|----------|---------|
| `generate_short_id()` | UUID v4 prefix (8 chars) |

---

## mDNS Domain Types (`koi-mdns`)

### `koi_mdns::protocol`

| Type | Purpose |
|------|---------|
| `RegisterPayload` | Registration request body |
| `RegistrationResult` | Registration response (id, lease info) |
| `RenewalResult` | Heartbeat renewal response |
| `LeaseMode` | Session / Heartbeat / Permanent |
| `LeaseState` | Alive / Draining |
| `AdminRegistration` | Full lifecycle view for admin commands |
| `DaemonStatus` | Daemon overview (id, uptime, registrations) |
| `RegistrationCounts` | Counts by state (alive, draining) |
| `Request` | Inbound NDJSON request enum |
| `Response` | Outbound response enum (custom Serialize) |
| `MdnsPipelineResponse` | Type alias: `PipelineResponse<Response>` |

### `koi_mdns::protocol` (free functions)

| Function | Purpose |
|----------|---------|
| `browse_event_to_pipeline()` | Convert browse event to pipeline response |
| `subscribe_event_to_pipeline()` | Convert subscribe event to pipeline response |
| `error_to_pipeline()` | Convert MdnsError to pipeline error response |

### `koi_mdns` (re-exports from `lib.rs`)

| Type | Purpose |
|------|---------|
| `MdnsCore` | Main domain facade (commands, state, events) |
| `BrowseHandle` | RAII browse cleanup (closure on drop) |
| `MdnsError` | Domain error enum (thiserror) |
| `MdnsEvent` | Domain event enum (Found, Resolved, Removed) |
| `LeasePolicy` | Session / Heartbeat(dur, grace) / Permanent |

### Internal (not re-exported)

| Type | Location | Purpose |
|------|----------|---------|
| `MdnsDaemon` | `daemon.rs` | mdns-sd wrapper (worker thread) |
| `Registry` | `registry.rs` | Thread-safe registration store |
| `Registration` | `registry.rs` | Single registration (payload + metadata) |

---

## Binary Crate Types (`koi`)

| Type | Location | Purpose |
|------|----------|---------|
| `Cli` | `cli.rs` | Top-level clap parser |
| `Command` | `cli.rs` | Subcommand enum (Mdns, Install, etc.) |
| `MdnsSubcommand` | `cli.rs` | mDNS subcommands (Discover, Announce, etc.) |
| `AdminSubcommand` | `cli.rs` | Admin subcommands (Status, List, etc.) |
| `Config` | `cli.rs` | Daemon runtime configuration |
| `KoiClient` | `client.rs` | Blocking HTTP client (ureq) for client mode & admin |

---

## Breadcrumb Discovery (`koi-config`)

Daemon writes endpoint to breadcrumb file for client auto-discovery:

| Platform | Path |
|----------|------|
| Windows | `%LOCALAPPDATA%\koi\koi.endpoint` |
| Unix | `$XDG_RUNTIME_DIR/koi.endpoint` |

---

## Error Codes (`koi_common::error::ErrorCode`)

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

## Dependencies (Workspace-managed)

| Crate | Version | Used By | Purpose |
|-------|---------|---------|---------|
| `mdns-sd` | 0.17 | koi-mdns | mDNS/DNS-SD engine |
| `axum` | 0.8 | koi-mdns, koi | HTTP framework |
| `tokio` | 1 (full) | all | Async runtime |
| `serde` / `serde_json` | 1 | all | Serialization |
| `clap` | 4 (derive, env) | koi | CLI parsing |
| `tracing` | 0.1 | all | Structured logging |
| `tower-http` | 0.6 | koi | CORS middleware |
| `thiserror` | 2 | koi-common, koi-mdns, koi | Error derive macros |
| `ureq` | 2 | koi | Blocking HTTP client |
| `uuid` | 1 (v4) | koi-common, koi | ID generation |
| `tokio-util` | 0.7 | koi-mdns, koi | CancellationToken |
| `windows-service` | 0.8 | koi (Windows) | Windows SCM |
