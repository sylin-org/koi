# Koi - Constants & Types Reference

Existing constants and types - don't reinvent these.

---

## Constants (Co-located, Not Centralized)

### koi-common (`crates/koi-common/src/id.rs`)

| Constant       | Value | Purpose                          |
| -------------- | ----- | -------------------------------- |
| `SHORT_ID_LEN` | 8     | UUID prefix for registration IDs |

### koi-mdns -- Core (`crates/koi-mdns/src/lib.rs`)

| Constant                     | Value | Purpose                       |
| ---------------------------- | ----- | ----------------------------- |
| `BROADCAST_CHANNEL_CAPACITY` | 256   | Event subscriber channel size |
| `REAPER_INTERVAL`            | 5s    | Lease expiry sweep frequency  |

### koi-mdns -- Daemon (`crates/koi-mdns/src/daemon.rs`)

| Constant          | Value | Purpose                    |
| ----------------- | ----- | -------------------------- |
| `RESOLVE_TIMEOUT` | 5s    | mDNS resolve wait duration |

### koi-mdns -- HTTP (`crates/koi-mdns/src/http.rs`)

| Constant                  | Value | Purpose                     |
| ------------------------- | ----- | --------------------------- |
| `DEFAULT_HEARTBEAT_LEASE` | 90s   | HTTP service lease duration |
| `DEFAULT_HEARTBEAT_GRACE` | 30s   | Grace period after expiry   |
| `DEFAULT_SSE_IDLE`        | 5s    | SSE stream idle timeout     |

### koi -- Pipe Adapter (`crates/koi/src/adapters/pipe.rs`)

| Constant        | Value | Purpose                  |
| --------------- | ----- | ------------------------ |
| `SESSION_GRACE` | 30s   | IPC session grace period |

### koi -- CLI Adapter (`crates/koi/src/adapters/cli.rs`)

| Constant        | Value | Purpose                  |
| --------------- | ----- | ------------------------ |
| `SESSION_GRACE` | 5s    | Piped stdin grace period |

### koi -- Main (`crates/koi/src/main.rs`)

| Constant           | Value | Purpose                 |
| ------------------ | ----- | ----------------------- |
| `SHUTDOWN_TIMEOUT` | 20s   | Hard shutdown limit     |
| `SHUTDOWN_DRAIN`   | 500ms | In-flight request grace |

### koi -- CLI (`crates/koi/src/cli.rs`)

| Constant            | Value | Purpose                            |
| ------------------- | ----- | ---------------------------------- |
| `DEFAULT_HTTP_PORT` | 5641  | Default daemon port ("KOI" keypad) |

### koi -- Client (`crates/koi/src/client.rs`)

| Constant         | Value | Purpose                   |
| ---------------- | ----- | ------------------------- |
| `HEALTH_TIMEOUT` | 200ms | Quick daemon health probe |

### koi -- Commands (`crates/koi/src/commands/mod.rs`)

| Constant          | Value | Purpose             |
| ----------------- | ----- | ------------------- |
| `DEFAULT_TIMEOUT` | 5s    | CLI command timeout |

### koi -- Certmesh Commands (`crates/koi/src/commands/certmesh.rs`)

| Constant               | Value | Purpose                              |
| ---------------------- | ----- | ------------------------------------ |
| `CA_DISCOVERY_TIMEOUT` | 5s    | mDNS browse timeout for CA discovery |

---

## Shared Helpers (Don't Duplicate)

### `adapters::dispatch` (`crates/koi/src/adapters/dispatch.rs`)

| Function           | Purpose                                                             |
| ------------------ | ------------------------------------------------------------------- |
| `new_session_id()` | Create session ID via `koi_common::id::generate_short_id()`         |
| `handle_line()`    | Parse NDJSON request, dispatch to MdnsCore, write responses         |
| `write_response()` | Serialize pipeline response with graceful fallback (no `.unwrap()`) |

Used by both `adapters::pipe` and `adapters::cli` - never duplicate this logic.

### `commands` (`crates/koi/src/commands/mod.rs`)

| Function                       | Purpose                                                                              |
| ------------------------------ | ------------------------------------------------------------------------------------ |
| `detect_mode()`                | Determine standalone vs client mode (breadcrumb check)                               |
| `resolve_endpoint()`           | Resolve daemon endpoint for admin commands                                           |
| `print_json()`                 | Serialize to JSON with graceful error handling (no `.unwrap()`)                      |
| `build_register_payload()`     | Construct `RegisterPayload` from CLI args                                            |
| `print_register_success()`     | Print registration result with ID and lease info                                     |
| `wait_for_signal_or_timeout()` | Wait for Ctrl+C or optional timeout (used by announce)                               |
| `run_streaming()`              | Generic `select! { stream, ctrl_c, timeout }` skeleton (used by discover, subscribe) |
| `effective_timeout()`          | Resolve explicit/default timeout to `Option<Duration>`                               |

Used by `commands::mdns` and `commands::certmesh` - never duplicate this logic.

### `format` (`crates/koi/src/format.rs`)

Single source of truth for ALL human-readable CLI output.

| Function                    | Purpose                                       |
| --------------------------- | --------------------------------------------- |
| `service_line()`            | One-line service display (discover output)    |
| `resolved_detail()`         | Multi-line resolved service details           |
| `subscribe_event()`         | Lifecycle event line (found/resolved/removed) |
| `browse_event_json()`       | Format browse SSE JSON for CLI                |
| `subscribe_event_json()`    | Format subscribe SSE JSON for CLI             |
| `registration_row()`        | Admin list row (tabular format)               |
| `registration_detail()`     | Admin inspect detail view                     |
| `unified_status()`          | Status command output                         |
| `certmesh_create_success()` | Certmesh create success message               |
| `certmesh_status()`         | Certmesh status display                       |

No other module should contain `println!`-based presentation functions.

---

## Shared Types (`koi-common`)

### `koi_common::types`

| Type            | Purpose                                             |
| --------------- | --------------------------------------------------- |
| `ServiceRecord` | Core service data (name, type, host, ip, port, txt) |
| `ServiceType`   | Parsed `_name._proto` type with validation          |
| `EventKind`     | Found / Resolved / Removed                          |
| `SessionId`     | Session identifier newtype                          |
| `META_QUERY`    | `"_services._dns-sd._udp.local."` constant          |

### `koi_common::error`

| Type        | Purpose                                       |
| ----------- | --------------------------------------------- |
| `ErrorCode` | Wire error codes with `http_status()` mapping |

### `koi_common::pipeline`

| Type                  | Purpose                                      |
| --------------------- | -------------------------------------------- |
| `PipelineResponse<B>` | Generic pipeline wrapper with status/warning |
| `PipelineStatus`      | Ongoing / Finished                           |

### `koi_common::id`

| Function              | Purpose                  |
| --------------------- | ------------------------ |
| `generate_short_id()` | UUID v4 prefix (8 chars) |

---

## mDNS Domain Types (`koi-mdns`)

### `koi_mdns::protocol`

| Type                   | Purpose                                     |
| ---------------------- | ------------------------------------------- |
| `RegisterPayload`      | Registration request body                   |
| `RegistrationResult`   | Registration response (id, lease info)      |
| `RenewalResult`        | Heartbeat renewal response                  |
| `LeaseMode`            | Session / Heartbeat / Permanent             |
| `LeaseState`           | Alive / Draining                            |
| `AdminRegistration`    | Full lifecycle view for admin commands      |
| `DaemonStatus`         | Daemon overview (id, uptime, registrations) |
| `RegistrationCounts`   | Counts by state (alive, draining)           |
| `Request`              | Inbound NDJSON request enum                 |
| `Response`             | Outbound response enum (custom Serialize)   |
| `MdnsPipelineResponse` | Type alias: `PipelineResponse<Response>`    |

### `koi_mdns::protocol` (free functions)

| Function                        | Purpose                                      |
| ------------------------------- | -------------------------------------------- |
| `browse_event_to_pipeline()`    | Convert browse event to pipeline response    |
| `subscribe_event_to_pipeline()` | Convert subscribe event to pipeline response |
| `error_to_pipeline()`           | Convert MdnsError to pipeline error response |

### `koi_mdns` (re-exports from `lib.rs`)

| Type           | Purpose                                      |
| -------------- | -------------------------------------------- |
| `MdnsCore`     | Main domain facade (commands, state, events) |
| `BrowseHandle` | RAII browse cleanup (closure on drop)        |
| `MdnsError`    | Domain error enum (thiserror)                |
| `MdnsEvent`    | Domain event enum (Found, Resolved, Removed) |
| `LeasePolicy`  | Session / Heartbeat(dur, grace) / Permanent  |

### Internal (not re-exported)

| Type           | Location      | Purpose                                  |
| -------------- | ------------- | ---------------------------------------- |
| `MdnsDaemon`   | `daemon.rs`   | mdns-sd wrapper (worker thread)          |
| `Registry`     | `registry.rs` | Thread-safe registration store           |
| `Registration` | `registry.rs` | Single registration (payload + metadata) |

---

## Certmesh Domain Types (`koi-certmesh`)

### `koi_certmesh` (re-exports from `lib.rs`)

| Type            | Purpose                                                 |
| --------------- | ------------------------------------------------------- |
| `CertmeshCore`  | Main domain facade (enrollment, status, CA init/unlock) |
| `CertmeshError` | Domain error enum (thiserror)                           |

### `koi_certmesh::protocol`

| Type                 | Purpose                                                           |
| -------------------- | ----------------------------------------------------------------- |
| `JoinRequest`        | Enrollment request (hostname, auth response)                      |
| `JoinResponse`       | Enrollment response (cert chain, CA fingerprint)                  |
| `CertmeshStatus`     | Status overview (ca_initialized, member_count, auth_method, etc.) |
| `CreateCaRequest`    | CA creation request (passphrase, entropy_hex, profile, operator)  |
| `CreateCaResponse`   | CA creation response (auth_setup, ca_fingerprint)                 |
| `UnlockRequest`      | CA unlock request (passphrase)                                    |
| `UnlockResponse`     | CA unlock response (success)                                      |
| `RotateAuthRequest`  | Auth credential rotation request (passphrase, optional method)    |
| `RotateAuthResponse` | Auth credential rotation response (auth_setup)                    |
| `AuditLogResponse`   | Audit log read response (entries)                                 |
| `DestroyResponse`    | Certmesh destroy response (destroyed)                             |
| `TrustProfile`       | CA policy (key size, validity, enrollment mode)                   |

### Internal (not re-exported)

| Type            | Location    | Purpose                                                    |
| --------------- | ----------- | ---------------------------------------------------------- |
| `CertmeshState` | `lib.rs`    | `pub(crate)` shared state (CA, roster, auth, rate limiter) |
| `CaState`       | `ca.rs`     | Certificate authority state (key pair, cert)               |
| `Roster`        | `roster.rs` | Enrolled members registry                                  |

---

## Binary Crate Types (`koi`)

| Type                 | Location          | Purpose                                             |
| -------------------- | ----------------- | --------------------------------------------------- |
| `Cli`                | `cli.rs`          | Top-level clap parser                               |
| `Command`            | `cli.rs`          | Subcommand enum (Mdns, Certmesh, Install, etc.)     |
| `MdnsSubcommand`     | `cli.rs`          | mDNS subcommands (Discover, Announce, etc.)         |
| `CertmeshSubcommand` | `cli.rs`          | Certmesh subcommands (Create, Join, etc.)           |
| `AdminSubcommand`    | `cli.rs`          | Admin subcommands (Status, List, etc.)              |
| `Config`             | `cli.rs`          | Daemon runtime configuration                        |
| `DaemonCores`        | `main.rs`         | Runtime state: `Option<Arc<Core>>` per domain       |
| `KoiClient`          | `client.rs`       | Blocking HTTP client (ureq) for client mode & admin |
| `Mode`               | `commands/mod.rs` | Execution mode enum (Standalone, Client)            |

---

## Data Directory (`koi-common::paths`)

All Koi data is machine-scoped. Nothing roams via AD roaming profiles.

| Platform | Data Dir                            | Env Var       |
| -------- | ----------------------------------- | ------------- |
| Windows  | `%ProgramData%\koi\`                | `PROGRAMDATA` |
| macOS    | `/Library/Application Support/koi/` | -             |
| Linux    | `/var/lib/koi/`                     | -             |

Override with `KOI_DATA_DIR` env var (for testing).

Sub-directories: `certs/`, `state/`, `logs/`, `certmesh/ca/`

---

## Breadcrumb Discovery (`koi-config`)

Daemon writes endpoint to breadcrumb file for client auto-discovery:

| Platform | Path                                                                |
| -------- | ------------------------------------------------------------------- |
| Windows  | `%ProgramData%\koi\koi.endpoint`                                    |
| Unix     | `$XDG_RUNTIME_DIR/koi.endpoint` (fallback: `/var/run/koi.endpoint`) |

---

## Error Codes (`koi_common::error::ErrorCode`)

| Code                  | HTTP Status | Meaning                         |
| --------------------- | ----------- | ------------------------------- |
| `invalid_type`        | 400         | Bad service type format         |
| `invalid_name`        | 400         | Bad service name                |
| `invalid_payload`     | 400         | Malformed request body          |
| `not_found`           | 404         | Registration not found          |
| `conflict`            | 409         | Duplicate registration          |
| `session_mismatch`    | 403         | Wrong session for operation     |
| `shutting_down`       | 503         | Daemon is shutting down         |
| `internal`            | 500         | Internal error                  |
| `ca_not_initialized`  | 503         | CA not yet created              |
| `ca_locked`           | 503         | CA key is locked                |
| `invalid_auth`        | 401         | Bad auth credential             |
| `rate_limited`        | 429         | Too many requests               |
| `enrollment_closed`   | 403         | Enrollment not open             |
| `capability_disabled` | 503         | Capability disabled at runtime  |
| `not_standby`         | 403         | Node is not a standby           |
| `promotion_failed`    | 500         | CA key transfer failed          |
| `renewal_failed`      | 500         | Certificate renewal failed      |
| `invalid_manifest`    | 400         | Bad roster manifest signature   |
| `scope_violation`     | 403         | Enrollment outside policy scope |

---

## Dependencies (Workspace-managed)

| Crate                  | Version         | Used By                   | Purpose                                  |
| ---------------------- | --------------- | ------------------------- | ---------------------------------------- |
| `mdns-sd`              | 0.17            | koi-mdns                  | mDNS/DNS-SD engine                       |
| `axum`                 | 0.8             | koi-mdns, koi             | HTTP framework                           |
| `tokio`                | 1 (full)        | all                       | Async runtime                            |
| `serde` / `serde_json` | 1               | all                       | Serialization                            |
| `clap`                 | 4 (derive, env) | koi                       | CLI parsing                              |
| `tracing`              | 0.1             | all                       | Structured logging                       |
| `tower-http`           | 0.6             | koi                       | CORS middleware                          |
| `thiserror`            | 2               | koi-common, koi-mdns, koi | Error derive macros                      |
| `ureq`                 | 2               | koi                       | Blocking HTTP client                     |
| `uuid`                 | 1 (v4)          | koi-common, koi           | ID generation                            |
| `tokio-util`           | 0.7             | koi-mdns, koi             | CancellationToken                        |
| `windows-service`      | 0.8             | koi (Windows)             | Windows SCM                              |
| `ring`                 | 0.17            | koi-crypto                | Cryptographic primitives                 |
| `rcgen`                | 0.13            | koi-crypto                | X.509 certificate generation             |
| `totp-rs`              | 5               | koi-crypto                | TOTP enrollment codes                    |
| `p256`                 | 0.13            | koi-crypto                | FIDO2 ECDSA P-256 signature verification |
| `chrono`               | 0.4             | koi-certmesh              | Timestamp handling                       |
