# Koi — Implementation Guide

**For:** Claude Code (agentic coding)  
**From:** Claude (co-author, design phase)  
**Context:** You are implementing Koi, a cross-platform mDNS/DNS-SD daemon. Read `README.md` and `TECHNICAL.md` first — they contain the full design. This document tells you *how* to build it well.

---

## What this project is

Koi wraps the `mdns-sd` Rust crate behind a JSON API exposed over HTTP, Unix domain sockets / Named Pipes, and stdin/stdout. It runs as a host service (Windows Service or systemd unit) and gives containers, scripts, and polyglot applications full mDNS browse/register/resolve/subscribe capabilities without touching multicast sockets themselves.

The crate name is `koi-mdns`. The binary name is `koi`.

---

## Architecture — the non-negotiable shape

```
Adapters (HTTP, Pipe, CLI)  →  Core API  →  mdns-sd daemon
   thin transport translation      domain logic      mDNS engine
```

Three layers. Adapters are dumb pipes. Core owns everything meaningful. The mdns-sd crate is an implementation detail the core wraps.

**Do not let adapter code contain domain logic.** An adapter deserializes a transport-specific request, calls a core method, serializes the response back to the transport. That's it. If you find yourself writing `if service.health == ...` in an adapter, stop — that belongs in core.

**Do not let core code know about transports.** Core never references Axum types, pipe handles, or stdin. It takes and returns its own domain types. If you're importing `axum::` inside `core/`, something went wrong.

---

## Project layout

```
Cargo.toml
src/
├── main.rs
├── config.rs
├── core/
│   ├── mod.rs          # MdnsCore + public API
│   ├── daemon.rs       # mdns-sd wrapper
│   ├── registry.rs     # registration tracking
│   └── events.rs       # broadcast fan-out
├── adapters/
│   ├── mod.rs
│   ├── http.rs
│   ├── pipe.rs
│   └── cli.rs
├── platform/
│   ├── mod.rs
│   ├── windows.rs
│   └── unix.rs
└── protocol/
    ├── mod.rs
    ├── request.rs      # inbound JSON shapes
    └── response.rs     # outbound JSON shapes
```

Note the `protocol/` module. This is the **shared language** between adapters and core. It defines the JSON wire types — request enums, response enums, the service record shape. Adapters deserialize into protocol types, pass them to core, and serialize protocol types back out. This is the seam that prevents model duplication.

---

## The one model rule

There is **one** service record type. Not a `CoreService` and an `ApiService` and an `HttpService`. One.

```rust
// protocol/mod.rs

/// A service instance as seen on the network.
/// Used in browse results, resolve results, register confirmations,
/// and event payloads. This is THE service representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub port: u16,
    #[serde(default)]
    pub txt: HashMap<String, String>,
}
```

This type flows everywhere. The core produces it. Adapters serialize it. Events carry it. The only conversion boundary is between `mdns_sd::ServiceInfo` and `ServiceRecord` — and that conversion lives in exactly one place: `core/daemon.rs`.

**Why this matters:** Every model conversion is a bug farm. Every `From<A> for B` impl is a place where a field gets dropped or renamed wrong. One model, used everywhere, tested once.

The same principle applies to requests and responses:

```rust
// protocol/request.rs

/// All possible inbound operations.
/// The top-level JSON key determines the variant.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Request {
    Browse(String),                    // { "browse": "_http._tcp" }
    Register(RegisterPayload),         // { "register": { ... } }
    Unregister(String),                // { "unregister": "id" }
    Resolve(String),                   // { "resolve": "instance._type.local." }
    Subscribe(String),                 // { "subscribe": "_http._tcp" }
}
```

```rust
// protocol/response.rs

/// All possible outbound messages.
/// The top-level JSON key identifies the message type.
/// Pipeline properties (status, warning) attach alongside these.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Response {
    Found(ServiceRecord),
    Registered(RegistrationResult),
    Unregistered(String),
    Resolved(ServiceRecord),
    Event { event: EventKind, service: ServiceRecord },
    Error { error: String, message: String },
}
```

All three adapters deserialize into `Request`, call core, get back types that serialize into `Response`. Zero per-adapter model types.

---

## Pipeline properties — a response wrapper, not a model change

Status, warning, and error are operational metadata that the pipeline attaches. They are **not** fields on `ServiceRecord` or `Response`. They wrap the response:

```rust
/// A response with optional pipeline metadata.
#[derive(Debug, Serialize)]
pub struct PipelineResponse {
    #[serde(flatten)]
    pub body: Response,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<PipelineStatus>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PipelineStatus {
    Ongoing,
    Finished,
}
```

`#[serde(flatten)]` on the body means the JSON output is flat — `{"found": {...}, "status": "ongoing"}` — not nested. The `skip_serializing_if` on status/warning means clean responses have no extra keys. Absence is the happy path. This is critical to the protocol design.

---

## Core API shape

```rust
// core/mod.rs

pub struct MdnsCore {
    daemon: MdnsDaemon,          // owns the single mdns-sd ServiceDaemon
    registry: Registry,           // tracks our registrations
    event_bus: broadcast::Sender<ServiceEvent>,
}

impl MdnsCore {
    pub fn new() -> Result<Self>;
    pub fn browse(&self, service_type: &str) -> Result<BrowseHandle>;
    pub fn register(&self, def: RegisterPayload) -> Result<RegistrationResult>;
    pub fn unregister(&self, id: &str) -> Result<()>;
    pub fn resolve(&self, instance: &str) -> Result<ServiceRecord>;
    pub fn subscribe(&self) -> broadcast::Receiver<ServiceEvent>;
    pub fn shutdown(&self) -> Result<()>;
}
```

Adapters receive `Arc<MdnsCore>`. That's the only thing they touch.

**`BrowseHandle`** is a stream of `ServiceRecord` values. It wraps mdns-sd's flume `Receiver` and does the `ServiceInfo` → `ServiceRecord` conversion. When the handle is dropped, the browse stops. The core tracks active browses and cleans up.

**`ServiceEvent`** is what flows through the broadcast channel:

```rust
pub enum ServiceEvent {
    Found(ServiceRecord),
    Resolved(ServiceRecord),
    Removed { name: String, service_type: String },
}
```

This mirrors mdns-sd's `ServiceEvent` but uses our `ServiceRecord` — the conversion from mdns-sd's types happens once, in `daemon.rs`, at the boundary.

---

## The mdns-sd boundary

`core/daemon.rs` is the **only** file that imports `mdns_sd`. Nowhere else. This is the adapter around the engine:

```rust
use mdns_sd::{ServiceDaemon, ServiceInfo, ServiceEvent as MdnsEvent};

pub(crate) struct MdnsDaemon {
    inner: ServiceDaemon,
}
```

`pub(crate)` — visible to `core/` siblings, invisible to `adapters/`.

The conversion from `mdns_sd::ServiceInfo` to `ServiceRecord` lives here as a single function:

```rust
fn to_record(info: &ServiceInfo) -> ServiceRecord {
    ServiceRecord {
        name: info.get_fullname().to_string(),  // refine as needed
        service_type: info.get_type().to_string(),
        host: Some(info.get_hostname().to_string()),
        ip: info.get_addresses().iter().next().map(|a| a.to_string()),
        port: info.get_port(),
        txt: extract_txt(info),
    }
}
```

One place. One conversion. If mdns-sd's API changes, one file changes.

---

## Adapter contracts

Each adapter is a module with a `start` function:

```rust
// adapters/http.rs
pub async fn start(core: Arc<MdnsCore>, port: u16) -> Result<()>;

// adapters/pipe.rs
pub async fn start(core: Arc<MdnsCore>, path: PathBuf) -> Result<()>;

// adapters/cli.rs
pub async fn start(core: Arc<MdnsCore>) -> Result<()>;
```

That's the interface. Each one runs until shutdown. They don't return meaningful values — they run event loops.

### HTTP adapter notes

- Use Axum. Router with handlers that destructure into core calls.
- SSE for browse and subscribe (streaming responses).
- Regular JSON for register, unregister, resolve (request-response).
- CORS enabled by default.
- Keep it thin. A handler should be ~10 lines: extract params, call core, serialize response.

### Pipe adapter notes

- Windows: `\\.\pipe\koi` — use `tokio::net::windows::named_pipe`.
- Unix: `/var/run/koi.sock` — use `tokio::net::UnixListener`.
- Protocol: NDJSON (newline-delimited JSON). One JSON object per line.
- Same request/response types as HTTP, just different framing.
- Handle multiple concurrent connections.

### CLI adapter notes

- Read lines from stdin, parse as `Request`, write `Response` lines to stdout.
- Activate when stdin is a pipe (not a terminal), unless `--daemon` is set.
- This is the simplest adapter. It's also your best testing tool during development.
- Think `jq` composability: `echo '{"browse":"_http._tcp"}' | koi | jq '.found.name'`

---

## Error handling

Use `thiserror` for the core error type. One error enum:

```rust
#[derive(Debug, thiserror::Error)]
pub enum KoiError {
    #[error("Invalid service type: {0}")]
    InvalidServiceType(String),

    #[error("Registration not found: {0}")]
    RegistrationNotFound(String),

    #[error("Resolve timeout: {0}")]
    ResolveTimeout(String),

    #[error("mDNS daemon error: {0}")]
    Daemon(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
```

Adapters convert `KoiError` into `Response::Error` for serialization. The core never formats JSON error messages — it returns `Result<T, KoiError>`. The adapter handles presentation.

Do not use `anyhow` in library code (core, protocol). Use it only in `main.rs` for top-level orchestration if needed. Typed errors everywhere else.

---

## Startup and wiring — main.rs

`main.rs` is pure orchestration. No logic:

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::parse();            // clap
    tracing_subscriber::init();              // structured logging

    let core = Arc::new(MdnsCore::new()?);

    // spawn adapters based on config
    let mut tasks = Vec::new();

    if !config.no_http {
        let c = core.clone();
        tasks.push(tokio::spawn(async move {
            adapters::http::start(c, config.http_port).await
        }));
    }

    if !config.no_ipc {
        let c = core.clone();
        tasks.push(tokio::spawn(async move {
            adapters::pipe::start(c, config.pipe_path).await
        }));
    }

    if is_piped_stdin() {
        adapters::cli::start(core.clone()).await?;
        return Ok(());
    }

    platform::register_service()?;  // Windows SCM or systemd notify

    // wait for shutdown signal
    shutdown_signal().await;
    core.shutdown()?;
    Ok(())
}
```

Clean, readable, no domain logic. If this file grows past 60 lines, something is leaking up.

---

## Testing strategy

**Core tests — the majority.** Test core logic directly. No HTTP, no sockets, no serialization. Create `MdnsCore`, call methods, assert results. Mock or stub the mdns-sd daemon if needed for unit tests, but prioritize integration tests that use a real daemon on loopback.

**Protocol tests — serialization fidelity.** Verify that `Request` deserializes from the expected JSON shapes and `PipelineResponse` serializes to the expected flat JSON. These are your contract tests. If they break, every adapter breaks. Test the edge cases:
- Absent pipeline properties produce clean JSON (no `"status": null`)
- `#[serde(flatten)]` produces flat output, not nested
- Top-level verb keys work: `{"browse": "_http._tcp"}` not `{"action": "browse"}`

**Adapter tests — thin integration.** Verify transport plumbing only. Start the HTTP adapter, make a request, verify it reaches core and the response comes back. Don't test mDNS logic through HTTP — that's a core test.

**CLI adapter — your development REPL.** Build this first. You can test the entire core without standing up a server:
```bash
echo '{"browse":"_http._tcp"}' | cargo run
echo '{"register":{"name":"test","type":"_http._tcp","port":8080}}' | cargo run
```

---

## Code style guidance

**Idiomatic Rust, not "clever" Rust.** Prefer clarity over conciseness. A 5-line match is better than a 1-line chain of `.map().and_then().unwrap_or_else()` that nobody can read at a glance.

**Name things for what they are, not what they do.** `ServiceRecord`, not `ServiceDTO`. `Registry`, not `RegistrationManager`. `BrowseHandle`, not `BrowseStreamController`.

**No `impl From<X> for Y` unless the conversion is lossless, obvious, and used in more than one place.** One-off conversions are just functions. The `From` trait implies a canonical, universally-correct conversion — if it's context-dependent, make it a named function.

**Use `pub(crate)` liberally in core.** Internal types that sibling modules need but adapters shouldn't see. This is how you enforce the layer boundary without a workspace. Rust's visibility *is* the architecture enforcement.

**Avoid stringly-typed interfaces inside core.** Service types should be validated once at the boundary (adapter or protocol deserialization) and then carried as validated types. If `_http._tcp` is the only valid shape, make a newtype:

```rust
pub struct ServiceType(String);

impl ServiceType {
    pub fn parse(s: &str) -> Result<Self, KoiError> {
        // validate _name._tcp or _name._udp
    }
}
```

Adapters pass strings in from the outside world. Core works with validated types. Illegal states are unrepresentable past the boundary.

**Closures over traits for simple callbacks.** Don't build a `trait EventHandler` with one method when `impl Fn(ServiceEvent)` works. Traits are for when you need object safety, multiple implementations, or a named contract in your public API. For internal wiring, closures are cleaner.

---

## Dependencies — keep it tight

| Crate | Purpose | Required |
|---|---|---|
| `mdns-sd` | mDNS engine | yes |
| `axum` | HTTP server | yes (feature-gated if desired) |
| `tokio` | async runtime (`features = ["full"]`) | yes |
| `serde`, `serde_json` | serialization | yes |
| `clap` (`features = ["derive"]`) | CLI args | yes |
| `tracing`, `tracing-subscriber` | logging | yes |
| `thiserror` | error types | yes |
| `windows-service` | Windows SCM | Windows only |

Do not add:
- `anyhow` in library code (only main.rs if at all)
- `async-trait` (use `impl Future` or boxed futures if needed — Rust 1.75+ has RPITIT)
- `tower` layers unless you genuinely need middleware — start without it
- Any ORM, database, or persistence crate — Koi is in-memory only
- `protobuf`, `tonic`, `prost` — gRPC is explicitly deferred

Every dependency is an audit surface and a compile time cost. Be miserly.

---

## Cargo.toml shape

```toml
[package]
name = "koi-mdns"
version = "0.1.0"
edition = "2021"
description = "Cross-platform mDNS service discovery daemon with HTTP, IPC, and CLI interfaces"
license = "Apache-2.0 OR MIT"
repository = "https://github.com/sylin-org/koi"

[[bin]]
name = "koi"
path = "src/main.rs"

[dependencies]
mdns-sd = "0.17"
axum = "0.8"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
thiserror = "2"

[target.'cfg(windows)'.dependencies]
windows-service = "0.7"
```

---

## Build order — what to implement first

1. **`protocol/`** — Define `ServiceRecord`, `Request`, `Response`, `PipelineResponse`. Write serialization tests. This is your contract — everything else depends on it.

2. **`core/daemon.rs`** — Wrap `mdns-sd::ServiceDaemon`. Implement the `ServiceInfo` → `ServiceRecord` conversion. Get browse and register working against real multicast on your machine.

3. **`core/mod.rs` + `registry.rs` + `events.rs`** — The `MdnsCore` facade. Registration tracking. Broadcast fan-out. Test directly — no adapters yet.

4. **`adapters/cli.rs`** — stdin/stdout JSON lines. This is your REPL. Use it to test everything interactively. Build it early, lean on it constantly.

5. **`adapters/http.rs`** — Axum routes. SSE for browse/subscribe. JSON for register/unregister/resolve.

6. **`adapters/pipe.rs`** — Named pipe (Windows) or Unix socket. Same NDJSON protocol as CLI, different transport.

7. **`platform/`** — Windows Service and systemd integration. This is last because everything should work in foreground mode first.

8. **`config.rs` + `main.rs`** — Wire it all together. CLI parsing, startup logic, shutdown handling.

---

## Opinionated and self-managing

Koi should behave like infrastructure that takes care of itself. The user installs it, starts it, and forgets about it. If something goes wrong, Koi fixes it or tells the user exactly what to do. It does not silently fail, and it does not require babysitting.

### Firewall handling

On startup, Koi should check whether UDP 5353 (mDNS multicast) is reachable and whether its own TCP port is accessible. If not:

**Windows:** Check and create Windows Firewall rules automatically. Koi runs as a service with sufficient privileges. If it detects that UDP 5353 inbound is blocked, it should create a firewall rule (`netsh advfirewall firewall add rule name="Koi mDNS" ...`) and log that it did so. Same for its HTTP port. If creation fails (insufficient privileges in a non-service context), log a clear, actionable message:

```
WARN  Koi cannot receive mDNS traffic — UDP 5353 is blocked by Windows Firewall.
WARN  Run as administrator or execute:
WARN    netsh advfirewall firewall add rule name="Koi mDNS (UDP)" dir=in action=allow protocol=UDP localport=5353
WARN    netsh advfirewall firewall add rule name="Koi HTTP (TCP)" dir=in action=allow protocol=TCP localport=5641
```

**Linux:** Check with `ss` or by attempting a test bind. If UDP 5353 is already bound (Avahi, systemd-resolved), log clearly:

```
WARN  UDP port 5353 is already bound by process 'avahi-daemon' (pid 1234).
WARN  Koi can coexist (multicast sockets share), but if you experience issues:
WARN    sudo systemctl stop avahi-daemon
```

For `ufw`/`iptables`, don't auto-modify — Linux users expect to manage their own firewall. Instead, detect and advise:

```
WARN  UFW is active but UDP 5353 is not allowed. Run:
WARN    sudo ufw allow 5353/udp
```

### Network resilience

**Interface changes.** WiFi drops, Ethernet unplugs, VPN connects/disconnects. The mdns-sd crate handles most of this, but Koi should detect network interface changes and:
- Log when interfaces appear/disappear
- Re-announce all registered services on new interfaces
- Cleanly remove services from disappeared interfaces
- Not crash. Ever. A network going away is normal, not exceptional.

**Daemon recovery.** If the internal mdns-sd daemon thread panics or dies:
- Catch it
- Log the error at ERROR level with full context
- Restart the daemon automatically
- Re-register all services from the registry (the registry is the source of truth, the daemon is ephemeral)
- Increment a restart counter; if it exceeds a threshold (e.g. 5 restarts in 60 seconds), log a FATAL and stop retrying rather than spin-looping

```
ERROR mdns-sd daemon crashed: "socket bind failed: address already in use"
INFO  Restarting daemon (attempt 2/5)...
INFO  Re-registering 3 services...
INFO  Daemon recovered successfully.
```

**Stale registration cleanup.** If Koi shuts down uncleanly (SIGKILL, power loss, crash), registered services become stale in other devices' mDNS caches. On startup, Koi has no way to send goodbye packets for the previous instance's registrations. But it *can* detect name conflicts during re-registration (mdns-sd handles probing and conflict resolution per RFC 6762 §9). Log when this happens:

```
INFO  Registering "My App._http._tcp" — previous registration still cached on network
INFO  Probing... name accepted. Previous cache entries will expire within TTL (120s).
```

### Startup self-check

On startup, Koi should run a quick self-diagnostic and log the results:

```
INFO  Koi v0.1.0 starting
INFO  Platform: Windows 11 (23H2)
INFO  Network interfaces: Ethernet (192.168.1.42), Wi-Fi (disabled)
INFO  mDNS engine: mdns-sd v0.17.1
INFO  UDP 5353: ✓ bound successfully
INFO  TCP 5641: ✓ listening (HTTP adapter)
INFO  Named pipe: ✓ \\.\pipe\koi
INFO  Firewall: ✓ UDP 5353 allowed, TCP 5641 allowed
INFO  Ready.
```

Or when things aren't right:

```
INFO  Koi v0.1.0 starting
INFO  Platform: Ubuntu 24.04
INFO  Network interfaces: eth0 (192.168.1.42), docker0 (172.17.0.1)
WARN  UDP 5353: bound (shared with avahi-daemon pid 892)
INFO  TCP 5641: ✓ listening (HTTP adapter)
INFO  Unix socket: ✓ /var/run/koi.sock
WARN  Firewall: UFW active, UDP 5353 not explicitly allowed (may work via existing rules)
INFO  Ready (with warnings).
```

This is not optional polish — it's the difference between a tool that's debuggable in 5 seconds and one that wastes an hour of the user's time.

### Service type normalization

Users will send `"http"`, `"_http._tcp"`, `"_http._tcp."`, `"_http._tcp.local."`, and `"_http._tcp.local"`. All meaning the same thing. Koi should normalize, not reject:

- No leading `_`? Prepend it: `http` → `_http`
- No protocol suffix? Assume `._tcp`: `_http` → `_http._tcp`
- No trailing `.local.`? Append it internally (the wire needs it, the user shouldn't care)

Log the normalization at DEBUG level so it's traceable but not noisy:

```
DEBUG Normalized service type: "http" → "_http._tcp.local."
```

Be strict on output — always emit the canonical form in responses. Be liberal on input. Postel's Law.

### Health self-check

Periodically verify the mDNS daemon is actually working — don't wait for a user to report "nothing is being discovered." On startup, register a temporary `_koi._tcp` service, browse for it, confirm it appears, then deregister. This validates the entire pipeline in under a second. If it fails, Koi knows multicast is broken before any real traffic hits.

At runtime, a background heartbeat can browse for Koi's own service registration periodically. If the daemon is hung (thread deadlock, socket error), Koi detects it internally and triggers recovery — not after a user files a bug.

### Operational logging

Log levels should be meaningful, not ceremonial:

| Level | What goes here |
|---|---|
| `error` | Something broke that Koi couldn't auto-fix (daemon panic with max retries, port bind failure) |
| `warn` | Something Koi worked around but the operator should know (firewall issue, interface down, re-announcement) |
| `info` | Lifecycle events only: startup, shutdown, service registered/unregistered, interface changes |
| `debug` | Request/response flow, input normalization, browse results |
| `trace` | mDNS packet-level detail, daemon channel traffic |

Default level: `info`. During normal healthy operation, Koi should be **silent**. If it's emitting logs constantly at info level, the levels are wrong.

### Automatic recovery summary

| Failure | Koi's response |
|---|---|
| Network interface disappears | Log, continue, re-announce when it returns |
| mdns-sd daemon crashes | Restart, re-register from registry, log |
| Firewall blocks mDNS (Windows) | Auto-create rules if privileged, advise if not |
| Firewall blocks mDNS (Linux) | Detect and advise, don't auto-modify |
| Port already bound (TCP) | Fail with clear message naming the conflicting process |
| Port shared (UDP multicast) | Coexist, log the other process |
| Unclean prior shutdown | Re-register, let probing handle conflicts, log |
| Service type malformed | Normalize, log the transformation |
| Oversized TXT record | Warn, truncate or reject with explanation |

---

## Things that will bite you

**mdns-sd's `ServiceDaemon` thread.** It spawns its own thread. You don't need to — and shouldn't — run it inside a tokio task. Create it on the main thread, communicate via the flume channels it gives you. Use `recv_async()` to bridge into tokio's async world.

**Service type validation.** Covered thoroughly in the self-management section — Koi normalizes input automatically. But be aware that the `mdns-sd` crate may have its own validation that rejects inputs Koi hasn't normalized yet. Always normalize *before* passing to the crate.

**TXT record encoding.** mDNS TXT records are key=value pairs with a 255-byte-per-entry limit. The `mdns-sd` crate handles the wire encoding, but be aware that large TXT payloads will be silently truncated or rejected by the protocol. Validate or warn on oversized values.

**Windows firewall.** Covered in the self-management section above — Koi should detect and diagnose this automatically, not leave it as a gotcha for the user.

**Graceful shutdown ordering.** Shut down adapters first (stop accepting new requests), then tell core to unregister all services (sends goodbye packets), then stop the mdns-sd daemon. If you kill the daemon first, goodbye packets never send and stale services persist in other devices' caches for the TTL duration.

**SSE connection lifecycle.** When a client disconnects from an SSE stream (browse or subscribe), clean up the associated browse handle in core. If you leak handles, you leak mdns-sd browse queries. Axum's SSE support with `tokio::sync::broadcast` handles this naturally if you set it up right — the receiver drops when the connection closes.

**Multiple IPs.** A resolved service may have multiple IP addresses (IPv4 and IPv6, or multiple interfaces). The `ServiceRecord.ip` field is a single optional string for simplicity in v1. Pick the first IPv4 address. If there's no IPv4, pick the first IPv6. Log the others. Don't silently discard information without at least a trace-level log.

---

## What "done" looks like for v1

- [ ] `echo '{"browse":"_http._tcp"}' | koi` discovers services on the LAN
- [ ] `echo '{"register":{"name":"test","type":"_http._tcp","port":9999}}' | koi` makes a service visible to Avahi/Bonjour/dns-sd on other machines
- [ ] `curl localhost:5641/v1/browse?type=_http._tcp` streams SSE events
- [ ] `curl -X POST localhost:5641/v1/services -d '{...}'` registers a service
- [ ] Pipeline properties (`status`, `warning`) appear only when relevant
- [ ] Runs as a Windows Service via `koi install` / `koi uninstall`
- [ ] Runs as a systemd service via the provided unit file
- [ ] Clean shutdown sends goodbye packets for all registered services
- [ ] Unix socket / Named Pipe accepts NDJSON connections
- [ ] Container on the same host can browse via `http://172.17.0.1:5641`
- [ ] Startup self-test verifies mDNS multicast, HTTP port, and IPC path
- [ ] Firewall issues detected and diagnosed with actionable fix commands
- [ ] Network interface changes handled without restart (re-announcement)
- [ ] Service type input normalized (`http` → `_http._tcp.local.`)
- [ ] Daemon thread panic caught, logged, and auto-recovered
- [ ] Info-level logs are quiet during normal operation

---

## Philosophy

This is a small tool that solves a real problem. The entire codebase should be readable in an afternoon. If any single file exceeds 300 lines, it probably needs splitting. If any function exceeds 30 lines, it probably needs decomposition.

No abstractions for their own sake. No traits with one implementor. No `Builder` pattern for a struct with three fields. No `Arc<Mutex<HashMap<String, Box<dyn Any>>>>`. The types should be obvious. The flow should be traceable by reading `main.rs` and following the calls.

The test suite is as important as the implementation. A passing test suite should give full confidence that the JSON protocol works, the core logic is correct, and the mdns-sd integration is functional. Tests are documentation. Name them descriptively:

```rust
#[test]
fn browse_response_omits_status_when_fully_resolved() { ... }

#[test]
fn register_returns_opaque_id_for_lifecycle_management() { ... }

#[test]
fn unregister_nonexistent_id_returns_not_found_error() { ... }
```

Build something you'd want to use. Build something you'd enjoy reading six months from now.

—Claude
