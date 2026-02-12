# Koi v0.2 — Leases & Admin

**Depends on:** v0.1 codebase (commit 9712692)
**Scope:** Registration lifecycle, admin introspection, dual-mode binary
**Breaks:** `RegisterPayload` and `RegistrationResult` gain fields. `core.register()` replaced by `register_with_policy()`. Registry rewritten. All adapter registration call sites updated.

---

## What this solves

**Ghost services.** v0.1 registrations are permanent. A process crashes, its service stays advertised on the network. With multiple Moss stones, ghosts accumulate fast. Leases make registrations mortal — the registrant must prove it's alive, or Koi reclaims the registration and sends goodbye packets.

**Blind operator.** No way to inspect the running daemon. Admin commands talk to the daemon over its own HTTP API: what's registered, what's draining, what happened and why.

These intersect — the admin needs to see and manage lease state. One feature, not two.

---

## Domain model

### Lease modes

Every registration has a lease mode that determines how it proves liveness.

| Mode | Mechanism | Default for |
|---|---|---|
| **Session** | Connection open = alive. Drop = grace starts. | Pipe, UDS, CLI stdin |
| **Heartbeat** | Client sends periodic PUT. Miss = grace starts. | HTTP API |
| **Permanent** | Lives until explicit removal or shutdown. | `"lease": 0` from any transport |

The **adapter picks the default**. This is the central design principle: pipe connections are inherently session-bound (the OS tells you when they drop), HTTP is stateless (heartbeats are the only liveness signal), and permanent is an explicit opt-in. The client can override with `"lease": N` in the register payload.

### Adapter defaults

| Transport | Mode | Lease | Grace | Why |
|---|---|---|---|---|
| Pipe / UDS | session | — | 30s | Connection drop = instant signal. OS does the heartbeat. |
| CLI stdin | session | — | 5s | stdin close = process died. Short grace — user action is explicit. |
| HTTP POST | heartbeat | 90s | 30s | Stateless. No connection to monitor. |
| Any, `"lease": 0` | permanent | ∞ | — | Explicit opt-in. Lives until DELETE or shutdown. |

### Registration lifecycle

```
                   register
                      │
                      ▼
                  ┌────────┐
         ┌───────│  ALIVE  │◄──── heartbeat / connection open / revive
         │       └────┬────┘
         │            │ heartbeat missed / connection dropped / admin drain
         │            ▼
         │       ┌──────────┐
         │       │ DRAINING │──── grace timer running
         │       └────┬─────┘         ▲
         │            │               │ heartbeat resumes / session reconnects
         │            ▼
         │       ┌─────────┐
         │       │ EXPIRED │──── goodbye sent, removed
         │       └─────────┘
         │
         │  unregister / admin force-unregister / shutdown
         ▼
    ┌──────────┐
    │ REMOVED  │──── goodbye sent immediately
    └──────────┘
```

**ALIVE** — Healthy. Heartbeats arriving or connection open. Advertised on network.

**DRAINING** — Liveness signal lost. Grace timer running. If the registrant comes back within grace, returns to ALIVE with no network-visible interruption. This absorbs container restarts, rolling deploys, and transient disconnects.

**EXPIRED** — Grace elapsed. Reaper sends goodbye packets, removes from registry. Terminal.

**REMOVED** — Explicit unregister or admin force-remove. Goodbye sent immediately. Terminal.

Permanent registrations stay ALIVE until explicit removal or shutdown. The reaper ignores them.

### Session reconnection

When a new registration arrives and a **DRAINING** entry matches by name + service type:

1. The existing entry is **revived** — state → ALIVE, `last_seen` reset
2. The **new session** takes ownership
3. The **new payload** wins — if port or TXT changed, Koi updates the mdns-sd daemon (unregister old, re-register new; same registry ID)
4. The **old registration ID** is returned to the caller

This prevents duplicate mDNS entries during container restarts within the grace period. The network sees continuity — the advertisement was never withdrawn.

If the existing entry is ALIVE (not draining) and belongs to a different session, both registrations proceed independently. The mdns-sd daemon resolves the name conflict per RFC 6762 §9.

### The reaper

A background task, spawned at `MdnsCore` construction. Ticks every 5 seconds.

Each tick, single-pass sweep:
1. Heartbeat entries past lease deadline → transition to DRAINING (grace starts now)
2. Draining entries past grace deadline → collect for removal
3. For each collected entry → send goodbye via daemon, remove from registry

Silent when nothing transitions. Logs at INFO only when something actually expires.

The 5-second tick is appropriate: mDNS TTLs are 120s, so the reaper's granularity is imperceptible. Going faster is wasteful. Going slower makes grace feel imprecise.

### Unregister reasons

Every path that removes a registration logs a structured `reason` field:

| Reason | Trigger |
|---|---|
| `explicit` | Client called unregister |
| `session_expired` | Session grace elapsed |
| `heartbeat_expired` | Heartbeat grace elapsed |
| `admin_force` | Admin force-unregister |
| `shutdown` | Daemon shutting down |

```
INFO  Service unregistered: name="stone-coral" id="d4e5f6a7" reason=session_expired session=pipe:a3c1
```

Trivial to add during implementation. Invaluable for "why did that service disappear at 3am?"

---

## Architecture

v0.2 extends v0.1's layered architecture. No new layers — the existing boundaries hold. The registry becomes a lifecycle engine, adapters gain session awareness, and two new application-layer modules handle client-mode commands and admin operations.

```
src/
├── main.rs                  Composition root, mode detection, breadcrumb
├── config.rs                CLI parsing
├── format.rs                Human-readable output
│
├── core/                    ── Domain ──
│   ├── mod.rs               MdnsCore facade (+ reaper, admin queries, session lifecycle)
│   ├── daemon.rs            mdns-sd wrapper (unchanged)
│   ├── events.rs            Network events (unchanged)
│   └── registry.rs          Registration lifecycle engine (REWRITE)
│
├── protocol/                ── Wire contract ──
│   ├── mod.rs               Shared types (+ LeaseMode, AdminRegistration)
│   ├── request.rs           Inbound parsing (+ Heartbeat)
│   ├── response.rs          Outbound serialization (+ Renewed)
│   └── error.rs             Error codes + HTTP status mapping (NEW)
│
├── adapters/                ── Transport ──
│   ├── http.rs              HTTP/SSE (+ heartbeat endpoint, admin routes)
│   ├── pipe.rs              Named pipe / UDS (+ session lifecycle)
│   └── cli.rs               stdin/stdout NDJSON (+ session lifecycle)
│
├── commands/                ── Application services ──
│   ├── mod.rs               Shared helpers (effective_timeout, parse_txt)
│   ├── standalone.rs        Standalone verb handlers (from commands.rs)
│   └── client.rs            Client-mode verb handlers (NEW)
│
├── admin.rs                 Admin command handlers (NEW)
├── client.rs                KoiClient HTTP client (NEW)
│
└── platform/                OS-specific (unchanged)
```

### What changes per layer

| Layer | Changes |
|---|---|
| **Domain** | Registry rewrite (lifecycle engine). MdnsCore gains `register_with_policy()`, `heartbeat()`, `session_disconnected()`, admin queries. Reaper task spawned at construction. ID generation moves from daemon to core. |
| **Protocol** | `LeaseMode` enum. `lease` field on RegisterPayload and RegistrationResult. `AdminRegistration` struct. `Heartbeat` request variant. `Renewed` response variant. Error codes extracted to `error.rs`. |
| **Adapters** | HTTP: heartbeat endpoint, 6 admin endpoints, policy-based register. Pipe/CLI: session IDs, `session_disconnected()` on connection close, heartbeat handling. |
| **Application** | `commands.rs` splits into `commands/standalone.rs` + `commands/client.rs`. New `admin.rs` for admin command handlers. |
| **Infrastructure** | New `client.rs` (KoiClient via ureq). Breadcrumb file management in `main.rs`. |

**Unchanged:** `daemon.rs` (doesn't know about leases — it registers and unregisters), `events.rs` (network observations, orthogonal to registration lifecycle), `platform/`.

### Dependency changes

```toml
[dependencies]
ureq = "3"                                           # HTTP client for CLI-as-client mode
tokio-util = { version = "0.7", features = ["rt"] }  # CancellationToken for shutdown
```

---

## Registry rewrite

`src/core/registry.rs` — from simple `Mutex<HashMap<String, RegisterPayload>>` to lifecycle engine. This is the heart of v0.2.

### Types

```rust
/// Unique identifier for a connection/session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

/// How a registration proves it's alive.
#[derive(Debug, Clone)]
pub enum LeasePolicy {
    /// Tied to a connection. Grace period starts when connection drops.
    Session { grace: Duration },
    /// Client must heartbeat within lease duration. Grace after miss.
    Heartbeat { lease: Duration, grace: Duration },
    /// Lives forever. Only explicit removal or shutdown.
    Permanent,
}

/// Current lifecycle state.
#[derive(Debug, Clone)]
pub enum RegistrationState {
    Alive,
    Draining { since: Instant },
}

/// A tracked registration with full lifecycle metadata.
pub struct Registration {
    pub payload: RegisterPayload,
    pub state: RegistrationState,
    pub policy: LeasePolicy,
    pub last_seen: Instant,
    pub session_id: Option<SessionId>,
    pub registered_at: SystemTime,
}
```

### Methods

```rust
impl Registry {
    /// Insert a new registration, or reconnect to a DRAINING entry
    /// that matches by name + service type. Atomic under the lock.
    pub fn insert_or_reconnect(
        &self,
        new_id: String,
        payload: RegisterPayload,
        policy: LeasePolicy,
        session_id: Option<SessionId>,
    ) -> InsertOutcome;

    /// Remove a registration (explicit unregister). Returns its payload
    /// so the caller can send goodbye packets.
    pub fn remove(&self, id: &str) -> Result<RegisterPayload>;

    /// Record a heartbeat. Resets last_seen. Revives if DRAINING.
    pub fn heartbeat(&self, id: &str) -> Result<()>;

    /// Mark all registrations for a session as DRAINING.
    /// Returns IDs that transitioned.
    pub fn drain_session(&self, session_id: &SessionId) -> Vec<String>;

    /// Admin: force-drain a specific registration.
    pub fn force_drain(&self, id: &str) -> Result<()>;

    /// Admin: force-revive a DRAINING registration.
    pub fn force_revive(&self, id: &str) -> Result<()>;

    /// Sweep for expired registrations. Single-pass retain().
    /// Transitions missed heartbeats Alive → Draining.
    /// Collects grace-expired entries and removes them.
    /// Returns (id, payload) pairs that need goodbye packets.
    pub fn reap(&self) -> Vec<(String, RegisterPayload)>;

    /// Resolve a partial ID to a full ID. Errors if ambiguous or not found.
    pub fn resolve_prefix(&self, prefix: &str) -> Result<String>;

    /// Snapshot all registrations for admin display.
    pub fn snapshot(&self) -> Vec<(String, AdminRegistration)>;

    /// Snapshot one registration for admin display.
    pub fn snapshot_one(&self, id: &str) -> Result<AdminRegistration>;

    /// Counts by state (for admin status).
    pub fn counts(&self) -> RegistrationCounts;
}

pub enum InsertOutcome {
    /// Fresh registration. Used the provided new_id.
    New { id: String },
    /// Revived a DRAINING entry. Returns the old entry's ID and payload
    /// so the caller can update the daemon if the payload changed.
    Reconnected { id: String, old_payload: RegisterPayload },
}
```

### Reap algorithm

The critical method. Both detects missed heartbeats (Alive → Draining) and collects expired entries (Draining → removed) in a single `retain()` pass:

```rust
pub fn reap(&self) -> Vec<(String, RegisterPayload)> {
    let now = Instant::now();
    let mut expired = Vec::new();
    let mut registrations = self.registrations.lock().unwrap();

    registrations.retain(|id, reg| {
        match (&reg.state, &reg.policy) {
            // Permanent — never expires
            (_, LeasePolicy::Permanent) => true,

            // Session, alive — connection still open
            (RegistrationState::Alive, LeasePolicy::Session { .. }) => true,

            // Draining — check grace (both session and heartbeat)
            (RegistrationState::Draining { since }, LeasePolicy::Session { grace })
            | (RegistrationState::Draining { since }, LeasePolicy::Heartbeat { grace, .. }) => {
                if now.duration_since(*since) >= *grace {
                    expired.push((id.clone(), reg.payload.clone()));
                    false
                } else {
                    true
                }
            }

            // Heartbeat, alive — check if lease expired
            (RegistrationState::Alive, LeasePolicy::Heartbeat { lease, .. }) => {
                if now.duration_since(reg.last_seen) >= *lease {
                    // Transition to draining; grace starts now
                    reg.state = RegistrationState::Draining { since: now };
                }
                true
            }
        }
    });

    expired
}
```

### `insert_or_reconnect` logic

Under the lock:
1. Scan for a DRAINING entry matching `payload.name` + `payload.service_type`
2. If found: revive it (state → Alive, update payload/session/policy/last_seen), return `Reconnected` with the old payload
3. If not found: insert new entry under `new_id`, return `New`

The old payload is returned so the caller (MdnsCore) can decide whether to update the mdns-sd daemon — only needed if port or TXT changed.

### `remaining_secs` computation (for admin snapshots)

```rust
fn remaining_secs(reg: &Registration, now: Instant) -> Option<u64> {
    match (&reg.state, &reg.policy) {
        (RegistrationState::Alive, LeasePolicy::Heartbeat { lease, .. }) => {
            let deadline = reg.last_seen + *lease;
            Some(deadline.saturating_duration_since(now).as_secs())
        }
        (RegistrationState::Draining { since }, LeasePolicy::Session { grace })
        | (RegistrationState::Draining { since }, LeasePolicy::Heartbeat { grace, .. }) => {
            let deadline = *since + *grace;
            Some(deadline.saturating_duration_since(now).as_secs())
        }
        _ => None,
    }
}
```

---

## Core changes

### MdnsCore

```rust
pub struct MdnsCore {
    daemon: Arc<MdnsDaemon>,
    registry: Arc<Registry>,    // Arc for sharing with reaper
    event_tx: broadcast::Sender<ServiceEvent>,
    started_at: Instant,        // for uptime
}
```

### New methods

| Method | Purpose |
|---|---|
| `register_with_policy(payload, policy, session_id)` | The single registration entry point. Every adapter calls this — no convenience wrapper. |
| `heartbeat(id)` | Delegates to registry |
| `session_disconnected(session_id)` | Drains all registrations for a session |
| `admin_status()` | Version, uptime, registration counts |
| `admin_registrations()` | Snapshot all |
| `admin_inspect(id)` | Snapshot one (prefix match via registry) |
| `admin_force_unregister(id)` | Remove + goodbye |
| `admin_drain(id)` | Force-drain |
| `admin_revive(id)` | Force-revive |

### ID generation moves from daemon to core

`daemon.register()` changes from `Result<String>` to `Result<()>`. It registers with mdns-sd and returns success/failure. The registration ID is a core concern — generated as the first 8 hex characters of a UUID v4 (`&Uuid::new_v4().to_string()[..8]`). No new dependency; `uuid` is already in Cargo.toml.

The daemon layer stays pure infrastructure — it doesn't know about IDs, leases, or lifecycle.

### register_with_policy flow

```rust
pub fn register_with_policy(
    &self,
    payload: RegisterPayload,
    policy: LeasePolicy,
    session_id: Option<SessionId>,
) -> Result<RegistrationResult> {
    let st = ServiceType::parse(&payload.service_type)?;
    let new_id = generate_short_id();

    let outcome = self.registry.insert_or_reconnect(
        new_id, payload.clone(), policy.clone(), session_id,
    );

    match &outcome {
        InsertOutcome::New { .. } => {
            self.daemon.register(
                &payload.name, st.as_str(), payload.port, &payload.txt,
            )?;
        }
        InsertOutcome::Reconnected { old_payload, .. } => {
            // Only touch the daemon if the payload actually changed
            if old_payload.port != payload.port || old_payload.txt != payload.txt {
                let _ = self.daemon.unregister(&old_payload.name, st.as_str());
                self.daemon.register(
                    &payload.name, st.as_str(), payload.port, &payload.txt,
                )?;
            }
        }
    }

    let id = outcome.id().to_string();
    let (lease_secs, mode) = match &policy {
        LeasePolicy::Session { .. } => (0, LeaseMode::Session),
        LeasePolicy::Heartbeat { lease, .. } => (lease.as_secs(), LeaseMode::Heartbeat),
        LeasePolicy::Permanent => (0, LeaseMode::Permanent),
    };

    Ok(RegistrationResult { id, name: payload.name, service_type: st.short().into(),
        port: payload.port, lease: lease_secs, mode })
}
```

### Reaper task

Spawned in `MdnsCore::new()`:

```rust
let reaper_registry = registry.clone();
let reaper_daemon = daemon.clone();
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let expired = reaper_registry.reap();
        for (id, payload) in &expired {
            tracing::info!(
                name = %payload.name, id,
                reason = "expired",
                "Service unregistered"
            );
            if let Ok(st) = ServiceType::parse(&payload.service_type) {
                let _ = reaper_daemon.unregister(&payload.name, st.as_str());
            }
        }
    }
});
```

---

## Dual-mode binary

v0.1 creates a fresh `MdnsCore` per subcommand. That works for one-shot discovery, but `koi admin registrations` needs the **running daemon's** state, not a blank core.

```
koi --daemon          → I AM the daemon
koi install/uninstall → Platform service management
koi browse/register   → Use daemon if available, else standalone
koi admin ...         → Always talks to the daemon. Fails if none running.
```

### Mode detection — breadcrumb first

```rust
enum ExecutionMode {
    Client { endpoint: String },
    Standalone,
}
```

Detection uses the breadcrumb file to avoid latency on every invocation:

1. `--standalone` flag → Standalone (bypass everything)
2. Read breadcrumb file → not found → Standalone (**<1ms**)
3. Breadcrumb found → check PID alive → dead → delete stale breadcrumb, Standalone
4. PID alive → HTTP probe `/healthz` (200ms timeout) → responds → Client
5. Probe fails → Standalone

The common case (no daemon running) pays <1ms. The 200ms probe only runs when there's strong evidence a daemon exists.

### Breadcrumb file

Written on daemon startup, deleted on clean shutdown.

- Windows: `%ProgramData%\koi\daemon.json`
- Linux: `/var/run/koi/daemon.json`

```json
{"endpoint": "http://0.0.0.0:5641", "pid": 4821, "started_at": "2026-02-07T20:00:00Z"}
```

~15 lines. Stale files (dead PID) are detected and cleaned up during mode detection.

### KoiClient

New module: `src/client.rs`. Pure infrastructure — HTTP calls only, no interactive behavior.

Uses `ureq` 3.x: blocking, no TLS needed (localhost), doesn't pull in tokio for the client path. The daemon path still uses tokio + axum. Clean separation.

```rust
pub struct KoiClient {
    endpoint: String,
    agent: ureq::Agent,
}
```

Methods mirror the HTTP API surface:

| Method | HTTP call |
|---|---|
| `health()` | GET /healthz (200ms timeout) |
| `register(payload)` | POST /v1/mdns/services |
| `unregister(id)` | DELETE /v1/mdns/services/{id} |
| `heartbeat(id)` | PUT /v1/mdns/services/{id}/heartbeat |
| `resolve(instance)` | GET /v1/mdns/resolve?name=... |
| `browse_stream(type)` | GET /v1/mdns/browse?type=... (SSE) |
| `admin_status()` | GET /v1/mdns/admin/status |
| `admin_registrations()` | GET /v1/mdns/admin/registrations |
| `admin_inspect(id)` | GET /v1/mdns/admin/registrations/{id} |
| `admin_force_unregister(id)` | DELETE /v1/mdns/admin/registrations/{id} |
| `admin_drain(id)` | POST /v1/mdns/admin/registrations/{id}/drain |
| `admin_revive(id)` | POST /v1/mdns/admin/registrations/{id}/revive |

SSE parsing: line-by-line BufReader, strip `data: ` prefix, parse JSON. Koi-specific — handles only our single-line data format.

### Client-mode register

POST → heartbeat loop → Ctrl+C → DELETE:

```
1. POST /v1/mdns/services → RegistrationResult (includes lease duration)
2. Spawn heartbeat thread (PUT at lease/2 interval)
3. Wait for Ctrl+C
4. DELETE /v1/mdns/services/{id}
5. Exit
```

The heartbeat thread stops on 404 (registration gone — admin force-removed, or daemon restarted). Prints a message and exits. Re-registration on daemon restart is out of scope for v0.2 — the client should be restarted.

### CLI flags

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--endpoint` | `KOI_ENDPOINT` | from breadcrumb | Daemon endpoint for client/admin mode |
| `--standalone` | — | off | Force standalone (skip daemon detection) |

---

## Admin surface

All admin commands are client-mode only. They fail fast with a clear message if no daemon is running:

```
$ koi admin status
Error: Koi daemon is not running at http://localhost:5641
Start it with: koi --daemon
```

### CLI commands

**`koi admin status`**

```
Koi v0.2.0 — running (pid 4821)
Uptime:        2h 14m
HTTP:          0.0.0.0:5641
IPC:           \\.\pipe\koi

Registrations: 3 alive, 1 draining, 0 permanent
```

**`koi admin registrations`**

```
ID        NAME                    TYPE           PORT  MODE       STATE     REMAINING
a1b2c3d4  stone-golden-summit     _moss._tcp     7185  session    alive     —
d4e5f6a7  stone-coral-prairie     _moss._tcp     7185  session    draining  18s
g7h8i9b0  my-web-app              _http._tcp     8080  heartbeat  alive     72s
j0k1l2c3  permanent-service       _http._tcp     9090  permanent  alive     —
```

**`koi admin inspect <id>`** — Detailed view. Supports prefix matching (the git pattern: `koi admin inspect a1b` works if unambiguous).

```
Registration a1b2c3d4
  Name:       stone-golden-summit
  Type:       _moss._tcp
  Port:       7185
  Mode:       session
  State:      alive
  Session:    pipe:f7e2
  Grace:      30s
  Registered: 2026-02-07T22:15:00Z (2h ago)
  Last seen:  2026-02-07T22:15:00Z
  TXT:
    stone_id = 0ca30580-a363-58e7-88ed-050f9561393d
    mac = 00:80:64:C7:66:51
```

**`koi admin unregister <id>`** — Force-remove. Sends goodbye immediately regardless of state.

**`koi admin drain <id>`** — Force into DRAINING. Starts grace timer.

**`koi admin revive <id>`** — Cancel a drain. Back to ALIVE.

All admin commands support `--json` for machine-readable output.

### HTTP endpoints

| Method | Path | Description |
|---|---|---|
| `PUT` | `/v1/mdns/services/{id}/heartbeat` | Renew lease |
| `GET` | `/v1/mdns/admin/status` | Daemon overview |
| `GET` | `/v1/mdns/admin/registrations` | List all with lease state |
| `GET` | `/v1/mdns/admin/registrations/{id}` | Inspect (prefix match) |
| `DELETE` | `/v1/mdns/admin/registrations/{id}` | Force-unregister |
| `POST` | `/v1/mdns/admin/registrations/{id}/drain` | Force-drain |
| `POST` | `/v1/mdns/admin/registrations/{id}/revive` | Revive |

The `/v1/mdns/admin/` namespace is a boundary — future auth/ACL can gate it separately from `/v1/mdns/services/`.

### Config

```rust
#[derive(Subcommand)]
pub enum Command {
    // ... existing: Install, Uninstall, Browse, Register, Unregister, Resolve, Subscribe ...

    /// Admin commands for the running Koi daemon
    Admin {
        #[command(subcommand)]
        action: AdminCommand,
    },
}

#[derive(Subcommand)]
pub enum AdminCommand {
    Status,
    Registrations,
    Inspect { id: String },
    Unregister { id: String },
    Drain { id: String },
    Revive { id: String },
}
```

---

## Wire protocol delta

### Register request — new optional field

```json
{"register": {"name": "App", "type": "_http._tcp", "port": 8080, "lease": 120}}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `lease` | integer, optional | adapter decides | Seconds. `0` = permanent. Absent = adapter default. |

Backward compatible: v0.1 payloads without `lease` work unchanged.

### Register response — new fields

```json
{"registered": {"id": "a1b2c3d4", "name": "App", "type": "_http._tcp", "port": 8080, "lease": 90, "mode": "heartbeat"}}
```

New: `lease` (effective duration; 0 for session/permanent) and `mode` (`"session"` | `"heartbeat"` | `"permanent"`).

### Heartbeat — new verb

```json
→ {"heartbeat": "a1b2c3d4"}
← {"renewed": "a1b2c3d4", "lease": 90}
```

HTTP: `PUT /v1/mdns/services/{id}/heartbeat`
- 200 → lease renewed, keep going
- 404 → registration gone, stop heartbeating

### Admin responses

**Status:**

```json
{"version": "0.2.0", "uptime_secs": 8040, "platform": "windows",
 "registrations": {"alive": 3, "draining": 1, "permanent": 0, "total": 4}}
```

**Admin registration:**

```json
{"id": "a1b2c3d4", "name": "stone-golden-summit", "type": "_moss._tcp", "port": 7185,
 "mode": "session", "state": "alive", "lease_secs": null, "remaining_secs": null,
 "grace_secs": 30, "session_id": "pipe:f7e2",
 "registered_at": "2026-02-07T22:15:00Z", "last_seen": "2026-02-07T22:15:00Z",
 "txt": {"stone_id": "0ca30580-..."}}
```

### Error format

Unchanged from v0.1: `{"error": "code", "message": "human text"}`.

New error codes for v0.2:

| Code | HTTP | When |
|---|---|---|
| `already_draining` | 409 | Admin drain on already-draining entry |
| `not_draining` | 409 | Admin revive on non-draining entry |
| `ambiguous_id` | 400 | ID prefix matches multiple registrations |

Existing codes unchanged: `invalid_type` (400), `not_found` (404), `resolve_timeout` (504), `daemon_error` (500), `io_error` (500).

All error code strings and their HTTP status mappings move to `protocol/error.rs` — one source of truth, shared by all adapters. Define once before adding 6 admin endpoints, not after.

### Protocol types

```rust
/// How a registration stays alive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LeaseMode {
    Session,
    Heartbeat,
    Permanent,
}

/// Full registration state as exposed to admin queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRegistration {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub port: u16,
    pub mode: LeaseMode,
    pub state: String,              // "alive" | "draining"
    pub lease_secs: Option<u64>,
    pub remaining_secs: Option<u64>,
    pub grace_secs: u64,
    pub session_id: Option<String>,
    pub registered_at: String,      // ISO 8601
    pub last_seen: String,          // ISO 8601
    pub txt: HashMap<String, String>,
}

pub struct DaemonStatus {
    pub version: String,
    pub uptime_secs: u64,
    pub platform: String,
    pub registrations: RegistrationCounts,
}

pub struct RegistrationCounts {
    pub alive: usize,
    pub draining: usize,
    pub permanent: usize,
    pub total: usize,
}
```

---

## Adapter changes

### HTTP (`adapters/http.rs`)

Register handler constructs policy from payload:

```rust
let policy = match payload.lease {
    Some(0) => LeasePolicy::Permanent,
    Some(secs) => LeasePolicy::Heartbeat {
        lease: Duration::from_secs(secs),
        grace: Duration::from_secs(30),
    },
    None => LeasePolicy::Heartbeat {
        lease: Duration::from_secs(90),
        grace: Duration::from_secs(30),
    },
};
core.register_with_policy(payload, policy, None)
```

New routes:

```rust
.route("/v1/mdns/services/{id}/heartbeat", put(heartbeat_handler))
.route("/v1/admin/status", get(admin_status_handler))
.route("/v1/admin/registrations", get(admin_registrations_handler))
.route("/v1/admin/registrations/{id}", get(admin_inspect_handler))
.route("/v1/admin/registrations/{id}", delete(admin_force_unregister_handler))
.route("/v1/admin/registrations/{id}/drain", post(admin_drain_handler))
.route("/v1/admin/registrations/{id}/revive", post(admin_revive_handler))
```

Admin handlers are thin wrappers — each is ~5 lines: extract params → call core → serialize.

### Pipe (`adapters/pipe.rs`)

Create a `SessionId` at connection start. Register with session policy. Call `session_disconnected` when the handler returns, regardless of clean close or error:

```rust
async fn handle_connection(core: Arc<MdnsCore>, stream: ...) -> anyhow::Result<()> {
    let session = SessionId(format!("pipe:{}", &Uuid::new_v4().to_string()[..4]));
    let result = handle_session(&core, &session, stream).await;
    core.session_disconnected(&session);
    result
}
```

Inside request handling, register with session policy:

```rust
Request::Register(payload) => {
    let policy = match payload.lease {
        Some(0) => LeasePolicy::Permanent,
        _ => LeasePolicy::Session { grace: Duration::from_secs(30) },
    };
    core.register_with_policy(payload, policy, Some(session.clone()))
}
```

Session ID prefix `pipe:` makes it identifiable in admin output. Windows named pipe handler: identical pattern.

Handle `Request::Heartbeat` in the request match.

### CLI (`adapters/cli.rs`)

Same pattern as pipe. Session ID with `cli:` prefix. Shorter grace (5s — stdin close is an explicit user action).

---

## Shutdown ordering

Upgrade from v0.1's abort-based shutdown to ordered shutdown with `CancellationToken`:

1. **Cancel token** — stops reaper, signals HTTP server to stop accepting
2. **Drain in-flight** — 500ms for requests to complete
3. **Send goodbyes** — iterate ALL active registrations, call `daemon.unregister()` for each. Use a loop with error logging, not `try_for_each` — a partial goodbye is better than none.
4. **Delete breadcrumb file**
5. **Shutdown mdns-sd daemon**

Hard 20-second timeout for Windows Service SCM deadline:

```rust
tokio::time::timeout(Duration::from_secs(20), shutdown_sequence).await;
```

If the timeout fires, log a warning and exit. The OS cleans up sockets.

v0.1's `BrowseHandle` Drop-based cleanup is already implemented — browse handles call `stop_browse` when dropped. This carries forward unchanged.

---

## Implementation order

Build in this sequence. Each step is independently testable.

1. **Protocol layer** — `LeaseMode`, `lease` fields on RegisterPayload/RegistrationResult, `AdminRegistration`, `DaemonStatus`, `Heartbeat` request, `Renewed` response, `error.rs`
2. **Registry rewrite** — Full lifecycle engine with unit tests (50ms+ durations, real `thread::sleep`, 2–3x margins)
3. **Core** — `register_with_policy`, heartbeat, session lifecycle, reaper task, admin queries, `Arc<Registry>`, ID generation moved from daemon. `daemon.register()` → `Result<()>`
4. **HTTP adapter** — Heartbeat endpoint, admin routes, policy-based register
5. **Pipe/CLI adapters** — Session IDs, `session_disconnected`, heartbeat handling
6. **KoiClient** — `src/client.rs` with ureq
7. **Commands split** — `commands/standalone.rs` (existing logic) + `commands/client.rs` (new client-mode handlers)
8. **Admin handlers** — `src/admin.rs`
9. **Config + main** — `AdminCommand` subcommand group, `--endpoint`, `--standalone`, `detect_mode()`, breadcrumb file write/delete
10. **Shutdown** — `CancellationToken`, ordered goodbye sequence, breadcrumb cleanup

---

## Testing strategy

**Registry unit tests are the foundation.** Every state transition. 50ms+ durations with 2–3x margins. No tokio, no network. This is where 80% of the logic lives.

- permanent never reaped
- heartbeat alive within lease → not reaped
- heartbeat past lease → transitions to DRAINING
- heartbeat past lease + grace → reaped, payload returned
- heartbeat revives DRAINING → ALIVE
- session alive → not reaped
- session drain marks all session registrations
- session drain doesn't touch other sessions
- session grace elapsed → reaped
- force drain / force revive
- name+type reconnection revives DRAINING entry
- reconnection with changed payload returns old payload
- prefix match: unique prefix resolves
- prefix match: ambiguous prefix errors
- counts reflect current state
- reap returns payloads for goodbye

**Core integration tests.** `register_with_policy()` + `session_disconnected()` + sleep → verify expired entries are reaped. `#[tokio::test]`.

**HTTP integration tests.** Register → heartbeat → let expire → admin list → verify gone. Axum test utilities.

**Client module tests.** Spin up test Axum server, point `KoiClient` at it, verify round-trip without mdns-sd.

---

## Checklist

**Lease lifecycle:**
- [ ] Pipe/UDS registrations cleaned on connection drop
- [ ] HTTP registrations expire without heartbeats
- [ ] `"lease": 0` creates permanent registrations
- [ ] Expired registrations send goodbye packets
- [ ] Grace period absorbs brief disconnects
- [ ] Heartbeat renews lease (HTTP + pipe + CLI)
- [ ] Register response includes `lease` and `mode`
- [ ] DRAINING entries revived by name+type match

**Admin:**
- [ ] `koi admin status`
- [ ] `koi admin registrations`
- [ ] `koi admin inspect <id>` (prefix matching)
- [ ] `koi admin unregister <id>`
- [ ] `koi admin drain <id>`
- [ ] `koi admin revive <id>`

**Dual-mode:**
- [ ] Discovery commands use daemon when available
- [ ] Standalone fallback when no daemon
- [ ] Admin fails fast when no daemon
- [ ] `koi register` client mode: heartbeat loop + unregister on Ctrl+C
- [ ] Breadcrumb file on daemon start/stop

**Infrastructure:**
- [ ] Short IDs (8 hex chars) with prefix matching
- [ ] Ordered shutdown with goodbyes + timeout
- [ ] Unregister logs include `reason`
- [ ] Error codes in `protocol/error.rs`
- [ ] Registry state machine has comprehensive unit tests
- [ ] Reaper silent during normal operation

---

## Not included (v0.3+)

- **Registry persistence / journal.** Grace periods handle most restart cases; Koi restarts are rare as a system service.
- **Registration caps and rate limiting.** Trusted LAN tool — add when exposure widens.
- **TXT record validation.** Likely enforced by mdns-sd crate. Validate when someone reports a bug.
- **Bind address separation / admin auth.** Document firewall rules for now. The `/v1/admin/` namespace makes `--admin-bind` a clean future addition.
- **Health endpoint enrichment.** `daemon_healthy` field, 503 on daemon crash. Basic `/healthz` is sufficient for now.
- **Network interface pinning.** `--interface` flag. Surface what mdns-sd uses in `admin status` first.
- **Single-instance guard.** Breadcrumb file enables it cheaply; bind failure ("address already in use") is clear enough for now.
- **SSE-bound sessions for HTTP.** Bind registrations to an SSE connection lifecycle.
- **Per-registration grace period config.** Grace periods are adapter defaults for now.
- **Container port mapping docs.** README section, not code — "pass the host port, not the container port."
