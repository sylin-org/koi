# Defensive Publication: Transport-Adaptive Lease Modes for Network Service Registration

**Publication Type:** Defensive Publication (Prior Art Establishment)
**Publication Date:** 2026-03-24
**Inventor:** Leo Botinelly (Leonardo Milson Botinelly Soares)
**Project:** Koi — a cross-platform local network service daemon written in Rust
**Family:** 5 — Transport-Adaptive Leases

---

## Abstract

This disclosure describes a service registration system that automatically selects different lease/liveness strategies based on the transport through which a service was registered. IPC connections (Named Pipes on Windows, Unix Domain Sockets on Unix/macOS) receive session-based leases tied to OS connection lifecycle. HTTP connections receive heartbeat-based leases requiring explicit periodic renewal. An explicit opt-in selects permanent leases requiring no renewal. Registrations transition through a four-state lifecycle (ALIVE, DRAINING, EXPIRED, REMOVED) with a revive mechanism that enables seamless service continuity during container restarts. A background reaper task sweeps for expired registrations at a configurable interval. Operator admin commands allow manual lifecycle management (drain, revive, force-unregister).

---

## Field of the Invention

Service discovery; network service management; distributed systems; service registration lifecycle management; mDNS/DNS-SD service announcement; container orchestration; IPC connection management.

---

## Keywords

service registration, lease management, heartbeat, session lease, transport-adaptive, service discovery, mDNS, lifecycle management, draining, revive, grace period, reaper, container restart, IPC, Named Pipe, Unix Domain Socket, HTTP heartbeat, permanent registration

---

## Problem Statement

Service registration systems require a mechanism to detect when registered services are no longer available. This is typically implemented through a lease or liveness model: the service must periodically prove it is alive, or its registration expires. However, different client connection types have fundamentally different liveness semantics:

**IPC Connections (Named Pipes, Unix Domain Sockets):** The operating system provides built-in connection lifecycle management. When a process exits or a pipe breaks, the OS signals the other end. A service registered over an IPC connection is alive as long as the connection is open. Requiring the IPC client to also send periodic heartbeat messages is redundant and wasteful.

**HTTP Connections:** HTTP is stateless. Each request is independent. There is no persistent connection lifecycle (even with HTTP keep-alive, the server cannot reliably detect client departure). A service registered via HTTP MUST send periodic heartbeat messages because the transport provides no liveness signal.

**Permanent Services:** Some services manage their own lifecycle and should never be automatically expired. They should be registered once and remain until explicitly removed or until the daemon shuts down. Requiring heartbeats for such services is unnecessary overhead.

### Existing Approaches

**Netflix Eureka:** Uses a fixed 30-second heartbeat interval with 90-second expiration for ALL registrations. There is no transport awareness. IPC clients (if supported) would need to implement the same heartbeat logic as HTTP clients.

**HashiCorp Consul:** Supports multiple check types (HTTP, TCP, TTL, script, gRPC), but the check type is operator-configured, not auto-detected from the registration transport. An operator must explicitly choose "TTL check" or "HTTP check" when registering a service. The system does not infer the appropriate check type from how the service connected.

**mDNS/DNS-SD TTL:** DNS record TTL values (typically 120 seconds) are set by the registrant and apply uniformly. There is no transport-dependent TTL and no lifecycle state machine beyond record expiry.

**etcd Leases:** TTL-based with keepalive streams. A single lease model applies to all clients regardless of connection type.

**Kubernetes Service Registration:** The Endpoint controller monitors pod health through the kubelet. There is no per-service lease concept and no transport-aware liveness detection.

**ZeroConf/Bonjour:** Apple's mDNS implementation uses DNS record TTL. No transport-adaptive behavior.

### Gap in the State of the Art

No existing service registration system:
1. Automatically selects different lease strategies based on the transport that received the registration
2. Provides a four-state lifecycle model with a revive transition from DRAINING back to ALIVE
3. Combines transport-adaptive leases with a revive mechanism for seamless container restart continuity
4. Allows heterogeneous clients (IPC, HTTP, permanent) to coexist in the same registry with appropriate liveness semantics for each

---

## Detailed Technical Description

### 1. System Architecture

The service registration system consists of:

```
+-------------------+     +-------------------+     +-------------------+
| IPC Adapter       |     | HTTP Adapter      |     | CLI Adapter       |
| (Named Pipe/UDS)  |     | (axum server)     |     | (stdin/stdout)    |
|                   |     |                   |     |                   |
| SESSION_GRACE=30s |     | HEARTBEAT_LEASE   |     | SESSION_GRACE=5s  |
|                   |     | =90s              |     |                   |
|                   |     | HEARTBEAT_GRACE   |     |                   |
|                   |     | =30s              |     |                   |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                         |
         v                         v                         v
    +----+-------------------------+-------------------------+----+
    |                        Registry                              |
    |  HashMap<String, Registration>                               |
    |  - insert_or_reconnect()                                     |
    |  - heartbeat()                                               |
    |  - drain_session()                                           |
    |  - remove()                                                  |
    |  - reap() [background task every 5s]                         |
    +------------------------------+-------------------------------+
                                   |
                                   v
                          +--------+--------+
                          |   mDNS Daemon   |
                          | (announce/      |
                          |  goodbye)       |
                          +-----------------+
```

Each transport adapter wraps registrations with the appropriate `LeasePolicy` before inserting them into the shared `Registry`. The registrant does NOT choose the lease mode — the adapter does.

### 2. Lease Modes

The system defines three lease modes, represented as an enum:

```
LeasePolicy:
    Session { grace: Duration }
    Heartbeat { lease: Duration, grace: Duration }
    Permanent
```

#### 2.1 Session Lease

**Trigger:** Registration received over an IPC connection (Named Pipe on Windows, Unix Domain Socket on Unix/macOS) or piped stdin/stdout.

**Semantics:** The registration is alive as long as the IPC connection is open. When the connection drops (process exit, pipe break, socket close), the adapter calls `drain_session(session_id)` on the registry, which transitions all registrations associated with that session to the DRAINING state.

**Grace Period:** A configurable duration (default 30 seconds for IPC pipe, 5 seconds for CLI stdin) during which the registration remains in DRAINING state. If the client reconnects and re-registers the same service (matching by name + service type) within the grace period, the registration is revived (DRAINING -> ALIVE) rather than creating a new registration.

**No Heartbeat Required:** The IPC client never needs to send heartbeat messages. The operating system's connection lifecycle provides the liveness signal.

**Implementation Detail:** The IPC adapter maintains a `session_id` (generated via `generate_short_id()` — a UUID v4 prefix of 8 characters) for each connection. All registrations from that connection are tagged with this session ID. When the connection drops, `drain_session(session_id)` transitions all matching registrations atomically.

#### 2.2 Heartbeat Lease

**Trigger:** Registration received over HTTP.

**Semantics:** The client must explicitly renew the lease by calling `PUT /heartbeat/{id}` before the lease expires. Each heartbeat resets the `last_seen` timestamp.

**Default Parameters:**
- `lease`: 90 seconds (`DEFAULT_HEARTBEAT_LEASE`). The client has 90 seconds between heartbeats.
- `grace`: 30 seconds (`DEFAULT_HEARTBEAT_GRACE`). After the lease expires, the registration enters DRAINING for 30 additional seconds before removal.

**Client Override:** The registration payload includes an optional `lease_secs` field. If specified and non-zero, it overrides the default lease duration. The grace period is fixed at 30 seconds regardless of the lease duration.

**Permanent Opt-In:** If `lease_secs: 0` is specified in the HTTP registration payload, the registration receives a Permanent lease instead of a Heartbeat lease. This is the only way for an HTTP client to avoid heartbeat requirements.

#### 2.3 Permanent Lease

**Trigger:** Explicit opt-in via `lease_secs: 0` in the registration payload.

**Semantics:** The registration lives until explicitly unregistered (via `DELETE /unregister/{id}` or `DELETE /admin/unregister/{id}`) or until the daemon shuts down.

**No Heartbeat Required:** No renewal mechanism. The reaper task ignores permanent registrations entirely.

**Session Drain Immunity:** When a session is drained (IPC connection drops), permanent registrations tagged with that session ID are NOT transitioned to DRAINING. This enables a pattern where a service registers permanently via IPC, then the IPC connection can be closed without affecting the registration.

### 3. Four-State Lifecycle

Each registration transitions through four states:

```
                          heartbeat()
                      revive (admin)
                    reconnect (IPC)
                   +------------------+
                   |                  |
                   v                  |
    +-------+    +---------+    +----------+    +---------+
    | (new) |--->|  ALIVE  |--->| DRAINING |--->| REMOVED |
    +-------+    +---------+    +----------+    +---------+
                      |              |
                      |              | (grace elapsed)
                      |              v
                      |         +---------+
                      +-------->| EXPIRED |---> REMOVED
                   (lease miss) +---------+
```

**Note on state representation:** The implementation uses a two-variant enum (`Alive`, `Draining { since: Instant }`) rather than four explicit states. The EXPIRED and REMOVED states are implicit — EXPIRED is "DRAINING with elapsed grace," and REMOVED is "removed from the HashMap." This is an optimization: the reaper task performs both transitions (DRAINING -> EXPIRED -> REMOVED) in a single pass by checking whether the grace period has elapsed and removing the entry if so.

#### 3.1 ALIVE State

The registration is active. The service is announced via mDNS. The registration appears in admin listings with state "alive."

**Transitions OUT:**
- **Lease expiry (heartbeat mode):** When the reaper detects that `now - last_seen >= lease_duration`, it transitions the registration to DRAINING. The transition timestamp is recorded.
- **Session drain (session mode):** When the IPC connection drops, `drain_session()` transitions all session-tagged registrations to DRAINING.
- **Admin drain:** An operator calls `POST /admin/drain/{id}` to manually begin draining.
- **Explicit removal:** An operator or client calls `DELETE /unregister/{id}` to skip directly to REMOVED.

#### 3.2 DRAINING State

The registration is in its grace period. The critical property: **the service is still announced via mDNS during the draining state.** This allows in-flight requests from other nodes on the network to complete. The service is not immediately yanked from the network — it gracefully winds down.

**Data:** The DRAINING state records the timestamp when draining began (`since: Instant`). The grace period is computed as `since + grace_duration`.

**Transitions OUT:**
- **Revive (heartbeat):** A `PUT /heartbeat/{id}` call revives the registration back to ALIVE and resets `last_seen`.
- **Revive (reconnect):** A new `insert_or_reconnect()` call with matching name + service type revives the existing DRAINING registration rather than creating a new one. The old registration ID is preserved.
- **Revive (admin):** An operator calls `POST /admin/revive/{id}`.
- **Grace expiry:** When `now - since >= grace_duration`, the reaper removes the registration (transition to REMOVED).
- **Explicit removal:** An operator calls `DELETE /admin/unregister/{id}`.

#### 3.3 EXPIRED / REMOVED States

These are implicit states. When the reaper determines that a DRAINING registration's grace period has elapsed, it removes the entry from the HashMap. The removal returns the registration payload, which is used to send mDNS "goodbye" packets (TTL=0 announcements) to inform other nodes that the service is no longer available.

### 4. The Reaper Task

A background task that runs at a configurable interval (default: 5 seconds, `REAPER_INTERVAL`) and performs a single-pass sweep of all registrations.

**Algorithm (single-pass retain):**

```
fn reap(now: Instant) -> Vec<(id, payload)>:
    expired = []
    registrations.retain(|id, reg|:
        match (reg.state, reg.policy):
            // Permanent — never expires
            (_, Permanent) -> true

            // Session, alive — connection still open, don't touch
            (Alive, Session { .. }) -> true

            // Draining — check grace (both session and heartbeat)
            (Draining { since }, Session { grace })
            (Draining { since }, Heartbeat { grace, .. }) ->
                if now - since >= grace:
                    expired.push((id, reg.payload))
                    false  // remove
                else:
                    true   // keep (still in grace)

            // Heartbeat, alive — check if lease expired
            (Alive, Heartbeat { lease, .. }) ->
                if now - reg.last_seen >= lease:
                    reg.state = Draining { since: now }
                true  // don't remove yet — grace period begins

    return expired
```

**Key Properties:**
- Single-pass: The reaper iterates through all registrations exactly once per sweep. It does not iterate separately for each state transition.
- Atomic state transitions: The heartbeat lease expiry (ALIVE -> DRAINING) happens within the same sweep that checks grace expiry (DRAINING -> REMOVED). A registration can transition from ALIVE to DRAINING in one sweep and from DRAINING to REMOVED in a subsequent sweep.
- Lock duration: The reaper holds the registry Mutex for the duration of the sweep. Since the sweep is O(n) with no I/O, this is fast even for hundreds of registrations.
- Return value: The reaper returns the list of expired `(id, payload)` pairs. The caller uses these to send mDNS goodbye packets outside the lock.

### 5. The Revive Mechanism

The revive mechanism is the key innovation for container environments. It addresses this scenario:

1. A containerized service registers via IPC (session lease, 30s grace).
2. The container restarts (rolling update, crash, health check restart).
3. The IPC connection drops. The registration enters DRAINING.
4. The new container instance starts and connects via IPC.
5. The new instance registers the same service (same name + same service type).
6. The `insert_or_reconnect()` method detects the DRAINING registration with matching name and type.
7. Instead of creating a new registration, it revives the existing one: sets state back to ALIVE, updates the payload (in case port or TXT records changed), updates the session ID (new connection), and resets `last_seen`.
8. The registration ID is preserved. Other nodes on the network that cached this service by ID continue to reach it.

**Match Criteria:** Revive matches on `(name, service_type)` pairs. This is stricter than matching on name alone (which could conflict with different service types) and more permissive than matching on the full payload (which would fail if the port changed during restart).

**Old Payload Return:** The `insert_or_reconnect()` method returns the old payload alongside the revived registration ID. This allows the caller to update the mDNS announcement if the payload changed (e.g., new port or updated TXT records).

**Outcome Enum:**
```
InsertOutcome:
    New { id: String }                              // Fresh registration
    Reconnected { id: String, old_payload: Payload } // Revived existing
```

The caller checks the outcome to determine whether to send a fresh mDNS announcement (New) or an update announcement (Reconnected with changed payload).

### 6. Registration Data Structure

Each registration contains:

```
Registration:
    payload: RegisterPayload      // Service identity (name, type, port, ip, txt, lease_secs)
    state: RegistrationState      // Alive | Draining { since: Instant }
    policy: LeasePolicy           // Session { grace } | Heartbeat { lease, grace } | Permanent
    last_seen: Instant            // Monotonic timestamp of last heartbeat or creation
    session_id: Option<SessionId> // IPC session tag (None for HTTP/permanent)
    registered_at_wall: SystemTime // Wall-clock creation time (for admin display)
    last_seen_wall: SystemTime     // Wall-clock last activity (for admin display)
```

**Dual Timestamps:** The registration tracks both monotonic (`Instant`) and wall-clock (`SystemTime`) timestamps. Monotonic timestamps are used for lease calculations (immune to clock adjustments). Wall-clock timestamps are used for human-readable admin display (showing "registered 5 minutes ago" or an ISO 8601 timestamp).

### 7. Admin Lifecycle Management

Operators can manually manage registration lifecycle through admin endpoints:

**Force Drain (`POST /admin/drain/{id}`):**
- Transitions an ALIVE registration to DRAINING.
- Returns error if already DRAINING (`AlreadyDraining`).
- Returns error if not found (`RegistrationNotFound`).
- Use case: Gracefully removing a service before maintenance.

**Force Revive (`POST /admin/revive/{id}`):**
- Transitions a DRAINING registration back to ALIVE.
- Resets `last_seen` to now.
- Returns error if not DRAINING (`NotDraining`).
- Returns error if not found (`RegistrationNotFound`).
- Use case: Canceling an accidental drain, keeping a service alive during investigation.

**Force Unregister (`DELETE /admin/unregister/{id}`):**
- Immediately removes the registration regardless of state.
- Returns the payload for goodbye packet.
- Use case: Emergency removal of a misbehaving service.

**Admin Status (`GET /admin/status`):**
- Returns daemon overview including registration counts by state.
```
RegistrationCounts:
    alive: usize
    draining: usize
    permanent: usize
    total: usize
```

**Admin List (`GET /admin/ls`):**
- Returns all registrations with full lifecycle metadata:
```
AdminRegistration:
    id: String
    name: String
    service_type: String
    port: u16
    mode: LeaseMode          // session | heartbeat | permanent
    state: LeaseState         // alive | draining
    lease_secs: Option<u64>   // Only for heartbeat mode
    remaining_secs: Option<u64> // Seconds until lease/grace expires
    grace_secs: u64
    session_id: Option<String>
    registered_at: String     // Unix epoch seconds
    last_seen: String         // Unix epoch seconds
    txt: HashMap<String, String>
```

**Admin Inspect (`GET /admin/inspect/{id}`):**
- Returns a single registration's full metadata.

**ID Prefix Resolution:** Admin commands accept ID prefixes. The `resolve_prefix()` method finds the unique registration matching the prefix. If the prefix is ambiguous (matches multiple registrations), it returns `AmbiguousId` error. If no match, `RegistrationNotFound`. This enables short-form IDs in CLI usage (e.g., `koi mdns admin drain abc` instead of `koi mdns admin drain abc12345`).

### 8. Transport Adapter Behavior

#### 8.1 IPC Pipe Adapter (Named Pipe / Unix Domain Socket)

```
on_connection(stream):
    session_id = generate_short_id()  // e.g., "a1b2c3d4"

    loop:
        line = read_ndjson_line(stream)
        match parse_request(line):
            Register(payload) ->
                policy = LeasePolicy::Session { grace: Duration::from_secs(30) }
                outcome = registry.insert_or_reconnect(new_id, payload, policy, Some(session_id))
                write_response(stream, registered(outcome))

            Heartbeat(id) ->
                lease_secs = registry.heartbeat(id)?
                write_response(stream, renewed(id, lease_secs))

            Unregister(id) ->
                payload = registry.remove(id)?
                daemon.goodbye(payload)
                write_response(stream, unregistered(id))

    on_disconnect:
        // OS signals connection drop
        drained_ids = registry.drain_session(session_id)
        // drained_ids now in DRAINING state with 30s grace
```

**Key:** The adapter chooses `LeasePolicy::Session` automatically. The client never specifies the lease mode. The client never sends heartbeats. The OS connection lifecycle is the liveness signal.

#### 8.2 HTTP Adapter

```
POST /announce:
    body = parse_json(request)
    if body.lease_secs == Some(0):
        policy = LeasePolicy::Permanent
    else:
        lease = body.lease_secs.map(Duration::from_secs)
            .unwrap_or(DEFAULT_HEARTBEAT_LEASE)  // 90s
        policy = LeasePolicy::Heartbeat { lease, grace: DEFAULT_HEARTBEAT_GRACE }  // 30s grace

    outcome = registry.insert_or_reconnect(new_id, payload, policy, None)
    return json(registered(outcome))

PUT /heartbeat/{id}:
    lease_secs = registry.heartbeat(id)?
    return json(renewed(id, lease_secs))
```

**Key:** The adapter chooses `LeasePolicy::Heartbeat` automatically unless the client explicitly opts into `Permanent` via `lease_secs: 0`. The adapter's constants (`DEFAULT_HEARTBEAT_LEASE`, `DEFAULT_HEARTBEAT_GRACE`) are co-located with the HTTP module, not in a centralized configuration.

#### 8.3 CLI Adapter (piped stdin/stdout)

```
on_start:
    session_id = generate_short_id()

    loop:
        line = read_stdin_line()
        match parse_request(line):
            Register(payload) ->
                policy = LeasePolicy::Session { grace: Duration::from_secs(5) }
                outcome = registry.insert_or_reconnect(new_id, payload, policy, Some(session_id))
                write_stdout(registered(outcome))
            ...

    on_eof:
        drained_ids = registry.drain_session(session_id)
```

**Key:** The CLI adapter uses a shorter grace period (5 seconds vs. 30 seconds for IPC pipe) because piped stdin is typically used for short-lived automation scripts where fast cleanup is preferred.

### 9. Interaction with mDNS Announcement

The registry is the single source of truth for service liveness. The mDNS daemon is informed of lifecycle changes:

- **Registration (ALIVE):** The daemon sends mDNS announcement packets (service record with configured TTL).
- **Draining begins:** NO mDNS change. The service continues to be announced. This is intentional — draining is a "soft" expiry that allows in-flight discovery to complete.
- **Grace expires (REMOVED):** The daemon sends mDNS "goodbye" packets (service record with TTL=0). Other nodes remove the service from their caches.
- **Revive (DRAINING -> ALIVE):** NO mDNS change needed if the payload hasn't changed. If the payload changed (different port or TXT), the daemon sends an updated announcement.
- **Heartbeat renewal:** NO mDNS change. Heartbeats only reset the internal lease timer.

This design means that from the network's perspective, a service is either "announced" (ALIVE or DRAINING) or "gone" (REMOVED). The DRAINING state is invisible to the network — it only affects the internal lifecycle timer.

### 10. Thread Safety

The `Registry` wraps its `HashMap<String, Registration>` in a `Mutex`. All public methods acquire the lock for the duration of the operation. The lock granularity is the entire registry (not per-registration) because:

1. `insert_or_reconnect()` needs to scan all registrations to find a matching DRAINING entry.
2. `drain_session()` needs to scan all registrations for a given session ID.
3. `reap()` needs to iterate all registrations.

For typical deployments (dozens to low hundreds of registrations), the contention is negligible. The lock is held only for in-memory HashMap operations — no I/O occurs under the lock.

**Poison Recovery:** The Mutex is acquired with `unwrap_or_else(|e| e.into_inner())`, which recovers from a poisoned mutex (caused by a panic while holding the lock). This prevents a single panic from permanently blocking the registry.

### 11. Remaining Lease Calculation

The `remaining_secs_for()` function computes the time until the next state transition:

```
fn remaining_secs_for(reg, now) -> Option<u64>:
    match (reg.state, reg.policy):
        // Heartbeat, alive: time until lease expiry
        (Alive, Heartbeat { lease, .. }) ->
            deadline = reg.last_seen + lease
            Some(deadline.saturating_sub(now).as_secs())

        // Draining: time until grace expiry
        (Draining { since }, Session { grace })
        (Draining { since }, Heartbeat { grace, .. }) ->
            deadline = since + grace
            Some(deadline.saturating_sub(now).as_secs())

        // All others (permanent, session alive): no deadline
        _ -> None
```

The `saturating_sub` prevents underflow when the deadline has already passed (returns 0 instead of panicking).

### 12. Comparison with Prior Art

| Property | Eureka | Consul | mDNS TTL | etcd | This Invention |
|----------|--------|--------|----------|------|----------------|
| Transport-adaptive lease | No | No | No | No | Yes |
| Lease selection | Fixed (30s/90s) | Operator-configured | Registrant-set | TTL | Auto from transport |
| Lifecycle states | UP/DOWN/OUT_OF_SERVICE | passing/warning/critical | alive/expired | active/expired | ALIVE/DRAINING/EXPIRED/REMOVED |
| Revive from draining | No | No | No | No | Yes |
| Grace period during drain | No (immediate removal) | Deregister critical timeout | No | No | Yes (service still announced) |
| IPC session awareness | N/A | N/A | N/A | N/A | Yes |
| Admin drain/revive | Yes (OUT_OF_SERVICE) | Maintenance mode | No | No | Yes (per-registration) |
| Heterogeneous clients | No | Partial (different check types) | No | No | Yes (IPC+HTTP+permanent) |

---

## Variants and Extensions

1. **Configurable grace periods per transport:** Grace periods could be configurable at registration time rather than fixed per adapter.

2. **Configurable reaper interval:** The 5-second reaper interval could be tunable based on deployment requirements (faster sweep for latency-sensitive environments, slower for resource-constrained).

3. **Health-check lease mode:** A fourth lease mode where liveness is determined by actively probing a health endpoint (HTTP GET to the service's health URL). The registry would periodically check the service and transition to DRAINING on probe failure.

4. **Service identity matching for revive:** The revive mechanism currently matches on `(name, service_type)`. It could be extended to match on `(service_type, port)` for scenarios where the service name changes but the endpoint is stable, or on custom identity attributes in TXT records.

5. **Cascading drain:** When a service is drained, all services that depend on it (specified via TXT metadata) could be automatically drained as well.

6. **Drain notification:** A webhook or event could be fired when a service enters DRAINING, allowing dependent services to prepare for the loss.

7. **Weighted grace periods:** The grace period could be dynamic based on the service's historical reconnection time (learned from previous drain/revive cycles).

8. **Lease telemetry:** Track lease renewal patterns to detect unhealthy services (e.g., a service that consistently renews at the last second before expiry).

---

## Implementation Evidence

The described system is implemented in the Koi project:

- `crates/koi-mdns/src/registry.rs` — `Registry` struct with `HashMap<String, Registration>`, `LeasePolicy` enum (`Session`, `Heartbeat`, `Permanent`), `RegistrationState` enum (`Alive`, `Draining { since }`), `InsertOutcome` enum (`New`, `Reconnected`), `insert_or_reconnect()`, `heartbeat()`, `drain_session()`, `reap()`, `force_drain()`, `force_revive()`, `remove()`, `resolve_prefix()`, `snapshot()`, `counts()`. Includes 20+ unit tests covering all state transitions.
- `crates/koi-mdns/src/lib.rs` — `BROADCAST_CHANNEL_CAPACITY` (256), `REAPER_INTERVAL` (5 seconds). `MdnsCore` facade that wires the registry to the mDNS daemon and broadcasts lifecycle events.
- `crates/koi-mdns/src/http.rs` — HTTP transport adapter. `DEFAULT_HEARTBEAT_LEASE` (90 seconds), `DEFAULT_HEARTBEAT_GRACE` (30 seconds). Automatically selects `Heartbeat` or `Permanent` lease policy based on `lease_secs` in the registration payload.
- `crates/koi/src/adapters/pipe.rs` — IPC pipe adapter. `SESSION_GRACE` (30 seconds). Automatically selects `Session` lease policy. Calls `drain_session()` on connection drop.
- `crates/koi/src/adapters/cli.rs` — CLI stdin/stdout adapter. `SESSION_GRACE` (5 seconds). Automatically selects `Session` lease policy. Calls `drain_session()` on EOF.
- `crates/koi-mdns/src/protocol.rs` — Wire format types: `LeaseMode` (session/heartbeat/permanent), `LeaseState` (alive/draining), `AdminRegistration` (full lifecycle view), `RegistrationCounts`.

---

## Claims-Style Disclosures

1. A method for automatic lease mode selection in service registration systems wherein: (a) the transport adapter that receives the registration determines the lease mode without explicit client configuration; (b) IPC connections (Named Pipes, Unix Domain Sockets) receive session-based leases tied to operating system connection lifecycle, requiring no heartbeat messages; (c) HTTP connections receive heartbeat-based leases requiring explicit periodic renewal at a configurable interval; (d) an explicit opt-in value (lease_secs of zero) selects permanent leases requiring no renewal; distinct from Consul, Eureka, mDNS, and etcd in that the lease strategy is automatically determined by the registration transport rather than uniformly applied or operator-configured.

2. A method for service registration lifecycle management using a four-state model (ALIVE, DRAINING, EXPIRED, REMOVED) wherein: (a) DRAINING is a grace state where the service remains announced on the network (mDNS records continue to be served) while an internal timer counts down; (b) a revive transition from DRAINING back to ALIVE is triggered by heartbeat renewal, new registration with matching service identity, or operator admin command; (c) the revive mechanism preserves the original registration ID, enabling seamless service continuity during container restarts where the client reconnects within the grace period; distinct from Eureka's immediate deregistration and Consul's critical-state timeout in that the service remains network-visible during the grace period.

3. A method for detecting service reconnection during container restarts wherein: (a) when a new service registration arrives with a name and service type matching an existing DRAINING registration, the existing registration is revived rather than creating a new registration; (b) the revived registration retains its original ID, preserving referential integrity for other nodes that cached the service; (c) the old registration payload is returned to the caller to enable mDNS announcement updates if the service endpoint changed during restart.

4. A system combining transport-adaptive lease selection, four-state lifecycle management with revive capability, and operator admin override (drain, revive, force-unregister) for network service registrations, enabling: (a) IPC clients to register services without heartbeat overhead; (b) HTTP clients to use explicit heartbeat renewal; (c) permanent services to avoid all renewal; (d) container services to restart seamlessly within grace periods; (e) operators to manually manage individual registration lifecycles; all within a single unified registry.

5. A method for single-pass lifecycle sweeping in a service registration system wherein: (a) a background reaper task iterates all registrations exactly once per sweep interval; (b) during the single pass, heartbeat leases that have expired are transitioned from ALIVE to DRAINING; (c) during the same pass, DRAINING registrations whose grace period has elapsed are removed and their payloads collected; (d) the collected payloads are used to send mDNS goodbye packets (TTL=0) outside the registry lock; (e) permanent registrations and session-ALIVE registrations are unconditionally retained.

---

## Antagonist Review Log

### Round 1

**Antagonist Attack — Abstraction Gap (Session ID Generation):**

The disclosure mentions "session_id" for IPC connections but does not clearly specify the relationship between sessions and connections. Is it one session per connection? Can a single connection have multiple sessions? What happens if the session ID collides?

**Author Revision:**

The relationship is 1:1 — one session per IPC connection. When a new pipe/socket connection is accepted, a new session ID is generated using `generate_short_id()`, which produces the first 8 characters of a UUID v4 (e.g., "a1b2c3d4"). All registrations from that connection are tagged with this session ID. When the connection drops, `drain_session(session_id)` transitions all registrations with that session ID to DRAINING.

Session ID collision: With 8 hex characters (32 bits of entropy) and typical concurrent connection counts in single digits, the collision probability is negligible (~1/4 billion). If a collision did occur, the impact would be that draining one session would also drain another session's registrations — undesirable but not catastrophic (those registrations would enter DRAINING with a grace period, and could be revived by heartbeat). For deployments requiring stronger guarantees, the session ID could use full UUID v4 (128 bits).

A single connection cannot have multiple sessions. The session ID is assigned at connection accept time and is immutable for the lifetime of the connection.

---

**Antagonist Attack — Reproducibility Gap (Reaper Timing):**

The disclosure says the reaper runs every 5 seconds, but does not specify the maximum latency for state transitions. If a heartbeat lease expires at T=0 and the reaper runs at T=4.9, the ALIVE->DRAINING transition happens at T=4.9, not T=0. The grace period then starts at T=4.9, not T=0. This means the effective lease is `lease + up_to(reaper_interval)` and the effective grace is exactly `grace`. Is this intentional?

**Author Revision:**

This is intentional and by design. The reaper is a polling mechanism with a known maximum latency of `REAPER_INTERVAL` (5 seconds). The effective lease is therefore `lease` to `lease + REAPER_INTERVAL` depending on when the reaper runs relative to the lease expiry.

This imprecision is acceptable because:
1. The lease durations (90 seconds) are much larger than the reaper interval (5 seconds), so the jitter is at most 5.5% of the lease.
2. The grace period provides additional tolerance — even if the reaper is slightly late, the grace period absorbs the delay.
3. A more precise approach (per-registration timers or a priority queue sorted by expiry time) would add complexity without meaningful benefit for the intended use case (LAN service discovery).

The lease is intentionally checked against `last_seen` (not against a precomputed deadline), so heartbeats that arrive between reaper sweeps correctly extend the lease from the heartbeat time, not from the last reaper sweep.

---

**Antagonist Attack — Prior Art Weakness (Consul Session Binding):**

Consul has "session" objects that can be bound to health checks and have configurable TTLs. When a session is invalidated, associated key/value pairs and service registrations can be released. How is this different from the session lease described here?

**Author Revision:**

Consul's session mechanism differs in several key ways:

1. **Explicit session creation:** Consul sessions must be explicitly created by the client via `PUT /v1/session/create`. The client must know it needs a session and configure its parameters (TTL, behavior, checks). In this invention, the session is implicit — the IPC adapter creates it automatically when a connection is accepted.

2. **No transport awareness:** Consul sessions are not tied to a transport. A Consul session over HTTP requires the same explicit TTL management as a session over any other transport. In this invention, the IPC transport provides the liveness signal; no TTL management is needed.

3. **No revive mechanism:** When a Consul session expires, its associated registrations are released. There is no grace period during which the registrations remain active and can be revived. In this invention, DRAINING registrations remain mDNS-announced and can be revived.

4. **Session behavior is global:** Consul session behavior (release vs. delete) is set once at session creation and applies to all associated data. In this invention, permanent registrations tagged with a session are immune to session drain, while session-leased registrations are drained — the behavior varies per-registration.

---

**Antagonist Attack — Scope Hole (Multiple Transports for Same Service):**

What happens if the same service is registered via both IPC and HTTP? Which lease policy wins?

**Author Revision:**

Each registration is independent. Registering the same service (same name + type) via IPC creates a session-leased registration. Registering the same service via HTTP creates a heartbeat-leased registration. Both registrations coexist in the registry with different IDs, different lease policies, and independent lifecycles.

The mDNS daemon will announce both. From the network's perspective, there appear to be two instances of the same service. This is correct behavior for mDNS/DNS-SD, which inherently supports multiple instances of the same service type.

If the intent is to have a single registration, the second registration should use the same ID (or the first should be unregistered before the second is created). The `insert_or_reconnect()` revive mechanism only matches DRAINING registrations, not ALIVE ones — it will not merge two ALIVE registrations.

---

**Antagonist Attack — Missing Edge Case (Daemon Shutdown):**

What happens to registrations during daemon shutdown? Are goodbye packets sent for all registrations?

**Author Revision:**

During daemon shutdown:
1. The `CancellationToken` is triggered, signaling all background tasks (including the reaper) to stop.
2. A 500ms drain period allows in-flight HTTP requests to complete.
3. The daemon iterates all registration IDs via `registry.all_ids()` and sends mDNS goodbye packets for each.
4. The daemon sends a "goodbye" for its own service registrations.
5. The mDNS daemon is shut down.
6. A 20-second hard timeout ensures the process exits even if shutdown stalls.

All registrations — regardless of lease policy (session, heartbeat, permanent) — receive goodbye packets during shutdown. Permanent registrations are not exempt from shutdown cleanup.

---

### Round 2

**Antagonist Attack — Terminology Drift (DRAINING vs. EXPIRING):**

The term "DRAINING" implies active load shedding (HTTP connection draining, Kubernetes pod draining). But in this system, the service continues to be announced and accept traffic. Isn't "EXPIRING" more accurate?

**Author Revision:**

The term "DRAINING" is chosen deliberately to align with the operational semantics:

1. The service IS draining — it is in the process of leaving the network. The grace period allows existing clients to complete their interactions.
2. The term aligns with Kubernetes terminology (pod draining, node draining) where the resource continues to serve existing connections but should not receive new ones.
3. In practice, the mDNS TTL means other nodes may cache the service for up to the DNS record TTL after the goodbye packet is sent. The DRAINING state accounts for this cache propagation delay.

"EXPIRING" would imply that the service is about to expire, which is technically true but doesn't convey the operational intent (graceful wind-down). The admin command is `drain`, not `expire`, and the reverse operation is `revive`, not `renew` — these verbs convey the lifecycle management semantics.

The disclosure consistently uses DRAINING in this specific sense throughout, and the admin API uses the same terminology (`/admin/drain/{id}`, `/admin/revive/{id}`), so there is no ambiguity.

---

**Antagonist Attack — Reproducibility Gap (Heartbeat Response):**

The disclosure mentions that `heartbeat()` returns `lease_secs`. What exactly is returned? The original lease duration? The remaining time? The new deadline?

**Author Revision:**

The `heartbeat()` method returns the configured lease duration in seconds (not the remaining time, not the new deadline). For a heartbeat-leased registration with `lease: 90s`, every heartbeat call returns `90`. For session-leased and permanent registrations, it returns `0` (as heartbeat is a no-op for these modes, but the method still succeeds for flexibility).

The client uses the returned `lease_secs` to schedule its next heartbeat. A typical client heartbeats at `lease_secs / 3` intervals (e.g., every 30 seconds for a 90-second lease) to provide margin for network latency and clock drift.

The heartbeat also has a side effect of reviving a DRAINING registration: if the registration was in DRAINING state (because a previous heartbeat was missed), the heartbeat transitions it back to ALIVE. This allows a temporarily network-partitioned client to recover without re-registration.

---

**Antagonist Attack — Section 101 / Obviousness:**

Combining session-based and heartbeat-based leases is arguably obvious — just use session tracking for persistent connections and heartbeat for stateless connections.

**Author Revision:**

This is a defensive publication, not a patent application. The purpose is to establish prior art. The more "obvious" the technique, the stronger it is as prior art — it demonstrates that the technique was publicly disclosed and therefore cannot be claimed as novel by a later patent applicant.

That said, the non-obvious aspects include:
1. The automatic selection based on transport (no prior system does this).
2. The four-state lifecycle with revive (no prior system has DRAINING with revive).
3. The combination of session lease, heartbeat lease, and permanent lease in a single registry with heterogeneous coexistence.
4. The DRAINING state preserving mDNS network announcement during the grace period.
5. The reconnect-based revive using `(name, service_type)` matching for container restart continuity.

Each individual component may have analogs in prior art. The combination and the specific design choices (transport-adaptive selection, revive via reconnect, continued announcement during draining) are the novel contribution.

---

**Antagonist declares: "No further objections — this disclosure is sufficient to block patent claims on the described invention."**

The disclosure provides:
- Precise data structures (LeasePolicy, RegistrationState, Registration, InsertOutcome, AdminRegistration)
- Exact algorithm descriptions (reaper single-pass, insert_or_reconnect matching, heartbeat revive)
- Concrete transport adapter behavior (IPC, HTTP, CLI) with specific constant values
- Complete lifecycle state machine with all transitions enumerated
- Clear differentiation from Eureka, Consul, mDNS TTL, etcd, and Kubernetes
- Edge case coverage (concurrent registrations, daemon shutdown, multiple transports, session collision, reaper timing)
- Working implementation references (6 source files)

A person having ordinary skill in the art of distributed systems and service discovery could reproduce the complete transport-adaptive lease system from this disclosure.
