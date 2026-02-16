# ADR-005: Registration Lease System

**Status:** Accepted  
**Date:** 2025-09-01  

## Context

In v0.1, all mDNS registrations were permanent. When a process crashed, its service stayed advertised on the network, creating "ghost services" that accumulated across restarts and machines. The mDNS protocol has a built-in goodbye mechanism, but nothing in Koi triggered it when a registrant died. The problem was compounded across transports: IPC connections have OS-level disconnect signals, HTTP is stateless with no inherent liveness, and some registrations genuinely need to be permanent (infrastructure services).

## Decision

Every registration carries a lease mode determined by the transport adapter:

| Mode | Default for | Liveness signal | Failure behavior |
|---|---|---|---|
| **Session** | IPC (pipe/UDS) | OS connection lifecycle | Goodbye on disconnect (30s grace) |
| **Heartbeat** | HTTP | Client sends `PUT /heartbeat/{id}` | 90s lease, 30s grace, then goodbye |
| **Permanent** | Explicit opt-in (`lease: 0`) | None | Lives until daemon restart or manual delete |

A background reaper task sweeps the registry every 5 seconds, transitioning missed heartbeats through four lifecycle states: `ALIVE → DRAINING → EXPIRED → REMOVED`. DRAINING registrations can be revived if the registrant reconnects within the grace period, enabling seamless container restarts.

An admin surface (`koi mdns admin ls`, `inspect`, `drain`, `revive`, `unregister`) provides operator visibility and manual override.

## Consequences

- Ghost services are eliminated for HTTP and IPC registrations. Network state reflects reality within lease + grace seconds.
- The registry was rewritten from `Mutex<HashMap>` to a lifecycle engine with four states and a reaper task.
- The 5-second reaper tick adds minimal CPU cost but means grace periods have ±5s granularity — acceptable given mDNS TTLs of 120s.
- IPC registrations have the cleanest lifecycle: the OS signals disconnect immediately, and Koi starts grace without any polling.
- Permanent mode remains available for operators who explicitly want "register and forget."
