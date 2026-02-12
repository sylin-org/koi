# SSE Event IDs

**Status:** Implemented
**Scope:** Koi HTTP adapter — SSE stream on `/v1/mdns/events`

---

## Problem

The SSE events endpoint does not emit `id:` fields. Clients cannot:

- **Resume after reconnection.** If the HTTP connection drops, the
  client restarts the stream from scratch and may miss events or receive
  duplicates with no way to distinguish them.
- **Deduplicate.** The same `resolved` event can arrive more than once
  (observed in practice). Without an event ID, clients cannot skip
  duplicates.

SSE natively supports `id:` fields and the `Last-Event-ID` request
header for resumption. We're leaving protocol-level functionality on
the table.

## Proposed design

### Event ID format: UUIDv7

Each SSE event gets a UUIDv7 identifier. UUIDv7 is:

- **Monotonic** — embeds a millisecond timestamp, so IDs sort
  chronologically without a shared counter
- **Globally unique** — no coordination across restarts or instances
- **Stateless** — no sequence file to persist or recover

The `uuid` crate (already a dependency with `v4` feature) supports v7
via the `v7` feature flag.

### Wire format

```
id: 019503a1-7c00-7def-8000-1a2b3c4d5e6f
event: resolved
data: {"type":"_http._tcp.local.","name":"My Server", ...}

id: 019503a1-7c01-7def-8000-2b3c4d5e6f7a
event: removed
data: {"type":"_http._tcp.local.","name":"My Server"}
```

### Replay buffer (future, optional)

Phase 1 (this proposal): Emit `id:` fields only. Clients get dedup
capability immediately. `Last-Event-ID` on reconnect tells the server
"I last saw this" but the server does not attempt replay — it starts a
fresh stream. This is still useful: the client knows it may have missed
events and can issue a one-shot browse to reconcile.

Phase 2 (future): Add a bounded in-memory ring buffer of recent events
(e.g. last 1000 or last 60 seconds). On reconnect with
`Last-Event-ID`, replay missed events before switching to live. This
enables true at-least-once delivery.

### Implementation sketch

1. Add `v7` to the `uuid` crate features in `Cargo.toml`
2. In the SSE stream builder (HTTP adapter), generate
   `Uuid::now_v7()` for each event
3. Emit as the SSE `id:` field before the `data:` line
4. Optionally include the ID in the JSON body as well for clients
   that parse the data but not the SSE framing

## Open questions

- Should the event ID also appear inside the JSON payload, or only as
  the SSE `id:` field? Including it in both places helps clients that
  consume events through a non-SSE intermediary (e.g. a WebSocket
  bridge).
- Ring buffer sizing for Phase 2: time-based (last N seconds) vs.
  count-based (last N events)? Time-based is more predictable for
  operators.
