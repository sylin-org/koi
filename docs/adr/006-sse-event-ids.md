# ADR-006: UUIDv7 Event IDs on SSE Streams

**Status:** Accepted  
**Date:** 2025-10-01  

## Context

The SSE endpoints (`/v1/mdns/discover`, `/v1/mdns/subscribe`) did not emit `id:` fields. Clients could not deduplicate events after reconnection — duplicate `resolved` events were observed in practice. SSE natively supports `id:` fields and the `Last-Event-ID` request header for resumption, but this protocol-level functionality was unused.

## Decision

Each SSE event gets a UUIDv7 identifier emitted as the SSE `id:` field. UUIDv7 was chosen because it is monotonic (embeds a millisecond timestamp), globally unique (no coordination across restarts), and stateless (no sequence file or counter to persist). The `uuid` crate's `v7` feature flag was enabled — no new crate additions.

Server-side replay is explicitly deferred. Clients receiving `Last-Event-ID` on reconnect get a fresh stream and reconcile via a one-shot browse. The event ID enables client-side deduplication immediately, which solves the observed problem without server-side state.

## Consequences

- Clients can deduplicate events out of the box by tracking the last-seen `id:`.
- Events may still be missed on reconnection until a replay buffer is implemented (deferred to a future version).
- UUIDv7 IDs also serve as correlation tokens in logs, providing natural time-ordering for debugging.
- The only cost is one additional `id:` line per SSE event — negligible for a LAN-local streaming protocol.
