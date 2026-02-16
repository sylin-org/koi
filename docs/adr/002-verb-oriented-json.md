# ADR-002: Verb-Oriented JSON Protocol

**Status:** Accepted  
**Date:** 2025-01-15

## Context

Koi exposes three transport adapters - HTTP, IPC (Named Pipe / Unix Domain Socket), and stdin/stdout - that all need a shared protocol. The protocol must be self-describing, parseable at a glance, and composable with tools like `jq`. Common patterns include envelope-based designs (`{"action": "browse", "params": {...}}`) and verb-oriented designs where the top-level key _is_ the intent.

## Decision

Request and response types are identified by their top-level JSON key. The key is the verb:

```json
→ { "browse": "_http._tcp" }
← { "found": { "name": "Server A", ... } }
← { "registered": { "id": "a1b2c3", ... } }
← { "error": "not_found", "message": "..." }
```

No envelope wrapper, no `action` field, no `type` discriminator. The JSON _is_ the intent. Pipeline properties (`status`, `warning`) attach alongside the verb as flat sibling keys via `#[serde(flatten)]`, not as a nested wrapper. Their absence is the happy path - clean responses have no extra keys.

All three adapters deserialize into a single `Request` enum and serialize from a single `Response` enum. Zero per-adapter model types.

## Consequences

- Messages are self-describing and parseable by `jq` without knowing the protocol schema.
- `#[serde(flatten)]` produces flat JSON output, keeping the wire format simple.
- Adding a new operation means adding a variant to `Request`/`Response`, not a new message type.
- The flat structure means error responses have a different shape than success responses (struct-level keys vs externally-tagged enum). Custom `Serialize` handles this.
- No room for protocol-level metadata (version, correlation ID) without adding top-level keys. Acceptable for a LAN-local tool.
