# ADR-004: Server-Driven Ceremony Engine

**Status:** Accepted  
**Date:** 2025-06-01

## Context

Creating a CA, joining a mesh, and unlocking keys are multi-step interactive operations that must work identically from CLI terminals and HTTP clients. A wizard-style linear flow (step 1 → step 2 → step 3) is fragile - adding a conditional step means rewriting the step index, and different transports render steps differently. The business logic (what to ask, how to validate, when to complete) must live in one place regardless of whether the user is typing in a terminal or submitting JSON.

## Decision

A generic ceremony engine in `koi-common/src/ceremony.rs` drives all interactive flows. The core model is a **bag of key-value pairs** (session state) evaluated by a **rules function**. There is no stage index or linear pipeline:

1. Client sends a `CeremonyRequest` with data (`{}` to begin)
2. Host merges data into the bag, calls `rules.evaluate(bag)`
3. Rules inspect the bag and return `NeedInput` (with prompts/messages), `ValidationError`, `Complete`, or `Fatal`
4. Client renders prompts, collects input, submits next request
5. Repeat until `Complete`

`CeremonyHost<R>` is generic over `R: CeremonyRules`. Sessions use UUIDv7 IDs with a 5-minute TTL. The CLI render loop (`ceremony_cli.rs`) is a "dumb loop" - it sends, renders, collects, repeats. It never contains domain logic.

`PondCeremonyRules` (in `koi-certmesh/src/pond_ceremony.rs`) implements four ceremonies: `init`, `join`, `invite`, and `unlock`.

## Consequences

- The same ceremony is consumed from CLI (terminal I/O) and HTTP (JSON round-trips) with identical business logic. Adding a web UI requires only a new render client.
- The bag-of-keys model means steps are implicitly ordered by what the rules function asks for - no step index to maintain.
- Debugging requires inspecting the bag state, which is less obvious than following a numbered step sequence. `tracing` logs at DEBUG level mitigate this.
- Session TTL means abandoned ceremonies are garbage-collected automatically.
