# Implementing a domain change

Start from the user journey and the existing owner. Add a domain only when a separate state/lifecycle invariant requires one; new capabilities are not the default response to a gap in the container/LAN workflow. Product priorities are in [launch readiness](../launch/README.md).

## Place the behavior

| Concern | Owner |
| --- | --- |
| Domain command and validation | Domain facade |
| Durable storage, status and semantic event | The same domain |
| External engine/session/socket | Provider/runtime owned by that domain |
| Cross-domain reaction | Typed bridge/orchestrator in `koi-compose` |
| Authentication and transport syntax | Adapter in `koi-serve` or the domain's HTTP module |
| Aggregate catalog/product projection | Composition |
| HTML/text rendering | Presentation adapter |

Read the nearest existing implementation and [architecture](architecture.md). Domain crates do not import other domains to inspect their state; shared contracts live in `koi-common`. Keep internal locks and stores private.

## Facade

A domain supplies three interfaces:

- Commands that validate intent and return a meaningful result.
- An immutable latest status, including unavailable/error states the domain can actually determine.
- Events for semantic changes, emitted after the accepted state is published.

Reuse `StatusFeed` and common event-channel primitives. A status revision changes when semantic state changes, not on every poll. Consumers must be able to recover from event lag using a snapshot. Avoid making a transport invent status from several unrelated reads.

## Runtime ownership

A long-running operation has a clear owner, cancellation path and bounded shutdown. Start publication only after the underlying resource exists. Track listener failure after startup; do not retain a permanent `running: true` flag after its task exits.

Generation checks prevent stale callbacks from publishing into a replacement session. Reconciliation must handle unavailable providers, changed interfaces, already-present resources and repeated stop/start. Pass every spawned task into the composition's lifecycle owner as it is created.

## Persistence

Use the shared persistence primitives and distinguish rejected writes, visible replacements and confirmed durability. Update accepted state consistently with the visible result. Use a transaction when one command changes several files that must agree. Do not overwrite malformed/future-schema state with defaults. Preserve exact cleanup ownership for credentials, trust roots and native resources.

## HTTP and clients

Keep route constants beside their handlers and include typed payloads in OpenAPI where applicable. Classify authentication for every new endpoint, especially aggregate GETs and streams, in [the route matrix](http-route-auth-matrix.md). Token-free GET is not an automatic safe default for a new projection.

Keep daemon and embedded serving behavior shared. Add client methods only for the intended public contract; do not expose a private domain method as a product workflow before its authorization, persistence and cleanup path exist.

## Evidence

Choose checks that prove the changed invariant: persistence fault injection, listener failure, identity continuity, unauthorized requests, event-lag recovery or real runtime recreation. A rendering snapshot or a synthetic backend cannot establish physical application reachability.

Use existing tests and the [QA suite](../qa/validation-suite.md). Record exact source, artifact, environment, assertions and restoration for native checks under [the fleet contract](../../fleet/CONTRACT.md). Review accepted architecture decisions in `docs/adr`; current task/readiness state belongs in the launch documents.
