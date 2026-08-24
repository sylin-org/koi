# ADR-028: Outbound Event Fan-Out (Webhook Sinks)

**Status:** Accepted (operator-ratified 2026-08-23)
**Date:** 2026-08-23
**Builds on:** the domain event-bus architecture (every domain's broadcast Events face), ADR-006 (SSE event IDs — stable event identity), ADR-013 (runtime adapters — transports are adapters), ADR-008 (composition-root wiring)
**Constrained by:** STACK-0001 (K2: generic webhook sinks only; no product-specific integrations in code)

---

## Context

Every domain broadcasts typed events on `tokio::sync::broadcast` channels, and ADR-006 already
gave those events stable identities for the dashboard SSE stream. Today, however, every
consumer is **in-process**: the dashboard forwarder, MCP resource deltas. The only way to
learn that a health check went red or a service left the zone is to be watching a screen.

Operators increasingly run push targets (self-hosted notification hubs, chat bridges, home
automation) that expect to *receive* an HTTP POST. The substrate already decided transports
are adapters (HTTP / IPC / NDJSON / MCP); outbound notification is the missing adapter
direction, and it is what turns Koi from a state store into the event bus of the LAN.

**Scope guard:** this is a push mirror of the existing event bus — not a programmable
automation engine. No rules, no transforms, no scripting. Consumers that want logic run it on
their side of the webhook.

---

## Decision

### 1. Home — composition layer, not a domain crate

The fan-out tap mirrors the `koi-dashboard` precedent: it owns no domain state machine and
emits no domain events of its own, so it is **not** a domain crate. It lives as the `webhook`
module in `koi-compose`, consuming the same merged event stream the dashboard forwarder uses,
and is wired by the binary and `koi-embedded` identically. One tap, one delivery engine,
shared by both consumers of Koi.

### 2. Configuration and tunables

Sinks are declared in daemon config:

```toml
[[webhooks]]
url     = "https://notify.internal/koi"
secret  = "…"            # HMAC key; file perms enforced, never echoed
enabled = true
```

Runtime tunable follows the house pattern: `--no-webhooks` / `KOI_NO_WEBHOOKS=1`, enforced by
the binary crate (no sink tasks spawned when disabled). `/v1/status` gains a `webhooks` field
(`{ enabled, sinks }`) under the transport-not-domain precedent set by `mcp_http`. No HTTP
routes are added; disabled webhooks need no 503 fallback because there is no inbound surface
to refuse.

### 3. Wire contract

One contract for machines, reusing the one humans already have:

```
POST <sink.url>
x-koi-event-id: <ADR-006 event id>
x-koi-signature: sha256=<hex HMAC-SHA256(body, sink.secret)>
content-type: application/json

<body> = { "v": <event version>, "event": <the event's existing serde JSON>,
           "provenance": { "node": <hostname>, "zone": <configured zone>, "seen_at": <RFC3339> } }
```

The inner `event` object is the **same serialized shape the SSE stream carries** — one wire
contract, two transports. Consumers must tolerate unknown fields; Koi never relies on them
not existing (serde deny-unknown-fields stays off for all published event types).

### 4. Delivery semantics — stated honestly

- **Best-effort with bounded retry:** up to 3 attempts per event per sink, exponential
  backoff (1s / 4s / 16s) with jitter. No durable queue; process exit drops in-flight
  deliveries. Webhooks complement the event bus, they do not archive it.
- **Never back-pressures the bus:** the tap subscribes lag-tolerant. On `Lagged`, it emits one
  `webhook_stream_lagged` diagnostic event and continues — a slow consumer can never slow
  discovery, health, or certmesh.
- **Bounded queues per sink:** drop-oldest at 256 pending; saturation emits
  `webhook_sink_overflow` once per episode (never recursively).
- Per-sender concurrency cap (4 in flight); order is best-effort per sink, with
  `x-koi-event-id` letting consumers reorder deterministically.

### 5. Security boundary

- Payloads are **domain events only**. The certmesh append-only audit log, DAT, invites, keys,
  passphrases, and token material are not events and therefore cannot leak through a sink.
- Sinks are **outbound only**: no mDNS record, no DNS TXT, nothing discovers Koi's sinks.
- Sink secrets live in the daemon config with platform-appropriate file permissions and are
  never echoed by status, logs, or CLI output (house serialization-safety rules apply).

### 6. What does NOT ship in 1.0

Retries across process restarts (no durable queue), transforms/templates, filters beyond
severity/domain allowlist, and any named-product integration (K2: ntfy/Discord/home-automation
compatibility is documented as recipes against the generic contract, never code paths).

---

## Protocol surface (net change)

| Surface | Change | Auth |
|---|---|---|
| Daemon config | `[webhooks]` sink array | local file |
| `/v1/status` | + `webhooks {enabled, sinks}` | read (existing rules) |
| Outbound | POST per event to each enabled sink | HMAC-SHA256 signature header |

No new ports, listeners, mDNS/DNS records, or crypto primitives (HMAC-SHA256 via the existing
ring dependency; no new HKDF labels).

---

## Consequences

- Koi gains the "LAN event bus" role without gaining an automation engine — the mirror stays
  dumb so smart consumers stay possible.
- The dashboard forwarder and the webhook tap share one merged-stream source; a future event
  shape change lands once (ADR-006 discipline continues to govern identity/versioning).
- Diagnostic events (`webhook_stream_lagged`, `webhook_sink_overflow`) are themselves domain
  events and therefore webhook-deliverable — bounded by the non-recursion rule above.

## Validation plan

- Unit: HMAC signature test vector; overflow drop-oldest behavior; single-emission-per-episode
  diagnostics; payload redaction scan asserting audit/token/key substrings can never appear;
  serde round-trip of the envelope.
- Integration: run-owned sink fixture (tiny local HTTP receiver) asserts delivery, header
  exactness, id monotonicity, and correct HMAC; a deliberately hung sink proves the bus stays
  healthy and the overflow path fires.
- Physical lane: extends the capability-story transaction with a run-owned sink fixture on the
  observer node, asserting real cross-host delivery plus the exact-cleanup discipline.
- SURFACES row for the new outbound surface; capability card for observability/events.
