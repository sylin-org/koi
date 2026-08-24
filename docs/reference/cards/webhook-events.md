---
type: REF
domain: events
title: "Webhook events — your LAN talks to your tools"
audience: [operators, developers]
status: current
last_updated: 2026-08-23
koi_version: v1.0.0-rc.1
validation:
  date_last_tested: 2026-08-24
  status: verified
  scope: "compose unit suite (envelope/redaction/backoff/manifest), real-TCP integration tests (exact headers, retry-after-failure, disabled-sink isolation), embedded parity test (configured sink receives a signed dns.updated over real TCP + /v1/status reports it), and koi-lab webhook-fanout physical runs v1-20260823T234022Z-ae31ed73 forward (45 deliveries) + reverse (41) — every delivery HMAC-verified at receive on the peer node over the real LAN."
---

# Webhook events — your LAN talks to your tools

> One-screen map of outbound event fan-out (ADR-028): every domain event Koi already
> broadcasts — mDNS finds, DNS changes, health flips, certmesh lifecycle — delivered as a
> signed HTTP POST to sinks you declare. Deeper contract: [ADR-028](../../adr/028-outbound-event-fanout.md).

**What it does** — The daemon's merged event stream (the same feed the dashboard consumes,
same stable event IDs) is mirrored to operator-declared HTTP sinks: notification hubs, chat
bridges, home automation. Each delivery is `POST`ed with `x-koi-event-id`, an HMAC-SHA256
body signature in `x-koi-signature`, and a JSON envelope `{v:1, event:{id,type,data},
provenance:{node,zone,seen_at}}`. Delivery is best-effort with bounded retry (3 attempts);
a dead sink can never slow discovery, health, or certmesh. Sinks are outbound-only — Koi
never advertises them.

## The one canonical pattern

Declare a manifest, point the daemon at it, receive signed events:

```jsonc
// webhooks.json — secrets live here, never on the command line
[
  { "url": "https://notify.internal/koi", "secret": "<long random string>", "enabled": true }
]
```

```bash
koi --daemon --webhooks ./webhooks.json     # foreground daemon
# service context: set KOI_WEBHOOKS=/etc/koi/webhooks.json instead
```

Verify a delivery at your receiver:

```python
expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, headers["x-koi-signature"])
```

## Commands & flags you'll use

| Flag / field | What it does |
|---|---|
| `--webhooks <path>` (`KOI_WEBHOOKS`) | Load the sink manifest (JSON array of `{url, secret, enabled}`). |
| `--no-webhooks` (`KOI_NO_WEBHOOKS`) | Disable fan-out entirely; `/v1/status` reports `webhooks {enabled:false, sinks:0}`. |
| `GET /v1/status` → `webhooks` | `{enabled, sinks}` — transport truth, not a domain rung. |
| `x-koi-event-id` | Same stable ID the dashboard SSE stream carries — dedupe/reorder on this. |
| `x-koi-signature` | `sha256=<hex HMAC-SHA256(body, secret)>`; verify before trusting. |

**Invalid manifests fail loud, not fatal**: a malformed manifest logs `tracing::error!` and
starts with fan-out disabled — matching the mDNS-init precedent (additive transport, never a
boot blocker).

## Embedding Koi

An embedded instance takes sinks programmatically — same engine, same wire contract, no
manifest file:

```rust
use koi_compose::webhook::WebhookSink;

let handle = koi_embedded::Builder::new()
    .http(true)
    .http_port(0)
    .dashboard(true)
    .webhooks(vec![WebhookSink {
        url: "https://notify.internal/koi".into(),
        secret: "<long random string>".into(),
        enabled: true,
    }])
    .build()?
    .start()
    .await?;
```

Sinks ride the merged event stream, so the instance needs `dashboard` **and** `http`
enabled; otherwise the sink logs one loud warning and stays inert.

## The escape hatch / limits

Best-effort means best-effort: no durable queue, no redelivery after process exit, no
transforms or per-event rules — consumers own logic. The certmesh append-only audit log is
**not** event-bus traffic and cannot leak through a sink.

## The proof it works

Compose unit tests pin envelope shape, closed key sets (redaction guard), backoff bounds,
and manifest validation. Real-TCP integration tests assert exact headers, retry carrying
identical id/body after a 500, and that disabled sinks spawn nothing. On hardware:
`koi-lab webhook-fanout` proved brook→granite (45 deliveries) and granite→brook (41), each
HMAC-verified by the receiving fixture itself, with exact cleanup and baseline restoration.
