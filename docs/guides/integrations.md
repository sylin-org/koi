# Connect Koi to existing tools

Adopt Koi for a specific remaining task in an existing container/LAN setup.
Keep a working resolver, proxy and monitoring system. The interfaces below have
prerequisites; consuming a familiar format does not prove a complete integration.

First establish [second-machine application access](../../CONTAINERS.md).
Use [release readiness](../launch/README.md) for named artifacts and accepted
partner versions. No new integration preview is implied by these source notes.

## Prometheus

Koi exposes HTTP service discovery at GET /v1/sd/prometheus:

```yaml
scrape_configs:
  - job_name: koi-lan
    http_sd_configs:
      - url: "http://127.0.0.1:5641/v1/sd/prometheus"
```

This assumes Prometheus can reach that local endpoint. A container or remote
Prometheus needs the correct host route and [authentication](api-authentication.md).
The default response includes managed targets; include=discovered additionally
includes observed HTTP services. A discovered HTTP service is not necessarily a
Prometheus metrics endpoint. Relabel/filter targets and metrics paths accordingly.

An empty result may reflect no eligible targets, not proof that all services are
absent. Verify a known app and an actual successful scrape.

Available metadata includes name, source, service type, health and, when matched,
certificate expiry. __meta_* labels exist during relabeling:

```yaml
relabel_configs:
  - source_labels: [__meta_koi_source]
    target_label: koi_source
  - source_labels: [__meta_koi_cert_expiry_days]
    target_label: koi_cert_expiry_days
```

Certificate metadata is present only when Koi can associate the target with a
known certmesh identity. It is not a handshake check of every target's TLS leaf.

## Existing routing labels

Koi can derive metadata from selected Traefik and caddy-docker-proxy labels.
Explicit koi.* metadata takes precedence; koi.enable=false opts out.
Reading labels can lead to derived discovery/naming resources: it is not merely
a passive inventory operation.

For Traefik, the parser reads the first Host value from a router rule and a
load-balancer server port. traefik.enable=false is respected.
For caddy-docker-proxy, it reads the first caddy hostname and a numeric port in
the reverse_proxy upstream directive.

The parser does not implement the full semantics of either routing engine.
Multiple hosts/rules, unsupported expressions and unpublished ports require
inspection. Check source metadata in /v1/runtime/instances, the derived endpoint,
and actual peer access before relying on it.

Labels do not automatically supply a matching service certificate.
[Runtime](runtime.md) and [container TLS](recipes/container-trusted-cert.md)
describe the boundary.

## Existing DNS

[Conditional forwarding](dns-coexistence.md) lets an existing resolver query
Koi's local zone. /v1/dns/zone can also export hosts, dnsmasq or JSON formats.

Forwarding tracks live answers; static imports need an update/removal mechanism.
Verify the client's ordinary DNS path and application URL. Removing a forwarding
rule ends this dependency; plan for services using those names.

## Existing certificate tooling

koi trust can manage a known CA root in the OS store. Test the actual browser or
language runtime, which may use another root source.

Koi's private ACME implementation needs P-256 account support, a DNS provider and
an exact account-bound grant. The current public grant/listener operation is
incomplete. [ACME](acme.md) describes its prerequisites; a stock proxy custom-CA
setting is not sufficient.

A maintained partner integration must prove initial setup, actual second-client
access, renewal, reload, interruption recovery and removal for named versions.

## Outbound webhooks

A daemon can send signed event envelopes to declared sinks. Select a JSON
manifest with --webhooks PATH or KOI_WEBHOOKS:

```json
[
  {
    "url": "https://receiver.example.invalid/koi",
    "secret": "<replace-with-a-private-random-shared-secret>",
    "enabled": true
  }
]
```

Replace the non-routable example URL and secret. Restrict manifest permissions.
It is read at daemon startup, not hot-reloaded. No manifest leaves fan-out off;
--no-webhooks disables it explicitly.

The envelope contains v:1, event:{id,type,data}, and provenance with node, zone
and seen_at. The x-koi-event-id header carries the event id. x-koi-signature is
sha256= followed by an HMAC-SHA256 of the exact body bytes using the shared secret.
Verify before parsing or acting; deduplicate repeated event ids.

Delivery is best effort, with at most three attempts per event and bounded
backoff/request timeout. There is no durable queue. A slow sink can lose events
without blocking the other sinks or source. Consumers should reread authoritative
state after reconnect or suspected loss. HMAC does not encrypt payloads; use a
properly trusted HTTPS receiver when privacy matters.

## Application and agent clients

[HTTP authentication](api-authentication.md) supports scripts and applications.
[Embedding](embedded.md) provides Rust APIs; [MCP](mcp.md) exposes observations
and selected actions to agent hosts. These are optional paths, not prerequisites
for the initial operator trial.

Test one concrete consumer, its authority, failure behavior and cleanup.
Avoid making broad interoperability claims from a sample response alone.
