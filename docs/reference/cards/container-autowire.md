---
type: REF
domain: runtime
title: "Container auto-wire (one label → mDNS+DNS+health+proxy)"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.4.2
validation:
  date_last_tested: 2026-06-22
  status: drafted
  scope: "code-reviewed against crates/koi-runtime/src/instance.rs (label/env/Traefik/Caddy extraction), crates/koi-compose/src/orchestrator.rs (start/stop/cleanup → mDNS/DNS/health/proxy), crates/koi-compose/src/cores.rs (--runtime/--no-runtime wiring), crates/koi/src/cli.rs; guarded by the koi-runtime unit suite (label precedence) + koi-compose orchestrator tests (health-kind). The live container start→announce→cleanup loop is not in a named integration test or the two-box suite — not independently live-tested for this card."
---

# Container auto-wire — capability card

> One-screen map of the runtime adapter: one container label drives mDNS + DNS + health + (optional) proxy, and cleans up on stop. Full flow: [runtime.md](../../guides/runtime.md) · partner-label ingestion: [integrations.md](../../guides/integrations.md) · inventory shapes: [http-api.md](../http-api.md).

**What it does** — The runtime adapter watches Docker/Podman lifecycle events. When a container **starts**, it reads `koi.*` labels (or the `koi.announce` / `KOI_MDNS_ANNOUNCE` shorthand) and auto-creates, in one step: an **mDNS announce** per published TCP port (service type from the container port, e.g. 80 → `_http._tcp`, 5432 → `_postgresql._tcp`, else `_koi-managed._tcp`), a **DNS** name (`<name>.<zone>` → host IP), a **health check** (HTTP when `koi.health.path` is set, TCP otherwise), and — only when `koi.proxy.port` is set — a **TLS proxy** entry. When the container **stops**, every resource it created is torn back down (and on daemon shutdown the whole map drains). It also ingests **Traefik/caddy-docker-proxy** routing labels with **zero `koi.*` labels** — the `Host(...)` rule becomes the DNS name and the upstream port becomes the proxy port (explicit `koi.*` always wins; `koi.enable=false` opts out).

## The one canonical pattern

One label on a `docker run` / compose service. Start it and it is announced; stop it and it is gone.

```bash
docker run -d -p 3000:3000 --label koi.announce=grafana grafana/grafana
#   mDNS:   grafana._http._tcp on host port 3000   (container 3000 → _http._tcp)
#   DNS:    grafana.internal → host IP
#   health: TCP check on the host port
docker stop grafana        # all three are removed within seconds
```

```yaml
# compose: same effect; com.docker.compose.service is preferred over the generated name
services:
  grafana:
    image: grafana/grafana
    ports: ["3000:3000"]
    labels:
      koi.announce: grafana
      koi.health.path: "/api/health"   # switch the check from TCP to HTTP GET
```

Zero-`koi.*` path: a container already labeled for Traefik/Caddy gets a DNS name + proxy port for free — Koi only *reads* the labels you wrote (see [integrations.md](../../guides/integrations.md)).

## Commands & flags you'll use

| Label / flag | What it does |
|---|---|
| `koi.announce=<name>` (or `KOI_MDNS_ANNOUNCE=<name>`) | Shorthand — sets `enable=true`, `name`, `dns_name`. Label beats env var. |
| `koi.enable=true\|false` | Explicit opt-in / opt-out. `false` wins over everything (incl. partner labels). |
| `koi.type` · `koi.name` · `koi.dns.name` · `koi.txt.<k>` | Override mDNS type / service name / DNS name / TXT entries. |
| `koi.health.path` · `koi.health.kind` · `koi.health.interval` · `koi.health.timeout` | HTTP path (implies HTTP) / `http`\|`tcp` / interval **30s** / timeout **5s**. |
| `koi.proxy.port` · `koi.proxy.remote` | Enable a TLS proxy on this listen port / allow remote connections. |
| `--runtime auto\|docker\|podman` (`KOI_RUNTIME`) | Backend selector. **Default `auto`.** Any other value is rejected at startup. |
| `--no-runtime` (`KOI_NO_RUNTIME=1`) | Disable the adapter entirely; every other capability still works. |

## The escape hatch / limits

Opt-out is per-container (`koi.enable=false`) or whole-adapter (`--no-runtime`). The orchestrator only acts on instances with an **explicit `enable=true`** (set directly, by the announce shorthand, or by a derived Traefik/Caddy hostname/port) — an unlabeled container is ignored. `koi.certmesh=true` is **parsed but inert**: it is surfaced in `GET /v1/runtime/instances` for external tooling, but Koi does **not** inject a per-container cert. mDNS announces use one registration per **TCP** port (UDP ports are skipped). Inspect what the adapter tracks via `GET /v1/runtime/status` and `GET /v1/runtime/instances` (the latter carries `source: traefik-labels`/`caddy-labels` when routing was derived).

## The proof it works

Unit: `crates/koi-runtime/src/instance.rs` tests cover the full label set, the `koi.announce`/`KOI_MDNS_ANNOUNCE` shorthand + precedence, and Traefik/Caddy extraction with the `explicit koi.* > partner-labels > heuristics` precedence (`explicit_koi_labels_beat_traefik`, `koi_enable_false_beats_everything`, `partner_parsing_never_panics_on_arbitrary_labels`). Orchestration: `crates/koi-compose/src/orchestrator.rs` tests assert the health-kind override/inference (`health_kind_tcp_overrides_path_heuristic`, `health_kind_absent_infers_from_path`); `start → mDNS/DNS/health/proxy` and `stop → teardown` live in `handle_start`/`handle_stop`/`cleanup_all`. The end-to-end **live** container start→announce→cleanup loop is documented in [runtime.md](../../guides/runtime.md) but is not yet pinned by a named integration test — treat the wiring above as code-reviewed, not independently live-validated for this card.
