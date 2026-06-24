---
type: REF
domain: health
title: "Health — services + machines at a glance"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.6.0
validation:
  date_last_tested: 2026-06-22
  status: drafted
  scope: "service-check transition path backed by the koi-health unit suite (lib::run_checks_emits_status_changed_through_core, lib::run_checks_probe_concurrently, state::defaults_are_stable); machine-health derivation (collect_machine_health) and the HTTP/CLI surface code-reviewed against crates/koi-health/{lib.rs,machine.rs,service.rs,checker.rs,http.rs}, crates/koi/src/commands/health.rs, and cli.rs — not independently live-tested"
---

# Health — services + machines at a glance

> One-screen map of Koi's health monitor: per-service probes plus auto-derived machine rows. Full flow: [health.md](../../guides/health.md) · endpoint shapes: [http-api.md](../http-api.md).

**What it does** — Koi watches two things from one view. **Services**: each check you add probes a target on its own interval — `Http` does a GET and counts any **2xx** as up (anything else, or a transport error, is down), `Tcp` does a plain connect (timeout = down). State changes are **change-only**: a probe that keeps a check in the same state is silent; only an actual `Up↔Down↔Unknown` transition appends a line to the transition log (`logs/health.log`) and fires a `StatusChanged` event. **Machines**: with no configuration, Koi derives one row per machine it knows about — the union of mDNS-seen hosts and the certmesh roster — carrying `status`, `last_seen_secs`, `sources` (`mdns`/`certmesh`), `cert_expires`, `dns_resolves`, and `warnings`. A machine is `Up` if it was seen within the **60-second** staleness threshold, `Down` if older, `Unknown` if never seen; warnings flag `cert_expired` (already past) or `cert_expiring` (within **7 days**). Proxy entries auto-register as `proxy:<name>` HTTP checks, and all service checks feed the Prometheus SD target groups.

## The one canonical pattern

Add a service check; read everything (machines + services) in one snapshot; watch live or read the transition log.

```bash
koi health add api --http https://api.internal/healthz   # GET; 2xx = up
koi health add db  --tcp  db.internal:5432               # connect = up

koi health status        # one view: Machines (auto) + Services (your checks)
koi health watch         # same view, live, refreshes every 2s (Ctrl+C to exit)
koi health log           # only state TRANSITIONS, newest appended (logs/health.log)
```

`status` shows machine rows (`[+] web-01 (last seen 4s)`) above your service rows (`[+] api -> https://api.internal/healthz`). `+`/`-`/`?` map to Up/Down/Unknown.

## Commands & flags you'll use

| Command / flag | What it does |
|---|---|
| `koi health add <name> --http <url>` | HTTP check; **2xx = up**, else down. |
| `koi health add <name> --tcp <host:port>` | TCP-connect check; connect = up, timeout/refuse = down. |
| `--interval <secs>` / `--timeout <secs>` | Per-check cadence + probe timeout. **Defaults `30` / `5`.** |
| `koi health status` / `watch [--interval <secs>]` | One snapshot / live view. **watch default `2`s.** |
| `koi health remove <name>` · `koi health log` | Drop a check (clears its state) · print the transition log. |
| `GET /v1/health/status` · `/list` | Read snapshot / list checks (token-free GET on loopback). |
| `POST /v1/health/add` · `DELETE /v1/health/remove/{name}` | Mutations — require the `x-koi-token` header. |

## The escape hatch / limits

Machine rows are **derived, not configured** — you cannot add a machine directly; populate them by joining the certmesh or letting mDNS see the host (kill both sources and the row goes `Unknown`). The staleness threshold (60s), the cert-expiry warning window (7 days), and the HTTP-client cap (10s) are fixed constants, not flags — the only per-check knobs are `--interval`/`--timeout`. Checks persist to `state/health.json`; the transition log is append-only and never rotated by Koi.

## The proof it works

`crates/koi-health/src/lib.rs::tests::run_checks_emits_status_changed_through_core` drives a real `Unknown→Down` transition through `HealthCore` (TCP check at a closed port) and asserts the change-only `StatusChanged` fires; `run_checks_probe_concurrently` proves N due checks probe in parallel (one timeout, not their sum); `state::tests::defaults_are_stable` pins the `30`/`5` defaults. The OpenAPI router test asserts `/v1/health/status` is mounted. Machine-health derivation (`machine::collect_machine_health`) and the CLI/HTTP surface are code-reviewed against the cited files; the live snapshot is the Health act in [whole-story-e2e-surface.md](../../testing/whole-story-e2e-surface.md).
