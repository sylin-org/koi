---
type: REF
domain: mdns
title: "mDNS discovery — find & announce services"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.6.0
validation:
  date_last_tested: 2026-06-22
  status: verified
  scope: "unit (koi-mdns suite; daemon::new_subscriber_replays_warm_cache + the per-type browse-multiplexing/receive-health tests in daemon.rs) + two-box cross-host (scripts/integration/cross-host-test.sh step 10: a member daemon's `koi mdns discover _certmesh._tcp` resolves the CA's record over real mDNS, plus the `_http._tcp` self-announce check)"
---

# mDNS discovery — find & announce services

> One-screen map of zero-config LAN service discovery. Full flow: [mdns.md](../../guides/mdns.md) · wire shapes (NDJSON / service records / SSE): [wire-protocol.md](../wire-protocol.md).

**What it does** — Koi speaks **mDNS / DNS-SD** (the `_name._proto.local.` protocol behind Bonjour/Avahi), so any host on the LAN can **announce** a service and any other host can **discover** it with **no daemon, no config, and no central registry**. `koi mdns discover` browses for live services, `koi mdns announce` publishes one, `koi mdns resolve` looks up a single instance's address/port/TXT, and `koi mdns subscribe` streams found/resolved/removed lifecycle events. It runs three ways transparently: **standalone** (a one-shot local browse, no daemon needed), **client** (the same command talks to a running daemon over HTTP and keeps the registration alive with heartbeats), and **piped** (NDJSON in/out for scripting). The `mdns-sd` engine is isolated behind one worker thread, with a single shared querier per service type fanned out to every subscriber.

## The one canonical pattern

Announce a service on one box; discover it from another. No setup on either side.

```bash
# On the service host — publish (runs until Ctrl+C; the record is withdrawn on exit):
koi mdns announce "My App" _http._tcp 8080            # name, type, port
koi mdns announce "My App" _http._tcp 8080 --ip 10.0.0.5 version=1.0 env=prod

# On any other LAN host — browse, then resolve one instance:
koi mdns discover                  # every type (meta-query) — one name per line
koi mdns discover _http._tcp       # just HTTP services, with host/ip/port
koi mdns resolve "My App._http._tcp.local."   # full address + TXT for one instance

# Watch lifecycle (found / resolved / removed) as a live stream:
koi mdns subscribe _http._tcp
```

`discover`/`subscribe` are SSE-style streams that auto-close after an idle window (default 5s, override with `--timeout <secs>`, `0` = run forever). A service type may be given bare (`http`) or fully qualified (`_http._tcp`).

## Commands & flags you'll use

| Command / flag | What it does |
|---|---|
| `koi mdns discover [type]` | Browse the LAN. Omit `type` for the all-types meta-query (one name per line); give a type for full records. |
| `koi mdns announce <name> <type> <port> [--ip <addr>] [KEY=VALUE ...]` | Publish a service. `--ip` pins one A record (default: advertise all); trailing `KEY=VALUE` pairs become TXT. |
| `koi mdns resolve <instance>` | Resolve one full instance name → host, ip, port, TXT. |
| `koi mdns subscribe <type>` | Stream found/resolved/removed events for a type. |
| `koi mdns unregister <id>` | Remove a service by the registration ID `announce` returned. |
| `--timeout <secs>` (global) | Stream/announce duration; `0` = run forever (default discover/subscribe idle is 5s). |
| `koi mdns admin {status,ls,inspect,drain,revive}` | Inspect/manage a daemon's registrations (client mode only). |

## Leases & the escape hatch

How long a record lives depends on **who registered it**: the standalone/CLI `announce` registers **permanent** (lives until Ctrl+C unregisters it); an IPC/pipe registration is **session-scoped** (dropped when the connection closes, after a grace); an HTTP registration uses a **heartbeat lease** (90s lease / 30s grace — the daemon-backed `koi mdns announce` auto-sends `PUT /v1/mdns/heartbeat/{id}` at half the lease). Discovery needs **no daemon** — it just works on the LAN; but if a daemon is running, the same command becomes a client of it (force a fresh local browse with `--standalone`). mDNS is LAN-scoped by design: it does **not** cross subnets/VLANs without an mDNS reflector. To carry these names off the `.local.` link, pair discovery with the DNS resolver ([dns.md](../../guides/dns.md)).

## The proof it works

Unit: the `koi-mdns` suite — `daemon::new_subscriber_replays_warm_cache` proves a `discover` joining a long-lived daemon sees already-resolved services (the warm-cache replay that fixed the daemon-browse defect), plus the per-type browse-multiplexing and receive-health verdict tests in `crates/koi-mdns/src/daemon.rs`. Live: the two-box cross-host gate (`scripts/integration/cross-host-test.sh`, step 10) confirms a member daemon's `koi mdns discover _certmesh._tcp` resolves the CA's record over **real mDNS**, and the `_http._tcp` self-announce is observed via `admin ls`. Surface ledger row: `mdns` in [SURFACES.md](../../SURFACES.md).
