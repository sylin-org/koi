---
type: REF
domain: mdns
title: "mDNS discovery — find & announce services"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-09-05
koi_version: v1.0.0-rc.2
validation:
  date_last_tested: 2026-08-31
  status: verified
  scope: "unit (provider policy, DNS-SD owner/target classification, subtype/escape normalization, transitions, boundaries, browse hub/cache/activity); Windows GNU cross-target compile; physical Avahi adapter; one-installed-process Linux provider transitions; prior two-box LAN interoperability; coordinated transition lane prepared at `scripts/integration/mdns-provider-transition.sh`; corrected Windows adapter still awaits physical issue-004 proof"
---

# mDNS discovery — find & announce services

> One-screen map of zero-config LAN service discovery. Full flow: [mdns.md](../../guides/mdns.md) · wire shapes (NDJSON / service records / SSE): [wire-protocol.md](../wire-protocol.md).

**What it does** — Koi speaks **mDNS / DNS-SD** (the `_name._proto.local.` protocol behind Bonjour/Avahi), so any host on the LAN can **announce** a service and any other host can **discover** it without a central registry. `koi mdns discover` browses for live services, `koi mdns announce` publishes one, `koi mdns resolve` looks up a single instance's address/port/TXT, and `koi mdns subscribe` streams found/resolved/removed lifecycle events. Commands are clients of the healthy installed service by default; `--endpoint` selects another service, while explicit `--standalone` creates a one-shot local composition only when no local service is alive. There is no implicit piped responder. The daemon keeps one stable `MdnsControlPlane` that routes non-overlapping operations to the best live provider sessions; native Koi is always the lowest-priority complete provider. One shared browse per service type fans out to every subscriber.

## The one canonical pattern

Announce a service on one installed Koi; discover it from another.

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

DNS-SD subtype selectors are also accepted, for example
`_printer._sub._http._tcp.local.`. The selector remains the observation query, but
matching PTR targets resolve in the base `_http._tcp.local.` instance namespace.
The authoritative snapshot exposes each demanded query's provider, generation and
availability separately from its accepted facts. This lets diagnostics distinguish
an empty browse from an unavailable source without inventing or discarding service
types. Unknown valid service types remain visible.

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

How long a record lives depends on **who registered it**: an explicit standalone `announce` registers **permanent** (lives until Ctrl+C unregisters it); an IPC/pipe registration is **session-scoped** (dropped when the connection closes, after a grace); an HTTP registration uses a **heartbeat lease** (90s lease / 30s grace — daemon-backed `koi mdns announce` auto-sends `PUT /v1/mdns/heartbeat/{id}` at half the lease). By default the CLI uses the installed responder. Use `--standalone` only for an intentional one-shot composition after stopping that service. mDNS is LAN-scoped by design: it does **not** cross subnets/VLANs without an mDNS reflector. To carry these names off the `.local.` link, pair discovery with the DNS resolver ([dns.md](../../guides/dns.md)).

## The proof it works

Unit: the `koi-mdns` suite guards capability planning, hysteretic transitions,
break-before-make ordering, publication replay, generation fencing, provider
isolation, one-browse-per-type fan-out, warm-cache replay, and receive activity.
Its mixed DNS-SD fixture proves that a meta-query accepts only PTRs whose owner is
the requested enumeration name, while ignoring legal additional instance/host
records; companion cases cover subtype targets, escaped labels, case/trailing-dot
normalization, duplicates, goodbye and source loss. A Windows GNU cross-target
check compiles that adapter path, but it is repository evidence rather than the
pending installed Windows issue-004 resource acceptance.
Physical adapter testing against CachyOS's Avahi proves entry-group publication,
browse, IPv4/IPv6 resolve, interface identity, TXT, explicit IP, and removal. The
same installed Koi process also completed live
`avahi → systemd-resolved+native → native → systemd-resolved+native → avahi`
transitions with exact host-service restoration. The prior two-box gate remains LAN
interoperability evidence; the provider-transition version is the separate
[`mdns-provider-transition.sh`](../../../scripts/integration/mdns-provider-transition.sh)
gate and is not inferred from the local transition. Surface ledger row: `mdns` in
[SURFACES.md](../../SURFACES.md).
