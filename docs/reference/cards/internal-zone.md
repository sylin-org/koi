---
type: REF
domain: dns
title: ".internal zone — capability card"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.4.2
validation:
  date_last_tested: 2026-06-22
  status: verified
  scope: "unit (cli.rs dns_zone default = \"internal\"); live default + override (KOI_DNS_ZONE) exercised on the Linux test host"
---

# .internal zone — capability card

> One-screen map of Koi's default local DNS zone. Names resolve as `<name>.internal`. Full DNS flow: [dns.md](../../guides/dns.md) · living-with-Pi-hole: [dns-coexistence.md](../../guides/dns-coexistence.md) · strategy: [ADR-016](../../adr/016-strategic-realignment.md).

**What it does** — Koi's resolver serves a single local zone, and that zone now defaults to **`.internal`** (changed from `.lan`; greenfield, pre-1.0, **no `.lan` compatibility shim**). `.internal` is the **ICANN-reserved private-use TLD** — the one suffix you can safely use on a LAN that will never collide with a real public name. That matters because it's the only private suffix Koi's CA can issue **warning-free TLS** for: certmesh's ACME facade restricts dns-01 issuance to **in-zone names**, so `web.internal` gets a real, browser-trusted cert from the local CA while `web.lan` (or any made-up TLD) cannot. discover → name (`.internal`) → trust (certmesh) → serve is the integrated pipeline ([ADR-016](../../adr/016-strategic-realignment.md)).

## The one canonical pattern

Add a record; it resolves (and is ACME-issuable) under `.internal`. Override the suffix only if you must.

```bash
# Default zone is "internal" — no flag needed:
koi dns add grafana 10.0.0.5            # → grafana.internal  A 10.0.0.5
koi dns lookup grafana.internal         # → 10.0.0.5
koi dns list                            # shows every resolvable .internal name

# Override the suffix (flag or env), e.g. to mirror an existing convention:
koi --dns-zone corp.example --daemon
KOI_DNS_ZONE=corp.example koi --daemon
```

A name issued in-zone is the same name certmesh/ACME will sign — so `https://grafana.internal` is trusted on any host that trusts the certmesh root (see [trust.md](../../guides/trust.md)).

## Commands & flags you'll use

| Command / flag | What it does |
|---|---|
| `--dns-zone <zone>` (`KOI_DNS_ZONE`) | Local zone suffix. **Default `internal`.** |
| `--dns-qps <n>` (`KOI_DNS_QPS`) | Max DNS queries/sec per client. **Default `200`.** Limiting is per source IP with a whole-resolver backstop; shed queries return `REFUSED`. |
| `koi dns add <name> <ip>` | Add a static record under the zone (`<name>.<zone>`). |
| `koi dns lookup <name>` | Resolve a local name (`A`/`AAAA`/`ANY`). |
| `koi dns list` / `koi dns status` | List resolvable names / show zone + record counts. |

## The escape hatch

`.internal` is the default, not a lock-in: set `--dns-zone` / `KOI_DNS_ZONE` to any suffix your environment already uses (but only `.internal` carries the ICANN private-use guarantee + warning-free ACME). And Koi is built to **coexist, not compete** with an existing resolver — it answers its own zone and defers the rest, so it sits alongside Pi-hole / AdGuard / Unbound rather than replacing them ([dns-coexistence.md](../../guides/dns-coexistence.md)).

## The proof it works

Unit: `crates/koi/src/cli.rs` asserts the `dns_zone` default is `"internal"` across the CLI/daemon config paths. Live: the default zone plus a `KOI_DNS_ZONE` override were exercised on the Linux test host; the resolve→issue path is the DNS/ACME acts in [whole-story-e2e-surface.md](../../testing/whole-story-e2e-surface.md).
