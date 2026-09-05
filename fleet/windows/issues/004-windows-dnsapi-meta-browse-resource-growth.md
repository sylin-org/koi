# Issue 004 — Windows DNS-SD meta-browse admits unrelated PTRs and expands native resources

**Opened:** 2026-09-04 during Epic 002 OD-3 soak
**Status:** resolved — R03 source correction and installed Windows acceptance complete; owner reconciliation requested
**Machine:** stone-leaded-sparkle
**Run:** `v1-20260904-od3-b3eb47e-win`
**Frozen source:** `b3eb47e08817045f9371703d780ada9aab00995d`

## Observed

The six-hour frozen-candidate SCM collector captured 361 one-minute samples and
passed every identity, health, provider, publication, transition and physical-peer
traffic check. It failed both bounded native resource checks:

| Counter | First report sample | Final report sample | Growth | Allowed |
|---|---:|---:|---:|---:|
| handles | 364 | 1,693 | 1,329 | 16 |
| threads | 75 | 355 | 280 | 8 |

The scheduled restart makes the report delta conservative rather than causal.
For the new PID `22564` alone, 300 samples began at 279 handles / 50 threads and
ended at 1,693 / 355, with maxima 1,749 / 429. The process remained elevated after
the collector. This is a real installed-service result, not a second daemon or an
isolated fixture.

The simultaneously observed browser snapshot contained 64 `service_types` but
only 27 instances. False types included:

- `Koi MCP (bluefin)._mcp._tcp`;
- `Google-Nest-Hub-…._googlecast._tcp`;
- rotating `I…._FC9F5ED42C8A._tcp` Android instance names;
- bare Android host labels.

These are instance FQDNs or host labels, not answers naming DNS-SD service types.
Each false type can feed the dashboard's `sync_type_pumps` path and start another
per-type browse/native worker. The snapshot cache retains zero-count false types,
so rotating instance labels make the set grow across an ordinary lived-in session.

## Responsible boundary

`crates/koi-mdns/src/windows_dnsapi.rs::open_dnsapi_browse` starts one
`DnsStartMulticastQuery` for a specific PTR owner. Its callback walks the complete
`DNS_QUERY_RESULT` record list and forwards every PTR. It reads each PTR's `pName`
into `query_name`, but never compares that owner with the query that was requested.

An mDNS response to `_services._dns-sd._udp.local.` may legally carry additional
PTR records for service-to-instance relationships. The current callback therefore
projects those additional records as meta-query answers. The same missing owner
check can contaminate an ordinary type browse with unrelated PTRs from the response.

The collector is behaving correctly: `WindowsScmObserver` uses structured Win32
process handle and thread counts, and the exact same short collector previously
passed. Raising thresholds would conceal the boundary failure.

## Required correction

1. At the Windows DNS API adapter boundary, accept a PTR only when its record owner
   is the normalized requested query name (case-insensitive DNS comparison and
   trailing-dot normalization). Do not try to repair false types in the dashboard.
2. Add negative tests proving a meta response's additional service-to-instance PTR
   is ignored and an ordinary browse ignores unrelated PTR owners. Preserve the
   existing TTL-zero removal path for matching records.
3. Prove the corrected Windows adapter still resolves real matching instances and
   withdrawals, then run a bounded installed-service resource test with the lived-in
   workbench/meta-browser active. The type set must remain composed only of actual
   service types and handle/thread growth must remain within the published limits.
4. A product correction invalidates the frozen OD-3 candidate. Do not relabel this
   failed report or reuse its run ID; the fleet owner must publish a replacement
   freeze and schedule any required physical rerun after the R01 handover decision.

## R03 implementation status — 2026-09-05

The source boundary now retains the requested query in the DNSAPI callback context
and admits a PTR only when its owner matches that query using ASCII
case-insensitive, trailing-dot-insensitive DNS comparison. Matching meta answers are
parsed as base service types; matching ordinary and subtype targets are parsed as
instances in their base service namespace, including escaped presentation labels.
The discovery snapshot now carries query/provider/generation/availability for empty
sources and source-scoped facts, while its compatibility vectors converge duplicate
case variants and matching goodbyes.

Portable regression coverage uses a synthetic mixed PTR/SRV/TXT/A/AAAA result and
negative unrelated-owner cases. The complete workspace also compiles for
`x86_64-pc-windows-gnu`, covering the changed adapter and Windows-only tests. These
are source checks only. This issue remains open until an operator-dispatched Windows
session proves matching instance resolution and withdrawal on the installed Koi,
then repeats the bounded lived-in meta-browser handle/thread gate under a new run ID.

## Windows acceptance — 2026-09-05

The operator-dispatched Windows run built and transactionally installed exact
published source `7344db3b99ff4107a93e1011ee4f0043967e1b1f`; its product binary SHA-256
is `b10718f8bf5cc7367b272b24ffd261801c9eab67b7e9e8b5efa5eda650d56b08`.
The real DNSAPI adapter resolved a matching run-owned CachyOS Avahi instance and,
after graceful peer withdrawal, emitted its removal through the same subscription.
The installed daemon independently retained the resolved and removed transition in
its authoritative browser snapshot.

With the installed workbench and meta-browser active, bounded run
`v1-20260905-r03-7344db3-win-01` captured 21 samples over 600 seconds. The service
kept PID `15528`, concrete DNSAPI/native routes, a converged permanent publication,
and 21/21 successful physical Debian Koi Pond reads. There were no unavailable
samples, PID changes, restarts or recovery events. First-to-final growth was
2,482,176 bytes RSS, 11 handles and 3 threads, passing the published 67,108,864-byte,
16-handle and 8-thread limits. The browser held 17 service types; every row matched
the concrete `_name._tcp|udp` shape, with no instance FQDN or host label admitted.

Peer Pond intent, peer publication processes, Windows Pond intent, config, operator
policy, service identity and workbench identity were restored or preserved exactly.
The Windows journal entry `2026-09-05 (26)` carries the complete native procedure,
harness-attempt disposition, hashes and reconciliation boundary. This closes the
Windows-owned defect evidence; Debian remains the R03 source/status owner and has a
ledger request to reconcile this result with its remaining CONTRACT handoff.

## Evidence

- Canonical report:
  `.lab-runs/v1-20260904-od3-b3eb47e-win/installed-service.json`, SHA-256
  `adbf90cc4584497f7eb93c22baa28ec1d8d03cbf23cc84d84045e7b669d072d5`.
- Collector transcript and scheduled-action receipts:
  `.tmp/od3-soak-windows/`.
- Windows journal entry `2026-09-04 (24)` records artifact/PID, peer traffic,
  cleanup and final installed state.
- Accepted replacement evidence:
  `.lab-runs/v1-20260905-r03-7344db3-win-01/installed-service.json`, SHA-256
  `511d015a975dd3da9e5dd24c0cf20ebed7ebf89f063e24a4a0526f6d6940d0b9`.
- Windows journal entry `2026-09-05 (26)` records the matching physical
  resolve/withdrawal, clean 17-type snapshot, bounded resource verdict, and exact
  peer/local restoration.
