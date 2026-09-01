# ADR-033: Koi Desktop Workbench

**Status:** Accepted (operator-directed 2026-08-24)
**Date:** 2026-08-24
**Builds on:** ADR-020 (truthful states), ADR-031 (desktop control plane), ADR-024 (product identity), ADR-040 (local operator control)
**Resides:** `sylin-org/koi-desktop` (separate repository, Ghostlight precedent)
**Constrained by:** headless daemon doctrine; binary-size discipline of `koi` itself; zero telemetry

---

## Context

ADR-031 sequenced desktop delight as L0 → L1 (tray-icon MVP) → L2 (embedded pane
shell, Tauri named as leading candidate, explicitly deferred). The operator has
now resolved that deferral early, with evidence:

1. The existing web dashboard is deprecated UX relative to the family's published
   experience (sylin.org / Ghostlight) and will not be embedded or extended.
2. Ghostlight (`browser-mcp`) has already solved the hard desktop problems
   in-family: Tauri 2 lifecycle, tray, plugins, Linux webview guards, packaging.
3. Stable-gate sequencing yields to product direction for a single-developer
   project: there is no competing feature work to protect.

## Decision

### 1. A purpose-built Tauri 2 workbench, in its own repository

`screens are native; the pond stays one.` The workbench is a separate artifact
(`koi-desktop`) so `koi`'s gates, size, and publish inventory stay untouched.
Tauri versions pin to Ghostlight's exact choices (tauri `=2.11.5`,
tauri-build `=2.6.3`) so family fixes transfer directly.

### 2. Visual language: Ghostlight's bones, Koi's skin

Borrow Ghostlight's proven UI system — ground/band/card anatomy, one motion
curve (`cubic-bezier(.22, 1, .36, 1)`), pure JS layers with document-free
transport/store, source-level guard tests. Re-skin with Koi's published
identity from sylin.org: accent `--a #60a5fa`, light `--al #93c5fd`, ground
`#0f0e12`; state colors from the family vocabulary (ok `#4ade80`,
attention `#fbbf24`). The mascot is the published `koi-mascot.png`.

### 3. One frontend rule

Native views exist only where a browser genuinely cannot go: tray presence,
enrollment/ceremony wizards, OS integration (autostart, notifications, config
custody). Everything else speaks to the daemon over its existing loopback HTTP
API — the frozen V1-11 contract. No parallel backend ever grows inside the
shell.

### 4. Intake adapters, not privileged paths

The daemon remains headless and authoritative. CLI, local web API, and the
workbench are three intake channels over the same substrate; the workbench
holds no state the daemon doesn't serve and never invents states (an unreachable
daemon reads "offline"). Long-term, the daemon's internal layering should treat
these uniformly as intake adapters over an application core (DDD hygiene noted
in the ledger, not mandated by this ADR).

The shell discovers that loopback surface through ADR-040's single local-daemon
resolver. It does not assume port 5641 and does not require access to a root/SYSTEM-owned
breadcrumb.

### 5. Scope: the whole capability surface, in value order

The workbench is Koi's primary surface, not a status accessory. Every domain the
daemon serves gets a pane speaking to the existing loopback API — no new backend
semantics; API gaps become daemon tickets, never UI improvisation:

| Pane | Backing surface |
|---|---|
| Status (service lifecycle) | SCM/sc + on-demand daemon ✅ scaffolded |
| Mesh roster ("the pond") + invite/join wizard | `/v1/certmesh/*` |
| DNS records editor (first editor, ADR-031 value order) | `/v1/dns/{list,add,remove,txt}` |
| Health checks + history | `/v1/health/*` |
| Proxy routes | `/v1/proxy/*` |
| Webhook sinks + delivery log | manifest today; sink CRUD = daemon ticket |
| Runtime inventory | runtime endpoints |
| mDNS browse | `/v1/mdns/browser` |

Delivery order follows ADR-031's value order (DNS first among editors), with the
ceremony wizard close behind as the CLI's highest-friction flow made friendly.

## Consequences

- `koi tray` (tray-icon MVP inside the main binary) is superseded before it was
  built; ADR-031's L1 is delivered by the workbench instead.
- Two repositories now carry user-facing frontend code; the visual-language
  borrow must stay deliberate (documented here), not accidental drift.
- Windows-first validation; Linux DE support rides webkit2gtk with Ghostlight's
  guards when ported.

## Alternatives considered

- Tray-icon MVP inside `koi` (ADR-031 L1 as written): days cheaper, but builds
  the wrong thing twice — superseded by this decision.
- Embedding/extending the existing web dashboard: rejected by operator — its UX
  is deprecated relative to the family standard.
- Full native rewrite of every capability view: rejected — duplicates served
  surfaces; the loopback API plus selective native views wins.
