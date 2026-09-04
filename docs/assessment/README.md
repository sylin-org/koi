# Project Assessment Corpus

Assessments of Koi's capabilities, repository quality, user experience, and strategic
direction. Each report is a dated snapshot; current release acceptance lives in the
active fleet epic and surface ledger.

## Start here

- **[2026-09-delight-mandates-and-ux-direction.md](2026-09-delight-mandates-and-ux-direction.md)** —
  User mandates following the assessment, screenshot findings, break-and-rebuild proposals,
  and the installation, network launchpad, second-machine, container, and secure-access experience.
  Distinguishes required outcomes from design recommendations.
- **[2026-09-sylin-visual-dictionary.md](2026-09-sylin-visual-dictionary.md)** —
  Source-derived Sylin/Ghostlight visual vocabulary for Koi: exact family tokens, components,
  motion, product-state meanings, and the mapping to Home, Devices, Settings, and About.
- **[2026-09-delight-and-1.0-assessment.md](2026-09-delight-and-1.0-assessment.md)** —
  September 4 assessment: delight by audience, current capabilities, good/bad/ugly,
  verified UX and documentation findings, repository quality, certmesh opportunities,
  and proposed 1.0 acceptance outcomes. [Verification and limits](2026-09-assessment-verification.md).
- **[realignment-2026-06-22.md](realignment-2026-06-22.md)** — **historical status** (2026-06-22):
  every defect, lean-plan move, shed item, and stage from the snapshot below, mapped to its
  then-current state against `dev` HEAD with commit/file evidence (**11 of 12 verified defects
  resolved**). Read this for what remained in June; read the snapshot below for the original
  analysis (preserved unchanged as history).
- **[2026-06-maturity-assessment.md](2026-06-maturity-assessment.md)** — the synthesis
  (2026-06-11 snapshot): identity (declared vs revealed), maturity scorecard, verified defects,
  strengths, the lean-architecture plan (keep / demote / shed), strategic opportunities, and the
  staged maturation roadmap.

## Evidence layer

- **[findings/verification-2026-06.md](findings/verification-2026-06.md)** — 14
  load-bearing claims adversarially verified against source, git history, dependency
  code, and live external state. All confirmed; read this before disputing any number in
  the synthesis.
- **findings/reader-*.md** — ten parallel deep-read reports, one per lens:

  | Report | Lens |
  |---|---|
  | [reader-vision-philosophy.md](findings/reader-vision-philosophy.md) | Stated philosophy, scope evolution v0.1→v0.2, defensive publications |
  | [reader-adr-history.md](findings/reader-adr-history.md) | Decision history, ADR forensics, the 010→013 reversal |
  | [reader-certmesh-deep.md](findings/reader-certmesh-deep.md) | The PKI pillar (45% of the codebase) |
  | [reader-mdns-core.md](findings/reader-mdns-core.md) | mDNS domain, lease engine, browse-concurrency bug |
  | [reader-small-domains.md](findings/reader-small-domains.md) | dns/health/proxy/udp/runtime; per-domain scaffolding tax |
  | [reader-binary-cli-dx.md](findings/reader-binary-cli-dx.md) | CLI ergonomics, four execution modes, manifest drift |
  | [reader-adapters-ux.md](findings/reader-adapters-ux.md) | HTTP/IPC adapters, dashboard & browser UX, XSS |
  | [reader-embedded-dx.md](findings/reader-embedded-dx.md) | koi-embedded / koi-client / command-surface |
  | [reader-quality-infra.md](findings/reader-quality-infra.md) | CI, release engineering, test pyramid, crates.io state |
  | [reader-docs-onboarding.md](findings/reader-docs-onboarding.md) | Docs accuracy, onboarding path, .agentic drift |

## Research layer

- **[research/landscape-2026.md](research/landscape-2026.md)** — incumbent analysis per
  capability (Avahi, Bonjour, Tailscale, mkcert, step-ca, Caddy, OrbStack…), the
  container-mDNS and LAN-TLS questions, new entrants, differentiation synthesis.
- **[research/trends-opportunities-2026.md](research/trends-opportunities-2026.md)** —
  strategic openings (MCP/agentic substrate, self-hosted consolidation, dev-loop golden
  path, IoT diagnostics, `.internal`), each with evidence strength and explicit
  anti-goals.
- **[research/collaboration-strategy-2026.md](research/collaboration-strategy-2026.md)** —
  the integrate-don't-replace strategy: nine further opportunities (ACME facade, DNS
  sync engine, `koi dns adopt`, tailnet coexistence, Prometheus/dashboard feeds, proxy
  collaboration, Home Assistant channel, generic truststore, Proxmox backend), five
  sharpened differentiation axes, and a collaboration doctrine.

## Execution layer

- **[Epic 003 - delight realignment](../../fleet/epics/003-delight-realignment.md)** —
  Linux-delegated September realignment with code, installation, four-module UI, local sharing,
  secure-service, documentation, accessibility and exact-candidate acceptance gates.
  [Thirty bounded prompts](../prompts/delight/README.md) and a single task ledger make
  it executable without prior conversation. Activation is separate from the current native campaign.
- **[June prompt stash](../prompts/README.md)** — historical P01–P14 session work
  orders and their [DX charter](../prompts/CHARTER.md). They preserve the earlier
  roadmap and do not govern Epic 003, which has its own execution contract.

## Caveats

- Reader reports are point-in-time (2026-06-11, working tree at commit 4426d77) and were
  generated by parallel AI agents; the synthesis only relies on claims that passed the
  verification pass, but the reader files themselves may contain unverified detail.
- Research documents cite external URLs as of June 2026.
