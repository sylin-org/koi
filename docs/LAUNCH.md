# Launch Plan (internal — publication requires operator authority)

Status: **paused** while the `1.0.0-dev.0` observable-domain-boundary rebuild and its
replacement validation complete. The former rc.2 soak/freeze is not an active launch gate.
Nothing here posts externally by itself; the operator executes every public action. This
document retains the launch sequence for a future explicitly accepted candidate.

---

## Positioning (one line, three audiences)

> **Koi gives everything on your LAN a real name, real TLS, and a real identity —
> no accounts, no cloud, no ceremony.** Containers, devices, scripts, and AI agents
> find each other, trust each other, and talk.

- Homelab/self-hosters: mDNS + DNS + HTTPS that just works; avahi coexistence; no
  accounts ever.
- Agent builders: your MCP callers get named, individually-revocable identities
  (Agent-Door) instead of shared bearer tokens.
- Rust embedders: `koi-embedded` puts the whole substrate in-process.

## Asset checklist

| # | Asset | Source | Owner | Status |
|---|---|---|---|---|
| A1 | Golden demo script | catalog-driven: Windows SDK caller → Arch CA → Debian services (mDNS/DNS/webhooks) | agent drafts | missing |
| A2 | Compatibility matrix page | planner output + SURFACES rows → generated table with run ids | agent drafts | missing |
| A3 | "Every claim has a run id" post | SURFACES.md + testing philosophy + D-deviation culture | agent drafts | missing |
| A4 | Verified 3-OS quickstart | install → running → dashboard < 5 min on Windows/Arch/Debian | needs ADR-031 L0/L1 | partial |
| A5 | Capability-card writeups | cards are ~80% blog-ready; add hero diagrams | light editing | partial |
| A6 | Honest-limits page | promote existing documented limits to first-class | light | partial |

## Channels & sequence (stable 1.0 = day 0)

- **Day −7..0:** A1–A4 complete; quickstart re-verified against the final tag.
- **Day 0:** stable release. README/quickstart live. crates.io/npm per their gates.
- **Day 1–2:** r/selfhosted + r/homelab posts (A6 + demo GIF). Tone: show the
  evidence culture; answer every comment with run ids.
- **Day 3–5:** Show HN ("Show HN: Koi – LAN discovery with real TLS, no accounts").
  The honesty ledger is the HN-proof: scrutiny is met with receipts.
- **Week 2:** MCP ecosystem listings/directories (agent angle), Lobsters crosspost of
  A3, first capability deep-dive post (certmesh: PKI without the ceremony).
- **Ongoing:** one card-turned-post per fortnight; matrix re-published with each
  release's new proven pairings.

## Rules (from the doctrine)

1. Announce proof, never promise surfaces. Every claim links evidence.
2. Capacitation tone: enable the reader's own LAN; no comparisons that punch down.
3. External accounts/services are never required for any advertised flow.
4. The operator performs all external posting; drafts and assets are prepared here.
