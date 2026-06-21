# ADR-016: Strategic Realignment — Koi as the LAN Trust & Discovery Substrate

**Status:** Accepted (operator-ratified 2026-06-18)
**Date:** 2026-06-18
**Extends:** ADR-012 (Consolidation Roadmap)
**Incorporates:** ADR-015 (Certmesh Enrollment Hardening) as the security spine
**Constrained by:** STACK-0001 (K2 consumer-neutrality, K3 frozen HKDF labels, D7 contract surface)
**Informed by:** the 2026-06 maturity assessment ([docs/assessment/](../assessment/2026-06-maturity-assessment.md)) and a real cross-platform deploy (Debian 13 + Windows) on 2026-06-18

---

## Context

The maturity assessment found Koi to be a **feasibility prototype wearing beta clothing**: the integration thesis is real and unclaimed in the market, but the product is "not yet honest" — the most user-visible promises (containers over HTTP, TLS termination, Windows parity, working install docs) describe a pre-2026-03-18 product. Separately, a design dialogue reframed Koi's security model (dual-mode → Koi as the node's trust plane) and produced ADR-015 (enrollment hardening). A live deploy on 2026-06-18 then validated the core thesis on real hardware and corrected several stale assumptions.

This ADR consolidates those threads into one accepted realignment: **what Koi is, what it must fix before it can claim anything, the ordered path, and the opportunity ledger.** It supersedes the implicit "all-in-one LAN box" positioning.

### Live-deploy evidence (2026-06-18)

A canonical static-musl Linux binary and a Windows `koi.exe` were built via the new `build.ps1 -Target` (mirrors `release.yml`) and both run. On a Debian 13 box, Koi came up as a systemd service and **the integration pipeline self-wired**: the certmesh+dns+truststore trio plus the `dns←mdns`, `dns←certmesh`, and `health←mdns` bridges all fired automatically (59 LAN services auto-resolvable, ~18 machines auto-discovered, member names auto-added to DNS on CA create, root CA auto-installed in the OS trust store, CA auto-unlocked from the keyring vault). This is the assessment's "the integration is the product" thesis, proven.

Three findings **correct stale effort estimates** (they make the top opportunities cheaper than the assessment implied):

1. **ACME (RFC 8555) already ships.** The daemon logs `ACME adapter listening port=5643`; the full `/acme` surface (self-served dns-01) is implemented. "Local Let's Encrypt your stack already speaks" is *mostly built* — a hardening/positioning task, not a from-scratch build.
2. **LAN HTTP bind already works.** `KOI_HTTP_BIND=0.0.0.0` binds `0.0.0.0` (assessment defect #2 appears resolved on `dev`).
3. **MCP HTTP transport already ships** (`/v1/mcp`, server-card, `_mcp._tcp`). The strongest opportunity needs *framing*, not a build.

Genuine quirks also found: (a) creating the CA on a *running* daemon doesn't start the mTLS/ACME listeners until restart (startup-gated wiring); (b) default DNS zone is `.lan`, not `.internal`; (c) the proxy is still excluded/panics (STACK-0001 D7).

---

## Decision

### 1. The reframe

**Koi is the LAN-native discovery-and-trust *substrate* — the boring, trustworthy layer everything else runs on top of — not an all-in-one box that competes feature-for-feature.** It loses every isolated comparison (Pi-hole/DNS, Caddy/proxy, step-ca/PKI, Tailscale/overlay) and wins the unclaimed fight: the **integrated pipeline** *discover → name → trust → serve → watch*, which no incumbent combines and which the live deploy proved self-wires.

Two operating postures:
- **Koi-as-authority** — run the whole stack greenfield.
- **Koi-as-feeder** — export in everyone else's formats (ACME, RFC 2136, OS split-DNS, Prometheus SD, container labels) and be the supply layer *under* the tools people already run.

The feeder posture operationalizes the **collaboration doctrine: integrate, don't replace** (coexist with Pi-hole/AdGuard; never compete on ad-blocking DNS).

### 2. Architecture corollary — the trust plane

Underneath, Koi's revealed identity is the **node security/identity/trust plane**: *"ask Koi, don't trust the wire"* — trust is cryptographic proof Koi adjudicates against the CA/roster; discovery announcements are untrusted hints. Therefore:

- **Primary surfaces:** identity custody, sign/verify, trust-resolution, posture (secure/non-secure), HTTPS-when-secure, and `.internal` certificate issuance. ADR-015 is the spine.
- **Glue (kept, framed honestly):** discovery, proxy, health.
- **Never grow:** a discovery/membership/mesh-gossip protocol — that belongs to the consumer layer (Zen Garden); Koi provides primitives only.
- Fix the **startup-gated mTLS/ACME listeners** so the trust plane is live whenever the CA exists (not only after a daemon restart).

### 3. The credibility floor (non-negotiable ordering)

**Every strategic opportunity is blocked on truth-telling first.** Announcing positioning while documented examples 401 and the proxy panics is a liability. The path is staged and the order is binding:

| Stage | Goal | Rough size |
|---|---|---|
| **0 — Truth** | Docs/CI/metadata match reality; `status()` stops lying; releases honest | days |
| **1 — Fix product-breaking defects** | proxy (honest status + minimal rustls passthrough), mDNS browse-multiplexing, dashboard XSS, Windows parity (defect #2 http-bind already resolved — verify) | 1–2 wk |
| **2 — Consolidation** | one orchestrator, certmesh diet, K2 consumer-name scrub, koi-common kernel; **ADR-015** lands here | 2–4 wk |
| **3 — Hardening** | the whole-story test surface (CI + cross-platform E2E), cargo-audit, SECURITY.md, re-audit | 2–3 wk |
| **4 — Launch** | SemVer reset, packaging, MCP framing + registry, comparison docs | 2–3 wk |

Strategic opportunities (Tiers B/C below) are **post-Stage-2**. Stage 0 and the cheap docs-only collaboration items may run in parallel.

### 4. DNS zone: `.internal` by default, break-and-rebuild

Change the **default DNS zone to `.internal`** — the ICANN-reserved (2024) private TLD that public CAs are forbidden from issuing for, making Koi's certmesh+dns+truststore trio the *only* warning-free-TLS path. **No `.lan` backward-compatibility shim** (pre-1.0, greenfield discipline; consistent with STACK-0001 and ADR-015). The `--dns-zone` / `KOI_DNS_ZONE` override remains for operators who choose a different zone; there is no legacy `.lan` special-casing.

### 5. Opportunity ledger

Effort reflects the live-deploy corrections. Tier A = foundation (the credibility floor); B = cheap high-narrative wins; C = the headline bets.

| # | Opportunity | Leverage | Effort | Notes |
|---|---|---|---|---|
| A1 | **Truth restoration** (docs/CI/metadata; `status()` truth) | High | S | Unblocked — start now |
| A2 | Fix remaining product defects (proxy panic→honest+passthrough; mDNS multiplexing; XSS; Windows parity) | High | M | Critical path |
| A3 | **ADR-015 enrollment hardening** + fix startup-gated mTLS | High | L (phased) | Trust-plane spine |
| A4 | Consolidation (one orchestrator, certmesh diet, K2 scrub) | High | L | Unblocks the rest |
| B1 | **`.internal` default + framing** (break-and-rebuild) | High | S | The free moat |
| B2 | **ACME = "local Let's Encrypt"** — harden/test/document the *existing* server | High | M | Reclassified ↓ from L (it ships) |
| B3 | DNS-sync Tier-1 (conditional-forwarding recipes: Pi-hole/AdGuard/Technitium) | High | S (docs) | Collaboration, now |
| B4 | Generic trust-store CLI (`koi trust install/list/verify`, any CA) | Med | S | Root-distribution is universal pain |
| C1 | **MCP substrate as the *identity oracle*** (discover + *verify* + posture); `_mcp._tcp` | High | S–M | Emptiest niche; mostly framing (ships) |
| C2 | **Dev-loop golden path** ("OrbStack domains for everyone, cross-platform") | High | M | Needs A2 (proxy); the legible demo |
| C3 | OS-resolver adoption (`koi dns adopt` split-DNS) + Tailnet coexistence | High | M | Kills the "repoint every device" friction |
| C4 | Prometheus HTTP-SD + Home Assistant add-on/HACS | Med–High | M | Selfhosted/HA acquisition channels |

**Headline narrative:** *"the trust & discovery substrate for the agentic LAN"* (C1), made legible by the *OrbStack-for-everyone* demo (C2), with `.internal` + ACME (B1/B2) proving warning-free LAN TLS is one install away — shipped only after A1–A2 close the credibility floor.

### 6. Shed list

Stop chasing: proxy feature-parity with Caddy/Traefik (frame as convenience glue only), ad-blocking DNS (coexist with Pi-hole/AdGuard), FIDO2 enrollment (ADR-015 F16), automatic CA-failover machinery (manual `promote` stays), the compliance endpoint, trust-profile indirection (expose the booleans), the `command-surface` crate (fold into the binary), the pipe/NDJSON IPC adapter, dashboards-as-product, tunneling/public ingress, overlay networking, Matter-controller ambitions, enterprise PKI/SPIFFE, mDNS reflection across VLANs, and the `docs/prior-art` + hand-maintained `.agentic/reference` doc bloat. Health folds from a domain crate into a status/dashboard re-projection (keep the service-checker).

---

## Consequences

### Positive
- A defensible, unclaimed position (substrate for the agentic LAN) instead of unwinnable feature fights.
- The two highest-ceiling bets (MCP, ACME) are near-term, not multi-month builds — the codebase is further along than the assessment implied.
- `.internal` + owns-the-DNS-zone (self-served dns-01) is a structural moat no other private CA has.
- The feeder posture turns every incumbent (Pi-hole, Caddy, Tailscale, Prometheus, HA) from a competitor into a distribution channel.
- Cross-platform is proven (live), neutralizing the OrbStack-is-macOS-only and Avahi-is-Linux-only gaps.

### Negative
- The credibility floor delays *announcing* opportunities until Stages 0–2 are done; discipline over momentum.
- `.internal` break-and-rebuild invalidates `.lan` setups (accepted, pre-1.0).
- Consolidation (A4) is real refactoring effort, though independently mergeable.

### Risk mitigation
- Each stage ships under the gate (`cargo test && cargo clippy -- -D warnings && cargo fmt --check`) and on the 3-OS CI matrix.
- The whole-story test surface (ADR's Stage 3) is the verifiability instrument that prevents regressing into "dishonest" again.
- ADR-015's "CA never emits a key" invariant + cross-platform E2E de-risk the trust-plane spine.
- STACK-0001 K2/K3/D7 remain hard constraints (no consumer naming, frozen HKDF labels, proxy excluded-until-tested).

---

## Relationship to in-flight work

This session already advanced the plan: **ADR-015** is A3's spec; **[docs/testing/whole-story-e2e-surface.md](../testing/whole-story-e2e-surface.md)** is the Stage-3 verifiability instrument; **`build.ps1 -Target`** proves the cross-platform claim and produces real binaries; and the **live deploy** validated the thesis and corrected the effort math above. The cross-node (Windows↔Linux) enrollment validation remains open and feeds Stage 3.

## References
- 2026-06 maturity assessment + research ([landscape](../assessment/research/landscape-2026.md), [trends-opportunities](../assessment/research/trends-opportunities-2026.md), [collaboration-strategy](../assessment/research/collaboration-strategy-2026.md)).
- ADR-012 (consolidation roadmap), ADR-015 (enrollment hardening), STACK-0001 (stack canon).
- Live deploy 2026-06-18 (Debian 13 `stone-granite-spring` + Windows host).
