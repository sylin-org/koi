Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z

# Results

Recommendation: repair first, then run a small evidence cohort; defer broad promotion.

## Why

Koi has credible whitespace as a local-first service identity and discovery layer for trusted LANs: it can turn one service record into discovery, a stable `.internal` name, trust, health, and serving, while feeding specialist tools through standard protocols. The real incumbent is a hand-assembled stack of mDNS, DNS, reverse proxy, and private-PKI tools; Consul and overlay networks are adjacent but solve heavier or different problems.

The implementation is unusually broad for a pre-1.0 project, with cross-platform artifacts, structured architectural boundaries, extensive documentation and tests, checksums, attestations, and an OCI SBOM. The launch evidence is not yet A+ grade. The current lockfile carries a high-severity advisory; public main CI is red; three consecutive scheduled QA runs are red; several advertised partner workflows are format-compatible rather than proven end to end; and the project explicitly says it is not load-bearing. Amplifying now would spend a small trust budget before the strongest story is demonstrable.

## Next three actions

1. Close the P0 trust gate: update the vulnerable QUIC dependency, make CI and scheduled QA green on all supported operating systems, remove the TOML BOM/cache warning, repair Docker/Podman list-watch-reconcile behavior, and resolve or sharply bound the management-transport and trust-lifecycle risks.
2. Build one versioned golden proof: from a clean install, start a labeled container and show `https://name.internal` working without warnings from a second mixed-OS device, entirely offline. Test declared ownership boundaries with real Caddy or Traefik, Pi-hole or AdGuard, Tailscale split DNS, and Prometheus/blackbox discovery.
3. Rebuild the owned front door around the outcome, not the feature inventory: update the repository description, homepage, topics, support/community files, claim wording, manual/provenance-first install path, and a five-to-ten-person design-partner kit. Measure activation and first value before selecting one public channel.

## Readiness blockers

- `Cargo.lock` retains `quinn-proto` 0.11.14, affected by high-severity RUSTSEC-2026-0185; the published main audit job fails and the fixed version is 0.11.15 or newer.
- The 2026-07-13 Windows integration job reports 119 of 129 checks passing with ten DNS, certmesh, and CLI contract mismatches. The Windows service lifecycle itself passes, but inherits those ten failures.
- Linux/macOS integration and Linux concurrency jobs fail during harness startup; use of an unset `$env:TEMP` occurs before `Cleanup` is defined, and the global trap masks the original error as `Cleanup not recognized`.
- Docker event handling lacks durable reconnect/reconciliation semantics and startup ordering can miss existing containers.
- Current Caddy/Traefik label interpretation can confuse partner-owned backend ports with ports Koi should bind. ACME DNS-01 lacks a production-standard mutation path, Prometheus HTTP-SD can emit non-metrics targets, and Tailscale/Headscale CGNAT addresses are rejected by the private-address policy.
- Security wording must stay bounded: off-loopback management HTTP is plaintext bearer-token transport; `Sealed` v0 is signed cleartext rather than confidential encryption; generic TLS revocation is not immediate; fail-soft startup can report readiness with capabilities absent.
- The public GitHub surface undersells and under-supports the product: its metadata does not link the existing Koi homepage or provide topics, there is zero public issue feedback, support/conduct/templates are missing, documentation has drifted, and several absolute or comparative README claims lack a proof artifact.

## Best-fit channels

- Now: owned GitHub README/docs/releases and crates.io metadata, used to repair comprehension and evidence rather than drive reach.
- After P0: a consent-based cohort of five to ten homelab, small-team lab, classroom/studio, and appliance-tool operators.
- After cohort proof: one owner-authored community trial, likely r/selfhosted when Koi can honestly meet its production-ready rule, or an owner-written Show HN when the golden demo is immediately tryable.
- Later: unpaid selfh.st curator outreach, WinGet, a project-owned Homebrew tap, and the MCP Registry only after supported OCI/MCPB packaging and a stable MCP experience.
- Avoid for now: Homebrew Core, broad launch aggregators, paid influence, or claims of replacing service meshes, overlay networks, or enterprise PKI.

## Owner decisions needed

- Approve the category promise: "stable, trusted `.internal` names for LAN services, automatically and offline" and the internal category "LAN service identity/control plane."
- Decide whether built-in DNS, proxy, CA, and monitoring remain dependable fallback implementations while specialist tools own advanced policy, or whether Koi intends to compete in any of those categories.
- Define the supported network boundary for v1.0: one trusted broadcast domain, routed VLANs through a gateway, Tailscale/Headscale clients, and the exact threat model for exposed management surfaces.
- Name the v1.0 reliability contract and support capacity: supported OS/runtime matrix, upgrade/recovery guarantees, response expectations, and maximum cohort/public-launch load.
- Choose the first three integration contracts to certify. Recommended: Docker/Podman reconciliation, delegated DNS with Pi-hole/AdGuard, and partner-owned HTTPS through Caddy/Traefik.

## Unresolved risks and evidence gaps

- No independent operator has supplied a recorded clean-install, second-device, warning-free HTTPS result.
- Offline operation, multi-subnet behavior, restart recovery, renewal, revocation, and uninstall/rollback need scenario evidence rather than architectural inference.
- Current public usage metrics are too small and too automation-sensitive to establish retention or problem fit.
- Maintainer capacity, governance, security-review independence, and the appetite for appliance embedding are owner choices or unmeasured hypotheses.
- Some integrations parse or emit compatible formats but lack real-product compatibility tests; "works with" should remain reserved for versioned end-to-end contracts.

## Archived predecessor

No predecessor existed. This was the first `.oss-adoption` run for Koi.

## Authorization reminder

External publication remains unauthorized. The publication pack is review material only. The workspace also contains absolute local paths and should be scrubbed before any commit or sharing.
