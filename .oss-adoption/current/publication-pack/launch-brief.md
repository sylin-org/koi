Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z
Publication gate: closed; future owner-authored launch only

# Launch brief

This is internal briefing material, not public copy. The owner must personally rewrite any
Show HN title, first comment, and replies because HN prohibits generated or AI-edited
comments: https://news.ycombinator.com/newsguidelines.html

## Headline and one-sentence positioning

**Owner-rewrite concept:** Koi connects LAN service discovery, local names, private trust,
and serving in one cross-platform, offline binary.

Koi is a local-network wiring substrate, not a replacement for Pi-hole/AdGuard, Tailscale,
Caddy/Traefik, Prometheus, Docker/Podman, MCP clients, or a public CA.

## Audience, trigger problem, and fit

The primary user is a homelabber or self-hoster with several services, mixed operating
systems, or bridge-networked containers. LAN developers and small teams are secondary
users. Their trigger is that a running service still needs discovery, a stable local name,
trusted HTTPS, health state, and lifecycle wiring.

Strong fit means a trusted private LAN where the operator controls hosts and wants offline
operation. Weak fit means WAN edge, enterprise PKI/DNS/RBAC, hostile multi-tenant hosts, or
immediate generic TLS revocation through CRL/OCSP.

## Proof and evidence links

- Owned landing page: https://sylin.org/koi
- Repository and current claims: https://github.com/sylin-org/koi
- Releases: https://github.com/sylin-org/koi/releases
- Getting started: https://github.com/sylin-org/koi/blob/main/docs/tutorials/getting-started.md
- Trusted HTTPS tutorial: https://github.com/sylin-org/koi/blob/main/docs/tutorials/trusted-https.md
- Security model: https://github.com/sylin-org/koi/blob/main/docs/reference/security-model.md
- Architecture: https://github.com/sylin-org/koi/blob/main/docs/reference/architecture.md
- Changelog: https://github.com/sylin-org/koi/blob/main/CHANGELOG.md

The final launch must also link a release-specific golden demo proven on clean Windows,
Linux, and macOS environments.

## Maturity, limitations, and non-claims

- At preparation time Koi is v0.9.0, pre-1.0, feasibility-validated, consolidating, and not
  recommended as load-bearing infrastructure.
- Koi assumes a trusted private LAN and trusted local processes; it is not enterprise or
  hostile-multitenant security infrastructure.
- Management HTTP binds loopback by default. Intentional remote exposure requires the
  documented authentication and confidential-transport boundary.
- Do not claim production readiness, universal zero configuration, complete instant TLS
  revocation, or compatibility that has not passed the release matrix.
- Preserve the owned site's bounded positioning and anti-scope rather than recreating it.

## Demo and first-success path

1. Install and verify an immutable released artifact on a clean host.
2. Run `koi mdns discover` for an immediate visible result.
3. Start the daemon and show its loopback dashboard and capability status.
4. Use one disposable service to demonstrate discover -> name -> trust -> serve plus health.
5. Show coexistence with an existing DNS sinkhole or reverse proxy.
6. Uninstall and verify documented service, state, and trust-root cleanup.

The demo gate passes only when an independent tester reproduces it across all three host
operating systems from public instructions.

## Likely questions and response owner

| Question | Response direction | Owner |
| --- | --- | --- |
| Why not Pi-hole/AdGuard/dnsmasq? | Keep them and delegate one zone or consume exports; Koi wires lifecycle across domains | Maintainer |
| Why not Tailscale? | Keep it for remote identity/reachability; Koi adds LAN discovery and local naming/trust | Maintainer |
| Why not Caddy/Traefik? | Keep the proxy; Koi provides private ACME/cert material and consumes existing labels | Maintainer |
| What is the security boundary? | Use only the documented loopback, token, private-CA, host-trust, and non-goal claims | Security owner |
| Is it production-ready? | Not at preparation time; change this answer only after the recorded evidence gate | Release owner |
| How do I leave? | Demonstrate capability toggles, exports, uninstall, state handling, and trust-root removal | Maintainer |

For Show HN, the maintainer is the sole public comment owner and must answer personally
without generated or AI-edited text.
