Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z

# Curator brief draft

Target curator: selfh.st/apps and Self-Host Weekly
Editorial posture: future unpaid consideration after readiness; no sponsorship or exchange
Publication gate: closed; contact requires separate owner authorization

## Why this fits the curator's audience

selfh.st covers self-hosted software, releases, and operational tooling, and its app
directory invites maintainers to share project details. Koi addresses the plumbing around
self-hosted apps: discovery, a stable local name, trusted HTTPS, health, and
container-aware lifecycle across Windows, Linux, and macOS.

Koi is infrastructure that complements apps already in the directory, not another media
server, dashboard, or SaaS replacement. Curator context verified 2026-07-19:
https://selfh.st/about/ and https://selfh.st/apps-about/.

## Verifiable project facts

- Owned landing page: https://sylin.org/koi
- Repository: https://github.com/sylin-org/koi
- License: Apache-2.0 or MIT
- Implementation: Rust workspace producing the `koi` binary and reusable crates
- Model: discover -> name -> trust -> serve
- Documented host targets: Windows, Linux, and macOS
- Documented adjacencies: Docker/Podman, Pi-hole/AdGuard/dnsmasq, Tailscale,
  Caddy/Traefik, Prometheus, ACME, and MCP
- Operation: local/offline with no account or cloud dependency
- Current release at research time: v0.9.0, June 2026
- Current maturity at research time: pre-1.0, consolidating, and explicitly not
  load-bearing

Recheck every fact against the release selected for outreach. The current maturity is a
reason to wait, not wording to hide.

## What changed and why it matters

Future outreach should attach to the first release that passes production-readiness gates,
not merely to a long feature list. It must show green multi-OS release/security checks, a
released-artifact golden demo, clean install/upgrade/uninstall/trust cleanup, resolved or
candidly scoped reliability blockers, and evidence from a 5-10 person mixed-network cohort.

That evidence gives the curator something useful: readers can evaluate a narrow proven
workflow instead of a broad pre-1.0 inventory.

## Evidence, license, demo, and maintainer links

- Releases: https://github.com/sylin-org/koi/releases
- Documentation hub: https://github.com/sylin-org/koi/blob/main/docs/index.md
- Getting started: https://github.com/sylin-org/koi/blob/main/docs/tutorials/getting-started.md
- Trusted HTTPS: https://github.com/sylin-org/koi/blob/main/docs/tutorials/trusted-https.md
- Integrations: https://github.com/sylin-org/koi/blob/main/docs/guides/integrations.md
- Security model: https://github.com/sylin-org/koi/blob/main/docs/reference/security-model.md
- Changelog: https://github.com/sylin-org/koi/blob/main/CHANGELOG.md
- Contributing: https://github.com/sylin-org/koi/blob/main/CONTRIBUTING.md
- Security reporting: https://github.com/sylin-org/koi/blob/main/SECURITY.md

The eventual brief must add a release-specific public golden demo. This draft does not
claim one is already available.

## Factual description available for adaptation

Koi is an open-source, cross-platform LAN service that connects mDNS/DNS-SD discovery,
local DNS, private certificate trust, TLS serving, health checks, and container lifecycle.
It runs locally without an account or cloud dependency and complements existing DNS,
tailnet, reverse-proxy, monitoring, and container tools. At the time of this brief Koi is
pre-1.0 and should be evaluated rather than used as load-bearing infrastructure.

The curator may adapt, shorten, independently verify, or decline this description. No
favorable wording, placement, ranking, or coverage is requested in exchange for money,
sponsorship, access, or influence.

## Contact authority

No outreach is authorized by this draft. After readiness, the maintainer may separately
authorize one concise contact through https://selfh.st/about/. Request independent unpaid
editorial consideration, offer factual corrections, send at most one polite follow-up, and
treat silence or a decline as final.
