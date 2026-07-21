Status: complete
Run ID: 20260719T034411Z
Project: koi
Created: 2026-07-19T03:44:11Z

# Release announcement draft

Release: future owner-designated production-ready release after P0 and cohort validation
Publication gate: closed; release facts and authorization must be revalidated

## What shipped

This future announcement is gated on evidence, not a guessed version. Adapt it only for a
release where the owner verifies:

- discover -> name -> trust -> serve passes from immutable release artifacts on clean
  Windows, Linux, and macOS environments;
- required CI, integration, security, packaging, checksum, and provenance checks are green;
- startup reconciliation, reconnect, data-root, lifecycle, management exposure, and
  trust/documentation risks are fixed, removed from scope, or stated accurately;
- install, upgrade, service removal, uninstall, and trust-root cleanup match the docs; and
- 5-10 design partners have tested mixed networks and all severe findings are resolved.

The central story is narrow: Koi provides one local wiring path from a discovered LAN
service to a stable name, private trust, serving, and health while integrating with the
operator's existing tools.

## Who benefits and how

- Homelabbers and self-hosters reduce hand-maintained glue among mDNS, local DNS, private
  certificates, reverse proxies, health checks, and containers.
- Mixed-platform operators use one model across Windows, Linux, and macOS.
- LAN developers and small teams avoid a public DNS name or cloud round trip.
- Container operators let the host handle multicast while labels/lifecycle drive local
  discovery, naming, trust, and health.
- Existing-tool users keep Pi-hole/AdGuard/dnsmasq, Tailscale, Caddy/Traefik, Prometheus,
  Docker/Podman, and MCP clients.

## Compatibility and migration impact

- The final text must name exact supported OSes, architectures, backends, state/config
  changes, and breaking changes from the selected release notes.
- Current upgrade guide: https://github.com/sylin-org/koi/blob/main/docs/guides/upgrading.md
- A production-ready release needs a tested upgrade path from the previous supported
  release and rollback/restore guidance where state migration is involved.
- Mention MCP Registry, WinGet, Homebrew, or catalog availability only after that exact
  release is present and verified there.
- Do not call a general OCI image a supported one-click MCP package unless its stdio
  entrypoint, ownership annotation, client matrix, and registry metadata pass.

## How to try it

1. Read current scope at https://sylin.org/koi and
   https://github.com/sylin-org/koi#project-status.
2. Read the security boundary at
   https://github.com/sylin-org/koi/blob/main/docs/reference/security-model.md.
3. Choose an immutable artifact from https://github.com/sylin-org/koi/releases and verify
   checksums/provenance as the release describes.
4. Run `koi mdns discover` for the first visible result.
5. Follow https://github.com/sylin-org/koi/blob/main/docs/tutorials/getting-started.md and
   the release-specific golden demo.
6. Start with a disposable service and verify the documented uninstall/trust-removal path.

## Limitations and known issues

- At preparation time v0.9.0 is pre-1.0 and explicitly not for load-bearing use, so this
  announcement remains unpublished until the owner changes that status on evidence.
- Koi targets trusted private LANs, not WAN edge, enterprise PKI/DNS/RBAC, or hostile
  multi-tenant security boundaries.
- Remote management exposure is opt-in and must document authentication plus confidential
  transport expectations for every non-loopback pattern.
- Generic TLS certificates do not gain instant universal revocation merely because Koi
  membership changes; state the selected release's exact behavior and certificate lifetime.
- Claims about message confidentiality, runtime reconnect, startup reconciliation,
  data-root isolation, and shutdown must match release regression evidence.
- Link the actual release's known-issues list rather than hiding limitations for launch tone.

## Acknowledgements and support route

Koi's mDNS foundation uses the pure-Rust `mdns-sd` project. Credit only design partners and
contributors who consent to public attribution; private testers remain private by default.

- Issues: https://github.com/sylin-org/koi/issues
- Contribution guidance: https://github.com/sylin-org/koi/blob/main/CONTRIBUTING.md
- Private security reporting: https://github.com/sylin-org/koi/blob/main/SECURITY.md
- Release history: https://github.com/sylin-org/koi/blob/main/CHANGELOG.md

Reserve support capacity before publication and pause outreach if a severe defect or an
untriaged backlog older than seven days appears.
