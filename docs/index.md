# Koi documentation

## Let everything local find, trust, and talk.

Koi is an open-source local connectivity substrate that makes containers,
applications, and devices delightfully discoverable, secure, and interconnected.
It bridges the boundaries between the LAN, container networks, and applications while
working with the resolvers, proxies, runtimes, and monitoring tools you already use.

New here? **[What is Koi — and is it for you?](overview.md)** is the short orientation
(the model, the trust boundary, and when *not* to use it). Then the tutorial, then the
guide for whatever you're doing.

---

## Start here (tutorials)

Learning-oriented, follow top to bottom:

- **[Getting started](tutorials/getting-started.md)** — install to a visible result in
  about a minute, then a first real task.
- **[Trusted HTTPS across two machines](tutorials/trusted-https.md)** — go from zero to a
  green `https://` in a browser, no public CA, ~10 minutes.

---

## By goal

| I want to… | Go to |
| ---------- | ----- |
| **Run it and see my network** | [Getting started](tutorials/getting-started.md) · [mDNS guide](guides/mdns.md) |
| **Name services on my LAN** | [DNS guide](guides/dns.md) · [coexist with my resolver](guides/dns-coexistence.md) |
| **Get trusted HTTPS working** | [Trusted-HTTPS tutorial](tutorials/trusted-https.md) · [certmesh](guides/certmesh.md) · [proxy](guides/proxy.md) |
| **Issue certs to Caddy/Traefik/lego** | [ACME guide](guides/acme.md) |
| **Let an AI agent see my LAN** | [MCP guide](guides/mcp.md) |
| **Run Koi with my containers** | [Containers](../CONTAINERS.md) · [runtime](guides/runtime.md) · [recipes](#recipes) |
| **Call the HTTP API from a script** | [API authentication](guides/api-authentication.md) · [HTTP API reference](reference/http-api.md) · [security model](reference/security-model.md) |
| **Install it as a service / fix a problem** | [Install & service](guides/install-and-service.md) · [Troubleshooting](guides/troubleshooting.md) · [Upgrading](guides/upgrading.md) |
| **Embed Koi in a Rust app** | [Embedded guide](guides/embedded.md) |
| **Keep my existing DNS / proxy** | [DNS coexistence](guides/dns-coexistence.md) · [integrations](guides/integrations.md) |
| **Distribute a CA root** | [Trust & CA-root distribution](guides/trust.md) |

---

## How-to guides

Task-oriented, one goal each.

**Find** — [mDNS](guides/mdns.md) · [DNS](guides/dns.md) ·
[DNS coexistence](guides/dns-coexistence.md) · [runtime / containers](guides/runtime.md)

**Trust** — [certmesh (private CA)](guides/certmesh.md) ·
[certmesh HA & recovery](guides/certmesh-ha-recovery.md) ·
[embedding certmesh (Rust library)](guides/certmesh-embedded.md) · [ACME server](guides/acme.md) ·
[trust (root distribution)](guides/trust.md)

**Connect** — [proxy (TLS endpoint)](guides/proxy.md) · [UDP bridging](guides/udp.md) ·
[containers](../CONTAINERS.md) · [integrations](guides/integrations.md)

**Operate** — [health checks](guides/health.md) · [install & service](guides/install-and-service.md) ·
[system status & config](guides/system.md) · [troubleshooting](guides/troubleshooting.md) ·
[upgrading](guides/upgrading.md)

**Expose & extend** — [API authentication](guides/api-authentication.md) ·
[MCP (for AI agents)](guides/mcp.md) ·
[embedded (Rust library)](guides/embedded.md)

### Recipes

Cross-cutting journeys that stitch several capabilities together:

- [A container gets a stable name + a trusted cert](guides/recipes/container-trusted-cert.md)
- [UDP bridging from inside a container](guides/recipes/container-udp.md)

---

## Capability cards

One-screen maps of a single capability — the canonical pattern, the flags you'll use, and
the proof it works. Faster than a guide when you already know what you want. Full list:
[cards index](reference/cards/index.md).

**Find** — [mDNS discovery](reference/cards/mdns-discovery.md) ·
[.internal zone](reference/cards/internal-zone.md)

**Trust** — [trusted HTTPS](reference/cards/trusted-https.md) ·
[certmesh invite](reference/cards/certmesh-invite.md) ·
[trust doctor & posture](reference/cards/trust-doctor.md) ·
[ACME issuance](reference/cards/acme-issuance.md)

**Connect & operate** — [TLS proxy](reference/cards/tls-proxy.md) ·
[UDP bridge](reference/cards/udp-bridge.md) · [health](reference/cards/machine-health.md) ·
[container auto-wire](reference/cards/container-autowire.md)

**Interfaces & embedding** — [MCP agent door](reference/cards/mcp-agent-door.md) ·
[install + verify](reference/cards/install-and-verify.md) ·
[embed Koi](reference/cards/embedded.md)

---

## Reference

Information-oriented, dry and exact.

- [HTTP API](reference/http-api.md) — every endpoint, request/response shapes, auth.
- [CLI](reference/cli.md) — every command, flag, and environment variable.
- [Wire protocol](reference/wire-protocol.md) — the mDNS NDJSON verb protocol over IPC/stdin.
- [Security model](reference/security-model.md) — the daemon access token, bind addresses, what is and isn't protected.
- [Ports & firewall](reference/ports.md) — every listening port, its bind default, the `--no-*` gate, and the firewall story.
- [Ceremony protocol](reference/ceremony-protocol.md) — the interactive setup engine.
- [Envelope encryption](reference/envelope-encryption.md) — how the CA key is protected.
- [Architecture](reference/architecture.md) — crate inventory, boundaries, dependency graph.
- [Domain template](reference/domain-template.md) — how to add a new domain crate.

---

## Understand the decisions

Architecture Decision Records live in [docs/adr/](adr/) — why things are built the way
they are. Start with [Koi's public identity: Find, Trust, Connect](adr/024-public-identity-find-trust-connect.md);
the cross-repo [stack canon (STACK-0001)](adr/STACK-0001-sylin-stack-canon.md) defines
the wider architectural boundary.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for setup, the verification commands, and the
code/architecture rules.

---

> **For maintainers:** the `prompts/`, `assessment/`, `plans/`, `research/`, `proposals/`,
> `qa/`, `prior-art/`, and `archive/` subtrees under `docs/` are internal working
> artifacts (the work-order stash, the maturity assessment, design notes) — not
> user-facing documentation. They are intentionally not linked from this index.
