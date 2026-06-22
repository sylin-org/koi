# Koi documentation

Koi is one binary that gives your local network a toolbox it doesn't ship with:
**discover** services (mDNS), **name** them (local DNS), **trust** them (a private
certificate authority + OS trust-store install), and **serve** them (a TLS endpoint) —
all reachable over a CLI, an HTTP API, and as an embeddable Rust library.

New here? Start with the tutorial, then jump to the guide for whatever you're doing.

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

**Discovery & naming** — [mDNS](guides/mdns.md) · [DNS](guides/dns.md) ·
[DNS coexistence](guides/dns-coexistence.md)

**Trust & serving** — [certmesh (private CA)](guides/certmesh.md) ·
[certmesh HA & recovery](guides/certmesh-ha-recovery.md) ·
[embedding certmesh (Rust library)](guides/certmesh-embedded.md) · [ACME server](guides/acme.md) ·
[trust (root distribution)](guides/trust.md) · [proxy (TLS endpoint)](guides/proxy.md)

**Operate** — [health checks](guides/health.md) · [UDP bridging](guides/udp.md) ·
[runtime / containers](guides/runtime.md) · [install & service](guides/install-and-service.md) ·
[system status & config](guides/system.md) · [troubleshooting](guides/troubleshooting.md) ·
[upgrading](guides/upgrading.md)

**Integrate & extend** — [integrations (Prometheus, Traefik/Caddy labels)](guides/integrations.md) ·
[API authentication](guides/api-authentication.md) · [MCP (for AI agents)](guides/mcp.md) ·
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

**Discovery & naming** — [mDNS discovery](reference/cards/mdns-discovery.md) ·
[.internal zone](reference/cards/internal-zone.md)

**Trust & serving** — [trusted HTTPS](reference/cards/trusted-https.md) ·
[certmesh invite](reference/cards/certmesh-invite.md) ·
[trust doctor & posture](reference/cards/trust-doctor.md) ·
[ACME issuance](reference/cards/acme-issuance.md) · [TLS proxy](reference/cards/tls-proxy.md)

**Operate** — [health](reference/cards/machine-health.md) ·
[UDP bridge](reference/cards/udp-bridge.md) ·
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
- [Ceremony protocol](reference/ceremony-protocol.md) — the interactive setup engine.
- [Envelope encryption](reference/envelope-encryption.md) — how the CA key is protected.
- [Architecture](reference/architecture.md) — crate inventory, boundaries, dependency graph.
- [Domain template](reference/domain-template.md) — how to add a new domain crate.

---

## Understand the decisions

Architecture Decision Records live in [docs/adr/](adr/) — why things are built the way
they are, including the cross-repo [stack canon (STACK-0001)](adr/STACK-0001-sylin-stack-canon.md).

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for setup, the verification commands, and the
code/architecture rules.

---

> **For maintainers:** the `prompts/`, `assessment/`, `plans/`, `research/`, `proposals/`,
> `qa/`, `prior-art/`, and `archive/` subtrees under `docs/` are internal working
> artifacts (the work-order stash, the maturity assessment, design notes) — not
> user-facing documentation. They are intentionally not linked from this index.
