---
type: REF
title: "Capability cards — index"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.5.1
---

# Capability cards

A **capability card** is a one-screen map of a single Koi capability: what it does, the one
canonical copy-paste pattern, the commands/flags you'll actually use, the limits/escape
hatch, and the proof it works. Cards are the fastest way to *use* a capability; the
[guides](../../index.md#how-to-guides) go deeper and the [reference](../../index.md#reference)
is the exhaustive contract.

Each card's frontmatter carries a `validation` block: **verified** means the canonical
pattern is backed by a named test or the two-box integration suite; **drafted** means it was
code-reviewed but not independently live-tested.

## Discovery & naming

- [mDNS discovery](mdns-discovery.md) — find & announce services on the LAN, no daemon, no config.
- [The `.internal` zone](internal-zone.md) — Koi's default local DNS zone and warning-free in-zone TLS.

## Trust & serving

- [Trusted HTTPS on the LAN](trusted-https.md) — a private CA → browser-trusted certs for `<name>.internal`.
- [Certmesh invite](certmesh-invite.md) — single-use, fingerprint-pinned host enrollment.
- [Trust doctor & posture](trust-doctor.md) — `koi trust diagnose` + the open/authenticated/confidential posture.
- [ACME issuance](acme-issuance.md) — RFC 8555 (dns-01) so Caddy / Traefik / lego get certs from your CA.
- [TLS proxy](tls-proxy.md) — a certmesh TLS endpoint in front of any plaintext backend.

## Operate

- [Health](machine-health.md) — service checks + auto-derived machine health.
- [UDP bridge](udp-bridge.md) — reach LAN UDP from a bridge-networked container.
- [Container auto-wire](container-autowire.md) — one Docker label → mDNS + DNS + health + proxy.

## Interfaces & embedding

- [MCP agent door](mcp-agent-door.md) — give an AI agent first-class access to your LAN.
- [Install + verify](install-and-verify.md) — the one-line install and the build-provenance check.
- [Embed Koi](embedded.md) — run Koi in-process as a Rust library.
