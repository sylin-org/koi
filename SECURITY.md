# Security Policy

Koi is a local-network trust tool — a private certificate authority, a DNS resolver, a
TLS endpoint, and an HTTP/IPC control surface. We take security reports seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via either:

- **GitHub Security Advisories** — the "Report a vulnerability" button on the repository's
  **Security** tab (preferred; keeps the report private and tracked).
- **Email** — `hello@sylin.org` with `koi security` in the subject.

Please include: the affected version/commit, a description of the issue and its impact, and
(ideally) a minimal reproduction. We aim to acknowledge within a few days. Coordinated
disclosure is appreciated — we'll work with you on a fix and timeline before any public
detail.

## Supported versions

Koi is pre-1.0 and ships from `main`. Security fixes target the latest released version on
crates.io and the current `main`; older tagged releases are not separately patched.

## Scope & trust model

Koi's security boundary is **the local network**, and its posture is documented in the
trust-protocol reference:

- [docs/reference/trust-protocol.md](docs/reference/trust-protocol.md) — the cross-sibling
  wire contract: posture, signed envelopes, sealing, the same-port dual-mode handshake.
- [docs/reference/http-api.md](docs/reference/http-api.md) — the HTTP surface and its
  Daemon Access Token (DAT) auth model.

Key properties relevant to reports:

- The HTTP adapter binds **loopback by default**; LAN exposure is opt-in (`--http-bind`),
  and mutations always require the `x-koi-token` (DAT) header regardless of bind address.
- Inter-node traffic is mutually authenticated (mTLS) against the mesh CA; the dial is
  posture-reactive (plaintext only while a node is Open, mTLS once it holds an identity).
- Certificate-authority private keys are encrypted at rest (envelope encryption); the CA
  key is unlocked with a passphrase or an OS-keychain-sealed credential.

### Deliberately unauthenticated reads

When the HTTP adapter is exposed on a non-loopback bind, a small set of **read-only** GETs
is intentionally answerable without the token, because members need them to bootstrap and
they carry no secrets:

- `GET /v1/certmesh/trust-bundle` — the signed, self-verifying mesh-truth bundle (member
  hostnames, cert fingerprints, expiries, the revocation list, the CA cert). It is treated
  like a CRL: integrity comes from its signature, not from access control.
- `GET /v1/certmesh/status`, `GET /v1/certmesh/diagnose`, `GET /v1/dns/list`,
  `GET /v1/dns/zone` — membership counts, trust-doctor output, and the resolvable name→IP
  map. This is LAN-topology reconnaissance, not credential material.

Reads that **do** carry secrets or live channels are token-gated even on GET: the CA audit
log (`/v1/certmesh/log`), the MCP transport (`/v1/mcp`), and the UDP surface
(`/v1/udp/status`, `/v1/udp/recv/{id}`). If you do not want the topology/roster readable by
the LAN, keep the default loopback bind. CORS reflection is restricted to exact loopback
origins, so a browser on another origin cannot read these cross-origin.

Out of scope: physical access to a node, compromise of a machine already inside the trust
boundary, and the unmanaged-device root-trust problem (installing the mesh root on phones /
TVs / appliances is unsolved industry-wide; Koi does not claim to solve it).
