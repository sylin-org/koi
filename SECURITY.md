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

Out of scope: physical access to a node, compromise of a machine already inside the trust
boundary, and the unmanaged-device root-trust problem (installing the mesh root on phones /
TVs / appliances is unsolved industry-wide; Koi does not claim to solve it).
