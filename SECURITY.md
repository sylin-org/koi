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
- [docs/reference/http-route-auth-matrix.md](docs/reference/http-route-auth-matrix.md) —
  the tested listener, route-class, and authority matrix.

Key properties relevant to reports:

- The HTTP adapter binds **loopback by default**; LAN exposure is opt-in (`--http-bind`).
  Operator mutations require the `x-koi-token` (DAT) regardless of bind address;
  enrollment is the narrow invite/TOTP-authorized exception shown below.
- Inter-node traffic is mutually authenticated (mTLS) against the mesh CA; the dial is
  posture-reactive (plaintext only while a node is Open, mTLS once it holds an identity).
- Certificate-authority private keys are encrypted at rest (envelope encryption); the CA
  key is unlocked with a passphrase or an OS-keychain-sealed credential.

### Read authorization on a non-loopback bind

Reads are token-free over loopback (local tooling — the CLI, the dashboard). When the HTTP
adapter is exposed on a non-loopback bind, reads fall into three tiers based on the **peer**
address (a loopback peer stays exempt; a remote peer is gated):

- **Always open (load-bearing in the unauthenticated protocol):**
  - `GET /v1/certmesh/trust-bundle` — signed Koi trust and revocation metadata;
    integrity comes from its ES256 signature against the pinned CA fingerprint. It
    is not a CRL and ordinary TLS stacks do not consume it.
  - `GET /v1/certmesh/bootstrap` — the narrow CA fingerprint and enrollment
    preflight for a node that does not yet hold a credential.
- **Loopback-only (token required from a remote peer):** full certmesh
  status/diagnosis, trust status, DNS list/zone/entries, inventory, and dashboard
  snapshot/event projections. These are operational/topology reconnaissance not
  needed by an unauthenticated remote peer.
- **Always token-gated, even on GET** — reads that carry secrets or live channels: the CA
  audit log and posture, event stream, Pond operator control, MCP transport, and UDP
  surface. See the linked matrix for exact paths.

Full status is not public remotely. If you do not want even the narrow bootstrap data
readable by the LAN, keep the default loopback bind. CORS reflection is restricted to exact loopback origins, so a browser on
another origin cannot read these cross-origin.

DNS query rate limiting is **per source IP** with a whole-resolver backstop, so one noisy
LAN peer cannot starve resolution for the rest; the per-client budget is `--dns-qps`
(env `KOI_DNS_QPS`, default 200).

Out of scope: physical access to a node, compromise of a machine already inside the trust
boundary, and the unmanaged-device root-trust problem (installing the mesh root on phones /
TVs / appliances is unsolved industry-wide; Koi does not claim to solve it).
