# Security policy

Koi operates discovery, local names and optional private trust for container/LAN
services. It is designed for networks administered by the machine owner.
Finding a service does not make it authorized, reachable or trusted.

## Report a vulnerability

Report privately using GitHub's repository Security Advisory reporting flow or
email hello@sylin.org with “koi security” in the subject. Include affected
version/source, impact and a minimal sanitized reproduction. Do not put an
unfixed vulnerability, private key or daemon token in a public issue.

Coordinate disclosure with the maintainer. There is no guaranteed response SLA.

## Versions and release claims

Security work targets active source and the affected current release. Older tags
are not independent maintained branches. [Release readiness](docs/launch/README.md)
identifies actual published versions and candidate status. Development CI success
does not certify a new release or an unaudited integration.

## Security boundaries

The [security model](docs/reference/security-model.md) and
[route/auth matrix](docs/reference/http-route-auth-matrix.md) are canonical for
listeners, peer classification, authentication and CORS.

- Management HTTP is loopback-bound by default. Exposing it is deliberate;
  a token authenticates requests but does not encrypt plaintext HTTP.
- Mutations require daemon/operator authority, with narrowly authorized
  enrollment paths. Sensitive reads and live streams have explicit protections.
- Authenticated mesh traffic uses the mesh identity and its authorization rules.
  An Open node and a node with a ready identity have different trust postures.
- CA private keys are encrypted at rest; key permissions, enrollment, renewal,
  name/account grants and recovery are security-sensitive behavior.
- Remote principal authority is coarse. Do not treat a principal as a
  fine-grained multi-tenant or restricted-agent credential.
- Koi revocation metadata is not CRL/OCSP distribution. Ordinary TLS clients can
  accept an unexpired certificate without consuming that metadata.
- Installing a root in an OS store does not prove that every browser/runtime
  uses that store. Verify the intended client through normal TLS validation.

[Trust protocol](docs/reference/trust-protocol.md) documents wire properties.
[ACME](docs/guides/acme.md) documents issuer/client requirements and limits.

Protect application authentication and network isolation. Never use a
certificate-warning bypass as a passing release proof. Local machine compromise,
physical access and unmanaged client root installation are outside Koi's
automatic guarantees.
