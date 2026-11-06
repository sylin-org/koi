# Security model

Koi is an owner-operated LAN tool. Its management interface, discovery observations, certificate identities and application listeners are separate boundaries. The initial container preview requires no CA or remote management exposure; trust features are an extension with their own acceptance evidence in [launch readiness](../launch/README.md).

## Management access

The main HTTP adapter defaults to `127.0.0.1:5641`. `--http-bind` deliberately selects loopback, a runtime bridge address, a specific IP or all IPv4 interfaces. This changes reachability, not authorization or transport encryption. Container access through Docker Desktop or a host alias must be verified for that runtime; a hostname is not a guarantee that a loopback socket is reachable.

Every daemon start generates a fresh daemon access token (DAT). Protected requests carry the bare token in `x-koi-token`, compared in constant time. It must not appear in URLs or discovery records. Normal mutations require it; enrollment is authorized by an invite/TOTP and policy instead. Protected reads and local-only preferences are classified in [the route matrix](http-route-auth-matrix.md).

Many read-only endpoints are intentionally readable locally. Some remain public when the operator exposes HTTP; sensitive catalog, inventory, zone and trust reads require DAT remotely and fail closed if peer identity is unknown. Authentication does not encrypt the HTTP link. Use an authenticated encrypted transport for remote operator credentials.

Browser CORS accepts exact HTTP loopback origins (`localhost`, `127.0.0.1`, `[::1]`, with optional ports); it does not admit arbitrary web origins. CORS is a browser policy, not client authorization. The authenticated operator browser transport also refuses sending a token to remote cleartext HTTP.

## Local operator and token custody

The private breadcrumb records the daemon endpoint and a `dat:`-prefixed token line. That prefix is storage syntax, not part of the header value.

| Platform | Default breadcrumb |
| --- | --- |
| Windows | `%ProgramData%\\koi\\koi.endpoint` |
| Linux/macOS | `$XDG_RUNTIME_DIR/koi.endpoint`, otherwise `/var/run/koi.endpoint` |

An installed machine service owns its files privately. Installation records one interactive operator; local IPC verifies the peer UID/SID before returning endpoint/token information. Windows uses a protected named-pipe DACL and exact operator SID validation. Unix admits root and the recorded UID. An explicit remote CLI endpoint never inherits the local token.

`koi token show` requires a terminal unless forced; `koi token write PATH` exports a private file for an authorized consumer. Granting the token grants broad daemon authority. There are no per-token scopes.

## Discovery and application reachability

mDNS is public, link-local discovery. Names, TXT records, posture hints and observed endpoints are untrusted input. They do not prove certificate identity or authorize an operation. A label/record does not open an application firewall, publish a missing container port, configure a resolver or create a route.

Health probes establish what the probing host can reach. The launch journey separately requires the actual application response on a second physical device. That distinction prevents a healthy management daemon from concealing an unreachable application.

## Certificate boundaries

Certmesh supports local private-key custody, CSR signing, hostname-bound single-use invitations, TOTP enrollment authentication and policy/approval checks. CA material is envelope-encrypted at rest; [unlock slots](envelope-encryption.md) describe the auto-unlock and platform-secret trade-offs. A process already controlling the operator account or an unlocked authority is outside that protection boundary.

The authority's mTLS listener validates a CA-chained client certificate and authorizes member operations. Remote MCP additionally checks its CN against active, unexpired, unrevoked roster membership. Principal authority is coarse, comparable to DAT access minus human-only surfaces; it is not tenant isolation or a read-only agent permission system.

Exact service-name authorization is separate from host membership. ACME requires a registered account and a grant for one exact nonwildcard service name. Its client must use P-256 accounts, trust the root and provide dns-01 TXT operations. The public grant/listener workflow is incomplete; see [ACME](../guides/acme.md).

Revocation has two consumers: Koi-authorized boundaries reject revoked members, and Koi-aware message verification consumes signed trust-bundle metadata. Ordinary TLS applications receive no CRL/OCSP status from this system and may accept the leaf until its actual expiry. A trusted root alone does not establish trust in every browser/runtime/container image.

## Other surfaces

Pond runs a separate reduced read-only router. Its public projection is not the main management API. Publication and desired-state controls remain DAT-protected. UDP reads as well as writes require DAT; bind/destination policies and lease cleanup apply.

DNS defaults to private clients with per-source-IP rate limits, a global load backstop and bounded client tracking. Rate-limited queries receive REFUSED. This does not make the resolver suitable as an unattended public recursive service.

## Persistence, recovery and verification

Identity/roster changes use journaled multi-file persistence. Interrupted recovery and unknown/corrupt schemas must remain visible instead of resetting security state. Platform trust changes and native installation have ownership/rollback contracts; read [fleet contract](../../fleet/CONTRACT.md) before acceptance work on an existing host.

Release checksums and available build attestations verify artifact integrity/provenance, not security certification or product behavior. Consult the exact release's assets and [launch gate](../launch/README.md) before claiming a distribution channel or scenario is verified.
