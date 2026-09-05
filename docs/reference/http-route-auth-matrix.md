# HTTP route and authentication matrix

This page is the authority map for Koi's network listeners. “Public” means that
Koi's outer access-token middleware permits the request; a route can still enforce
its own protocol authorization. In particular, enrollment validates an invite or
TOTP in the handler, ACME validates JWS/EAB, and the mTLS listener validates a
client certificate.

## Main HTTP adapter (5641)

The main adapter binds to loopback by default. If an operator deliberately exposes
it with `--http-bind`, transport security and distribution of the daemon access
token (DAT) are the operator's responsibility.

| Route class | Loopback request | Remote request | Authority |
| --- | --- | --- | --- |
| Ordinary `GET`/`HEAD`, including `/healthz` and public discovery descriptors | Public | Public | Read-only response |
| `GET /v1/certmesh/bootstrap`, `/ca-cert`, or `/trust-bundle` | Public | Public | Deliberately narrow enrollment/trust bootstrap; the signed bundle verifies itself |
| `POST /v1/certmesh/join` | Public to DAT middleware | Public to DAT middleware | The handler requires a valid invite or TOTP and enrollment policy permits the join |
| Full posture reads: certmesh status/diagnose, trust status, DNS list/zone/entries, inventory, dashboard snapshot/events | Public | DAT required | Loopback peer identity or valid `x-koi-token` |
| Audit log, certmesh posture, unified events, UDP reads, `/v1/pond`, and every method under `/v1/mcp` | DAT required | DAT required | Valid `x-koi-token` |
| Other `POST`/`PUT`/`DELETE` mutations | DAT required | DAT required | Valid `x-koi-token` |
| `OPTIONS` | Public | Public | CORS preflight only; it does not return a protected resource body |

The focused test
`documented_route_auth_matrix_matches_production_middleware` sends representative
requests through `dat_auth_middleware`, using the production route constants. The
nearby protected-read, audit, UDP, MCP, trust-mutation, and enrollment tests cover
the remaining members of each class.

## Authenticated remote principal (5642)

The certmesh listener is a separate TLS adapter. It requires a client certificate
signed by the mesh CA before HTTP routing. Certmesh inter-node handlers additionally
authorize the certificate identity for the requested member operation. When remote
MCP is enabled, `/v1/mcp` is mounted here and its guard maps the authenticated
certificate CN to an active, unexpired, unrevoked roster member. A DAT is not the
authority on this listener.

## ACME listener (5643)

ACME is a separate server-auth TLS listener under `/acme/`. ACME requests use RFC
8555 JWS account authorization; closed enrollment also requires EAB for account
creation. The DAT and certmesh member mTLS rules do not apply to this protocol.

## Pond public listener

Pond never exposes the main operator router. Its public router allowlists only:

- `/` and the pinned `/_koi/ui/{revision}` bundle;
- `/healthz`;
- `/v1/status` (a public projection, not full operator status);
- `/v1/mdns/browser/snapshot`;
- `/v1/dns/entries` (a public projection).

Pond configuration and bundle publication remain on the main adapter at `/v1/pond`
and `/v1/ui`, behind DAT authentication. The public-route allowlist is exercised by
the `koi-serve` Pond router tests.
