# Route and authentication matrix

"Public" below means permitted by the main DAT middleware. Individual handlers can require their own protocol authorization. These boundaries describe current source; [launch readiness](../launch/README.md) records which complete user scenarios are certified.

## Main HTTP adapter

The default bind is loopback. Deliberately exposing HTTP does not encrypt it or relax token checks. The bare daemon token travels in `x-koi-token`.

| Route class | Loopback | Remote/unknown peer | Additional contract |
| --- | --- | --- | --- |
| Ordinary GET/HEAD, liveness and discovery descriptors | Public | Public | Only the route's read projection |
| Certmesh bootstrap, ca-cert, trust-bundle | Public | Public | Narrow bootstrap; bundle self-verifies against trusted anchor |
| POST Certmesh join | No DAT | No DAT | Invite/TOTP, enrollment state and approval authorization |
| Certmesh status/diagnose, Trust status, DNS list/zone/entries, inventory, catalog, dashboard snapshot/events | Public | DAT | Peer identity comes from accepted connection metadata |
| Catalog events, unified events, Certmesh posture/audit, UDP reads, Pond control | DAT | DAT | Resource-bearing streams/reads |
| Every resource-bearing /v1/mcp method | DAT | DAT | MCP requests and SSE |
| Operator /v1/ui/shell, /v1/ui/state and /v1/ui/mdns/query | DAT | DAT | Rendered/typed operator state and bounded mDNS query actions |
| Main-adapter /v1/mdns/browser/* | DAT | DAT | On-demand browser discovery, observations and query lifecycle; Pond has a separate public projection |
| Preferences read/write | DAT + local operator | Rejected even with DAT | Local personal intent |
| Other POST/PUT/DELETE mutations | DAT | DAT | Handler validation and operation-specific semantics; the retired UI publication API returns 404 |
| OPTIONS | Public | Public | Body-free CORS preflight, not a protected resource |

The implementation is [dat_auth_middleware](../../crates/koi-serve/src/http.rs). The route-matrix test and adjacent negative tests exercise representative classes using production constants. Any added aggregate read/stream needs explicit classification; do not infer safety from the GET method.

## Authority mTLS

The separate authority listener requires a mesh-CA client certificate before routing. Inter-node handlers authorize the verified identity for the member operation. Optional remote MCP maps CN to active, unexpired, unrevoked membership. Its authority is the certificate/roster, not DAT. Permissions remain coarse and do not provide tenant isolation.

## ACME

The separate server-auth TLS listener accepts ACME JWS account authorization and replay nonces. Closed enrollment requires EAB for account creation. Certificate issuance additionally requires an exact account-bound service-name grant; successful registration alone grants no DNS name. DAT protects the DNS proof-writing API separately.

## Pond

The separate public router allowlists the built-in shared UI, liveness, a reduced status projection, the existing public mDNS browser snapshot and reduced DNS entries. It does not expose the full catalog, preferences, token, operator discovery provenance/query results, arbitrary management routes or full Certmesh status.

Pond desire remains on the main DAT-protected adapter. UI publication and generation selection were retired by ADR-047. Refer to [HTTP semantics](http-api.md) for the current shared renderer and [security](security-model.md) for local operator custody and transport boundaries.
