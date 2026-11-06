# HTTP API reference

The default management endpoint is `http://127.0.0.1:5641`. This document maps the stable concepts and important contracts; the running daemon's `/openapi.json` and `/docs` describe exact supported HTTP payloads for its version. MCP uses its own protocol and is not represented by OpenAPI.

API availability does not certify a product journey. For the container/second-device preview and later exact-service HTTPS, use [launch readiness](../launch/README.md).

## Authentication

Protected requests carry the bare DAT in `x-koi-token`. Ordinary mutations require it, but `POST /v1/certmesh/join` uses invite/TOTP authorization and enrollment policy. Sensitive reads/streams and local-only preferences have distinct rules; see [the complete route matrix](http-route-auth-matrix.md). An unknown peer fails closed for peer-gated reads.

Exposing HTTP with `--http-bind` adds no encryption. Tokens must not appear in query strings, cookies, event payloads or persistent browser storage. Body-free OPTIONS preflight is token-free. CORS allows exact HTTP loopback origins, not arbitrary sites.

## System and projections

| Method | Path | Contract |
| --- | --- | --- |
| GET | `/healthz` | Plain-text daemon liveness; not application reachability |
| GET | `/v1/status` | Composition-owned capability status |
| GET | `/v1/host` | Host identity/network view |
| GET | `/v1/inventory` | Coherent inventory projection |
| GET | `/v1/catalog` | Schema-1 authoritative catalog snapshot |
| GET | `/v1/catalog/events` | DAT-protected complete catalog snapshots over SSE |
| GET | `/v1/events` | DAT-protected unified event stream |
| GET | `/v1/sd/prometheus` | JSON HTTP-SD target groups; optional `include=discovered` |
| POST | `/v1/admin/shutdown` | Daemon lifecycle cancellation |
| GET | `/openapi.json`, `/docs` | Schema and interactive reference when enabled |

Catalog fields include `schema`, `epoch`, `revision`, `generated_at`, `devices`, `services` and `local_candidates`. An epoch changes across process restart; revisions only compare within their epoch. Catalog events carry complete snapshots as `event: catalog`. Replace state on a new epoch and recover by reading the snapshot after a lost stream, gap or malformed event. Display names/ports are not stable identifiers.

## Local preferences

`GET /v1/preferences` and the service/candidate PUT routes require DAT and a local operator peer. Even a token-bearing remote request is rejected with `local_operator_required`.

Service updates go to `/v1/preferences/services/{service_id}` and include schema, expected revision and the matching stable service key. Candidate updates go to `/v1/preferences/candidates/{candidate_id}` and use the stable recognizer/source key. Favorites, friendly aliases and dismissal are personal intent; they do not mutate a discovered service's network identity.

A stale update returns 409 `stale_revision` with the current revision. Malformed persisted preferences report `recovery_required`; a future schema reports `unsupported_schema` and remains read-only. Neither condition silently erases the file.

## Domain routes

All paths below are relative to the listed prefix. Consult the linked source/OpenAPI for exact methods and payload fields rather than constructing requests from a route name alone.

| Prefix | Operations | Source |
| --- | --- | --- |
| `/v1/mdns` | snapshot, discover, announce, heartbeat, unregister, resolve, subscribe; admin status/ls/inspect/drain/revive/unregister | [mDNS routes](../../crates/koi-mdns/src/http.rs) |
| `/v1/runtime` | status, instances | [Runtime routes](../../crates/koi-runtime/src/http.rs) |
| `/v1/dns` | status, lookup, list, entries, zone, add/remove, serve/stop, ephemeral txt | [DNS routes](../../crates/koi-dns/src/http.rs) |
| `/v1/health` | status, list, log, add/remove | [Health routes](../../crates/koi-health/src/http.rs) |
| `/v1/proxy` | status, list, add/remove | [Proxy routes](../../crates/koi-proxy/src/http.rs) |
| `/v1/certmesh` | bootstrap, status, posture, diagnose, ca-cert, trust-bundle, join/invite, local CSR/certificate custody, create/unlock, renewal, promotion, policy, audit, backup/restore/revoke/destroy | [Certmesh routes](../../crates/koi-certmesh/src/http.rs) |
| `/v1/trust` | status, install, ensure, remove, inspect, reconcile | [Trust routes](../../crates/koi-trust/src/http.rs) |
| `/v1/udp` | bind, recv, send, heartbeat, status, unbind | [UDP routes](../../crates/koi-udp/src/http.rs) |

A disabled capability returns a capability-disabled response rather than pretending to be an empty running system. JSON errors commonly contain `error` and `message`; individual typed command responses, streaming framing and ACME problem documents must be handled according to their own schemas.

### mDNS and runtime

A minimal announcement body is:

```json
{"name":"My App","type":"_http._tcp","port":8080}
```

POST it to `/v1/mdns/announce` with DAT and JSON content type. HTTP registrations use heartbeat leases; renew with `PUT /v1/mdns/heartbeat/{id}` and release with `DELETE /v1/mdns/unregister/{id}`. See [wire framing and service records](wire-protocol.md).

Runtime status includes backend/watch state and normalized instances. Inventory metadata may contain a `certmesh` request without an issued identity. Check accepted resource state and the application from another device; do not treat inventory presence as reachability.

### DNS and health

DNS TXT proofs use `PUT /v1/dns/txt` and `DELETE /v1/dns/txt` with `name` and exact `value`. They are ephemeral; clear only the value the client owns. Zone exports support hosts/dnsmasq/JSON representations through the documented format query. Protected zone reads require DAT off-loopback.

Health probes run from Koi's host. A passing status is not proof that a different client can resolve/reach/trust the same name. Proxy status identifies real listener liveness and certificate source/revision; self-signed fallback must not be presented as exact-service trusted HTTPS.

### Enrollment and authority

A fresh joiner obtains the minimal public bootstrap projection, pins the authority through its trusted invitation flow, creates its key/CSR locally, and sends the CSR with an invite or TOTP to the authority. Local key-custody routes belong to the joiner's daemon; remote authority selection must not redirect them. Private key bytes never belong in the join response.

Full status is an operator view rather than the bootstrap contract. Member renewal/promotion/health use the separate mTLS-authorized inter-node router. Public service-name grant creation and listener wiring are incomplete; a callable CA primitive is not an end-user ACME setup.

## Operator HTML and Pond

`GET /ui` serves the token-entry page and `GET /ui/transport.js` the same-origin transport. `GET /v1/ui/shell` is DAT-protected even on loopback and returns Rust-rendered operator content. `GET /v1/ui/state` is also DAT-protected and supplies the typed operator projection used by the native adapter. Both accept the shared bounded view query. Responses are no-store, frame-denied and constrained by CSP where they contain HTML. Refresh replaces the dated snapshot; auth/content failures clear stale display, and forgetting/exiting clears the token.

The mDNS destination uses `tab=mdns` and arms the existing
lazy browse-all worker. Its typed state includes authoritative observations and
the bounded browser removal projection. Ordinary Catalog reads do not arm this
demand. The main adapter's `/v1/mdns/browser/*` routes require DAT; Pond retains
its explicitly allowlisted public browser snapshot.

`POST /v1/ui/mdns/query` requires DAT and accepts only `{"kind":"requery"}`,
`{"kind":"browse","value":"_ipp._tcp.local."}`, or
`{"kind":"resolve","value":"Printer._ipp._tcp.local."}`. Query names and
request size are bounded and validated before execution. The result distinguishes
`started`, `answers`, `no_answer` and `error`; it includes returned records/types,
the query and response observation time. Cache replay is labeled. A restart
acknowledgment or a lack of replies does not establish service health or a
firewall diagnosis. These controls are absent from Pond.

Pond is a reduced read-only listener on HTTP port plus three. Control remains on
the main adapter at `GET|PUT|DELETE /v1/pond`. Enabling desire does not itself
prove a reachable listener; status reports real bind/interface/firewall
conditions.

Pond's `/` renders the built-in shared Koi interface. It projects only
mDNS-derived service rows and coarse allowlisted capability health, with no
operator action bridge. UI bundle upload, selection and generation routes do
not exist. Its public API allowlist contains liveness and reduced status/mDNS/DNS
projections, never the main operator router. See [the route matrix](http-route-auth-matrix.md)
and [ADR-047](../adr/047-one-interface-built-in-presenter.md).

## MCP and ACME

`/.well-known/mcp/server-card.json` describes transport, path and authentication without disclosing credentials. Main-adapter `/v1/mcp` requires DAT on all resource-bearing methods. Optional authority mTLS MCP uses active roster-principal authorization instead. See [MCP](../guides/mcp.md).

ACME lives under `/acme/` on a separate server-auth TLS port, normally 5643. Requests use JWS account authorization and replay nonces; closed enrollment requires EAB for registration. Orders require one exact account-granted nonwildcard service name, P-256 accounts and dns-01. Responses use RFC 8555 problem documents. The DAT-protected DNS proof API and the ACME account are distinct authorities. See [ACME](../guides/acme.md).
