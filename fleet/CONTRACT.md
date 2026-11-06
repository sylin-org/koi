# Current implementation and evidence contract

[ADR-046](../docs/adr/046-container-lan-adoption.md) and
[Epic 004](epics/004-container-lan-adoption.md) govern adoption work.
[The launch ledger](launch/LEDGER.md) is the authority for readiness evidence.
This reference preserves current architectural constraints without making every
possible service-experience capability a release prerequisite.

## Architecture and existing owners

Domain facades own commands, authoritative snapshots and semantic events.
`koi-compose` owns explicit cross-domain projection and coordination.
`koi-serve` adapts transport and authorization. Presentation consumes those values.
No frontend or event log reconstructs domain truth; transports contain no business
rules, and domains do not read each other's repositories.

Cross-domain wiring uses explicit integration traits; domain crates do not depend
on each other. Keep the common kernel dependency-light and free of transport/HTML
machinery. `mdns-sd` remains encapsulated in `koi-mdns`, with no backend types crossing
the crate boundary. Co-locate constants with their owners and reuse existing types.
Typed domain errors map explicitly to shared error codes and transport status; do
not hide failures behind panics or silent fallbacks.

| Concern | Current source owner | Scope |
| --- | --- | --- |
| Shared service vocabulary | [koi-common service](../crates/koi-common/src/service.rs) | Device, Service, Endpoint, observations, checks, actions and versioned DTOs |
| Installation identity | [koi-config installation](../crates/koi-config/src/installation.rs) | Durable non-secret installation ID |
| Source/provider observations | [koi-common integration](../crates/koi-common/src/integration.rs) | Provider-scoped status, provenance and availability |
| Catalog projection | [koi-compose catalog](../crates/koi-compose/src/catalog.rs) | Bounded cross-domain latest-value projection |
| Preferences | [koi-preferences](../crates/koi-preferences/src/lib.rs) | Atomic favorite/alias/dismissal intent and recovery |
| Container lifecycle | [koi-runtime](../crates/koi-runtime/src/lib.rs) | Runtime observations and label-derived effects |
| Name/certificate authority | [CertMesh service names](../crates/koi-certmesh/src/service_names.rs) | Service-name grants and host certificate issuance/renewal |
| DNS, mDNS, proxy, trust and health effects | Their domain facades | Each owns its resources and authoritative status |
| Catalog/preference transport | [catalog](../crates/koi-serve/src/catalog.rs), [preferences](../crates/koi-serve/src/preferences.rs) | HTTP authorization and DTO adaptation |
| Assembly and shutdown | [koi-compose cores](../crates/koi-compose/src/cores.rs) | Explicit construction and retained lifecycle ownership |
| User rendering | [koi-ui](../crates/koi-ui/src/lib.rs) | Shared Rust presentation; desktop remains a separate repository |

These modules exist in source. That does not certify a packaged installation or an
end-to-end user journey. In particular, general local-listener candidate adapters,
durable sharing/secure-service coordinators, and a general composed URL-diagnosis
runtime are design boundaries, not implemented modules to cite as shipping. Their
future names or DTOs do not establish working endpoints. The current HTTP reference
and source routes define what a client can actually call.

[ADR-043](../docs/adr/043-observable-domain-boundaries.md),
[ADR-044](../docs/adr/044-service-experience-ownership.md) and
[ADR-045](../docs/adr/045-shared-rust-renderer.md) retain their architectural decisions.
The launch epic decides which bounded implementation is needed for its workflows;
it does not require recreating a broad service-management platform.

## Identity and freshness

- Raw DNS-SD records are observations, not durable application identities.
  Installation, device, service, endpoint and observation IDs have distinct meanings.
  Keep them opaque and preserve provider, interface and observer provenance.
- Correlate explicit installation/service identity first, then a source-owned identity
  under the same installation, then a proven device with the same normalized endpoint
  and compatible protocol. Name, IP, port, service type or TXT similarity alone cannot
  merge records or transfer a favorite, permission or operation.
- Strong identity disagreement remains ambiguous. Preserve scoped IPv6 addresses;
  link-local endpoints without usable interface scope are not openable.
- A catalog epoch identifies the process instance; revision increases on semantic
  change. Domain revisions are not comparable across domains or restarts. Clients
  refetch snapshots after gaps, a changed epoch, decode failure or lost subscription.
- Explicit withdrawal changes the record immediately. Source loss makes observations
  stale rather than pretending they were removed. Current catalog bounds are 4,096
  services, 16 observations and 32 checks per service, with at most ten minutes of
  stale retention; the owning source constants remain authoritative.
- An advertisement establishes discovery. `responding` requires current check
  evidence. State, expiry and eligibility are owned by the domain/projector, not a
  frontend clock.
- `CatalogSnapshot.discovery` (additive schema 1: unknown|available|partial|unavailable)
  comes only from the authoritative mDNS browse-source routes and watch availability,
  never row counts; absence decodes as unknown, never healthy; availability-only
  changes publish a revision; it says nothing about reachability or completeness.
  Services renders it independently of rows.
- `CatalogSnapshot.local_device_id` (additive, optional) is the observer's explicit
  device identity; older producers leave it unknown; compare it opaquely and never
  derive it from names, addresses or advertised installation IDs; Pond's public
  projection omits it (always null).

Preferences remain durable personal intent. Malformed storage exposes recovery;
unsupported future schemas are read-only and never become empty state. Optimistic
revision conflicts return a typed conflict. Absent favorites keep bounded safe
context and never adopt a same-named stranger.

## Authority and scoped effects

Discovery or mesh membership does not grant operator authority. A remote DAT does
not turn a caller into the local operator. Local control authenticates the OS
principal and bootstraps the existing operator HTTP path.
[ADR-040](../docs/adr/040-local-operator-control-plane.md) and the
[route/auth matrix](../docs/reference/http-route-auth-matrix.md) define that boundary.

Pond uses the separately managed, allowlisted read-only listener in
[ADR-042](../docs/adr/042-pond-read-only-lan-adapter.md). Never expose the complete
operator router by changing its default loopback bind. Public projections exclude
credentials, private diagnostics, native mutation actions and internal control data.

`koi-client::comparison` reads a peer's existing `/v1/mdns/snapshot` with no DAT
(only the observer's own local read carries its DAT), no redirects, a 4-second
deadline and a 1 MiB limit. Comparison scope is each observer's active mDNS `.local`
query set; unequal or unavailable scopes are incomplete, and only two successful
compatible reads can report no differences. It adds no listener, firewall rule or
enrollment. No shipped destination renders comparison yet (see the
[retained-task audit](../docs/ux/retained-task-audit.md)).

When a workflow adds or reverses DNS, advertisements, listeners, firewall rules or
certificates, retain explicit ownership and the exact selected scope. Preflight
name/port conflicts; do not silently take over a foreign resource or shift a reviewed
endpoint. Persist admitted durable intent before external effects and track receipts
sufficient to reconcile or reverse only owned resources. Cancellation of a waiter
must not abandon those effects. Shutdown retains durable desire; explicit Stop
reverses owned resources and preserves the underlying application and unrelated state.

## Trusted HTTPS

The focused trusted workflow uses host TLS termination and an exact authorized
service name. CertMesh service-name grants bind a stable ServiceId and a normalized
non-wildcard name to a host-proxy owner or an existing ACME account. Duplicate grants
are idempotent; conflicting owners do not transfer implicitly. Host private keys
remain in CertMesh/Proxy custody. Issuance and reload failures preserve usable
accepted material.

Report separately: name resolution, name grant, leaf SAN/expiry, listener, backend,
client root installation, and the named second client's ordinary TLS request. Local
checks never become browser or phone evidence. Grant removal blocks future issuance;
ordinary copied TLS leaves may remain acceptable until their actual NotAfter without
client revocation enforcement. Root installation alone is not HTTPS proof.

Container certificate-request labels do not prove workload key/certificate delivery.
General phone/appliance root rollout, public certificates and arbitrary client support
require their own implementation and evidence before being claimed.

## Proof and bounded diagnosis

Each check identifies observer/client, endpoint, source revision, timestamp,
timeout/freshness, result and stable reason. Unknown and not-run are not success.
A timeout alone is not proof of firewall blocking. Read-only diagnosis must bound
time, concurrency, redirects and response sizes; it cannot install trust, change
resolvers/firewalls, open listeners or disable TLS validation.

Follow the [fleet protocol](PROTOCOL.md) for exact artifact and restoration evidence.
The initial proof is a labeled real container reached from a second device, then
recreated and removed correctly. Trusted HTTPS is separately gated. All new launch
proof starts pending and belongs in the current ledger.
