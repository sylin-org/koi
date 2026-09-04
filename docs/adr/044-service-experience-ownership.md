# ADR-044: Service experience ownership

- **Status:** Accepted
- **Date:** 2026-09-04
- **Builds on:** ADR-040, ADR-042, ADR-043, STACK-0001
- **Supersedes:** presentation-owned service grouping, browser-only watched state, and
  ad-hoc multi-domain setup sequences

## Context

Koi already has authoritative domain snapshots, a coherent `KoiStatus` aggregate,
native lifecycle ownership, authenticated local control, and a deliberately narrow
Pond adapter. It does not yet have one product model for the thing a person is trying
to use. The current surfaces expose mDNS records, DNS entries, health checks, runtime
instances, proxy listeners, CertMesh members, and recent events independently. The
desktop groups and watches some of those values in browser state, so another client
cannot reproduce the same answer and a restart can lose user intent.

Epic 003 makes Device, Service, and Connection the everyday concepts. That requires
correlation across domains, but ADR-043 forbids rebuilding truth from best-effort
events or hiding domain ownership behind a global bus. Sharing a loopback service and
setting up HTTPS also require several domain mutations. Those operations must survive
UI closure and process restart without turning the frontend into a workflow owner or
letting a cancelled request abandon admitted native work.

The old June charter preferred incremental page changes and treated durable UI state
as disposable. The owner has since authorized task-oriented interface changes and a
break-and-rebuild before 1.0, while explicitly requiring settings, favorites,
identity, keys, certificates, roots, and unrelated native configuration to survive.

## Decision

### 1. One shared service vocabulary

`koi-common::service` owns the dependency-light, serializable vocabulary used by
catalog, clients, transports, SDKs, and presentation:

- opaque `InstallationId`, `DeviceId`, `ServiceId`, `EndpointId`, `ObservationId`,
  `OperationId`, and `NetworkScopeId` newtypes;
- `Device`, `Service`, `Endpoint`, `Observation`, `CheckEvidence`,
  `AvailableAction`, `ServiceCondition`, and their source/authority enums;
- versioned `CatalogSnapshot`, preference commands, operation summaries, and typed
  service-operation errors.

These are product read-model types, not replacements for `MdnsStatus`, `DnsStatus`,
`HealthStatus`, `ProxyStatus`, `RuntimeStatus`, or CertMesh status. Domain types remain
authoritative in their current crates. Raw `ServiceRecord` remains the mDNS wire
record and is evidence supplied to the catalog, not the catalog's service identity.

### 2. Catalog projection belongs to composition

`koi-compose::catalog::ServiceCatalogRuntime` is the sole cross-domain catalog
projector. It subscribes to authoritative status/watch feeds, including specialized
mDNS, DNS, health, runtime, proxy, roster, and local-candidate projections. It
publishes a cheap `Arc<CatalogSnapshot>` and a coalescing watch receiver. It may emit
best-effort semantic catalog events for activity, but no consumer reconstructs the
snapshot from those events.

The catalog retains observations and provenance. It may correlate them only in this
precedence order:

1. the same explicit Koi service or installation identifier;
2. the same source-owned durable runtime/share identifier on the same installation;
3. the same proven device plus the same normalized endpoint and compatible protocol;
4. otherwise, no merge.

Display names, service types, IP addresses, ports, and TXT similarity alone never
merge services. Conflicting high-confidence identifiers remain separate and carry an
ambiguity reason. One device may host any number of unrelated services.

Every installation creates one non-secret UUIDv7 `InstallationId`, durably owned by
`koi-config::installation` at `state/installation.json`. It is advertised only in
Koi-owned presence/service metadata, never inferred from hostname or CertMesh. A
CertMesh fingerprint is separate authentication evidence; it may strengthen device
correlation but does not replace the installation ID or imply caller authority.

### 3. Durable personal intent gets a domain owner

A new dependency-light `koi-preferences` domain owns favorites, friendly aliases, and
dismissed local suggestions in `state/preferences.json`. Its `PreferencesCore` has
the ADR-043 command/status/event faces and uses versioned atomic commits. Preferences
bind to stable service/candidate keys plus their last known context; they never copy
the raw discovery cache or change a network service's real name.

`koi-compose` joins preferences into the catalog snapshot. It does not read the
preference repository directly. Presentation local storage is a migration source,
not an ongoing authority. An absent favorite stays visible as absent with bounded
last-known context, and a same-named stranger cannot inherit it.

### 4. Explicit bounded coordinators own multi-domain operations

The following coordinators live in `koi-compose`; each has a specific input, durable
intent/receipt where it mutates, typed status, a retained execution owner, and a
joined shutdown path:

| Coordinator | Responsibility | Durable file |
| --- | --- | --- |
| `sharing::SharingRuntime` | one deliberate HTTP/API share and exact Stop | `state/shares.json` |
| `diagnosis::ServiceDiagnosis` | bounded read-only diagnosis of one service or URL | none |
| `secure_service::SecureServiceRuntime` | name, authorized leaf, TLS listener, health and client-verification progress | `state/secure-services.json` |

They are not a workflow framework and share no generic step engine. They call narrow
typed domain facades and platform ports. DNS owns names, mDNS owns advertisements,
Proxy owns forwarding/TLS listeners, Health owns checks, CertMesh owns name grants and
leaves, Trust owns local OS roots, and the platform firewall adapter owns native rule
effects. A coordinator records only its intent, the exact resource receipts returned
by those owners, and progress needed for idempotent recovery.

Successful mutating operations preserve ADR-043's order: durable intent first,
domain/native convergence second, settled receipt and coordinator status third,
semantic event fourth, acknowledgement last. Once mutation is admitted, dropping an
HTTP request or closing the UI cancels only the waiter. Stop is a durable command that
reverses only receipts carrying the same operation/owner generation. Foreign or
pre-existing resources are reported and preserved.

### 5. The first sharing and secure paths are intentionally narrow

The minimum sharing path is an explicitly selected private IPv4 interface/CIDR and
one HTTP or opaque HTTP-compatible API endpoint. A directly reachable existing
endpoint may be advertised without claiming ownership of its listener. A loopback
backend uses a Koi-owned bounded plain TCP forwarder in the Proxy domain, on a port
selected and shown before commitment. The share coordinator obtains a DNS name,
mDNS advertisement, scoped native firewall receipt, listener receipt, and health
evidence. It does not edit the application's configuration. Unknown/public network
scope, an occupied name/port, or missing native enforcement fails specifically.

The first secure-service path is host TLS termination in `koi-proxy`: one authorized
`.internal` service name, one CertMesh-issued leaf covering that exact name, a
Koi-owned TLS listener forwarding to the existing backend, scoped firewall/name
resources, and a real second-client HTTPS check. Private keys remain with the host
termination owner and are never injected into a container. Per-workload key delivery,
arbitrary wildcard issuance, public-internet exposure, and a generic access gateway
are out of scope.

Publication, resolution, reachability, device identity, caller authorization, OS root
presence, and client TLS validation are separate evidence. A share may be locally
running while peer verification is pending. Secure setup is not complete until the
named client resolves the URL and validates the actual leaf without bypass.

### 6. Transports preserve authority and projection boundaries

`koi-serve` owns HTTP/SSE and authenticated local IPC adapters. The full catalog is a
protected operator read model. Catalog subscription, preferences, sharing, diagnosis,
and secure-service mutation routes require the DAT; every preference/share/secure
mutation is additionally loopback-only. Possession of a DAT on a remote connection
does not turn it into a local operator action. The existing local IPC remains the
versioned bootstrap that authenticates the workstation principal and returns the
HTTP endpoint/DAT; it does not grow a second catalog streaming protocol.

Pond receives an explicit allowlisted `PublicCatalogSnapshot`, not a serialized full
snapshot followed by redaction. It contains only network-visible service/device
labels, safe endpoints, coarse conditions, freshness, and non-mutating actions. It
contains no preferences, local candidates, TXT/private diagnostics, CertMesh roster,
operator actions, share receipts, or secure-setup progress.

`koi-client` owns typed HTTP methods and refetch-on-gap behavior. CLI, desktop, MCP,
SDKs, and embedded presentations consume those methods or the in-process typed
snapshot. They do not join domain requests themselves.

### 7. Revisions, freshness, and retention are explicit

Every catalog snapshot has `schema`, a process-instance `epoch`, and a monotonic
revision. Revisions compare only within one epoch. A changed epoch, revision gap,
subscription loss, or incompatible schema requires a complete snapshot refetch;
process-local counters are never compared across restart.

Each observation and check identifies its source/observer, target, observation time,
and `valid_until`. Explicit withdrawal changes availability immediately. Source loss
retains the last accepted observation as stale for a bounded ten minutes; stale
evidence cannot enable Open, Share-complete, or client-verified actions. The catalog
retains at most 4,096 services, 16 observations per service, and 32 latest check
results per service. A preference may retain one bounded last-known summary after the
observation is evicted. Terminal operation receipts retain the latest 32 per kind for
30 days; active intent is retained until stopped or explicitly abandoned after safe
recovery.

These constants live beside `ServiceCatalogRuntime` or the owning operation, not in a
global constants module. Time-based transitions are owned timers which publish a new
snapshot; presentations do not independently age evidence.

### 8. Presentation owns user language; R06 owns the renderer decision

One Rust presentation boundary, provisionally rooted at `crates/koi-ui/`, owns the
everyday labels, action explanations, state copy, and shared components consumed by
desktop and headless web builds. `koi-dashboard` remains the current presentation
until the replacement is accepted. R06 alone chooses the renderer, exact component
map, asset pipeline, and build commands after measured Windows, glibc, musl, and
headless evidence. R01 does not select Dioxus, Tauri, or another renderer.

Domain and composition types expose typed facts, stable codes, and technical detail;
they do not embed competing novice sentences. Advanced raw domain tools remain
reachable even when task-oriented commands and pages replace their current primary
placement.

### 9. Migration is fail-closed and preserves durable user state

Before switching a durable schema, the owning domain writes a versioned backup,
validates the complete proposed model, atomically commits it, and only then marks the
migration complete. Unknown future schema versions are read-only errors, never empty
defaults. Failed migration leaves the original bytes authoritative and reports one
recoverable error.

R05 imports the existing desktop `koi-watched` local-storage values only when the
desktop can map them unambiguously to a current stable service. Ambiguous/unmatched
values remain in the old store and are reported for manual review; they are not
attached by display name. Settings, favorites, installation identity, CertMesh
material, trust roots, DNS/proxy configuration, and unrelated native policy survive
upgrades. Deliberate CLI/API breaks get release notes and typed compatibility errors;
frozen cryptographic labels and established wire identities do not change in place.

## Consequences

### Positive

- Every presentation can answer from one coherent service snapshot without stealing
  domain ownership.
- Preferences and long-running operations survive UI and daemon restarts.
- Sharing and HTTPS setup expose partial truth, exact ownership, and safe reversal.
- Remote read access, local operator authority, mesh identity, and client trust stay
  visibly separate.

### Negative

- `koi-preferences` adds a domain crate and the product aggregate becomes richer.
- Correlation deliberately leaves some duplicate-looking observations separate.
- The supported first sharing path is narrower than a generic port-forwarding or
  identity-aware gateway product.

### Neutral

- This ADR fixes ownership and contracts, not implementation or native acceptance.
- Existing domain commands and advanced views remain available during bounded
  migration, but superseded primary presentation paths are removed after replacement
  acceptance rather than maintained indefinitely.

## Alternatives considered

- **Let each UI correlate records and keep favorites locally.** Rejected because it
  creates several current truths, loses intent, and cannot support SDK/MCP parity.
- **Create a global workflow engine or event bus.** Rejected because it hides domain
  ownership, conflicts with ADR-043, and makes cancellation/shutdown harder to prove.
- **Put preferences in `koi-config`.** Rejected because launch configuration and
  mutable personal product intent have different owners, schemas, and event/status
  semantics.
- **Treat CertMesh membership as sharing authorization.** Rejected because ordinary
  HTTP clients do not prove a CertMesh principal and visibility is not enforcement.
- **Choose the UI framework in R01.** Rejected because R06 owns the required measured
  portability and native-lifecycle spike.

## References

- [Epic 003 contract](../prompts/delight/CONTRACT.md)
- [Observable domain boundaries](043-observable-domain-boundaries.md)
- [Authenticated local control](040-local-operator-control-plane.md)
- [Pond read-only adapter](042-pond-read-only-lan-adapter.md)
- [Sylin stack canon](STACK-0001-sylin-stack-canon.md)
