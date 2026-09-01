# ADR-039: mDNS Control-Plane Ownership and Provider Sessions

**Status:** Accepted (operator mandate 2026-08-31)
**Date:** 2026-08-31
**Supersedes:** ADR-038's `MdnsProvider` facade, duplicated publication projection,
and whole-plan transition mechanics
**Builds on:** ADR-020, ADR-030, ADR-035, ADR-037, ADR-038

## Context

ADR-038 established the correct product direction: adapters inspect their own
platform facilities, Koi selects capability routes at runtime, and the built-in
engine is an ordinary low-priority provider. Its first implementation put too
many responsibilities in `MdnsSupervisor`, however. The supervisor became a
provider facade, planner, command bus, second publication registry, session
lifecycle manager, browse fence, and diagnostics formatter. Mutating provider
calls were fire-and-forget, so an HTTP 201 could precede real publication.

That shape also confused failures at three different scopes. One rejected
publication could make an otherwise usable provider unhealthy; an adapter
temporarily recovering its own native resources could cause the supervisor to
tear it down and arm the same adapter again; and whole-plan replacement disturbed
routes whose providers had not changed.

The desired experience is operational rather than rhetorical: Koi should use the
best facilities already present, recover through normal platform churn, preserve
registrations and subscriptions, avoid duplicate responders or publications, and
report success only after a real native resource exists.

## Decision

### 1. Four components have exclusive ownership

The bounded context has four meaningful runtime owners:

1. `RegistrationRegistry` owns registration identity, desired announcements,
   lease policy, renewal, draining, and transactional publication intent.
2. `DiscoveryHub` owns browse demand, one real browse per canonical type, cache,
   fan-out, retry, and subscriber continuity.
3. `MdnsControlPlane` owns provider assessment, capability-route policy, open
   sessions, route transitions, and synchronization of real publication leases
   against registry intent.
4. Each provider session owns its native connection, resource handles, detector,
   recovery, and shutdown.

There is no second map of desired announcements. The control plane stores only
materialized `PublicationLease`s and reconciles them against registry snapshots.

### 2. Adapters open stateful provider sessions

An adapter exposes a static descriptor, a read-only assessment, and `open`.
`open` returns a `ProviderSession`, not another Koi facade. A session reports one
of `ready`, `recovering`, or `lost` and exposes only capabilities backed by real
native operations.

Assessment includes whether the installed Koi service identity can use each API
non-interactively. Method presence is not capability: for example, resolve1 may
expose `RegisterService` while polkit denies a user-scoped daemon. In that case
the adapter advertises point resolution but not publication, allowing native Koi
to fill only the unavailable route. Custom policy grants are honored through the
platform authorization authority; Koi does not install policy exceptions.

Publication returns an owned lease only after the provider has established the
native resource. Withdrawal consumes that lease and completes only after release.
A browse returns an owned browse lease whose close is awaited. Shutdown completes
only after the session has released its entry groups, registered objects,
browsers, sockets, worker threads, and native daemon state.

Provider errors are typed by operation and failure kind. Human detail remains
diagnostic text; orchestration never parses it.

### 3. Adapters recover their own resources

Avahi owns D-Bus owner epochs, server state, entry groups, browser objects,
collision handling, and reconstruction after restart. resolve1 owns its D-Bus
owner, live API/configuration assessment, registered object paths, and
reconstruction. Native Koi owns `mdns-sd` monitoring, acknowledged announcements,
browser barriers, unregister completion, and daemon shutdown.

An operation failure is scoped to that operation. Browser EOF, a rejected
registration, or a failed point resolution does not declare the whole session
lost. A session is `recovering` while its native facility is expected to return;
the control plane changes routes only after repeated independent assessment or a
genuinely lost session.

Production Koi never starts, stops, enables, disables, or reconfigures an
external responder. Such changes belong only to explicitly coordinated tests.

### 4. Route transitions disturb only changed routes

Publication and explicit-address publication are independent write routes;
continuous browse and point resolution are independent read routes.

- A changed write route is break-before-make: old leases are withdrawn and
  awaited before the same desired announcements are established through the new
  route.
- Read routes may open the replacement session before advancing the browse epoch.
  Late events from an older epoch are discarded, and the `DiscoveryHub` reconnects
  its still-live demand through the new route.
- A session is shut down only when no route or lease still uses it.
- Unchanged routes, publications, and browse sessions are untouched.
- A candidate write route is committed only after every desired publication is
  materialized. Any replay failure retires candidate-only sessions and restores
  the previous route and its publications.

Every reconciliation also diffs registry intent against materialized leases.
This provides eventual recovery for interleavings, provider restart, and a
single-record replay failure without duplicating domain state.

### 5. Registration is transactional and asynchronous

The registry marks publication or withdrawal intent before the control-plane
command. Public registration returns only after a real publication lease exists;
failure rolls back the registry change. Public withdrawal returns only after the
provider resource has been released; failure leaves retryable intent. Reaper and
shutdown use the same path.

This makes the HTTP, IPC, embedded, MCP, and standalone surfaces agree on what
success means.

### 6. Structured state is canonical

The admin status contract exposes control-plane state, generation, each route,
adapter evidence, session state, and desired/established/pending/failed
publication counts. The unified human summary is derived from that structure.
Tests and fleet workbooks assert structured fields and never parse prose.

The wire/domain status types live once in `koi-common`; provider-native types
remain inside their adapter modules. `mdns-sd` remains isolated to `native.rs`.

## Consequences

- The registry is the single source of desired publication truth.
- Provider sessions can recover without being needlessly replaced by themselves.
- One bad service cannot erase otherwise healthy discovery capability.
- Route upgrades use all safe platform capability without disrupting unrelated
  traffic.
- API success has a concrete native-resource meaning.
- Windows adapters implement the same descriptor/assessment/session/lease
  contracts, including Bonjour when genuinely installed; they do not fork the
  architecture.
- The public async registration change is intentional and propagated through all
  in-process consumers.

## Validation

1. Pure registry and route-policy state-machine tests.
2. Test-only adapter conformance for acknowledgements, route-local transitions,
   exact replay, session recovery, and browse epoch fencing.
3. Real ignored tests for Avahi, resolve1, and native publication, browse,
   resolution, withdrawal, restart, and shutdown.
4. One installed Koi on each of test-01 and test-02, with coordinated bidirectional
   publish/browse/resolve/TXT/removal across Avahi, best fallback, native-only, and
   restored Avahi phases.
5. Capture and restore both hosts' original provider state on every exit path;
   leave exactly one healthy Koi per host.
