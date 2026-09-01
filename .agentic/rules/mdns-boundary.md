---
globs: crates/koi-mdns/src/{adapter,provider,control_plane,native,avahi,systemd_resolved,discovery}.rs,crates/koi-compose/src/mdns.rs
alwaysApply: false
---
# mDNS Provider Boundary Rules

## Ownership

- `RegistrationRegistry` is the only owner of registration identity, desired
  publication intent, and lease policy.
- `DiscoveryHub` is the only owner of browse demand, per-type multiplexing,
  cache, fan-out, and subscriber continuity.
- `MdnsControlPlane` is the only owner of adapter assessment, capability-route
  policy, provider sessions, route transitions, and materialized publication
  leases. It never owns a second desired-publication map.
- Each provider session owns its detector, native connection, callbacks/tasks,
  resource handles, recovery, and acknowledged shutdown.

Composition lists platform adapters only. The control plane appends native Koi
as the reserved, lowest-priority provider. Complementary providers may be open
only for the routes they actually own.

## Real operation contract

- `MdnsAdapter::assess` is read-only. It must not start, stop, enable, disable,
  or reconfigure an external responder.
- Capability evidence includes non-interactive authorization for the installed
  Koi service identity. API presence alone must not claim an operation. Preserve
  independently usable routes when one operation is unauthorized.
- `MdnsAdapter::open` returns a real stateful `ProviderSession`; production
  placeholders, fakes, TODO endpoints, and capability guesses are forbidden.
- `publish` returns a `PublicationLease` only after the native resource exists.
- `withdraw`, browse-lease `close`, and session `shutdown` return only after the
  owned native resource has been released. A failed release stays retryable.
- Provider errors are typed by operation and failure scope. Orchestration never
  parses human diagnostic text.
- Operation rejection is local to that operation. Sessions report
  `recovering` during native owner/config churn and `lost` only when their epoch
  cannot continue.
- Async command cancellation must not orphan a resource. Provider actors clean
  up undeliverable replies; registry transaction guards restore intent.

## Route transitions

- Publication, explicit-address publication, continuous browse, and direct
  resolution are independent routes.
- Changed write routes are break-before-make and await withdrawal first.
- Changed browse routes advance an epoch; stale events are discarded and live
  demand reconnects through `DiscoveryHub`.
- Unchanged routes, sessions, publications, and browses are not disturbed.
- Publication replay is part of the route transaction. A failed replay restores
  the prior working route and materializations.
- A quiet DNS-SD stream is telemetry, not a health failure.

## Native library isolation

`crates/koi-mdns/src/native.rs` is the only file allowed to import `mdns-sd`.
It converts every library type to provider-neutral values before crossing the
session boundary. `avahi.rs` and `systemd_resolved.rs` likewise contain their
own D-Bus types.

The native engine keeps one querier per canonical service type. `DiscoveryHub`
therefore opens one real browse for N subscribers and closes it only after the
last subscriber leaves. Keys always come from `discovery::canonical_key`.

## Validation

Fakes belong only in tests. Unit tests cover registry and routing state
machines; ignored real-adapter tests exercise native APIs; fleet acceptance uses
one installed Koi per host and an independent LAN peer. Fleet scripts assert
the structured `control_plane` status fields and never parse prose summaries.
