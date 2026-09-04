# ADR-037: One mDNS Control Plane, Native Platform Providers

**Status:** Superseded by ADR-038 (accepted 2026-08-31)
**Date:** 2026-08-31
**Builds on:** ADR-020 (truthful status), ADR-030 (coexistence), ADR-035 (gentle participation)
**Amends:** ADR-030's rule that Koi skips mDNS when Avahi is active

> **2026-08-31:** ADR-038 replaces the boot-only, one-backend decision in this
> ADR with adapter-owned runtime inspection and capability-aware reconciliation.
> The provider-neutral port, concrete API isolation, and real-provider-only
> rules below remain architectural inputs; the “no dynamic switch” clauses are
> retained only as history. ADR-043 later retired the implicit piped mode named
> below because it created an uncoordinated second control plane.

## Context

Skipping Koi's mDNS capability on an Avahi host avoided two responders, but it
also removed Koi's discovery, leases, fan-out, HTTP/IPC/MCP surfaces, and network
control-plane value. Avahi is not a competing product surface; it is the native
Linux mDNS engine Koi should use when it is healthy. Where no suitable system
engine exists, Koi still needs its built-in RFC-compatible engine.

The same distinction matters on Windows: Koi's opportunity is not a proprietary
wire protocol or a second responder. It is a dependable, observable,
language-neutral control plane over the best real mDNS facility the OS provides.

## Decision

### 1. A provider port is the only domain dependency

`MdnsCore` and the shared browse hub depend on `MdnsProvider`. The port owns only
platform operations and health: publish, withdraw, browse, stop, status, and
shutdown. Provider-neutral observations retain every address plus interface/scope
identity. The hub owns Koi concerns: leases, registry, cache, one-browse-per-type
fan-out, resolve semantics, retries, public events, and the current single-IP
compatibility projection.

Concrete API types never cross adapter boundaries:

- `native.rs` alone imports `mdns-sd`;
- `avahi.rs` alone imports and speaks Avahi's `zbus`/D-Bus contract;
- future Windows platform APIs stay inside the Windows adapter.

There is no plugin registry, service locator, shadow provider, or dynamic
mid-process provider switch.

### 2. Bootstrap selects and injects exactly one provider

The `koi-compose` composition root probes once per process start:

- Linux, live Avahi D-Bus owner and `RUNNING` server: inject the Avahi adapter;
- Linux, Avahi definitely absent and UDP 5353 exclusively available: inject the
  native adapter;
- Linux, Avahi present but broken, or Avahi absent with an ambiguous 5353 owner:
  report an initialization error and do not arm native beside it;
- platforms without a completed system adapter: inject native.

Koi does not activate a stopped Avahi service merely because it is installed.
This makes an operator-stopped service a real absence decision and keeps fallback
validation deterministic. Every production bootstrap path—daemon, installed
service, embedded, standalone CLI, piped mode, and mDNS-consuming helpers—uses
the same composition policy.

### 3. Recovery stays inside the selected adapter

Provider choice is stable for the process lifetime. The Avahi adapter watches the
live D-Bus owner and server state, closes invalid browser objects on provider loss,
retains desired publications, and recreates them when Avahi returns. Closing a
browse stream activates the hub's bounded retry. A Koi restart is the boundary at
which provider selection runs again.

### 4. Publication is collision-safe and observable

Native publication keeps `mdns-sd`'s RFC 6762 probing enabled. Avahi publication
waits for a real entry group to become established; on collision it asks Avahi for
an alternative service name and retries with a bound. Adapter or publication
failure marks mDNS unhealthy rather than leaving an empty browser labeled healthy.
The capability summary names the selected provider and its live detail.

### 5. Tests may substitute; product behavior may not

Deterministic unit tests may inject a test provider. Production capabilities,
endpoints, bootstrap decisions, and conformance evidence must use real provider
implementations. No placeholder success, fake endpoint, or TODO-backed capability
is acceptable.

## Consequences

- Avahi hosts retain one responder while gaining Koi's complete control-plane
  surface.
- Windows and future adapters share the smallest meaningful contract without
  importing Linux architecture.
- The native engine remains valuable on machines where the system has no usable
  provider.
- A broken known provider fails visibly instead of causing an unsafe second
  responder.
- Provider selection and provider recovery are separate concerns, which makes
  restart behavior deterministic and diagnosable.

## Validation

- Strict compile/clippy/unit/composition gates.
- Real Avahi D-Bus publish, browse, IPv4/IPv6 resolve, TXT, explicit address, and
  removal on the CachyOS workstation.
- Installed-service validation with `/v1/status` naming `avahi`, real
  publish/browse/resolve/remove through Koi's public surface, and an Avahi
  stop/start recovery cycle without a provider switch.
- Serial fallback validation: stop Koi, stop Avahi, start the same installed Koi,
  prove `native`, stop Koi, restore Avahi, then start Koi and prove `avahi`.
- Leave exactly one healthy installed Koi and restore the workstation's original
  Avahi-enabled state.
