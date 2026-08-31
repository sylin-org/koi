# ADR-038: Runtime mDNS Provider Orchestration

**Status:** Accepted and implemented (operator mandate 2026-08-31)
**Date:** 2026-08-31
**Supersedes:** ADR-037's boot-only selection and process-lifetime provider lock
**Builds on:** ADR-020 (truthful status), ADR-035 (gentle participation), ADR-037 (provider port)

## Context

An operating system can expose several useful mDNS/DNS-SD facilities at once,
and those facilities do not necessarily implement the same operations. Avahi
offers a complete asynchronous DNS-SD control plane over D-Bus. Newer
systemd-resolved releases expose real service publication and point resolution
over resolve1 D-Bus, but no continuous DNS-SD browser and no explicit-address
publication. Windows 10 and later expose official asynchronous DNS-SD APIs in
`dnsapi.dll`; a machine may additionally have Apple Bonjour/mDNSResponder and
its DNS-SD client library installed. Avahi itself is not a Windows product.

A bootstrap `if Avahi { ... } else { ... }` cannot represent that world. It puts
platform detection in composition, discards partial but valuable facilities,
cannot recover when resources change, and turns every new platform adapter into
another policy branch. Retaining provider choice inside an adapter is equally
wrong: it makes infrastructure decide application policy and duplicates desired
publication state across unrelated implementations.

The product requirement is stronger than fallback. Koi is the stable mDNS
control plane, uses every safe native capability available, fills only missing
operations itself, changes its plan at runtime, and never claims an operation a
provider does not implement.

## Decision

### 1. Adapters own evidence and native mechanics

Every provider adapter implements one boundary:

- a static identity, preference, native API surface, and maximum capabilities;
- read-only `inspect`, reporting presence, configuration, liveness, current
  capabilities, and actionable detail without activating a stopped service;
- `arm`, returning only real operations backed by that native facility.

Provider-specific service-manager, socket, D-Bus, Win32, Bonjour, and library
types stay inside their adapter. Composition only supplies the target's adapter
catalog. It does not test ports, processes, packages, or service state.

### 2. Capabilities, not provider names, determine the plan

The agnostic model declares these independently:

- publication and withdrawal;
- explicit-address publication;
- continuous browse whose events include resolved SRV/TXT/address data;
- direct point resolution;
- the native API surface used for evidence and diagnostics.

The supervisor selects the highest-priority ready adapter for each required
route. One complete provider collapses to one armed adapter. Partial providers
compose only where their operations do not overlap. For example, without Avahi,
resolve1 may own ordinary publication and direct resolution while native Koi
owns continuous browse and explicit-address publication. No service is
published by two adapters, and only one adapter owns a browse route.

The built-in Koi adapter is an ordinary full provider. It is always appended to
the catalog on every platform and has a reserved lowest preference; platform
catalogs cannot replace or undercut it. It is not selected by an OS-specific
fallback branch. Armed providers must explicitly declare capabilities, API
surface, and health—there are no optimistic trait defaults.

Expected platform catalogs are:

- Linux: Avahi, systemd-resolved, native Koi;
- Windows: official Win32 DNS-SD, Bonjour when genuinely installed and healthy,
  native Koi;
- other platforms: completed native facilities in preference order, then
  native Koi.

### 3. One supervisor owns runtime policy and desired projection

`MdnsSupervisor` is the stable `MdnsProvider` facade injected into `MdnsCore`.
Its single actor:

1. starts adapter inspections concurrently;
2. applies pure priority-and-capability policy as reports arrive, without
   waiting for an irrelevant lower-capability adapter;
3. requires repeated observations before failover or preferred-provider
   promotion;
4. serializes publications, withdrawals, browses, resolution, and transitions;
5. retains a provider-facing projection of desired publications solely for
   transition replay;
6. reports the active routes, generation, adapter evidence, and transition
   reason through the existing capability status.

`MdnsCore` remains authoritative for registration identity, leases, sessions,
and cache semantics. The projection is an infrastructure outbox, not a second
domain registry.

Adapter inspection also owns liveness. Continuous-browse activity (event count
and last-event age) is surfaced as telemetry, but generic code never treats a
quiet DNS-SD event stream as a failed provider: these APIs emit changes, not
keepalives. Explicit independent-peer traffic is the receive-path acceptance
proof.

### 4. Transitions are break-before-make and generation fenced

Before arming a replacement plan the supervisor:

1. refuses new publication while transitioning;
2. advances the browse generation so late events are discarded immediately;
3. shuts down every adapter no longer in the plan and waits for resource
   release;
4. refuses to arm a replacement if retirement cannot be proven;
5. arms and capability-validates the new plan;
6. replays the current publication projection through exactly one route per
   registration.

The existing browse hub observes the retired receiver close and reconnects
through the stable supervisor. Public subscriptions, registration IDs, leases,
and transports survive. Initial absence does not remove the mDNS core; it stays
mounted, unhealthy, and able to recover when a viable plan appears.

### 5. Native participation is cooperative and measured

The native adapter performs a real reuse-enabled IPv4/IPv6 UDP 5353 bind probe
matching RFC 6762 coexistence before it reports ready. It holds those proof
sockets until `mdns-sd` reports its own daemon running. Koi never stops,
reconfigures, or activates another provider merely to make selection succeed.

### 6. Product behavior is always real

No production endpoint, report, capability, or successful operation may be
backed by a fake, placeholder, or future TODO. Test adapters are allowed only in
tests. A partial native facility declares only completed operations and is never
routed an unsupported call.

## Consequences

- Platform additions implement one adapter rather than edit domain policy.
- Windows can prefer its official DNS-SD API, use an installed Bonjour service
  when it is the better live provider, and retain native Koi as the guaranteed
  low-priority candidate.
- Linux benefits from resolve1's real D-Bus operations instead of treating its
  UDP socket as an obstruction.
- Provider loss and recovery no longer require a Koi restart.
- Complementary providers may be armed together, but routes never overlap; the
  singular product control plane and one-Koi-process rule remain intact.
- Status becomes more explicit because a plan can name different publish,
  browse, explicit-address, and direct-resolution routes.

## Validation

- Pure policy tests for priority, pending reports, capability composition, and
  irrelevant-provider non-blocking.
- Actor tests for hysteresis, break-before-make ordering, exact publication
  replay, and retired-generation event rejection.
- Ignored real-adapter tests for Avahi, resolve1, and native Koi.
- A coordinated physical provider-transition lane using one installed Koi per
  host and at least one independent peer. It proves bidirectional
  publish/browse/resolve/TXT/removal before, during, and after provider changes;
  captures process/socket/provider generations; and restores every service to
  its recorded baseline on all paths.

The local installed-service half ran on CachyOS on 2026-08-31. One unchanged
Koi PID and binary completed generations 1→5 across
`avahi → systemd-resolved+native → native → systemd-resolved+native → avahi`;
resolve1 held a real Koi DNS-SD registration, browse reception resumed at each
transition, and every host service returned to its active/enabled baseline. The
independent-peer half is encoded in
`scripts/integration/mdns-provider-transition.sh` and remains a required paired
fleet execution; the local run is not presented as cross-host evidence.
