# ADR-024: Public Identity — Find, Trust, Connect

**Status:** Accepted (operator-ratified 2026-07-19)
**Date:** 2026-07-19
**Builds on:** ADR-001 (host service as the container mDNS bridge), ADR-016 (strategic realignment), ADR-023 (delightful trust)
**Refines:** the public positioning in ADR-016; its technical direction and maturity ordering remain in force
**Constrained by:** STACK-0001 (K2 consumer-neutrality, D7 contract surface)

---

## Context

Koi began with one concrete absence: containers live on a local network, but a
bridge network prevents them from participating in mDNS. Running a small host
service that translated between multicast on the LAN and ordinary container
interfaces solved that problem.

Making containers first-class network citizens exposed the next missing seams.
A discovered workload still needed a stable name. A named workload still needed
identity and trust. A trusted workload still needed a practical route across
container, host, application, and device boundaries. All of them needed lifecycle
and health semantics so arrivals, changes, and departures remained honest.

Koi grew into those empty crevasses. The resulting capability set is coherent,
but its public descriptions drifted between three incomplete identities:

- a "LAN toolbox," which described the inventory but not the outcome;
- a `discover → name → trust → serve` pipeline, which described one useful
  implementation journey but made Koi sound linear and endpoint-centric; and
- a trust-and-discovery substrate, which correctly identified the architectural
  layer but leaned too heavily on security and under-described bidirectional
  participation.

The product needs one identity that preserves the whole shape: discovery, security,
and interconnection, with containers, applications, and devices as equal network
participants.

## Decision

### 1. The banner

Koi's canonical public banner is:

> **Let everything local find, trust, and talk.**

The canonical one-sentence description is:

> **Koi is an open-source local connectivity substrate that makes containers,
> applications, and devices delightfully discoverable, secure, and interconnected.**

When plainer language is preferable:

> **Koi bridges containers, applications, and devices so they can discover, trust,
> and communicate with one another across a private network.**

The three durable public outcomes are **Find. Trust. Connect.** The word *talk* in
the banner is the human expression of *connect*; it promises participation, not a
particular transport or network topology.

### 2. The three outcomes

**Find** means that local things can become visible, receive useful names, and stay
accurate through their lifecycle. mDNS/DNS-SD, `.internal` DNS, container runtime
observation, leases, and health make this outcome real.

**Trust** means that names and peers can carry locally governed identity instead of
depending on an unverified announcement or a browser exception. Certmesh, ACME,
OS trust-store integration, mTLS, signing, verification, renewal, revocation, and
diagnosis make this outcome real. Security is a pillar of Koi, not Koi's entire
identity.

**Connect** means that local participants can communicate across boundaries that
normally isolate them. Containers can announce, discover, and watch mDNS without host
networking; applications can use the CLI, HTTP, IPC, or embedded APIs; UDP can
cross a container bridge; existing proxies, resolvers, monitoring systems, and
agents can consume standard interfaces. Connectivity is bidirectional participation,
not merely publishing an inbound route.

Lifecycle and observability support all three outcomes. They are not a fourth slogan:
the promise is incomplete if a departed service remains findable, an expired identity
appears trusted, or a broken route appears connected.

### 3. The implementation pipeline remains useful, but subordinate

The integrated lifecycle remains a truthful way to explain how capabilities compose:

`arrive → receive a name → be discovered → be reached → be trusted → report health → change → leave cleanly`

Likewise, `discover → name → trust → serve → watch` remains useful for a particular
end-to-end journey. Neither sequence is the product's public identity. They are
evidence that Find, Trust, and Connect are integrated rather than a bag of unrelated
features.

### 4. Koi collaborates with the local stack

The collaboration doctrine from ADR-016 remains binding: **integrate, don't replace.**
Koi should close connective seams and expose useful context through formats other
tools already understand. Operators should be able to keep their resolver, overlay
network, reverse proxy, monitoring system, container runtime, and applications.

Koi may act as the authority for a small greenfield network or as a feeder beneath an
existing stack. It should not expand into ad blocking, a general-purpose reverse proxy,
an overlay network, an enterprise PKI, a container orchestrator, or an application
service mesh merely because those products touch the same data.

### 5. Capability admission test

A proposed capability belongs in Koi when it satisfies all of these conditions:

1. It materially helps a local container, application, or device find, trust, or
   connect with another participant.
2. It closes an otherwise unowned boundary or lifecycle seam.
3. Koi can own the responsibility once at a meaningful chokepoint instead of forcing
   every consumer to evaluate the same problem independently.
4. It composes with established tools through a standard or deliberately small
   interface and remains easy to disable or leave.

If an established tool already owns the responsibility well, Koi should integrate,
translate, or provide context rather than reproduce it.

### 6. Public communication rules

Public orientation material should:

- lead with the banner and the user-visible transformation;
- name containers, applications, and devices, rather than treating containers as an
  edge case;
- explain Find, Trust, and Connect before enumerating implementation domains;
- tell the origin story because it makes the breadth legible rather than arbitrary;
- present `.internal`, certmesh, and trusted HTTPS as the Trust pillar without making
  security the entire story;
- describe container participation in both directions: containers can be found and
  can find or watch the LAN;
- show how Koi works with existing tools and state honest boundaries; and
- preserve the pre-1.0 maturity warning until the evidence supports removing it.

Public orientation material should not lead with "toolbox," a feature count, "service
mesh," or a security-only category. Detailed reference material may still describe
the concrete pipeline appropriate to that capability.

## Consequences

- Koi has one memorable promise without hiding the breadth that makes it distinctive.
- Security remains central and visible, but it no longer eclipses discovery and
  interconnection.
- New capabilities face a responsibility-and-chokepoint test, limiting accumulation
  and encouraging fewer, more meaningful moving parts.
- The product can explain collaboration with adjacent tools without defining itself
  as a weaker replacement for each of them.
- Public docs require a distinction between stable product outcomes and changeable
  implementation inventory.
- ADR-016 remains the source for the strategic roadmap and trust-plane architecture;
  this ADR supersedes only its public headline and weighting.

## Rejected alternatives

### "The missing LAN toolbox"

Accurate as an inventory metaphor, but it makes the capabilities appear collected
rather than composed and gives no principled boundary for adding another tool.

### "The trust and discovery substrate"

Architecturally defensible, but incomplete. It omits the reason the bridge, proxy,
UDP, runtime, HTTP, IPC, embedded, and integration surfaces exist: enabling actual
participation across boundaries.

### "A local service mesh"

Familiar but misleading. Koi does not own application routing, sidecars, traffic
policy, or an overlay data plane, and many participants are devices rather than
services under an orchestrator.

### Lead with the implementation pipeline

The pipeline demonstrates integration but overfits one journey. Find, Trust, and
Connect remain meaningful independently and cover bidirectional use cases that do not
end in Koi terminating TLS.

## STACK alignment

This identity preserves consumer-neutrality: it describes infrastructure outcomes and
contracts without importing a downstream product's vocabulary. The admission test also
reinforces the stack boundary by preferring reusable primitives and chokepoints over
consumer-specific orchestration.
