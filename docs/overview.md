# Is Koi useful for your network?

Koi is an open-source host service for container/LAN developers and capable
homelab operators, with particular focus on Windows and Linux. It connects
opted-in container lifecycle to service discovery, local names and health checks.

Certmesh is its private-space identity and trust capability: create a locally
governed trust group for machines and participating applications. Container
discovery is the first task; shared identity is available when the service needs it.

Use it when you repeatedly configure where a container service lives, how another
machine finds it, and what should disappear when the container is replaced.

## The first task

Run an application in a bridge-networked container with a published port.
Add `koi.announce` or `KOI_MDNS_ANNOUNCE`, confirm Koi's runtime
observation, discover the service from a second machine, and open its actual
application endpoint. Stop, restart and recreate it, checking the app and derived
state at each step.

The [container guide](../CONTAINERS.md) is the working path. The
[release-readiness record](launch/README.md) states which artifact and environment
have completed that path. CLI and HTTP are sufficient; a polished workbench is
not a prerequisite for this initial task.

## What runs where

Koi runs on the host that can observe the engine and participate on the LAN.
Containers keep their bridge network. Koi can publish their reachable host ports,
and participating applications can ask Koi's HTTP API about LAN services.

This does not give every unmodified application transparent multicast access.
A program must use the API or a protocol-specific adapter for that direction of
discovery. UDP relay is an explicit application interface, not a general VPN.

The daemon runs locally without a hosted account or control plane. Discovery
still depends on the interfaces, firewall and broadcast domain. A VLAN or wireless
isolation boundary may require network configuration outside Koi.

## Keep existing tools

- Keep Docker or Podman. Koi reads opted-in runtime metadata and selected existing routing labels.
- Keep your resolver. Delegate the Koi zone or import an export; verify client resolution.
- Keep your reverse proxy. Koi's built-in proxy is a TLS byte forwarder, not a path router.
- Keep monitoring. Prometheus HTTP service discovery can consume Koi targets.

These are integration points with prerequisites, not a promise that every existing
configuration works unchanged. [Integration guides](guides/integrations.md)
state the configuration boundaries.

<a id="add-trust-when-the-task-needs-it"></a>

## Private-space identity and trust

Use Certmesh to establish your own CA, admit machines to a trust group and manage
their identity lifecycle. It provides enrollment, certificate renewal, signed
membership/revocation information and backup/recovery. The authority and member
identities stay under your control, without a hosted account or public CA.

Koi-aware applications can verify peer identities and signed messages, consume
membership changes and apply their own access rules. This supports a private
trust space for a homelab, small team or lab alongside Koi's discovery APIs.
Applications must integrate those identity checks; joining a mesh does not
automatically configure every service's authentication or isolate its network.

See [Certmesh](guides/certmesh.md), [recovery](guides/certmesh-ha-recovery.md)
and [application embedding](guides/certmesh-embedded.md). You can start with
discovery and add shared identity when it solves a recurring need.

### HTTPS for a service name

A usable HTTPS URL requires a reachable listener, a certificate covering that
exact name, an unexpired valid chain, and trust in the actual client. Member
certificates cover host identities; a container label does not add a service's
vanity name to that certificate.

Source contains exact service-name grants and certificate lifecycle primitives.
The public operation composing these with Proxy and a complete external ACME
workflow remains unfinished. See [container TLS](guides/recipes/container-trusted-cert.md)
and [ACME](guides/acme.md). Do not substitute a TLS warning bypass for successful
setup.

## Where Koi fits poorly

Koi's current primary scope is an owner-operated LAN. Consider another approach
when the main requirement is public hosting, remote overlay routing, enterprise
identity governance, or transparent support for an unmodified multicast protocol.

If existing DNS, proxy and discovery tools already solve your task, Koi needs to
remove a specific remaining burden to justify another service. A public domain
with externally automated certificates may also be preferable when client root
installation is the main obstacle.

Nontechnical households need supported client setup and diagnostics that current
development does not yet establish. macOS implementation and release artifacts
exist, but a platform claim still needs evidence for the selected journey.

## Security and operation

Management HTTP is loopback by default. Exposing it to a container bridge or LAN
is deliberate and does not relax authentication. A bearer token does not encrypt
plaintext HTTP. Use the [security model](reference/security-model.md).

Private-CA membership is not a fine-grained multi-tenant authorization system.
Ordinary TLS clients do not consume Koi's revocation metadata and may accept
a copied leaf until expiry. Check client-specific trust and revocation needs.

## Choose your next step

- [Getting started](tutorials/getting-started.md) for a first evaluation.
- [Containers](../CONTAINERS.md) for the full task and application-side API use.
- [User guide](../GUIDE.md) for operation and diagnosis.
- [Installation](guides/install-and-service.md) and [upgrading](guides/upgrading.md) for artifact selection.
- [Release readiness](launch/README.md) for supported scope and evidence.
