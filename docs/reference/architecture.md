# Architecture

Koi is a modular Rust application with one composition and lifecycle owner. Its initial product task is concrete: turn an opted-in container's reachable host endpoint into useful LAN discovery, verify the actual application from a second device, and reconcile stop/recreate accurately. Exact service HTTPS and a verified existing-tool integration extend that path. See [launch readiness](../launch/README.md).

## Ownership

| Layer | Crates | Responsibility |
| --- | --- | --- |
| Host entry points | `koi-net`, `koi-embedded` | CLI/native service or application-owned startup and terminal shutdown |
| Composition | `koi-compose` | Construct domains, install typed bridges, reconcile runtime resources, aggregate accepted state, own tasks |
| Transports | `koi-serve`, `koi-mcp`, `koi-client` | HTTP/IPC/TLS/MCP adapters and blocking client calls |
| Presentation | `koi-ui`, `koi-dashboard` | Render accepted snapshots and expose browser-facing projections |
| Domains | `koi-mdns`, `koi-runtime`, `koi-dns`, `koi-health`, `koi-proxy`, `koi-certmesh`, `koi-trust`, `koi-udp`, `koi-preferences` | Commands, authoritative state, semantic events and provider lifetime |
| Shared infrastructure | `koi-common`, `koi-config`, `koi-crypto` | Contracts, persistence primitives, path/config discovery and cryptographic building blocks |

The workspace manifest defines exact package/features. Package presence is not a release or platform acceptance claim.

## Container lifecycle

The runtime backend normalizes Docker/Podman observations into instance state. Its owned status stream separates a healthy current inventory from unavailable/stopped backend state. The orchestrator repeatedly reconciles that state into runtime-owned mDNS, DNS, health and proxy resources. It does not make runtime-derived records operator-owned persistent configuration.

An observed container port must be projected into a reachable host endpoint before it is advertised. Reconciliation and deterministic resource identity allow withdrawal and replacement. A synthetic runtime test establishes this logic; an independent physical client establishes that the endpoint actually works on the selected platform/network.

`koi.certmesh` is request metadata, not automatic container certificate issuance. Certmesh's service-name authorization facade exists separately; current operator/listener wiring is tracked in launch readiness.

## Domain contract

Each domain exposes commands, one immutable latest status and semantic events. Internal locks and mutable stores stay private. Providers own external engines behind typed ports. Composition connects domains; adapters do not inspect files or infer another domain's truth.

Status is recoverable latest state; events indicate transitions and may be missed by a slow consumer. Consumers recover from authoritative snapshots after lag/reconnection. Catalog snapshots have a process epoch and revision; display names and ports are not stable identity.

See [domain implementation guidance](domain-template.md) and the preserved [observable-boundaries decision](../adr/043-observable-domain-boundaries.md).

## Lifecycle and persistence

`RunningCores` owns background work. Partial startup and shutdown preserve task ownership, cancel dependent work and release listeners/resources in order. The installed service and embedded host share the composition instead of copying it.

Accepted durable state precedes published state and its semantic event. Atomic replacement can become visible before directory durability is confirmed; code must distinguish visible truth from fully confirmed persistence. Certmesh uses a journaled multi-file repository so keys, membership and audit state do not silently form mixed generations after a failed command. Unknown/corrupt persistent schemas must not be silently reset.

## Network and trust boundaries

The main management HTTP adapter defaults to loopback. Writes and sensitive reads require the daemon token. Local IPC authenticates the recorded operator before returning access information. Separate authority listeners serve mTLS and ACME; Pond exposes a reduced read-only projection. These are distinct authority boundaries, documented in [security](security-model.md) and the [route matrix](http-route-auth-matrix.md).

mDNS reports unauthenticated observations. A DNS name, healthy host probe, trusted CA, authenticated mesh member and exact-service HTTPS each establish different facts. Presentation must preserve those distinctions.

## Validation

Architecture tests, ordinary domain tests and platform cross-compilation guard structure. Real Docker, native provider transitions, installed service recovery and second-device application requests require their own evidence. Read [validation](../qa/validation-suite.md) and [fleet contract](../../fleet/CONTRACT.md) before claiming a supported scenario is verified.
