# Koi documentation

Koi helps container/LAN developers and capable homelab operators publish, find
and maintain usable local services. The starting task is one container, one
second-machine application check, and correct lifecycle through change.

## Start here

1. [Choose and install an artifact](guides/install-and-service.md).
2. [Getting started](tutorials/getting-started.md).
3. [Publish, open and recreate a container service](../CONTAINERS.md).
4. [Diagnose the step that failed](guides/troubleshooting.md).

[Release readiness](launch/README.md) is the authority for supported artifacts and
verified environments. Published stable is 0.9.0; published prerelease is
1.0.0-rc.2; current source is 1.0.0-dev.0. These guides describe current source
unless they identify another version. Use release-matched documentation when
evaluating an older artifact.

## Private-space identity and trust

Certmesh provides a locally governed trust group for machines and participating
applications, with enrollment, identity renewal and signed membership changes.
Use it when your services need shared identity alongside discovery.

- [Create and operate a private trust space](guides/certmesh.md).
- [Back up or recover the authority](guides/certmesh-ha-recovery.md).
- [Use Certmesh inside an application](guides/certmesh-embedded.md).
- [Understand identity verification and membership propagation](reference/trust-protocol.md).

## Operate a service

| Task | Documentation |
| --- | --- |
| Understand the scope and fit | [Overview](overview.md), [user guide](../GUIDE.md) |
| Publish or discover services | [Containers](../CONTAINERS.md), [runtime](guides/runtime.md), [mDNS](guides/mdns.md) |
| Configure names clients can resolve | [DNS](guides/dns.md), [existing resolver](guides/dns-coexistence.md) |
| Check readiness and changes | [Health](guides/health.md), [system operation](guides/system.md) |
| Run continuously or upgrade | [Installation](guides/install-and-service.md), [upgrading](guides/upgrading.md) |
| Add TLS for a host member name | [Trusted HTTPS tutorial](tutorials/trusted-https.md), [proxy](guides/proxy.md) |
| Understand exact container service-name TLS | [Container TLS limits and configuration](guides/recipes/container-trusted-cert.md) |
| Use an existing monitoring/proxy stack | [Integrations](guides/integrations.md), [ACME prerequisites and limits](guides/acme.md) |

Discovery, reachability and client trust are separate observations. A DNS entry
inside Koi does not configure the client resolver. A private root in an OS store
does not establish that every browser or runtime consumes that store.

## Advanced capabilities

The initial container journey needs neither a private CA nor every interface.
These guides remain available when a concrete integration needs them.

| Capability | Guide |
| --- | --- |
| HTTP authentication | [API access](guides/api-authentication.md) |
| CA root management | [Trust](guides/trust.md) |
| Application-side UDP relay | [UDP](guides/udp.md), [container recipe](guides/recipes/container-udp.md) |
| Agent interface | [MCP](guides/mcp.md) |
| Rust integration | [Embedding](guides/embedded.md), [embedded certmesh](guides/certmesh-embedded.md) |

## Reference and project direction

- [CLI](reference/cli.md), [HTTP API](reference/http-api.md), [wire protocol](reference/wire-protocol.md).
- [Security model](reference/security-model.md), [route authorization](reference/http-route-auth-matrix.md), [ports](reference/ports.md).
- [Architecture](reference/architecture.md), [capability cards](reference/cards/index.md).
- [Contributing](../CONTRIBUTING.md).
- [Container/LAN adoption decision](adr/046-container-lan-adoption.md).
- [Experience direction and interactive concept](ux/README.md).
- [Release readiness](launch/README.md).
