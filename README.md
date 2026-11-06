# Koi

### Container services that belong on your LAN

Koi is an open-source host service for container/LAN developers and capable
homelab operators, especially on Windows and Linux. It connects container
lifecycle to local service discovery, names and health checks.

For services that need shared identity, [Certmesh](#private-space-identity-and-trust)
adds locally governed membership and certificates: establish trust within your
own private space, alongside the services Koi helps you find.

Add a label to a container, find its published endpoint from another machine,
and verify that the application opens. When the container changes or stops,
Koi reconciles the discovery and naming state. This is the initial adoption
focus; the [container guide](CONTAINERS.md) walks through the actual application
and lifecycle checks.

Koi runs locally without an account or hosted control plane. It can work alongside
Docker or Podman, an existing resolver, and an existing reverse proxy.

## Choose an artifact

| Channel | Version | Use |
| --- | --- | --- |
| Published stable | `0.9.0` | Existing stable installation; use its matching release documentation |
| Published prerelease | `1.0.0-rc.2` | Explicitly pinned prerelease with its own validation record |
| Repository source | `1.0.0-dev.0` | Development; not a published candidate or a stable release |

These docs describe current source unless a version is stated. A passing source
check does not establish a supported installed journey. See
[release readiness](docs/launch/README.md) for the chosen artifact, supported
environment and outstanding verification. See the [upgrade guide](docs/guides/upgrading.md)
before changing an existing installation.

Download a pinned archive from [GitHub Releases](https://github.com/sylin-org/koi/releases),
verify its accompanying checksum, and put the binary on your PATH. The
[installation guide](docs/guides/install-and-service.md) explains the checksum-verified
bootstrap scripts, version selection and service installation. npm and
package-manager scaffolds are not advertised as available installation paths.

## Try one container

With a suitable Koi binary and a running Docker engine:

```sh
koi version
koi --daemon
```

Leave the daemon running. In another terminal:

```sh
docker run -d --name koi-demo -p 8080:80 --label koi.announce=koi-demo nginx:alpine
koi mdns discover _http._tcp
koi dns lookup koi-demo
koi health status
```

HTTP examples use curl; in Windows PowerShell select curl.exe or
Invoke-RestMethod. Use a free host port if 8080 is occupied. The image is an example application,
not a pinned acceptance fixture. Confirm runtime access with
`curl -fsS http://127.0.0.1:5641/v1/runtime/status`; access to the Docker/Podman engine must be configured
for the account running the daemon.

From a second machine on the LAN, discover the service and open its actual
HTTP endpoint. Then stop/restart/recreate the container and check the application
and discovery state again. The [complete walkthrough](CONTAINERS.md) explains
these checks and cleanup.

A record in Koi's resolver does not automatically configure the other machine's
DNS. Use the discovered LAN address and port for the first check, then configure
[zone forwarding](docs/guides/dns-coexistence.md) before claiming the friendly
name works through the client's ordinary resolver.

<a id="works-with-your-stack"></a>

## What Koi contributes

| Task | Current capability | Limit to verify |
| --- | --- | --- |
| Publish a container service | Docker/Podman labels or announce environment variable drive mDNS, DNS and health state | A published port and runtime access are required; a running container is not proof the app is ready |
| Discover LAN services from an application | CLI, HTTP and Rust interfaces expose mDNS observations and events | The application must use Koi or an adapter; this is not transparent multicast for unmodified software |
| Keep names in an existing stack | Koi serves a local zone and exports records | Clients or an existing resolver must be configured to use that zone |
| Build a private trust space | Certmesh provides member enrollment, certificate renewal and signed membership/revocation information | Participating applications consume Koi's identity APIs and apply their own access rules |
| Add HTTPS | Trust-root tools and a TLS proxy use the chosen certificate | URL, certificate name and this client's trust must agree |
| Use exact service-name certificates | Grant and certificate primitives exist in source | The public grant/proxy and complete external ACME setup are unfinished |
| Observe and automate | HTTP/TCP health, events, Prometheus export and MCP | Observations have a location and freshness; they do not prove every client can connect |

The `koi.certmesh` container label records a request; it does not issue or
inject a workload certificate. Read the [secure-container limits](docs/guides/recipes/container-trusted-cert.md)
before combining labels with a TLS listener. Existing Caddy/Traefik deployments
can use selected integrations, but current ACME requires additional provider
and grant wiring; see the [ACME guide](docs/guides/acme.md).

## Private-space identity and trust

Certmesh lets you operate a private CA and decide which machines join your trust
group. Enroll members, renew their identities, distribute signed membership and
revocation information, and keep recovery material under your control. This is
useful when a homelab, small team or lab application needs a shared local identity
system without a hosted account or public certificate authority.

Koi-aware applications can verify a peer's certificate-backed identity or signed
messages and consume membership changes. The application chooses what that
identity may do. An ordinary browser or unmodified service still needs its own
TLS and access configuration; Koi's membership updates are enforced by consumers
that understand them.

Start with [Certmesh enrollment and operation](docs/guides/certmesh.md),
[backup and recovery](docs/guides/certmesh-ha-recovery.md), or
[embedding Certmesh](docs/guides/certmesh-embedded.md). The first container
walkthrough works without creating a CA; exact service-name HTTPS has the
separate setup boundary described above.

## Operate it

The foreground daemon is useful for evaluation. For persistent use, follow
[install and service management](docs/guides/install-and-service.md).
`koi install` needs the platform's required elevation.

The management HTTP API binds to loopback by default. Reads have differing
authorization requirements and mutations require authentication. Containers
using HTTP on native Linux need deliberate bridge exposure and credentials.
Use the [security model](docs/reference/security-model.md) and
[API authentication guide](docs/guides/api-authentication.md).

```sh
koi status
koi launch
koi mdns
koi mdns announce?
```

The CLI and HTTP API are sufficient for the initial supported journey.
`koi launch` opens Koi's built-in interface (Services, mDNS, Certmesh, Settings,
About), the same presentation the desktop app renders; it does not substitute
for verifying the application from a second machine.

## Documentation and development

- [Getting started](docs/tutorials/getting-started.md): choose an artifact and establish a usable endpoint.
- [Container guide](CONTAINERS.md): publication, second-machine access, lifecycle and application-side discovery.
- [User guide](GUIDE.md): daily operation and where to investigate failures.
- [Documentation index](docs/index.md): DNS, TLS, integration and advanced guides.
- [Contributing](CONTRIBUTING.md): development and validation.
- [Adoption decision](docs/adr/046-container-lan-adoption.md): scope and priorities.
- [Release readiness](docs/launch/README.md): evidence required for public claims.

Building current source requires [Rust](https://rustup.rs/) 1.92 or later:

```sh
cargo build --release --locked
```

Source and packaged versions can differ. Report the exact version, installation
method, OS/runtime, expected result and failing step when reporting a problem;
omit tokens, private keys and private network inventory.

Koi is licensed under Apache-2.0 OR MIT.
