# Koi user guide

Use Koi to publish and find container services on a LAN, then verify that the
application remains usable through changes. Start with a single host and a second
client. Add DNS forwarding or HTTPS after that path works.

The [release-readiness page](docs/launch/README.md) identifies the artifact and
environment supported by each claim. Stable 0.9.0, prerelease 1.0.0-rc.2 and source
1.0.0-dev.0 are distinct. Use matching documentation for an installed release.

## Start with the application

Follow [getting started](docs/tutorials/getting-started.md) and the
[container walkthrough](CONTAINERS.md). A successful trial establishes:

1. The application responds through its published host port.
2. Koi observes the opted-in container and publishes the expected endpoint.
3. An independent client discovers the endpoint and opens the real application.
4. Stop, restart and recreation produce the expected application and discovery changes.
5. Cleanup removes the trial container and its derived Koi state.

A discovered endpoint is an observation. Check the app from the client that will
use it. A TCP health check proves a connection from the checking host; it does not
prove an HTTP response, client DNS or TLS trust.

## Use the CLI

```sh
koi version
koi status
curl -fsS http://127.0.0.1:5641/v1/runtime/status
koi mdns discover _http._tcp
koi health status
koi dns list
```

Commands use `koi <domain> <verb>`. A domain without a verb presents its
commands and examples; a command followed by `?` presents detailed help.
Use `--json` where supported for integrations, and `-v` or `-vv` for diagnostics.

Normal commands use the running local service. `--endpoint URL` selects an
explicit daemon. `koi --daemon` starts a foreground daemon; bare
`koi` shows status and help, not a new service.
`koi --standalone mdns discover` is an explicit one-shot option when no
local service owns the operation. Do not run a second Koi beside an installed service.

## Keep it running

Use [install and service management](docs/guides/install-and-service.md) for the
supported SCM, systemd, OpenRC or launchd setup. Confirm the actual account,
engine-socket access, executable and configuration used by the service. A daemon
started in your terminal may have different access than the installed service.

`koi status` reports observed domain state. A disabled or unavailable
capability is not an empty healthy inventory. Use the corresponding domain's
status and the service log to investigate.

## Give the endpoint a name

```sh
koi dns add app 192.0.2.10
koi dns lookup app
koi dns list
```

Replace the documentation address with the application's real LAN address.
`koi dns lookup` queries Koi. For a browser on another machine to use
`app.internal`, configure its resolver or delegate the zone from your
existing DNS server. Test with that client's ordinary resolver and then its browser.

[DNS](docs/guides/dns.md) describes record precedence and configuration;
[DNS coexistence](docs/guides/dns-coexistence.md) covers forwarding and exports.
Removing a forwarding rule ends resolution through Koi; account for applications
that depend on those names when changing it.

## Establish private-space identity and trust

Use [Certmesh](docs/guides/certmesh.md) when machines and participating applications
need identities governed by your own CA. Enroll members, renew certificates,
distribute signed membership changes and maintain [recovery material](docs/guides/certmesh-ha-recovery.md).
Applications can [consume those identities](docs/guides/certmesh-embedded.md) and
apply their own access rules. A first container discovery trial needs no CA.

## Add HTTPS deliberately

Use [trusted HTTPS](docs/tutorials/trusted-https.md) for an existing host member
name and a known application. Verify the actual certificate SAN, chain, expiry,
client trust and URL.

Container labels do not finish exact service-name certificate setup. The
[container TLS guide](docs/guides/recipes/container-trusted-cert.md) distinguishes
the host member certificate from a certificate for `app.internal`.
The [ACME guide](docs/guides/acme.md) states the current public workflow gap.

A private CA is optional. Keep an existing proxy or certificate authority when
it already solves your task.

## Integrate an application

Applications inside containers can use Koi's HTTP API for discovery and lifecycle
events. Native Linux bridge access needs an explicit bind and appropriate token
handling; changing the bind does not change authorization. Start with
[containers](CONTAINERS.md) and [API authentication](docs/guides/api-authentication.md).

Further options:

| Need | Guide |
| --- | --- |
| Export targets to monitoring or consume selected labels | [Integrations](docs/guides/integrations.md) |
| Discover and announce programmatically | [mDNS](docs/guides/mdns.md) |
| Check an endpoint from the Koi host | [Health](docs/guides/health.md) |
| Expose discovery to an agent | [MCP](docs/guides/mcp.md) |
| Use a host UDP socket through HTTP/SSE | [UDP](docs/guides/udp.md) |
| Run Koi inside a Rust application | [Embedding](docs/guides/embedded.md) |
| Operate a private CA or recover it | [Certmesh](docs/guides/certmesh.md), [recovery](docs/guides/certmesh-ha-recovery.md) |

## Diagnose the failing step

- No runtime instance: check engine availability, socket permissions and opt-in metadata.
- No discovered record: check publication state, interface, multicast reach and peer observation.
- Record exists but the app fails: test the published port and application readiness from that client.
- IP works but name fails: verify the client's resolver path.
- HTTPS fails: inspect URL/SAN match, issuer, expiry and the client's root source.

Use [troubleshooting](docs/guides/troubleshooting.md) for commands and
[security boundaries](docs/reference/security-model.md) before exposing an API.
The [documentation index](docs/index.md) contains the full reference.
