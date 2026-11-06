# Start with one usable container service

Use Koi to publish a container service, find and open its application from a
second machine, and verify stop/recreate behavior. This tutorial establishes
the host setup and directs you through that full check.

No account or hosted control plane is required. The target operator is comfortable
with containers and basic LAN configuration. No measured setup time or already
accepted new preview is implied.

## Select an artifact

Read [release readiness](../launch/README.md) for a named artifact and supported
scenario. Stable 0.9.0, prerelease 1.0.0-rc.2 and source 1.0.0-dev.0 are distinct.
Current-source commands below should not be assumed available in an older release.

The [installation guide](../guides/install-and-service.md) covers downloads,
checksums and service setup. Bootstrap scripts choose the latest stable release
unless a version is supplied. They install the binary; service startup is a
separate step.

```sh
koi version
```

Record the version, artifact/checksum, OS, engine version and client machine.

## Establish the daemon

If a local Koi service already runs, inspect it:

```sh
koi status
```

Otherwise start a foreground daemon and leave it running:

```sh
koi --daemon
```

Management HTTP defaults to loopback port 5641. DNS can require privileges or
coexistence configuration. Read observed status and
[troubleshooting](../guides/troubleshooting.md); do not silently replace an
existing resolver.

Use [service installation](../guides/install-and-service.md) when evaluating
persistent startup and recovery. Do not start a second daemon beside it.

## Verify runtime access

In another terminal:

```sh
curl -fsS http://127.0.0.1:5641/v1/runtime/status
curl -fsS http://127.0.0.1:5641/v1/runtime/instances
```

Koi's running account must reach the Docker/Podman engine. An unavailable engine
is not an empty healthy inventory. Resolve account/socket access first.

## Complete the container trial

Follow [Publish and use a container service on your LAN](../../CONTAINERS.md)
through application startup, independent discovery/access, stop, restart,
recreation and cleanup.

Initial target environments are Windows x64 with Docker Desktop and Linux glibc
x64 with Docker Engine, paired with native clients. They require separate
artifact-specific results. Other implementations do not inherit this proof.

The meaningful result is the application being usable. A Koi row, DNS lookup or
screenshot alone is insufficient. CLI and HTTP are enough for this first task;
a broader workbench redesign is not a prerequisite.

## Optional: discover existing services

With a local daemon:

```sh
koi mdns discover _http._tcp
```

With no local service:

```sh
koi --standalone mdns discover _http._tcp
```

This reveals matching announcements, not every application, tested endpoint or
trusted identity on the LAN. `koi launch` opens Koi's interface;
[Find and open a service](home.md) covers search, details and Open in Services.

## Add names and trust after access works

- Configure [DNS forwarding](../guides/dns-coexistence.md) and test the client's ordinary lookup.
- Use [host-member HTTPS](trusted-https.md) if that exact certificate name meets the need.
- Read [container-name TLS limits](../guides/recipes/container-trusted-cert.md) before promising a vanity HTTPS URL.
- Keep existing resolver, proxy and certificate tools where they already work.

Report the failing step, version and expected/actual result without tokens,
private keys or private device inventories.
