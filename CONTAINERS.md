# Publish and use a container service on your LAN

Koi runs on the container host. It observes opted-in Docker/Podman workloads
and derives mDNS announcements, local DNS records and health checks from their
published endpoints. Applications can also use its HTTP API to discover LAN services.

The first adoption outcome is a container application that a second machine can
find and open, with correct behavior when the container stops or is recreated.
This procedure is not a claim that a new operator preview has passed.
Check [release readiness](docs/launch/README.md) for the exact artifact and accepted
environment.

The initial target scenarios are Windows x64 with Docker Desktop and Linux glibc
x64 with Docker Engine, using independent native clients. Podman and other
platform implementations remain available; each needs its own journey evidence.

## Prerequisites

- Choose an artifact and matching documentation: stable 0.9.0, prerelease
  1.0.0-rc.2 and source 1.0.0-dev.0 are different lines.
- Run Koi on the host, where its running account can reach the engine and LAN.
- Use a published host port reachable by the second machine.
- Use a network permitting the required multicast and application traffic.
  Discovery across VLANs or isolated Wi-Fi is not automatic.
- Preserve an existing Koi installation. Use its normal controls instead of
  starting a second daemon beside it.

A Koi container behind NAT is not equivalent to the host-service architecture.
Publishing port 5641 alone does not forward LAN multicast.
See [installation](docs/guides/install-and-service.md).

## 1. Verify the daemon and runtime

If no Koi service already exists, run:

```sh
koi version
koi --daemon
```

Leave it running. In another terminal:

```sh
koi status
curl -fsS http://127.0.0.1:5641/v1/runtime/status
curl -fsS http://127.0.0.1:5641/v1/runtime/instances
```

HTTP examples use curl; in Windows PowerShell use curl.exe or Invoke-RestMethod.
They target the default local port; use the observed endpoint when it differs.

The account running Koi needs engine access. An installed system service may not
share your terminal's access to a user-owned or rootless socket. Resolve that
before treating an empty inventory as a discovery problem.
[Runtime configuration](docs/guides/runtime.md) covers engine selection.

For this label-driven path, containers do not need Koi HTTP credentials. The
host daemon reads the runtime and owns the derived resources.

## 2. Run one known HTTP application

Use a free port and a distinct container name. The image below is illustrative;
acceptance must record an exact image digest.

```sh
docker run -d --name koi-demo -p 8080:80 --label koi.announce=koi-demo --label koi.health.path=/ nginx:alpine
```

Equivalent Compose configuration:

```yaml
services:
  demo:
    image: nginx:alpine
    ports:
      - "8080:80"
    labels:
      koi.announce: koi-demo
      koi.health.path: /
```

Use one example, not both. An environment variable can replace the announce label:

```yaml
environment:
  KOI_MDNS_ANNOUNCE: koi-demo
```

Confirm the application responds at `http://127.0.0.1:8080/` on the host.
A container's running state does not establish HTTP readiness.

## 3. Inspect Koi's observations

```sh
curl -fsS http://127.0.0.1:5641/v1/runtime/instances
koi mdns discover _http._tcp
koi dns lookup koi-demo
koi health status
```

Check the correct published port and a LAN address the other machine can reach.
A Docker bridge, VPN-only or loopback address is not interchangeable with that
LAN address.

The shorthand derives `koi-demo.internal` in the default Koi zone.
The lookup above verifies Koi's answer, not another client's resolver setup.
The health check runs from the Koi host and has a freshness window.

## 4. Open the actual app from another machine

On a second machine with a running local Koi service:

```sh
koi mdns discover _http._tcp
```

With only a binary and no local Koi service:

```sh
koi --standalone mdns discover _http._tcp
```

Another DNS-SD browser can also inspect the announcement. Locate the demo and
open `http://<host-lan-ip>:8080/` using its observed address; replace the
placeholder. Success is the actual application response, not a service row.

Once IP access works, configure [zone forwarding](docs/guides/dns-coexistence.md)
through the client's existing resolver. Check that client's ordinary DNS answer
and then open `http://koi-demo.internal:8080/`. Koi does not install
resolver rules on every other machine.

## 5. Check lifecycle and cleanup

Stop the trial container:

```sh
docker stop koi-demo
```

Verify the application no longer answers and observe withdrawal of the derived
announcement, DNS record and health check. Discovery clients may retain caches
until withdrawal or expiry; record the client and timing.

Restart it:

```sh
docker start koi-demo
```

Wait for application readiness, rediscover it from the second machine and open it
again. Recreate the trial container:

```sh
docker rm -f koi-demo
docker run -d --name koi-demo -p 8080:80 --label koi.announce=koi-demo --label koi.health.path=/ nginx:alpine
```

Check the new instance does not leave duplicate announcements or old derived
resources. Finally remove only the trial container:

```sh
docker rm -f koi-demo
```

For Compose, use its own stop/up/down lifecycle. Retain pre-existing Koi state and
unrelated workloads. Before claiming a supported persistent setup, also verify
the chosen daemon restart and runtime reconnect recovery.

## Diagnose by layer

| Observation | Next check |
| --- | --- |
| App fails on the host | Container logs, startup and published port |
| App works, no runtime instance | Engine connection, running account and selected backend |
| Instance exists, not opted in | Label/env spelling, explicit disable and scope |
| Publication visible only locally | LAN interface, multicast/firewall and peer discovery |
| Peer discovers but cannot open | Advertised address, published port, firewall and readiness |
| IP works but name fails | Client resolver and forwarding |
| HTTPS warns | URL/SAN, chain, expiry and the intended client's root source |

[Troubleshooting](docs/guides/troubleshooting.md) provides more detail. Do not use
a TLS verification bypass to declare a trusted path successful.

## A container discovers LAN services through HTTP

This is a separate integration requiring an application using Koi or an adapter.
It does not transparently replace native multicast calls in unmodified software.

HTTP defaults to loopback. Docker Desktop supplies a
`host.docker.internal` route; verify it on the target installation.
On native Linux, make the API reachable deliberately:

```sh
koi --daemon --http-bind bridge
```

Configure an existing service through its own controls instead of starting a
second daemon. Use the actual bridge gateway or host mapping; rootless engines
and custom networks may differ. A bridge bind is narrower than a wildcard LAN bind.

On the host, write a token file in an operator-owned location:

```sh
koi token write /path/owned-by-you/koi-token
```

Mount it read-only as a secret using suitable platform permissions. Read it at
runtime, not from the image. Refresh the secret when the daemon token changes.
In a POSIX container, after setting KOI_HOST to the verified host endpoint:

```sh
TOKEN=$(cat /run/secrets/koi_token)
curl -fsS "http://$KOI_HOST:5641/healthz"
curl -N -H "x-koi-token: $TOKEN" "http://$KOI_HOST:5641/v1/mdns/discover?type=_http._tcp"
```

Non-loopback inventory and sensitive reads require authentication. A token does
not encrypt plaintext HTTP. [API authentication](docs/guides/api-authentication.md)
defines route rules. [mDNS](docs/guides/mdns.md) covers announcement, events,
heartbeat and removal. [UDP relay](docs/guides/recipes/container-udp.md) is an
explicit socket interface for participating applications.

## Trusted service names are a separate extension

Keep an existing proxy and certificates when they meet the need.
`koi.proxy.port` adds a listener, not proof of a matching trusted URL.
`koi.certmesh` records intent and does not issue or inject a workload
certificate. Exact service-name primitives exist in development source; public
grant/listener and client setup are incomplete.

See [container TLS](docs/guides/recipes/container-trusted-cert.md),
[host-member HTTPS](docs/tutorials/trusted-https.md) and
[ACME limits](docs/guides/acme.md). A trusted-service extension must prove the
intended client's trust, renewal and recovery.

## Further configuration

[Runtime labels](docs/guides/runtime.md) ·
[Existing-tool integrations](docs/guides/integrations.md) ·
[DNS forwarding](docs/guides/dns-coexistence.md) ·
[Security model](docs/reference/security-model.md)
