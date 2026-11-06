# Derive discovery and names from container lifecycle

Koi observes Docker/Podman inventory and derives resources for opted-in
containers. The first task is [publish, open from a second machine and verify
recreation](../../CONTAINERS.md). Current source behavior is described here;
[release readiness](../launch/README.md) identifies accepted artifacts.

The runtime domain is configured by daemon options and inspected through HTTP.
There is no separate koi runtime CLI command.

## Inspect the engine connection

```sh
koi status
curl -fsS http://127.0.0.1:5641/v1/runtime/status
curl -fsS http://127.0.0.1:5641/v1/runtime/instances
```

These examples use the default local HTTP port. In Windows PowerShell, select
curl.exe rather than an alias, or use Invoke-RestMethod. Adjust the endpoint if
the installed service uses another port.

The account running Koi must access the engine socket. A terminal user and
system service can have different permissions, particularly with rootless Podman
or Docker Desktop. A retained inventory with an unavailable source is not
current proof of running applications.

## Choose the backend

Accepted names are auto, docker and podman. Other values are rejected.

```sh
koi --daemon --runtime docker
koi --daemon --runtime podman
```

Use one configuration appropriate to the host. Apply it through the installed
service if one exists. The Docker backend uses its platform socket/named pipe;
Podman uses its Docker-compatible API. Do not assume a default socket belongs
to the service account.

--no-runtime disables observation. Runtime is opt-in for embedded consumers;
daemon defaults do not establish a suitable engine for every installation.

## Opt in one application

```yaml
services:
  app:
    image: nginx:alpine
    ports:
      - "8080:80"
    labels:
      koi.announce: app
      koi.health.path: /
```

An environment variable can supply the same shorthand:

```yaml
environment:
  KOI_MDNS_ANNOUNCE: app
```

The shorthand sets name, DNS name and enable metadata. Explicit koi.* values
override shorthand/derived values. Explicit koi.enable=false opts out.
Selected Traefik/Caddy labels can also contribute metadata; see
[integrations](integrations.md). Inspect the resulting inventory rather than
assuming support for every routing expression.

Use a published TCP port. Port/protocol heuristics are metadata guesses, not
a successful request to the application. Supply an HTTP health path for a known
web service and verify actual readiness.

## Label reference

| Label | Purpose |
| --- | --- |
| koi.announce | Shorthand name/DNS-name/enable |
| koi.enable | Explicit opt in/out |
| koi.type | DNS-SD service type |
| koi.name | Display/service name |
| koi.dns.name | DNS name in the configured zone |
| koi.txt.* | TXT metadata |
| koi.health.path | HTTP health path |
| koi.health.kind | Explicit http or tcp check |
| koi.health.interval | Poll interval, default 30 seconds |
| koi.health.timeout | Timeout, default 5 seconds |
| koi.proxy.port | Host TLS listener port |
| koi.proxy.remote | Permit a non-loopback plaintext backend |
| koi.certmesh | Request metadata only; no workload certificate issuance/injection |
| koi.scope | Limit derivation to the corresponding configured daemon scope |

Without scope, the base daemon handles its eligible unscoped containers.
A scoped daemon only derives its matching scope. Scope is not a mechanism for
running multiple conflicting installed services or bypassing authority.

Compose service/project metadata helps derive readable names. Multiple published
ports, loopback-only bindings and address conflicts require inspection; do not
present every port as a working HTTP launch destination.

## Lifecycle and reconciliation

Runtime publishes an authoritative snapshot. The composition layer subscribes
before reading initial state, reconciles existing containers, retries incomplete
derived applications and removes resource sets no longer desired.

It maintains mDNS registrations, DNS records, health checks and optional proxy
entries. Those domains own their listeners and persistent/runtime state;
container metadata does not directly edit their private files.

While the watcher is running, waiting temporarily or stopping, the retained
inventory can remain actionable. Once observably stopped/failed or before a fresh
generation is reconciled, the inventory is diagnostic history rather than current
network desire. Reconnection reconciles the engine inventory, not just the next
event. Verify this behavior for the selected installed artifact.

A container running state is separate from application readiness. A daemon-host
check is separate from second-client access. A client may cache discovery records
after withdrawal; record timing and actual application behavior.

## Verify changes and removal

Follow the [container walkthrough](../../CONTAINERS.md) for stop/start/recreate
and cleanup. Inspect:

- App response on the host and second client.
- Correct address and published port in the peer announcement.
- Current resolver answer and client resolver path.
- Readiness transitions and freshness.
- No duplicate or orphaned derived resources after replacement.
- Recovery after the chosen engine reconnect and Koi restart.

Do not manually remove a runtime-owned DNS/proxy resource while expecting
reconciliation to preserve that removal. Change the owning container metadata
or stop/remove that workload.

## TLS and existing tools

A proxy label does not produce a matching trusted service certificate.
The current exact service-name public setup is incomplete. Keep a working
external proxy/CA when it already meets the task, and read
[container TLS](recipes/container-trusted-cert.md) before adding this extension.

## HTTP contract

| Route | Purpose |
| --- | --- |
| GET /v1/runtime/status | Revisioned watcher state and normalized inventory |
| GET /v1/runtime/instances | Tracked instance details |

Use observed state and freshness with the revision. A process-local revision
is not a durable engine cursor. Non-loopback reads need appropriate credentials;
see [API authentication](api-authentication.md).
