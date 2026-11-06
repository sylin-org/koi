# Verify HTTPS for a host member name

This advanced manual path uses a host's certmesh identity for an application
already reachable on the LAN. It does not automatically issue a certificate for
an arbitrary container name.

Complete the [container application check](../../CONTAINERS.md) first.
HTTPS does not gate that initial trial. See [release readiness](../launch/README.md)
for accepted artifacts and client combinations; this procedure does not establish
a new trusted-service preview.

## Prerequisites

- A daemon on the application host and a known HTTP backend, for example
  `127.0.0.1:3000`.
- A certmesh CA on that host or another reachable daemon.
- A separate client where the intended resolver and root source can be configured.
- Matching artifact documentation for [certmesh](../guides/certmesh.md),
  [proxy](../guides/proxy.md) and [security](../reference/security-model.md).

Use an existing service's normal lifecycle; do not start a second daemon.

## Create or join the CA

On the intended CA host:

```sh
koi certmesh create --profile just-me
koi certmesh status
```

Creation is interactive, including passphrase and TOTP setup. Understand custody,
unlock and recovery before relying on it. The just-me profile permits enrollment
without an approval queue; choose a different policy when needed.

If the application host is separate, enroll using the supported invitation or
interactive join procedure:

```sh
koi certmesh join
koi certmesh status --json
```

Discovery alone does not authorize enrollment. The [certmesh guide](../guides/certmesh.md)
covers endpoint selection, invites and locked-CA recovery.

Inspect the application's host certificate SANs in the actual status. Current
default-zone issuance uses its hostname and configured-zone FQDN; persisted or
older certificates can differ. Do not assume localhost or a vanity name is covered.

## Configure the matching name and listener

Use a real SAN. On the resolver host, add the application's LAN address if the
needed record is absent:

```sh
koi dns add host-b 192.0.2.20
koi dns lookup host-b
```

Replace the documentation name/address. Configure the client's
[resolver or forwarding](../guides/dns-coexistence.md), then test its ordinary
lookup. A Koi lookup alone is not this test.

On the application host:

```sh
koi proxy add app --listen 9443 --backend 127.0.0.1:3000
koi proxy status
```

Verify the listener is running with the intended identity. A self-signed fallback
is not successful trusted setup. Proxy state does not prove client reachability.

## Configure the actual client

On the CA host:

```sh
koi trust export --ca > koi-root.pem
```

Transfer the public root through a channel you control and verify its identity
through the intended bootstrap process. On a client with Koi:

```sh
koi trust install ./koi-root.pem
koi trust list
```

Root installation can require elevation. Without Koi, use the platform's own
root-installation mechanism. Some browsers/runtimes use another root source;
configure and test the actual client. See [root trust](../guides/trust.md).

## Verify without bypasses

From the client, use the exact certificate name and listener port:

```sh
curl -v https://host-b.internal:9443/
```

On Windows select the intended curl executable or native HTTP client. Verify the
application response, name and chain without an insecure flag or trust exception.
Then open the same URL in the intended browser and test it separately.

Record the artifact, OS/browser/runtime, DNS result, certificate fingerprint and
expiry, and actual application response. A successful curl build does not certify
another client's trust source.

For continued use, verify renewal and the application after daemon restart.
Keep [CA recovery](../guides/certmesh-ha-recovery.md) available.

## A service name such as app.internal

A container label does not add app.internal to the host certificate. Development
source implements exact service-name grants and leaf lifecycle primitives, but
the public grant/listener operation is incomplete. ACME also requires an
account-bound grant and provider wiring.

Read [container TLS](../guides/recipes/container-trusted-cert.md) and
[ACME](../guides/acme.md). Do not apply an older “any in-zone name” recipe to
current source or modify private state to bypass a missing public workflow.

## Remove the trial

Remove only the listener created for this trial:

```sh
koi proxy remove app
```

Remove trial static DNS entries through the DNS command, and remove a trial root
by its actual tracked name only when no remaining service depends on it.
Destroying a shared CA is not routine trial cleanup.
