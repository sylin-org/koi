# Container discovery and lifecycle

Run Koi on the container host with access to its Docker/Podman runtime. Opt a container in with `koi.enable=true`; set `koi.name=demo` for a useful display name. Koi derives records from its observed host port mappings.

## Use and verify

Start with a published application port reachable on the LAN. From a second physical device, discover the service and request the actual application's response. Stop the container, observe withdrawal, then recreate it and verify the replacement endpoint.

## Boundaries

A label is metadata, not connectivity. A host-only binding, firewall, guest isolation or unreachable container address still blocks the application. `koi.certmesh=true` does not issue/inject an identity. Existing runtime integration is source-backed; the exact certified scenarios are in the launch matrix.

See [the capability guide](../../guides/runtime.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
