# Health observations

Run `koi health status` for service checks and derived machine state. HTTP checks probe the configured URL; TCP checks verify a connection. State changes feed status and events.

## Use and verify

For the adoption journey, compare the host probe with a real request from the second device, including the expected application body or marker.

## Boundaries

A local successful check does not prove remote reachability, name resolution or trust. Discovery age is an observation signal rather than a full machine-monitoring guarantee.

See [the capability guide](../../guides/health.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
