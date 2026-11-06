# Local DNS names

Koi's local zone defaults to `internal`. `koi dns add demo 192.168.1.42` creates a static address record; substitute the application's real reachable address.

## Use and verify

Configure the client resolver or a conditional forwarder for the zone, then resolve `demo.internal` from the second device. Preserve existing DNS ownership for other names.

## Boundaries

A record does not install resolver configuration on every device, authorize a certificate, open a firewall or create a route. Runtime-derived records and static records have distinct ownership.

See [the capability guide](../../guides/dns.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
