# ACME issuance reference

Koi includes an ACME server on a separate TLS listener. `koi certmesh acme status` reports its state; `koi certmesh acme enable` prints connection information rather than starting a new server.

## Use and verify

A client needs P-256 account keys, trust in the private root, a dns-01 provider that writes/clears Koi TXT records, and an exact account-bound service-name grant.

## Boundaries

Orders accept one authorized nonwildcard service name. Public creation/wiring of service grants is incomplete, so these protocol capabilities are not a certified stock-Caddy/Traefik workflow. Certification of one existing-tool integration is tracked by the launch gate.

See [the capability guide](../../guides/acme.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
