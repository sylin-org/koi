# Certmesh enrollment

An authority can mint a hostname-bound, expiring, single-use invitation with `koi certmesh invite HOSTNAME`. A joining host uses `koi certmesh join ENDPOINT --invite TOKEN` through its local running daemon.

## Use and verify

The joiner generates and retains its private key locally. Pin the authority identity from the trusted invitation/bootstrap process; the authority signs a CSR. Enrollment policy and approval requirements still apply.

## Boundaries

Enrollment creates a host/client mesh identity, not automatic service-name authorization. Revocation is enforced at Koi-aware boundaries; ordinary TLS clients can retain acceptance until the leaf expires. Do not log or commit invitation tokens.

See [the capability guide](../../guides/certmesh.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
