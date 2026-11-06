# Embedded Rust interface

`koi-embedded` provides a Builder, typed domain handles and shared lifecycle ownership for applications that need selected capabilities in process.

## Use and verify

Use complete examples and feature definitions from the crate and [embedded guide](../../guides/embedded.md). Start application listeners before announcing their endpoints and retain shutdown ownership.

## Boundaries

Embedding retains host port/provider/trust requirements. It is not necessary for the initial installed-service container journey. Unit tests of an embedded host do not certify an installed native service.

See [the capability guide](../../guides/embedded.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
