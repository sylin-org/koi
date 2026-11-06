# Install and verify

Select an available release artifact and its verification instructions from [launch readiness](../../launch/README.md) and the [installation guide](../../guides/install-and-service.md). Record the source revision/version and artifact hash.

## Use and verify

After installation, confirm the native service is healthy and that exactly one intended Koi instance owns its paths/listeners. Then run the actual container/second-device journey.

## Boundaries

Checksums establish artifact integrity relative to the expected checksum; attestations establish build provenance. Neither establishes application behavior. Package-manager source files do not prove a package is published, and an archive for an OS is not proof of that OS's full journey.

See [the capability guide](../../guides/install-and-service.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
