# winget packaging

This directory documents the prospective winget channel. Check [launch readiness](../../docs/launch/README.md) before treating it as available. A generated manifest or a repository recipe is not a published package.

Use the exact Windows release artifact and its verified SHA-256 to generate manifests with winget's current authoring tools. Select installer/portable metadata that matches the actual artifact; do not describe an archive as a service installer or assume signing/SmartScreen reputation.

Validate the candidate through the package manager, submit through its normal review process and retain the public submission/release identity. A service-installing workflow must preserve Koi's operator, token, native service and rollback contracts.

Before advertising the channel, perform a clean install from its published entry point, verify the expected executable/version and one intended native service, then run the container/second-device application and stop/recreate checks. Record results in [the launch ledger](../../fleet/launch/LEDGER.md). Package-manager validation alone does not certify that journey.
