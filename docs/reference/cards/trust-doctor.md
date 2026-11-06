# Trust diagnosis

Run `koi trust diagnose` to combine certificate identity findings with the OS Trust domain's state. Check the reported causes and remedies.

## Use and verify

A red result exits unsuccessfully; warnings require attention but are not the same as red. Re-run diagnosis after applying a relevant remedy and verify the intended client application separately.

## Boundaries

A trusted root on the host does not prove that a browser, container image or language runtime reads that root store. Diagnose reports local/Koi state, not universal client trust.

See [the capability guide](../../guides/trust.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
