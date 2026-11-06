# TLS proxy

Koi's proxy terminates TLS and forwards bytes to a configured backend. `koi proxy status` reports the actual listener and certificate state.

## Use and verify

Check the listen port, backend permission, certificate source and exact SAN before testing from another device. Renewed/replaced material is selected for subsequent handshakes.

## Boundaries

There is no HTTP path router or header rewriting. A self-signed fallback or a host certificate can start TLS without meeting the intended service-name/browser-trust requirement.

See [the capability guide](../../guides/proxy.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
