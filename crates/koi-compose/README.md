# koi-compose

Composition root shared by the command-line daemon, installed service and embedded host. It constructs domain cores, installs typed bridges, maintains coherent product/catalog projections and owns background work and ordered shutdown.

Runtime reconciliation maps accepted container state into mDNS, DNS, health and proxy desire. Certificate issuance is not implied by the `koi.certmesh` label.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-compose --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
