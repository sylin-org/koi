# koi-common

Shared contracts and low-level primitives used by Koi domains and adapters: identifiers, service/catalog types, protocol payloads, errors, status feeds, lifecycle support, persistence and ceremony types.

Keep shared contracts independent of concrete providers. Cross-domain ports belong here when required; orchestration belongs in `koi-compose`.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-common --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
