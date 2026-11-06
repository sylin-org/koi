# koi-config

Configuration discovery, data-root conventions and endpoint/breadcrumb support for Koi's daemon and clients.

Configuration roots and a discovered endpoint are different concerns. An installed service can grant its recorded local operator access through authenticated local IPC without making its token file public.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-config --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
