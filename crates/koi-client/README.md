# koi-client

Blocking Rust HTTP client for an existing Koi daemon, used by the CLI and other synchronous callers. Async applications should keep blocking calls off their executor threads.

Use the daemon's current OpenAPI document for exact payloads. Explicit remote endpoints do not inherit the local daemon token.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-client --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
