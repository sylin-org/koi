# koi-dns

Local DNS domain serving the configured zone, default `internal`, with persistent static entries and transient derived records. The resolver supports controlled upstream resolution and bounded per-client/global query admission.

Clients must actually route the zone to Koi. A record existing in Koi is not proof that another device can resolve it. Keep an existing resolver and delegate the zone where appropriate; Koi does not provide remote network connectivity.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-dns --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
