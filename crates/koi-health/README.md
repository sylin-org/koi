# koi-health

HTTP/TCP service checks, transition events and machine-health projections for Koi's known participants.

Health provides operational evidence for a target from the probing host. A successful local probe does not establish second-device reachability, hostname resolution or browser trust. Checks and lifecycle state remain authoritative in this domain.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-health --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
