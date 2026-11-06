# koi-dashboard

Snapshot/SSE and lazy mDNS browser adapters over composition-owned state.

The crate owns no product HTML. `koi-ui` is the sole presentation owner; these
adapters supply current observations to it and to documented data clients.
Network browsing is lazy and shared. A visible catalog entry is evidence of
observation, not a guarantee that its application is reachable from another device.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-dashboard --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
