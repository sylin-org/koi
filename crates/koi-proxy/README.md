# koi-proxy

TLS termination followed by bidirectional byte forwarding to a configured backend. It supports certificate replacement for subsequent handshakes and reports actual listener state.

There is no HTTP routing layer. Backend reachability is separately validated; remote backends require explicit permission. Certificate selection can use a Proxy-owned override, supplied Certmesh identity or a self-signed fallback. A running TLS listener does not imply that its certificate covers the service name or is trusted on the client.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-proxy --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
