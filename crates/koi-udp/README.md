# koi-udp

Leased host UDP sockets exposed through Koi's HTTP/SSE interface. Containers that can reach the API can bind, receive, send, renew and release datagram bindings without owning the host socket directly.

All UDP API reads and writes require the daemon token. Bind/send policies default to loopback and reject prohibited destinations. This does not create a general multicast reflector or a cross-subnet tunnel.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-udp --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
