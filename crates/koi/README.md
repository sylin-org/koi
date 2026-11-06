# koi-net

The `koi-net` package builds the `koi` command and host service. Koi helps container/LAN developers and capable homelab operators expose a labeled application's reachable host endpoint, discover it from another device, and keep that view accurate when the container stops or is recreated.

The daemon coordinates optional DNS, health, proxy, certificate and UDP capabilities. Their presence does not certify an end-to-end user journey.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-net --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.

## Commands

```sh
koi --daemon
koi status
koi mdns discover _http._tcp
koi mdns announce "My App" _http._tcp 8080
```

Run the daemon command in its own terminal; the following commands address the installed/running service. Bare `koi` shows status and command discovery. For an intentional daemon-free session when no local service is active, use `koi --standalone mdns discover`. Installation choices are in the [service guide](../../docs/guides/install-and-service.md).
