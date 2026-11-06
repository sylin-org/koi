# CLI reference

The binary is `koi`; its Cargo package is `koi-net`. Bare `koi` shows live status and the command catalog. `koi <domain>` and `koi --help` expose command help. Exact flags come from [cli.rs](../../crates/koi/src/cli.rs) for the running source/version.

## Execution modes

| Command/option | Meaning |
| --- | --- |
| `koi --daemon` | Run the host daemon in the foreground |
| `koi install` | Install/start through the platform service workflow; elevation/operator selection can be required |
| `koi status` | Read the selected daemon's accepted state |
| `--endpoint URL --token TOKEN` | Select and authenticate an explicit daemon |
| `--standalone` | Intentional one-shot local composition when no local service is active |
| `--json` | Machine-readable output; streams use their documented framing |

Normal commands use the healthy local service. An explicit remote endpoint does not inherit the local token. `--standalone` is not a parallel-daemon workaround for a broken installed service.

## Container/LAN workflow

Configure runtime observation with `--runtime auto|docker|podman` (environment `KOI_RUNTIME`). Runtime labels opt in the application and select metadata; use the [runtime guide](../guides/runtime.md) for the complete fixture. Verify the published application from a second device, then stop/recreate it. The current scenario matrix is in [launch readiness](../launch/README.md).

```sh
koi mdns discover _http._tcp
koi mdns subscribe _http._tcp
koi mdns announce "My App" _http._tcp 8080
koi mdns resolve "My App._http._tcp.local."
koi mdns unregister ID
```

`announce` takes positional name, service type and port. The application must already listen on the advertised endpoint. Registration lifetime is described in the [wire protocol](wire-protocol.md).

## Naming and observation

```sh
koi dns status
koi dns serve
koi dns lookup demo.internal
koi dns add demo 192.168.1.42
koi dns list
koi dns remove demo
koi health status
koi health add demo --http http://127.0.0.1:8080/ --interval 30 --timeout 5
koi health watch
koi health log
```

Substitute a real reachable application address. Creating a DNS record does not configure every client's resolver. A local health check does not prove remote reachability.

## Trust and proxy reference

```sh
koi certmesh create
koi certmesh status
koi certmesh invite HOSTNAME
koi certmesh join ENDPOINT --invite TOKEN
koi certmesh renew
koi certmesh unlock
koi trust diagnose
koi proxy status
koi proxy add demo --listen 8443 --backend 127.0.0.1:8080
koi certmesh acme status
```

CA creation, enrollment and proxy startup are separate operations. Exact service HTTPS requires the correct name grant, leaf and trust distribution. The public service-grant workflow is incomplete; do not treat these commands as a certified trusted-container recipe.

Enrollment is open/closed with optional approval; there is no timed window or CIDR/domain enrollment policy. Authority promotion is manual. Backup/restore, revocation, hooks and destructive operations are documented in [Certmesh](../guides/certmesh.md) and [recovery](../guides/certmesh-ha-recovery.md).

## Interfaces and advanced tools

`koi launch` opens the operator interface. `koi mcp serve` serves MCP over stdio. UDP, trust-store and Pond commands are available through their domain help; see the [reference cards](cards/index.md). Advanced capabilities are retained independently of preview acceptance requirements.

## Listener configuration

| Option | Environment | Default |
| --- | --- | --- |
| `--port` | `KOI_PORT` | 5641 |
| `--http-bind` | `KOI_HTTP_BIND` | loopback |
| `--dns-port` | `KOI_DNS_PORT` | 53 |
| `--dns-zone` | `KOI_DNS_ZONE` | internal |
| `--dns-qps` | `KOI_DNS_QPS` | 200 per source IP |
| `--mtls-port` | `KOI_MTLS_PORT` | 5642 |
| `--acme-port` | `KOI_ACME_PORT` | 5643 |

`--http-bind` accepts `loopback`, `bridge`, a specific IP or `0.0.0.0`. Exposure does not remove authentication or add encryption. `--announce-http` advertises; it does not change a bind address. Capability `--no-*` flags disable the corresponding adapter/domain; inspect current help for the full set. See [ports](ports.md) and [security](security-model.md).
