# ADR-013: Runtime Adapters (koi-runtime)

**Status:** Accepted
**Date:** 2026-03-26
**Supersedes:** ADR-010 (Docker Adapter Kept Separate)

## Context

ADR-010 kept Docker integration out of Koi core to avoid coupling a DNS-SD daemon to a specific container runtime. This decision was correct at the time but assumed a sidecar architecture (separate process, HTTP API communication).

The consolidation work (ADR-012) and the introduction of the vault module demonstrated that Koi's single-binary, in-process architecture is its strength. A sidecar adapter would be invisible to embedded consumers (koi-embedded), require separate deployment, and duplicate the HTTP client/heartbeat logic already in koi-client.

Multiple container/VM runtimes exist (Docker, Podman, Kubernetes, systemd, Incus/LXC) and they all share the same integration pattern: watch lifecycle events, extract metadata, resolve network topology, and drive Koi capabilities (mDNS, DNS, certmesh, health, proxy).

## Decision

Add a new workspace crate `koi-runtime` that implements runtime integration as a domain capability within the Koi binary. Runtime backends are behind a `RuntimeBackend` trait — the core depends on the abstraction, not on any specific runtime.

### Architecture

```
crates/koi-runtime/
├── src/
│   ├── lib.rs          # RuntimeCore facade, RuntimeEvent, RuntimeConfig
│   ├── backend.rs      # RuntimeBackend trait
│   ├── instance.rs     # Normalized Instance, PortMapping, KoiMetadata
│   ├── heuristics.rs   # Port → service type mapping table
│   ├── docker.rs       # Docker/Podman backend (bollard)
│   ├── http.rs         # HTTP routes at /v1/runtime/
│   └── error.rs        # RuntimeError
```

### Domain Boundary Model

`koi-runtime` follows the same pattern as every other domain crate:

- **Commands**: `RuntimeCore` exposes `start_watching()`, `stop_watching()`, `list_instances()`, `status()`
- **State**: Read-only snapshots of discovered instances
- **Events**: `RuntimeEvent` variants via `tokio::sync::broadcast`
- **Routes**: Mounted at `/v1/runtime/` by the binary crate

### Runtime Tunables

- `--no-runtime` / `KOI_NO_RUNTIME=1` — disable runtime adapter
- `--runtime docker|podman|systemd|incus|kubernetes|auto` / `KOI_RUNTIME` — select backend (default: `auto`)
- Auto-detection: check for Docker/Podman socket, Incus socket, systemd D-Bus (in that order)

### Embedded Integration

```rust
let koi = Builder::new()
    .runtime(RuntimeBackendKind::Docker)
    .mdns(true)
    .dns(|cfg| cfg.zone("lan"))
    .build()?;
```

### What the Adapter Does

When an instance starts:
1. Extract metadata (name, ports, labels/annotations)
2. Apply port→service-type heuristics for unlabelled ports
3. Announce via mDNS (heartbeat-leased)
4. Add DNS entry (`{name}.{zone}`)
5. Register health check (from runtime health config or TCP probe)
6. Configure proxy if `koi.proxy.port` label is present

When an instance stops:
1. Unregister mDNS announcement
2. Remove DNS entry
3. Remove health check
4. Remove proxy entry

When a cert is renewed:
1. Redistribute cert files to instances with `koi.certmesh=true`

### Metadata Namespace

All runtimes map to a unified `KoiMetadata` struct. Runtime-specific keys:

| Koi key | Docker label | K8s annotation | systemd | Incus config |
|---------|-------------|----------------|---------|-------------|
| `koi.enable` | `koi.enable` | `koi.sylin.org/enable` | `X-Koi-Enable` | `user.koi.enable` |
| `koi.type` | `koi.type` | `koi.sylin.org/type` | `X-Koi-Type` | `user.koi.type` |
| `koi.name` | `koi.name` | `koi.sylin.org/name` | `X-Koi-Name` | `user.koi.name` |
| `koi.dns.name` | `koi.dns.name` | `koi.sylin.org/dns-name` | `X-Koi-DnsName` | `user.koi.dns.name` |
| `koi.health.path` | `koi.health.path` | `koi.sylin.org/health-path` | `X-Koi-HealthPath` | `user.koi.health.path` |
| `koi.proxy.port` | `koi.proxy.port` | `koi.sylin.org/proxy-port` | `X-Koi-ProxyPort` | `user.koi.proxy.port` |
| `koi.certmesh` | `koi.certmesh` | `koi.sylin.org/certmesh` | `X-Koi-Certmesh` | `user.koi.certmesh` |
| `koi.txt.*` | `koi.txt.*` | `koi.sylin.org/txt-*` | `X-Koi-Txt-*` | `user.koi.txt.*` |

### Port-to-Service-Type Heuristics

When no `koi.type` label is present, the adapter infers service type from published ports:

| Port | Service Type | Confidence |
|------|-------------|------------|
| 80, 8080, 3000, 8000 | `_http._tcp` | High |
| 443, 8443 | `_https._tcp` | High |
| 1883 | `_mqtt._tcp` | High |
| 5432 | `_postgresql._tcp` | High |
| 3306 | `_mysql._tcp` | High |
| 6379 | `_redis._tcp` | High |
| 27017 | `_mongodb._tcp` | Medium |
| 9090 | `_prometheus._tcp` | Medium |
| 3100 | `_loki._tcp` | Medium |
| Other | `_koi-managed._tcp` | Fallback |

## Consequences

### Positive

- Single binary — no sidecar to deploy, monitor, or restart
- Embedded consumers get runtime integration via builder API
- Direct in-process access to all domain cores — no serialization overhead
- Consistent lifecycle management via CancellationToken
- Trait-based backends — core never couples to a specific runtime
- Auto-detection — works out of the box on most systems

### Negative

- Reverses ADR-010's separation decision — Docker (via bollard) is now compiled into the binary
- Binary size increases (~2MB for bollard + dependencies)
- Docker socket access implies root-equivalent permissions — documented, not mitigated
- Future backends (K8s, Incus) add more dependencies

### Migration from ADR-010

ADR-010's recommended approach (manual `curl` commands in container entrypoints) still works. The runtime adapter is additive — it automates what was previously manual. `CONTAINERS.md` should be updated to recommend labels over manual API calls when the adapter is available.
