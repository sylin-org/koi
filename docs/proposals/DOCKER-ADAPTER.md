# Docker Adapter (koi-docker)

**Status:** Idea
**Scope:** Separate sidecar/companion — no changes to Koi core

---

## Problem

When a containerized application registers with Koi, it needs to
advertise the **host-side** port — the one other devices on the LAN will
connect to. But the application inside the container only knows its own
listening port. The Docker port mapping (e.g. `8080:80`) lives in the
orchestration layer, not inside the container.

Today the workaround is to pass the host port explicitly via environment
variable or registration payload. This works but requires the operator
to duplicate port information that Docker already knows.

## Why not build it into Koi?

Koi is a DNS-SD daemon. It speaks a runtime-agnostic JSON protocol over
HTTP, IPC, and stdin/stdout. Baking Docker awareness into Koi would:

- Create a hard dependency on the Docker socket (`/var/run/docker.sock`)
- Require container runtime detection heuristics (fragile across Docker,
  Podman, containerd, etc.)
- Couple a network protocol daemon to a specific orchestration runtime
- Expand the security surface — the Docker socket grants root-equivalent
  access

The information needed to resolve port mappings already exists at the
orchestration layer. The right place to do the translation is a sidecar
that reads that information and calls Koi's API.

## Proposed design

A standalone adapter (`koi-docker`) that:

1. Connects to the Docker API (socket or TCP)
2. Watches container lifecycle events (start, stop, die)
3. Reads declarative labels from containers to determine what to register
4. Resolves host-side ports from Docker's port mapping
5. Calls Koi's HTTP API to register/unregister services
6. Maintains heartbeats for lease-based registrations

### Container labels

```yaml
services:
  web:
    image: nginx
    ports:
      - "8080:80"
    labels:
      koi.enable: "true"
      koi.service.name: "My Web Server"
      koi.service.type: "_http._tcp"
      koi.service.port: "80"           # container port — adapter resolves to host port
      koi.service.ip: "192.168.1.50"   # optional — pin to specific host IP
      koi.service.txt.path: "/api"     # optional — TXT record key=value
```

The adapter sees `koi.service.port: 80`, queries Docker for the host
mapping of container port 80, discovers `8080`, and registers with Koi
using port `8080`.

### Lifecycle

| Docker event     | Adapter action                        |
|------------------|---------------------------------------|
| container start  | Register service(s) with Koi          |
| container stop   | Unregister service(s)                 |
| container die    | Unregister (or let lease expire)      |
| adapter startup  | Scan running containers, register all |
| adapter shutdown | Unregister all managed services       |

### Runtime compatibility

The Docker Engine API is also implemented by Podman (via
`podman.sock`). The adapter should accept a configurable socket path,
making it compatible with both runtimes without code changes.

### Deployment

```yaml
services:
  koi-docker:
    image: sylin/koi-docker
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      KOI_HOST: host.docker.internal
      KOI_PORT: 5641
```

Or as a host-level binary alongside Koi:

```bash
koi-docker --koi-endpoint http://localhost:5641
```

## Prior art

- **Traefik** — reads Docker labels for routing rules
- **Registrator** — watches Docker events, registers with Consul/etcd
- **Consul Connect** — sidecar proxies with service mesh integration

## Open questions

- Should the adapter live in the same repo (monorepo) or a separate one?
- Language choice: Rust (consistency with Koi) vs. Go (richer Docker
  ecosystem) vs. a simple shell/Python script for v0?
- Should Koi publish a client SDK crate to make adapter development
  easier?
