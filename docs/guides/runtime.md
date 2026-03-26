# Runtime - Container & Service Lifecycle

Docker containers start and stop. Every time one starts, you want it discoverable — announced via mDNS, resolvable by name, health-checked. Every time it stops, all of that should clean up. Automatically.

Koi's runtime adapter watches Docker or Podman for lifecycle events and drives Koi's capabilities without manual API calls. Add one label to your container, and Koi handles the rest.

```bash
docker run -d -p 3000:3000 --label koi.announce=grafana grafana/grafana
```

That single label triggers:

1. **mDNS**: `grafana._http._tcp` announced on the LAN (port 3000 → HTTP heuristic)
2. **DNS**: `grafana.lan` resolves to the host IP
3. **Health**: TCP check registered on port 3000

Stop the container → all three are removed. Start it again → all three are recreated.

---

## The lifecycle

The runtime adapter has two layers: **detection** (koi-runtime crate) and **orchestration** (binary crate). Detection watches the container runtime API. Orchestration translates events into domain operations.

```
┌──────────┐      ┌──────────────┐      ┌───────────────┐
│  Docker   │─────→│  koi-runtime │─────→│ orchestrator   │
│  events   │      │  (detection) │      │ (binary crate) │
└──────────┘      └──────────────┘      └───────┬───────┘
                                                │
                         ┌──────────────────────┼──────────────────────┐
                         ▼                      ▼                      ▼
                   ┌──────────┐          ┌──────────┐          ┌──────────┐
                   │ MdnsCore │          │ DnsCore  │          │HealthCore│
                   │ register │          │ add_entry│          │ add_check│
                   └──────────┘          └──────────┘          └──────────┘
```

### What happens when a container starts

1. Docker emits a `start` event
2. koi-runtime inspects the container: ports, labels, env vars, image
3. The orchestrator checks opt-in: is `koi.announce`, `koi.enable=true`, or `KOI_MDNS_ANNOUNCE` present?
4. If yes, for each published TCP port:
   - Infer service type from the container port (80 → `_http._tcp`, 5432 → `_postgresql._tcp`, etc.)
   - Call `MdnsCore::register()` with permanent lease — the orchestrator owns the lifecycle
5. Add a DNS entry: `{name}.{zone}` → host IP
6. Add a health check: HTTP if `koi.health.path` is set, TCP otherwise
7. If `koi.proxy.port` is set, configure a TLS-terminating proxy entry
8. Store all resource IDs in an internal map, keyed by container ID

### What happens when a container stops

1. Docker emits a `die` or `stop` event
2. The orchestrator looks up the container ID in its resource map
3. Calls `MdnsCore::unregister()` for each mDNS registration
4. Calls `DnsCore::remove_entry()` for the DNS name
5. Calls `HealthCore::remove_check()` for the health check
6. Calls `ProxyCore::remove()` if a proxy entry was created
7. Removes the entry from the resource map

### Other scenarios

**Koi starts with containers already running**: The adapter lists all running containers on connect and emits `Started` events for each. The orchestrator treats them identically to live starts.

**Container restarts**: The `Stopped` event arrives first (resources cleaned up), then `Started` (resources recreated). Brief unavailability window — correct behavior.

**Docker daemon disconnects**: The orchestrator keeps existing registrations alive. When Docker reconnects, the adapter reconciles and emits fresh `Started` events. The orchestrator handles duplicates idempotently.

**Koi shuts down**: The orchestrator drains its resource map, removing all mDNS announcements, DNS entries, health checks, and proxy entries before exit.

---

## The quick way: announce shorthand

Most containers only need one thing: "make me discoverable under this name."

**As a Docker label:**

```bash
docker run -d -p 8080:80 --label koi.announce=pi-hole pihole/pihole
```

**As an environment variable** (works from inside the container too):

```bash
docker run -d -p 8080:80 -e KOI_MDNS_ANNOUNCE=pi-hole pihole/pihole
```

Both produce the same result:

- mDNS: `pi-hole._http._tcp` announced on host port 8080 (container port 80 → `_http._tcp` heuristic)
- DNS: `pi-hole.lan` added to the local resolver
- Health: TCP check registered on host port 8080

For containers with multiple published ports, each TCP port gets its own mDNS announcement:

```bash
docker run -d -e KOI_MDNS_ANNOUNCE=pi-hole -p 8080:80 -p 5353:53/udp pihole/pihole
```

→ `pi-hole._http._tcp` on port 8080 (port 80 is TCP and HTTP)

**Precedence** (highest wins):

1. Explicit `koi.*` labels — full control over every field
2. `koi.announce` label — shorthand, heuristics fill the rest
3. `KOI_MDNS_ANNOUNCE` env var — same as the label, lower precedence
4. No signal — container ignored

The announce shorthand sets `name`, `dns_name`, and `enable=true`. Combine it with explicit labels to override specific fields:

```yaml
labels:
  koi.announce: pi-hole
  koi.type: "_dns._tcp"        # override the port heuristic
  koi.health.path: "/admin"    # switch from TCP to HTTP health check
```

---

## Full label reference

All labels are optional. Without any `koi.*` labels or `KOI_MDNS_ANNOUNCE` env var, the container is ignored.

| Label | Purpose | Example |
|-------|---------|---------|
| `koi.announce` | Announce shorthand (sets name + dns_name + enable) | `koi.announce=pi-hole` |
| `koi.enable` | Opt in/out (`true`/`false`) | `koi.enable=true` |
| `koi.type` | mDNS service type | `koi.type=_http._tcp` |
| `koi.name` | Override service name | `koi.name=My Grafana` |
| `koi.dns.name` | Override DNS name (without zone suffix) | `koi.dns.name=grafana` |
| `koi.txt.*` | mDNS TXT record entries | `koi.txt.version=10.4` |
| `koi.health.path` | HTTP health check path (implies HTTP kind) | `koi.health.path=/api/health` |
| `koi.health.kind` | Health check type (`http`/`tcp`) | `koi.health.kind=http` |
| `koi.health.interval` | Check interval in seconds (default: 30) | `koi.health.interval=60` |
| `koi.health.timeout` | Check timeout in seconds (default: 5) | `koi.health.timeout=10` |
| `koi.proxy.port` | Enable TLS proxy on this listen port | `koi.proxy.port=443` |
| `koi.proxy.remote` | Allow remote proxy connections | `koi.proxy.remote=true` |
| `koi.certmesh` | Enable certmesh cert injection | `koi.certmesh=true` |

Environment variable alternative:

| Env var | Equivalent to | Example |
|---------|---------------|---------|
| `KOI_MDNS_ANNOUNCE` | `koi.announce` label (lower precedence) | `KOI_MDNS_ANNOUNCE=pi-hole` |

---

## Examples

### Minimal: one label

```yaml
services:
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    labels:
      koi.announce: grafana
```

Result: `grafana._http._tcp` on port 3000, `grafana.lan` DNS, TCP health check.

### With health check

```yaml
services:
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    labels:
      koi.announce: grafana
      koi.health.path: "/api/health"
```

Result: same as above, but health check is HTTP GET on `/api/health` instead of TCP probe.

### Database

```bash
docker run -d -p 5432:5432 --label koi.announce=db postgres:16
```

Result: `db._postgresql._tcp` on port 5432 (heuristic), `db.lan` DNS, TCP health check.

### Multiple services

```yaml
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
    labels:
      koi.announce: web

  api:
    image: myapp:latest
    ports:
      - "3000:3000"
    labels:
      koi.announce: api
      koi.health.path: "/health"

  db:
    image: postgres:16
    ports:
      - "5432:5432"
    labels:
      koi.announce: db
```

`docker compose up` → three mDNS announcements, three DNS entries, three health checks. `docker compose down` → all cleaned up.

### Environment variable (no image changes needed)

```yaml
services:
  redis:
    image: redis:7
    ports:
      - "6379:6379"
    environment:
      KOI_MDNS_ANNOUNCE: cache
```

Result: `cache._redis._tcp` on port 6379, `cache.lan` DNS, TCP health check. The Redis image is used unmodified.

---

## Port heuristics

When no `koi.type` label is present, the adapter infers the mDNS service type from the **container** port:

| Port | Inferred type |
|------|--------------|
| 80, 3000, 5000, 8000, 8080, 8888, 9000 | `_http._tcp` |
| 443, 8443 | `_https._tcp` |
| 1883 | `_mqtt._tcp` |
| 5432 | `_postgresql._tcp` |
| 3306 | `_mysql._tcp` |
| 6379 | `_redis._tcp` |
| 27017 | `_mongodb._tcp` |
| 5672 | `_amqp._tcp` |
| 9092 | `_kafka._tcp` |
| 9090 | `_prometheus._tcp` |
| 3100 | `_loki._tcp` |
| 9200 | `_elasticsearch._tcp` |
| 22 | `_ssh._tcp` |
| 53 | `_dns._tcp` |
| Other | `_koi-managed._tcp` |

The mDNS announcement always uses the **host** port (the one reachable from the network). Labels always override heuristics.

---

## Docker Compose integration

Docker Compose adds labels that Koi uses for cleaner naming:

| Compose label | How Koi uses it |
|--------------|-----------------|
| `com.docker.compose.service` | Preferred service name (over random container name) |
| `com.docker.compose.project` | Available for namespacing |

When you use Compose, `docker compose up grafana` produces an mDNS announcement named `grafana` (the service name), not `monitoring-grafana-1` (the generated container name).

---

## Supported runtimes

| Runtime | Status | Socket | Notes |
|---------|--------|--------|-------|
| **Docker** | Implemented | `/var/run/docker.sock` (Unix), named pipe (Windows) | Default, auto-detected |
| **Podman** | Implemented | `/run/user/{uid}/podman/podman.sock` | Docker-compatible API |
| **systemd** | Planned | D-Bus | Unit lifecycle events |
| **Incus/LXC** | Planned | REST API | Containers + VMs |
| **Kubernetes** | Planned | K8s API server | Pod/Service/Ingress watch |

Select explicitly:

```
koi --daemon --runtime docker
koi --daemon --runtime podman
```

Or auto-detect (default):

```
koi --daemon --runtime auto
```

---

## Disabling the adapter

```
koi --daemon --no-runtime
# or
KOI_NO_RUNTIME=1 koi --daemon
```

All other capabilities work without it.

---

## Getting started

```
koi install
```

If Docker is running, the adapter connects automatically. Check with:

```
curl -s http://localhost:5641/v1/runtime/status
```

Then start a container:

```bash
docker run -d -p 3000:3000 --label koi.announce=grafana grafana/grafana
```

Verify it was announced:

```bash
koi mdns discover _http._tcp
```

You should see `grafana._http._tcp` in the results.

Check the DNS entry:

```bash
koi dns lookup grafana
```

Check the health status:

```bash
koi health status
```

Stop the container:

```bash
docker stop grafana
```

All registrations are removed within seconds.

---

## HTTP API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/runtime/status` | Adapter status (active, backend, instance count) |
| GET | `/v1/runtime/instances` | List all tracked instances with ports, labels, state |

---

## Embedded usage

For Rust applications using `koi-embedded`:

```rust
use koi_embedded::{Builder, RuntimeBackendKind};

let koi = Builder::new()
    .runtime(RuntimeBackendKind::Docker)
    .mdns(true)
    .dns(|cfg| cfg.zone("lan"))
    .build()?;

let handle = koi.start().await?;
// Docker containers are now auto-announced.
```

Runtime is **opt-in** for embedded (unlike the daemon where it's on by default), since embedded consumers may not have a container runtime.
