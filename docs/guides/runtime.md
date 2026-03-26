# Runtime - Container & Service Lifecycle

Docker containers start and stop. Kubernetes pods come and go. systemd services restart. Every time something starts, you want it discoverable - announced via mDNS, resolvable by name, health-checked, maybe fronted by a TLS proxy. Every time it stops, all of that should clean up automatically.

Koi's runtime adapter watches your container or service runtime for lifecycle events and drives all of Koi's capabilities without manual API calls. Start a container with `koi.type=_http._tcp` in its labels, and Koi announces it on the network. Stop the container, and the announcement disappears. No entrypoint scripts, no sidecars, no configuration files.

**When to use the runtime adapter**: You run Docker or Podman and want containers auto-discovered. You want `grafana.lan` to work as soon as you `docker compose up`. You're tired of manually calling the Koi API from container entrypoints.

**When not to use it**: You already have a bespoke service mesh. You don't run containers (mDNS, DNS, health, and proxy work fine without the runtime adapter). You need Kubernetes-native service discovery (CoreDNS + kube-proxy).

---

## How it works

The adapter connects to your runtime's API, watches for container lifecycle events, and translates them into Koi operations:

| Container event | Koi action |
|----------------|------------|
| **Start** | Announce via mDNS (heartbeat-leased), add DNS entry, register health check |
| **Stop** | Unregister mDNS, remove DNS entry, remove health check |
| **Metadata change** | Update mDNS TXT records, re-evaluate health check config |

The adapter runs inside the Koi daemon - no separate process to deploy. All capabilities compile into the single binary.

---

## Getting started

The runtime adapter is enabled by default in daemon mode. If Docker or Podman is running, Koi detects and connects automatically:

```
koi install    # or: koi --daemon
```

Check the daemon log for:

```
Runtime adapter: docker (auto-detected via /var/run/docker.sock)
```

Or on Windows:

```
Runtime adapter: docker (auto-detected via named pipe)
```

If no supported runtime is found, the daemon starts normally without the adapter. All other capabilities work as before.

### Verify with the status endpoint

```
curl -s http://localhost:5641/v1/runtime/status
```

```json
{
  "active": true,
  "backend": "docker",
  "instance_count": 3
}
```

### List discovered instances

```
curl -s http://localhost:5641/v1/runtime/instances
```

```json
[
  {
    "id": "a1b2c3d4...",
    "name": "grafana",
    "ports": [
      {"host_port": 3000, "container_port": 3000, "protocol": "tcp", "host_ip": "0.0.0.0"}
    ],
    "ips": ["172.17.0.2"],
    "metadata": {"service_type": "_http._tcp"},
    "backend": "docker",
    "state": "running",
    "image": "grafana/grafana:latest"
  }
]
```

---

## The quick way: announce shorthand

Most containers only need one thing: "make me discoverable under this name." The announce shorthand does exactly that.

**As a Docker label:**

```bash
docker run -d -p 8080:80 --label koi.announce=pi-hole pihole/pihole
```

**As an environment variable** (works from inside the container too):

```bash
docker run -d -p 8080:80 -e KOI_MDNS_ANNOUNCE=pi-hole pihole/pihole
```

Both produce the same result:

- mDNS: `pi-hole._http._tcp` announced on host port 8080 (port 80 → `_http._tcp` heuristic)
- DNS: `pi-hole.lan` added to the local resolver
- Health: TCP check registered on port 8080

For containers with multiple published ports, each gets its own announcement:

```bash
docker run -d -e KOI_MDNS_ANNOUNCE=pi-hole -p 8080:80 -p 5353:53/udp pihole/pihole
```

→ `pi-hole._http._tcp` on port 8080 + `pi-hole._dns._udp` on port 5353

**Precedence** (highest wins):

1. Explicit `koi.*` labels — full control over every field
2. `koi.announce` label — shorthand, heuristics fill the rest
3. `KOI_MDNS_ANNOUNCE` env var — same as the label, lower precedence
4. No signal — container not announced

The announce shorthand sets `name`, `dns_name`, and `enable=true`. You can combine it with explicit labels to override specific fields:

```yaml
labels:
  koi.announce: pi-hole
  koi.type: "_dns._tcp"        # override the port heuristic
  koi.health.path: "/admin"    # add an HTTP health check
```

---

## Full label reference

The adapter reads `koi.*` labels from containers to control what Koi does. All labels are optional - when absent, the adapter uses heuristics.

| Label | Purpose | Example |
|-------|---------|---------|
| `koi.announce` | Announce shorthand (sets name + dns_name + enable) | `koi.announce=pi-hole` |
| `koi.enable` | Opt in/out (`true`/`false`) | `koi.enable=true` |
| `koi.type` | mDNS service type | `koi.type=_http._tcp` |
| `koi.name` | Override service name | `koi.name=My Grafana` |
| `koi.dns.name` | Override DNS name | `koi.dns.name=grafana` |
| `koi.txt.*` | mDNS TXT record entries | `koi.txt.version=10.4` |
| `koi.health.path` | HTTP health check path | `koi.health.path=/api/health` |
| `koi.health.kind` | Health check type (`http`/`tcp`) | `koi.health.kind=http` |
| `koi.health.interval` | Check interval (seconds) | `koi.health.interval=30` |
| `koi.proxy.port` | Enable TLS proxy on this port | `koi.proxy.port=443` |
| `koi.certmesh` | Enable cert injection | `koi.certmesh=true` |

| `KOI_MDNS_ANNOUNCE` | Env var announce shorthand (same as `koi.announce`) | `KOI_MDNS_ANNOUNCE=pi-hole` |

### Example: Docker Compose (simple)

```yaml
services:
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    labels:
      koi.announce: grafana
```

That's it. Port 3000 → `_http._tcp` heuristic, `grafana.lan` DNS entry, auto health check.

### Example: Docker Compose (detailed)

```yaml
services:
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    labels:
      koi.announce: grafana
      koi.type: "_http._tcp"
      koi.txt.version: "10.4"
      koi.health.path: "/api/health"
      koi.health.kind: "http"
```

The explicit labels refine what `koi.announce` started: custom service type, TXT records, and an HTTP health check path.

When `docker compose down` runs, all registrations are cleaned up automatically.

### Example: Docker CLI

```bash
docker run -d \
  --name postgres \
  -p 5432:5432 \
  --label koi.type=_postgresql._tcp \
  --label koi.dns.name=db \
  postgres:16
```

---

## Port heuristics

When no `koi.type` label is present, the adapter infers the service type from the published port number:

| Port | Inferred type |
|------|--------------|
| 80, 3000, 5000, 8000, 8080 | `_http._tcp` |
| 443, 8443 | `_https._tcp` |
| 1883 | `_mqtt._tcp` |
| 5432 | `_postgresql._tcp` |
| 3306 | `_mysql._tcp` |
| 6379 | `_redis._tcp` |
| 27017 | `_mongodb._tcp` |
| 9090 | `_prometheus._tcp` |
| Other | `_koi-managed._tcp` |

This means a container with `-p 5432:5432` is announced as `_postgresql._tcp` automatically, no labels needed. Labels always override heuristics.

---

## Docker Compose integration

Docker Compose adds extra labels that Koi uses for cleaner naming:

| Compose label | How Koi uses it |
|--------------|-----------------|
| `com.docker.compose.service` | Preferred service name (over random container name) |
| `com.docker.compose.project` | Available for namespacing (e.g., `grafana.monitoring.lan`) |

When you use Compose, `docker compose up grafana` produces an mDNS announcement named `grafana` (the service name), not `monitoring-grafana-1` (the container name).

---

## Supported runtimes

| Runtime | Status | Socket | Notes |
|---------|--------|--------|-------|
| **Docker** | Implemented | `/var/run/docker.sock` (Unix), named pipe (Windows) | Default, auto-detected |
| **Podman** | Implemented | `/run/user/{uid}/podman/podman.sock` | Docker-compatible API |
| **systemd** | Planned | D-Bus | Unit lifecycle events |
| **Incus/LXC** | Planned | REST API | Containers + VMs |
| **Kubernetes** | Planned | K8s API server | Pod/Service/Ingress watch |

Select a backend explicitly:

```
koi --daemon --runtime docker
koi --daemon --runtime podman
```

Or let Koi auto-detect (default):

```
koi --daemon --runtime auto
```

---

## Disabling the adapter

If you don't want the runtime adapter:

```
koi --daemon --no-runtime
```

Or via environment variable:

```
KOI_NO_RUNTIME=1 koi --daemon
```

The adapter is completely optional. All other Koi capabilities work without it.

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
// Access runtime state:
let runtime = handle.runtime()?;
```

Runtime is **opt-in** for embedded (unlike the daemon where it's on by default), since embedded consumers may not have a container runtime.
