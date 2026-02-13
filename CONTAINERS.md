# Koi Container Guide

Docker containers can't do mDNS. The bridge network doesn't forward multicast traffic, and every workaround — `--network=host`, macvlan, mDNS reflectors — sacrifices isolation or adds fragility.

Koi solves this at the infrastructure level. It runs on the host, speaks multicast mDNS on the physical network, and exposes everything through a plain HTTP API. Containers make HTTP calls; Koi translates them into mDNS. No special network modes, no multicast forwarding, no libraries needed inside the container.

This guide starts with the simplest setup and builds toward production patterns.

---

## The basic setup

You need two things: Koi running on the host, and containers that can reach it.

### Start Koi on the host

On Windows, install Koi as a service (run as Administrator):

```powershell
koi install
```

On Linux/macOS, install as a system service or run in the foreground:

```bash
sudo koi install
# or
koi --daemon
```

Either way, Koi binds to `0.0.0.0:5641` — every network interface, including the Docker bridge gateway. Containers can reach it without any extra configuration.

### Test from a container

```bash
docker run --rm curlimages/curl \
  curl -s http://host.docker.internal:5641/healthz
```

```
OK
```

That's it. The container made a plain HTTP request to the host, and Koi responded. If you see `OK`, every mDNS operation is available to that container.

---

## Container profiles

Pick a usage profile based on what your container needs. Each profile maps to a small set of endpoints.

### Profile A — Discovery only (mDNS)

Use this when the container only needs to discover LAN services.

```bash
# Browse services
curl -s "http://$KOI_HOST:5641/v1/mdns/discover?type=_http._tcp"

# Resolve a specific instance
curl -s "http://$KOI_HOST:5641/v1/mdns/resolve?name=My%20NAS._http._tcp.local."
```

### Profile B — Discovery + naming (mDNS + DNS)

Use this when containers need friendly names mapped to LAN IPs.

```bash
# DNS lookup
curl -s "http://$KOI_HOST:5641/v1/dns/lookup?name=grafana&type=A"

# Add a static entry
curl -s -X POST http://$KOI_HOST:5641/v1/dns/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"grafana","ip":"192.168.1.42"}'
```

### Profile C — Discovery + naming + health

Use this when containers rely on shared health checks (HTTP/TCP).

```bash
# Add a TCP check
curl -s -X POST http://$KOI_HOST:5641/v1/health/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"db","kind":"tcp","target":"10.0.0.10:5432"}'

# Health status
curl -s http://$KOI_HOST:5641/v1/health/status
```

### Profile D — Full stack (mDNS + DNS + health + certmesh + proxy)

Use this when containers manage TLS endpoints or need certmesh policy controls.

```bash
# Certmesh status
curl -s http://$KOI_HOST:5641/v1/certmesh/status

# Proxy status
curl -s http://$KOI_HOST:5641/v1/proxy/status
```

### Reaching the host

How a container reaches the host depends on the platform:

| Platform | Address | Notes |
|----------|---------|-------|
| Docker Desktop (Mac/Windows) | `host.docker.internal` | Built-in DNS name, works out of the box |
| Linux (Docker 20.10+) | `host.docker.internal` | Requires `--add-host=host.docker.internal:host-gateway` or the `extra_hosts` Compose directive |
| Linux (any version) | `172.17.0.1` | Default bridge gateway — works without any flags |
| Custom Docker network | Gateway IP of that network | Find with `docker network inspect <name>` |

For the rest of this guide, we'll use `$KOI_HOST` as a placeholder. Set it to whatever works for your environment:

```bash
export KOI_HOST=host.docker.internal   # Mac/Windows
export KOI_HOST=172.17.0.1             # Linux default bridge
```

---

## Discovering services

A container that needs to find services on the local network — printers, NAS boxes, Home Assistant, Chromecast — can browse with a single HTTP call.

### Browse for a service type

```bash
# From inside a container
curl -s http://$KOI_HOST:5641/v1/mdns/discover?type=_http._tcp
```

This returns a Server-Sent Events stream. Each line is a discovered service:

```
data: {"found":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
data: {"found":{"name":"Pi-hole","type":"_http._tcp","host":"pihole.local.","ip":"192.168.1.10","port":80,"txt":{}}}
```

The stream closes automatically after 5 seconds of quiet — once all known services have been reported. For long-lived watching, set `idle_for=0`:

```bash
curl -s "http://$KOI_HOST:5641/v1/mdns/discover?type=_http._tcp&idle_for=0"
```

### Resolve a specific instance

If you know the name of the service you want:

```bash
curl -s http://$KOI_HOST:5641/v1/mdns/resolve?name=My%20NAS._http._tcp.local.
```

```json
{"resolved":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{"version":"2.1"}}}
```

This returns the IP, port, and TXT metadata in one shot. Useful when a container needs to connect to a specific service at startup.

---

## Registering services from containers

This is the part that's normally impossible. A container behind Docker's NAT bridge can't send mDNS multicast. But with Koi, it can register a service that appears on the physical LAN — other devices (phones, laptops, IoT) will see it as if it were running directly on the network.

### Register a service

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/mdns/announce \
  -H 'Content-Type: application/json' \
  -d '{"name": "My Container App", "type": "_http._tcp", "port": 8080}'
```

```json
{"registered":{"id":"a1b2c3d4","name":"My Container App","type":"_http._tcp","port":8080,"mode":"heartbeat","lease_secs":90}}
```

The service is now visible to every mDNS client on the network. The `mode: heartbeat` means you need to periodically tell Koi the service is still alive.

### Keep it alive with heartbeats

HTTP registrations use a lease model. The default lease is 90 seconds — if Koi doesn't hear from you within that window, it starts a 30-second grace period, then removes the service from the network.

Send a heartbeat at half the lease interval (every 45 seconds is a safe default):

```bash
curl -s -X PUT http://$KOI_HOST:5641/v1/mdns/heartbeat/a1b2c3d4
```

```json
{"renewed":{"id":"a1b2c3d4","lease_secs":90}}
```

### Register permanently

If the service should live for as long as Koi runs (or until you explicitly remove it), set `lease_secs` to 0:

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/mdns/announce \
  -H 'Content-Type: application/json' \
  -d '{"name": "My Container App", "type": "_http._tcp", "port": 8080, "lease_secs": 0}'
```

```json
{"registered":{"id":"a1b2c3d4","name":"My Container App","type":"_http._tcp","port":8080,"mode":"permanent"}}
```

No heartbeats needed. The registration persists until you delete it or Koi shuts down. Good for infrastructure services that are always running.

### Unregister

```bash
curl -s -X DELETE http://$KOI_HOST:5641/v1/mdns/unregister/a1b2c3d4
```

```json
{"unregistered":"a1b2c3d4"}
```

Koi sends mDNS goodbye packets so other devices remove the service from their caches immediately.

---

## Docker Compose

Here's a practical setup: Koi on the host, two containers that use it.

```yaml
# docker-compose.yml
services:
  web:
    image: nginx
    ports:
      - "8080:80"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - KOI_HOST=host.docker.internal
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://host.docker.internal:5641/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3

  api:
    image: my-api:latest
    ports:
      - "3000:3000"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - KOI_HOST=host.docker.internal
```

Start Koi on the host (if it isn't already running as a service), then bring up the containers:

```bash
# On the host (skip if Koi is already installed as a service)
koi --daemon

# In another terminal
docker compose up -d
```

Now register the web server from inside its container:

```bash
docker exec web curl -s -X POST http://host.docker.internal:5641/v1/mdns/announce \
  -H 'Content-Type: application/json' \
  -d '{"name": "Nginx", "type": "_http._tcp", "port": 8080, "lease_secs": 0}'
```

Any mDNS client on the network — a phone, another laptop, a different server — will now discover "Nginx" as an HTTP service.

---

## Startup registration pattern

Most containers need to register on startup and unregister on shutdown. Here's how to do that cleanly.

### Shell entrypoint

Wrap your container's entrypoint in a script that registers on start and cleans up on exit:

```bash
#!/bin/sh
# entrypoint.sh

KOI=${KOI_HOST:-host.docker.internal}
KOI_URL="http://$KOI:5641"

# Wait for Koi to be available
until curl -sf "$KOI_URL/healthz" > /dev/null 2>&1; do
  echo "Waiting for Koi at $KOI_URL..."
  sleep 2
done

# Register this service
RESULT=$(curl -sf -X POST "$KOI_URL/v1/mdns/announce" \
  -H 'Content-Type: application/json' \
  -d "{\"name\": \"$SERVICE_NAME\", \"type\": \"_http._tcp\", \"port\": $SERVICE_PORT, \"lease_secs\": 0}")

REG_ID=$(echo "$RESULT" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
echo "Registered with Koi: $REG_ID"

# Unregister on exit
cleanup() {
  echo "Unregistering from Koi..."
  curl -sf -X DELETE "$KOI_URL/v1/mdns/unregister/$REG_ID" > /dev/null 2>&1
}
trap cleanup EXIT TERM INT

# Run the actual application
exec "$@"
```

```dockerfile
FROM nginx:alpine
RUN apk add --no-cache curl
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV SERVICE_NAME="My Web Server"
ENV SERVICE_PORT=80
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
```

### With heartbeats

If you want crash detection (service disappears from the network when the container dies), use heartbeat mode instead of permanent:

```bash
#!/bin/sh
# entrypoint-heartbeat.sh

KOI=${KOI_HOST:-host.docker.internal}
KOI_URL="http://$KOI:5641"

until curl -sf "$KOI_URL/healthz" > /dev/null 2>&1; do
  sleep 2
done

RESULT=$(curl -sf -X POST "$KOI_URL/v1/mdns/announce" \
  -H 'Content-Type: application/json' \
  -d "{\"name\": \"$SERVICE_NAME\", \"type\": \"_http._tcp\", \"port\": $SERVICE_PORT}")

REG_ID=$(echo "$RESULT" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)

# Background heartbeat loop
(while true; do
  sleep 45
  curl -sf -X PUT "$KOI_URL/v1/mdns/heartbeat/$REG_ID" > /dev/null 2>&1 || break
done) &
HEARTBEAT_PID=$!

cleanup() {
  kill $HEARTBEAT_PID 2>/dev/null
  curl -sf -X DELETE "$KOI_URL/v1/mdns/unregister/$REG_ID" > /dev/null 2>&1
}
trap cleanup EXIT TERM INT

exec "$@"
```

The difference: if the container crashes hard (OOM kill, kernel panic, host power loss), the heartbeat stops, and Koi removes the service after 90 + 30 = 120 seconds. With permanent mode, the stale registration would linger until someone manually removes it or Koi restarts.

---

## Discovering services at startup

Some containers need to find another service before they can start — a database, an API gateway, a configuration server. Koi's resolve endpoint handles this.

```bash
#!/bin/sh
# wait-for-service.sh

KOI=${KOI_HOST:-host.docker.internal}
KOI_URL="http://$KOI:5641"

# Wait for the dependency to appear on the network
echo "Looking for $DEPEND_SERVICE..."
while true; do
  RESULT=$(curl -sf "$KOI_URL/v1/mdns/resolve?name=$DEPEND_SERVICE" 2>/dev/null)
  if echo "$RESULT" | grep -q '"resolved"'; then
    IP=$(echo "$RESULT" | grep -o '"ip":"[^"]*"' | cut -d'"' -f4)
    PORT=$(echo "$RESULT" | grep -o '"port":[0-9]*' | cut -d: -f2)
    echo "Found $DEPEND_SERVICE at $IP:$PORT"
    export DEPEND_HOST="$IP"
    export DEPEND_PORT="$PORT"
    break
  fi
  sleep 2
done

exec "$@"
```

```yaml
services:
  worker:
    image: my-worker:latest
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - KOI_HOST=host.docker.internal
      - DEPEND_SERVICE=Config Server._http._tcp.local.
```

The worker container waits until "Config Server" appears on the network, extracts its IP and port, then starts.

---

## Subscribing to events

For containers that need to react to services coming and going — load balancers, monitoring dashboards, mesh proxies — use the SSE events endpoint.

```bash
curl -s -N http://$KOI_HOST:5641/v1/mdns/subscribe?type=_http._tcp
```

```
data: {"event":"found","service":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
data: {"event":"resolved","service":{"name":"My NAS","type":"_http._tcp","host":"nas.local.","ip":"192.168.1.50","port":8080,"txt":{}}}
data: {"event":"removed","service":{"name":"My NAS","type":"_http._tcp","txt":{}}}
```

Like browse, this stream closes after 5 seconds of quiet by default. For long-lived watching (load balancers, dashboards), set `idle_for=0`:

```bash
curl -s -N "http://$KOI_HOST:5641/v1/mdns/subscribe?type=_http._tcp&idle_for=0"
```

Each event tells you what happened:

| Event | Meaning |
|-------|---------|
| `found` | A new service appeared (we know its name) |
| `resolved` | We now have its IP, port, and TXT records |
| `removed` | The service is gone |

A Python container consuming this might look like:

```python
import requests
import json

KOI = "http://host.docker.internal:5641"
response = requests.get(f"{KOI}/v1/mdns/subscribe?type=_http._tcp&idle_for=0", stream=True)

for line in response.iter_lines(decode_unicode=True):
    if line.startswith("data: "):
        event = json.loads(line[6:])
        kind = event["event"]
        name = event["service"]["name"]

        if kind == "resolved":
            ip = event["service"]["ip"]
            port = event["service"]["port"]
            print(f"Service up: {name} at {ip}:{port}")
        elif kind == "removed":
            print(f"Service gone: {name}")
```

---

## DNS from containers

Containers can use Koi's DNS resolver to map friendly names to LAN IPs.

### Lookup a local name

```bash
curl -s "http://$KOI_HOST:5641/v1/dns/lookup?name=grafana&type=A"
```

```json
{"name":"grafana.lan.","ips":["192.168.1.42"],"source":"static"}
```

### List known names

```bash
curl -s "http://$KOI_HOST:5641/v1/dns/list"
```

### Add and remove static entries

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/dns/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"grafana","ip":"192.168.1.42"}'

curl -s -X DELETE http://$KOI_HOST:5641/v1/dns/remove/grafana
```

If you need to start or stop the resolver from a container, use:

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/dns/serve
curl -s -X POST http://$KOI_HOST:5641/v1/dns/stop
```

---

## Health checks from containers

Use Koi to maintain a shared health view for services that containers depend on.

### Add a TCP check

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/health/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"db","kind":"tcp","target":"10.0.0.10:5432"}'
```

### Add an HTTP check

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/health/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"api","kind":"http","target":"http://10.0.0.20:8080/health"}'
```

### View and remove checks

```bash
curl -s http://$KOI_HOST:5641/v1/health/status
curl -s http://$KOI_HOST:5641/v1/health/checks
curl -s -X DELETE http://$KOI_HOST:5641/v1/health/remove/db
```

---

## Certmesh from containers

Containers can call certmesh endpoints for status, audit logs, and policy management.
Certificate creation and enrollment are still best managed on the host so the trust
store and cert files live in the host data directory.

```bash
curl -s http://$KOI_HOST:5641/v1/certmesh/status
curl -s http://$KOI_HOST:5641/v1/certmesh/log
curl -s -X POST http://$KOI_HOST:5641/v1/certmesh/open-enrollment -H 'Content-Type: application/json' -d '{}'
curl -s -X POST http://$KOI_HOST:5641/v1/certmesh/close-enrollment
```

If you do enroll from a container, the `/v1/certmesh/join` response includes PEM
material you can store in the container, but it will not update the host trust store.

---

## Proxy configuration from containers

The proxy capability lets you terminate TLS on the host using certmesh-managed
certificates and forward traffic to local backends.

### Add a proxy entry

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/proxy/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"app","listen_port":443,"backend":"http://127.0.0.1:8080"}'
```

### List or remove entries

```bash
curl -s http://$KOI_HOST:5641/v1/proxy/status
curl -s http://$KOI_HOST:5641/v1/proxy/list
curl -s -X DELETE http://$KOI_HOST:5641/v1/proxy/remove/app
```

---

## IPC via mounted socket

HTTP works for most cases, but if you want zero network overhead for same-host containers, you can mount Koi's Unix domain socket into the container.

Start Koi with a known socket path (the default on Linux is `$XDG_RUNTIME_DIR/koi.sock`):

```bash
koi --daemon --pipe /var/run/koi.sock
```

Mount the socket into your container:

```yaml
services:
  app:
    image: my-app:latest
    volumes:
      - /var/run/koi.sock:/var/run/koi.sock
```

Inside the container, speak NDJSON over the socket:

```bash
echo '{"browse":"_http._tcp"}' | socat - UNIX-CONNECT:/var/run/koi.sock
```

IPC registrations use session-based leases instead of heartbeats. As long as the socket connection is open, the registration stays alive. When the connection drops (container stops, crashes, is removed), Koi starts a 30-second grace period and then removes the service. No heartbeat loop needed.

This is the lowest-latency option and has the cleanest lifecycle semantics — the OS tells Koi immediately when a container's connection drops.

---

## Port mapping considerations

When a container registers a service with Koi, the port in the registration should be the **host-side** port — the one other devices on the network will connect to.

```yaml
services:
  web:
    image: nginx
    ports:
      - "8080:80"  # host:container
```

Register with port `8080`, not `80`:

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/mdns/announce \
  -H 'Content-Type: application/json' \
  -d '{"name": "My Web Server", "type": "_http._tcp", "port": 8080}'
```

When another device discovers this service via mDNS, it sees port 8080 and connects to the host on that port. Docker forwards the traffic to the container's port 80.

If you're using `--network=host` (where there's no port mapping), use the container's actual port.

---

## IP pinning

By default, Koi advertises **all** of the host's IP addresses in the mDNS A record. On machines with Docker bridges, WSL virtual adapters, or VPN interfaces, this can include addresses that other devices on the LAN can't reach (e.g. `172.17.0.1`, `127.0.0.1`).

Use the `ip` field to pin the registration to a specific LAN address:

```bash
curl -s -X POST http://$KOI_HOST:5641/v1/mdns/announce \
  -H 'Content-Type: application/json' \
  -d '{"name": "My Service", "type": "_http._tcp", "port": 8080, "ip": "192.168.1.42"}'
```

Or from the CLI:

```bash
koi mdns announce "My Service" http 8080 --ip 192.168.1.42
```

When `ip` is present, only that address is advertised. When `ip` is absent, all machine IPs are included (the original auto-detect behavior).

This is especially useful for container hosts where the host machine has multiple network interfaces and you want mDNS clients to connect to the correct one.

---

## Kubernetes

Koi runs on the node, not in a pod. Deploy it as a DaemonSet so every node has an instance:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: koi
spec:
  selector:
    matchLabels:
      app: koi
  template:
    metadata:
      labels:
        app: koi
    spec:
      hostNetwork: true
      containers:
        - name: koi
          image: your-registry/koi:latest
          args: ["--daemon"]
          ports:
            - containerPort: 5641
              hostPort: 5641
```

Pods on each node reach Koi via the node's IP. Use the downward API to inject the node IP:

```yaml
env:
  - name: KOI_HOST
    valueFrom:
      fieldRef:
        fieldPath: status.hostIP
```

Then from any pod:

```bash
curl -s http://$KOI_HOST:5641/v1/mdns/discover?type=_http._tcp
```

The DaemonSet needs `hostNetwork: true` because mDNS requires multicast on the physical network interface. Koi handles the multicast; pods talk to it over plain HTTP.

---

## Health checks

Use Koi's health endpoint as a dependency check in your container health probes:

```yaml
services:
  app:
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://host.docker.internal:5641/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

Or in Kubernetes:

```yaml
livenessProbe:
  httpGet:
    host: $(KOI_HOST)
    path: /healthz
    port: 5641
  periodSeconds: 30
```

If Koi becomes unreachable, the container is marked unhealthy. This is useful when your application depends on service discovery being available.

---

## Troubleshooting

**Container can't reach Koi**

Verify the host is reachable:

```bash
docker run --rm curlimages/curl curl -s http://172.17.0.1:5641/healthz
```

If this fails, check that:
- Koi is running on the host (installed as a service, or `koi --daemon` in the foreground)
- The firewall allows TCP port 5641 (on Windows, `koi install` configures this automatically)
- The container can route to the host (try `ping 172.17.0.1` from inside the container)

On Linux with `host.docker.internal`, you need Docker 20.10+ and either `--add-host=host.docker.internal:host-gateway` or the `extra_hosts` Compose directive.

**Services aren't appearing on the network**

Koi needs multicast access on the host's network interface. Check that:
- The host's firewall allows UDP port 5353 (mDNS)
- The host is on a network that supports multicast (most LANs do; some corporate networks block it)

Run `koi mdns discover` on the host to verify mDNS is working at the host level before debugging the container path.

**Stale registrations after container crash**

Heartbeat-mode registrations expire automatically (default: 90s lease + 30s grace = 120s total). If you used permanent mode (`lease_secs: 0`), stale entries must be removed manually:

```bash
# From the host
koi mdns admin ls
koi mdns admin unregister <id>
```

Or via the HTTP API from another container:

```bash
curl -s -X DELETE http://$KOI_HOST:5641/v1/mdns/admin/unregister/<id>
```

For automatic cleanup, prefer heartbeat mode over permanent mode in containers.

**CORS errors from browser-based containers**

Koi allows all origins (CORS is fully permissive), so this shouldn't happen. If you see CORS errors, they're likely from a reverse proxy between the browser and Koi, not from Koi itself.

---

## Quick reference

```bash
# Health check
curl -s http://$KOI_HOST:5641/healthz

# Browse for HTTP services (SSE stream)
curl -s http://$KOI_HOST:5641/v1/mdns/discover?type=_http._tcp

# Resolve a specific instance
curl -s http://$KOI_HOST:5641/v1/mdns/resolve?name=My%20NAS._http._tcp.local.

# Register a service (heartbeat mode, 90s lease)
curl -s -X POST http://$KOI_HOST:5641/v1/mdns/announce \
  -H 'Content-Type: application/json' \
  -d '{"name": "My App", "type": "_http._tcp", "port": 8080}'

# Register permanently (no heartbeat needed)
curl -s -X POST http://$KOI_HOST:5641/v1/mdns/announce \
  -H 'Content-Type: application/json' \
  -d '{"name": "My App", "type": "_http._tcp", "port": 8080, "lease_secs": 0}'

# Send heartbeat
curl -s -X PUT http://$KOI_HOST:5641/v1/mdns/heartbeat/{id}

# Unregister
curl -s -X DELETE http://$KOI_HOST:5641/v1/mdns/unregister/{id}

# Subscribe to lifecycle events (SSE stream)
curl -s http://$KOI_HOST:5641/v1/mdns/subscribe?type=_http._tcp

# Discover all service types
curl -s http://$KOI_HOST:5641/v1/mdns/discover?type=_services._dns-sd._udp.local.

# DNS lookup
curl -s "http://$KOI_HOST:5641/v1/dns/lookup?name=grafana&type=A"

# DNS list
curl -s http://$KOI_HOST:5641/v1/dns/list

# Add a DNS entry
curl -s -X POST http://$KOI_HOST:5641/v1/dns/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"grafana","ip":"192.168.1.42"}'

# Health status
curl -s http://$KOI_HOST:5641/v1/health/status

# Add a health check
curl -s -X POST http://$KOI_HOST:5641/v1/health/add \
  -H 'Content-Type: application/json' \
  -d '{"name":"db","kind":"tcp","target":"10.0.0.10:5432"}'

# Certmesh status
curl -s http://$KOI_HOST:5641/v1/certmesh/status

# Proxy status
curl -s http://$KOI_HOST:5641/v1/proxy/status
```
