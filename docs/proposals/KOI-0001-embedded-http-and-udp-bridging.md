# KOI-0001: Embedded HTTP Self-Hosting & UDP Bridging

**Status:** Draft  
**Date:** 2026-02-16  
**Authors:** Leo Botinelly, Claude  
**Depends On:** Koi Embedded Integration (approved)  
**Depended On By:** zen-garden ORCH-0001, ORCH-0002, ORCH-0003

---

## Abstract

This proposal adds two capabilities to `koi-embedded`:

1. **HTTP self-hosting** — When `http_enabled` is true, koi-embedded spawns its own axum listener (default `:5641`) exposing the same HTTP API surface as standalone Koi. This activates an existing dead config field.

2. **UDP bridging** (`koi-udp`) — A new Koi domain crate that bridges host UDP sockets into HTTP/SSE, allowing containerized applications on Docker bridge networking to receive and send UDP datagrams through the host's network stack.

Together, these give containerized offerings access to the full host network control plane — DNS resolution, mDNS service discovery, TLS proxy management, and UDP mesh participation — without requiring `network_mode: host` or any Garden-specific API wrappers.

**Motivation:** The ORCH offering orchestration suite (ORCH-0001/0002/0003) in zen-garden requires containerized orchestrators to interact with the Garden mesh (UDP port 7184), register DNS names, announce mDNS services, and discover other offerings. None of this is currently possible from Docker bridge networking.

---

## Table of Contents

1. [Background](#background)
2. [Part 1: HTTP Self-Hosting in koi-embedded](#part-1-http-self-hosting-in-koi-embedded)
3. [Part 2: UDP Bridging (koi-udp)](#part-2-udp-bridging-koi-udp)
4. [Part 3: Consumer Wiring (zen-garden)](#part-3-consumer-wiring-zen-garden)
5. [Security Considerations](#security-considerations)
6. [Implementation Phases](#implementation-phases)
7. [Testing](#testing)

---

## Background

### Current State

Moss (zen-garden) embeds `koi-embedded` in-process:

```rust
let koi = koi_embedded::Builder::new()
    .data_dir(koi_data_dir)
    .service_mode(koi_embedded::ServiceMode::EmbeddedOnly)
    .mdns(true)
    .dns_enabled(false)
    .health(false)
    .certmesh(true)
    .proxy(false)
    .build()?;
```

This provides programmatic access via `KoiHandle` sub-handles (`mdns()`, `dns()`, `certmesh()`, etc.), but **no HTTP surface**. The `http_enabled` config field exists in `KoiConfig` but is never read — it's a dead placeholder.

### Container Isolation Problem

Docker containers on default bridge networking have **zero path** back to the host:

| What's missing | Impact |
|---|---|
| No `extra_hosts` | No `host.docker.internal` resolution |
| No env var injection | Containers don't know where Moss or Koi are |
| No custom DNS | Containers can't resolve `.lan` names |
| No UDP access | Containers can't participate in Garden mesh (chirps, beacons) |

The only bridge to host state is a bind-mounted topology directory — a stale snapshot, not a live connection.

### Why This Blocks Orchestration

The AI Capability Router (ORCH-0002) is a containerized offering that needs to:

1. **Listen to Garden mesh** — `stone_chirp` and `tools_beacon` on UDP `:7184` reveal hardware capabilities, VRAM, model loading state, and offering health across all Stones
2. **Register DNS** — The router takes over `ollama.lan` to become the single entry point
3. **Discover instances** — mDNS browse for Ollama instances on the LAN
4. **Get TLS** — Proxy with certmesh-issued certificates for HTTPS

None of these are possible today.

---

## Part 1: HTTP Self-Hosting in koi-embedded

### Approach

Activate the existing `http_enabled` config field. When true, `KoiEmbedded::start()` spawns an axum HTTP listener using the domain route functions already exposed by each Koi crate.

### What Exists Today

Every Koi domain crate already exposes HTTP routes:

| Crate | Function | Prefix |
|-------|----------|--------|
| `koi-mdns` | `koi_mdns::http::routes(core) -> Router` | `/v1/mdns` |
| `koi-dns` | `koi_dns::http::routes(runtime) -> Router` | `/v1/dns` |
| `koi-health` | `koi_health::http::routes(core) -> Router` | `/v1/health` |
| `koi-certmesh` | `certmesh.http_routes() -> Router` | `/v1/certmesh` |
| `koi-proxy` | `koi_proxy::http::routes(runtime) -> Router` | `/v1/proxy` |

The standalone Koi binary (`crates/koi/src/adapters/http.rs`) assembles these into a Router with CORS, `/healthz`, `/v1/status`, and disabled-capability fallbacks (503). This logic is ~150 lines.

### Changes in Koi

#### 1. New config field: `http_port`

```rust
// crates/koi-embedded/src/config.rs
pub struct KoiConfig {
    // ... existing fields ...
    pub http_enabled: bool,     // existing, currently dead
    pub http_port: u16,         // NEW, default 5641
}
```

Builder method:

```rust
pub fn http_port(mut self, port: u16) -> Self {
    self.config.http_port = port;
    self
}
```

#### 2. New module: `crates/koi-embedded/src/http.rs`

Simplified version of `crates/koi/src/adapters/http.rs`:

```rust
pub(crate) async fn start(
    mdns: Option<Arc<MdnsCore>>,
    certmesh: Option<Arc<CertmeshCore>>,
    dns: Option<Arc<DnsRuntime>>,
    health: Option<Arc<HealthRuntime>>,
    proxy: Option<Arc<ProxyRuntime>>,
    port: u16,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let mut app = Router::new()
        .route("/healthz", get(|| async { "OK" }));

    // Mount each enabled domain, 503 fallback for disabled
    app = mount_or_disabled(app, "/v1/mdns", mdns.map(koi_mdns::http::routes));
    app = mount_or_disabled(app, "/v1/dns", dns.map(koi_dns::http::routes));
    // ... certmesh, health, proxy ...

    app = app.layer(CorsLayer::permissive());

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await?;
    Ok(())
}
```

#### 3. Wire into `start()`

In `crates/koi-embedded/src/lib.rs`, after domain cores are created:

```rust
if self.config.http_enabled {
    let cancel = cancel.clone();
    let port = self.config.http_port;
    tasks.push(tokio::spawn(async move {
        if let Err(e) = http::start(
            mdns_core.clone(), certmesh_core.clone(),
            dns_runtime.clone(), health_runtime.clone(),
            proxy_runtime.clone(), port, cancel,
        ).await {
            tracing::error!("koi http adapter failed: {e}");
        }
    }));
}
```

#### 4. New dependency

Add `tower-http` to `crates/koi-embedded/Cargo.toml` (for `CorsLayer`). `axum` is already a dependency.

#### 5. Standalone simplification (optional, later)

The standalone binary's `daemon_mode()` can be simplified to use `koi-embedded` with `http(true)` instead of assembling cores + HTTP adapter itself. This is a dedup opportunity, not a blocker.

### API Surface (unchanged from standalone Koi)

When enabled, the HTTP listener on `:5641` serves the full Koi API:

- `GET /healthz` — liveness probe
- `GET /v1/status` — unified capability status
- `/v1/mdns/*` — 12 endpoints (discover, announce, resolve, subscribe, admin)
- `/v1/dns/*` — 8 endpoints (lookup, list, add, remove, serve, stop)
- `/v1/certmesh/*` — 18 endpoints (join, status, renew, roster, etc.)
- `/v1/health/*` — 4 endpoints (status, list, add, remove)
- `/v1/proxy/*` — 4 endpoints (status, list, add, remove)

Disabled capabilities return `503 {"error":"capability_disabled"}`.

---

## Part 2: UDP Bridging (koi-udp)

### Motivation

Docker bridge networking blocks UDP multicast and broadcast. Containers cannot receive Garden mesh traffic (`stone_chirp`, `tools_beacon` on port 7184) or send UDP datagrams (Wake-on-LAN, SSDP discovery, syslog).

This is the same pattern Koi already applies to other host network primitives:

| Capability | Host primitive | Bridge via HTTP |
|---|---|---|
| mDNS | Multicast 5353 | `/v1/mdns/*` |
| DNS | UDP/TCP 53 | `/v1/dns/*` |
| Proxy | TLS listeners | `/v1/proxy/*` |
| **UDP** | **Raw datagrams** | **`/v1/udp/*`** |

### New Crate: `koi-udp`

A new Koi domain crate following the established pattern.

#### Core Types

```rust
/// A registered UDP binding
pub struct UdpBinding {
    pub id: String,              // unique binding ID (UUID)
    pub name: String,            // human-readable label
    pub port: u16,               // host port to listen on
    pub multicast: Option<IpAddr>, // join multicast group (optional)
    pub share: bool,             // SO_REUSEADDR + SO_REUSEPORT
    pub lease_secs: Option<u64>, // None=90s heartbeat, 0=permanent, N=custom
    pub created_at: DateTime<Utc>,
}

/// An incoming datagram relayed over SSE
pub struct UdpDatagram {
    pub src: IpAddr,
    pub src_port: u16,
    pub data: String,            // base64-encoded payload
    pub len: usize,              // original byte count
    pub ts: u64,                 // unix millis
}

/// Outbound send request
pub struct UdpSendRequest {
    pub dest: IpAddr,
    pub dest_port: u16,
    pub data: String,            // base64-encoded payload
    pub broadcast: Option<bool>, // set SO_BROADCAST
}
```

#### HTTP Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/udp/status` | List active bindings |
| `POST` | `/v1/udp/bind` | Create binding (returns ID) |
| `DELETE` | `/v1/udp/unbind/{id}` | Remove binding |
| `PUT` | `/v1/udp/heartbeat/{id}` | Renew lease |
| `GET` | `/v1/udp/recv/{id}` | SSE stream of incoming datagrams |
| `POST` | `/v1/udp/send` | Send a datagram from host |

#### Bind Request

```json
POST /v1/udp/bind
{
  "name": "garden-mesh",
  "port": 7184,
  "multicast": null,
  "share": true,
  "lease_secs": null
}
→ 201 {"id": "abc123", "port": 7184, "lease_secs": 90}
```

- `share: true` — sets `SO_REUSEADDR` + `SO_REUSEPORT`, allowing coexistence with Moss's own listener on port 7184
- `multicast` — if provided, joins the specified multicast group (for protocols like SSDP on `239.255.255.250`)
- `lease_secs` — follows the same lease model as koi-mdns: `null` = 90s heartbeat, `0` = permanent, `N` = custom heartbeat interval

#### Receive Stream (SSE)

```
GET /v1/udp/recv/abc123
Accept: text/event-stream

data: {"src":"192.168.1.42","src_port":7184,"data":"eyJ0eXBlIjoic3RvbmVfY2hpcnAi...","len":3847,"ts":1739750400000}
data: {"src":"192.168.1.103","src_port":7184,"data":"eyJ0eXBlIjoidG9vbHNfYmVhY29u...","len":5210,"ts":1739750410000}
```

Base64 encoding adds ~33% overhead. For control-plane datagrams (1-5 KB), this produces 1.3-6.7 KB SSE events — well within HTTP throughput.

#### Send Request

```json
POST /v1/udp/send
{
  "dest": "192.168.1.255",
  "dest_port": 9,
  "data": "//8AAAAAAADI...",
  "broadcast": true
}
→ 200 {"sent": true, "bytes": 102}
```

#### Internal Architecture

```
                        koi-udp crate
┌────────────────────────────────────────────────────────────┐
│                                                            │
│  UdpRuntime                                                │
│  ├─ bindings: HashMap<String, UdpBindingState>             │
│  │                                                         │
│  │  UdpBindingState                                        │
│  │  ├─ socket: Arc<UdpSocket>                              │
│  │  ├─ sender: broadcast::Sender<UdpDatagram>              │
│  │  ├─ cancel: CancellationToken                           │
│  │  └─ recv_task: JoinHandle                               │
│  │       └─ loop { socket.recv_from() → sender.send() }   │
│  │                                                         │
│  ├─ send_socket: UdpSocket (shared, for outbound)          │
│  └─ lease_reaper: background task (heartbeat expiry)       │
│                                                            │
│  http::routes(runtime) -> Router                           │
│  ├─ POST /bind     → create socket + spawn recv task       │
│  ├─ GET  /recv/:id → subscribe to broadcast channel → SSE  │
│  ├─ POST /send     → send_socket.send_to()                 │
│  └─ ...                                                    │
└────────────────────────────────────────────────────────────┘
```

Each binding gets:
- A `UdpSocket` with `bind(0.0.0.0:port)` (and `SO_REUSEADDR`/`SO_REUSEPORT` if `share: true`)
- A tokio task running `socket.recv_from()` in a loop, forwarding datagrams into a `broadcast::Sender`
- SSE clients subscribe to that broadcast channel

Lifecycle: when the binding is removed (explicit unbind or lease expiry), the cancel token fires, the recv task ends, and the socket is dropped.

#### Design Scope

UDP bridging is for **control-plane and discovery traffic**:

| Use Case | Fits | Why |
|---|---|---|
| Garden chirps/beacons (`:7184`) | Yes | ~3 KB datagrams, 10-30s intervals |
| SSDP/UPnP discovery | Yes | Small, infrequent |
| Wake-on-LAN | Yes | Fire-and-forget sends |
| CoAP (IoT) | Yes | Small datagrams |
| Syslog (UDP) | Yes | Log forwarding |
| Video/audio streaming | No | Too much throughput for SSE bridge |
| Game servers | No | Latency-sensitive |

### Builder & Config Integration

```rust
// KoiConfig
pub udp_enabled: bool,         // default: false

// Builder
pub fn udp(mut self, enabled: bool) -> Self {
    self.config.udp_enabled = enabled;
    self
}
```

Standalone Koi: `--no-udp` / `KOI_NO_UDP` CLI flag.

---

## Part 3: Consumer Wiring (zen-garden)

These changes are made in the `zen-garden` repo by Moss (the primary consumer of koi-embedded).

### 3a. Docker `extra_hosts`

```rust
// zen-garden: src/moss/src/docker.rs, in install_service()
let host_config = HostConfig {
    port_bindings: Some(port_bindings),
    binds: Some(binds),
    restart_policy: Some(RestartPolicy { ... }),
    extra_hosts: Some(vec![
        "host.docker.internal:host-gateway".to_string(),
    ]),
    ..Default::default()
};
```

This gives every container a DNS entry for the host. Requires Docker 20.10+ (all Garden-supported Stones).

### 3b. Environment Variable Injection

```rust
// zen-garden: src/moss/src/docker.rs, in install_service()
let mut env = env;  // take ownership of caller's env
env.push(format!("KOI_ENDPOINT=http://host.docker.internal:{}", koi_port));
env.push(format!("GARDEN_STONE_ENDPOINT=http://host.docker.internal:{}", moss_port));
env.push(format!("GARDEN_OFFERING_NAME={}", name));
```

| Variable | Value | Purpose |
|---|---|---|
| `KOI_ENDPOINT` | `http://host.docker.internal:5641` | Koi API for DNS/mDNS/UDP/proxy |
| `GARDEN_STONE_ENDPOINT` | `http://host.docker.internal:7185` | Moss API for tools/presence/election |
| `GARDEN_OFFERING_NAME` | The offering name | Self-identification for scoped operations |

### 3c. Enable DNS in Koi Builder

```rust
// zen-garden: src/moss/src/bootstrap/run.rs
let koi = koi_embedded::Builder::new()
    .data_dir(koi_data_dir)
    .service_mode(koi_embedded::ServiceMode::EmbeddedOnly)
    .mdns(true)
    .dns_enabled(true)      // ← was false
    .dns_auto_start(true)   // ← NEW: start DNS resolver at boot
    .certmesh(true)
    .http(true)             // ← NEW: self-host HTTP on :5641
    .udp(true)              // ← NEW: enable UDP bridging
    .build()?;
```

### 3d. Container DNS Configuration (optional, high value)

Point containers at the Stone's DNS resolver for native `.lan` resolution:

```rust
// zen-garden: src/moss/src/docker.rs
let host_config = HostConfig {
    // ... existing fields ...
    dns: Some(vec![resolved_ip.to_string()]),  // e.g. "192.168.1.100"
    ..Default::default()
};
```

This means `curl http://ollama.lan:11434/api/generate` works from inside any container — resolved through Koi's DNS, no code changes.

---

## Security Considerations

### Port 5641 Exposure

Koi HTTP binds `0.0.0.0:5641`, accessible from LAN. This matches standalone Koi behavior and is intentional — Koi is a local network service. If tighter scoping is needed later, bind to `127.0.0.1` + Docker bridge subnet.

### Port 53 Conflict

`systemd-resolved` typically holds port 53 on Linux. Mitigations:
- Koi DNS port is configurable via `DnsConfig::port()`
- Moss already has port remediation logic in `docker.rs` for conflict detection
- Alternative: bind DNS to a non-standard port; Docker's `dns` config works with any port since it's set per-container

### UDP Binding Trust Model

V1 trusts offerings — any container can bind any port. This matches the current trust model where containers get read-write access to topology files. Scoping (port allowlists, offering-level restrictions) can be added later.

### UDP `share` Mode

`SO_REUSEPORT` has platform-specific behavior:
- **Linux**: Multiple sockets receive copies of broadcasts/multicast; unicast is load-balanced (kernel 3.9+)
- For Garden mesh (broadcast to `:7184`), all shared listeners receive all datagrams — correct behavior

---

## Implementation Phases

### Phase 0a: HTTP Self-Hosting in koi-embedded

**Effort:** ~1-2 days  
**Repo:** `koi`

1. Add `http_port: u16` to `KoiConfig` (default 5641) and builder method
2. Add `tower-http` dependency to `koi-embedded`
3. Create `crates/koi-embedded/src/http.rs` — simplified adapter (~150 lines)
4. Wire into `start()`: if `http_enabled`, spawn HTTP task
5. Update standalone to optionally delegate to embedded HTTP (dedup, not blocking)
6. Test: `Builder::new().http(true).mdns(true).build()` → `:5641` serves `/v1/mdns/admin/status`

### Phase 0b: koi-udp Crate

**Effort:** ~3-5 days  
**Repo:** `koi`

1. Create `crates/koi-udp/` following koi-dns/koi-health pattern
2. `UdpRuntime`, `UdpBinding`, `UdpDatagram`, `UdpSendRequest` types
3. `http::routes(runtime) -> Router` with bind/unbind/recv/send/status/heartbeat
4. Lease reaper task (heartbeat expiry, same model as koi-mdns)
5. SSE relay via `broadcast::channel`
6. Wire into koi-embedded: `udp_enabled` config, builder method, spawn in `start()`
7. Wire into standalone: `--no-udp` flag, mount `/v1/udp` routes
8. Test: bind port, send datagram from another process, verify SSE delivery

### Phase 0c: Moss Container Wiring

**Effort:** ~1 day  
**Repo:** `zen-garden`

1. `docker.rs`: Add `extra_hosts` to `HostConfig`
2. `docker.rs` or `job_executors.rs`: Inject `KOI_ENDPOINT`, `GARDEN_STONE_ENDPOINT`, `GARDEN_OFFERING_NAME` env vars
3. `run.rs`: Enable `dns_enabled(true)`, `dns_auto_start(true)`, `http(true)`, `udp(true)` in Koi builder
4. `docker.rs`: Optionally add `dns` config pointing at Stone IP
5. `tool.json`: Update Koi entry — `retired: false`, update description
6. Test: deploy any container offering, verify env vars present, verify `curl http://host.docker.internal:5641/healthz` returns OK from inside container

---

## Testing

### Unit Tests (koi-udp)

- `bind()` with `share: true` — verify `SO_REUSEADDR` set
- `unbind()` — socket dropped, recv task cancelled
- Lease expiry — binding auto-removed after timeout
- Heartbeat — lease renewed
- `send()` — datagram reaches destination
- SSE encoding — base64 round-trip fidelity

### Integration Tests

- Container → Koi HTTP: `curl $KOI_ENDPOINT/healthz` from inside bridge container
- Container → DNS: `nslookup something.lan $STONE_IP` from container
- Container → UDP recv: bind port 7184, verify Stone chirps arrive as SSE events
- Container → UDP send: send datagram from container, verify receipt on host
- Multi-subscriber: two SSE clients on same binding, both receive all datagrams
- Koi lifecycle: `KoiHandle::shutdown()` stops HTTP listener and all UDP bindings

### Manual Verification

- [ ] Koi starts with embedded HTTP → `:5641` is listening
- [ ] `curl http://localhost:5641/healthz` → `OK`
- [ ] `curl http://localhost:5641/v1/dns/status` → DNS running
- [ ] `curl http://localhost:5641/v1/udp/status` → `{"bindings": []}`
- [ ] Deploy container → env vars present (`docker inspect`)
- [ ] From container: `curl http://host.docker.internal:5641/v1/mdns/admin/status`
- [ ] From container: bind UDP 7184, verify chirps stream via SSE
- [ ] Standalone Koi still works unchanged
