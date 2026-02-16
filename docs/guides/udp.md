# UDP - Datagram Bridging

Docker containers on bridge networking can't touch UDP. No multicast, no broadcast, no raw sockets. If your containerized application needs to participate in a Garden mesh, send Wake-on-LAN packets, or receive SSDP discovery traffic, it's out of luck - the bridge network simply doesn't forward those frames.

Koi's UDP capability bridges this gap. It binds real UDP sockets on the host and relays datagrams over HTTP and SSE - the same pattern Koi already uses for mDNS (multicast → HTTP), DNS (UDP/TCP → HTTP), and proxy (TLS listeners → HTTP). UDP bridging extends this philosophy to arbitrary datagram traffic.

**When to use UDP bridging**: You have a containerized application that needs to receive UDP datagrams from the LAN. A service that needs to send Wake-on-LAN magic packets. An orchestrator that listens for mesh chirps and beacons on a shared UDP port. A CoAP or syslog forwarder. Anything where a container needs datagram access to the host's network stack without `--network=host`.

**When not to use it**: video/audio streaming, game servers, or anything latency-sensitive or throughput-heavy. The HTTP/SSE bridge adds overhead that's negligible for control-plane traffic (1–5 KB datagrams every few seconds) but unacceptable for media streams.

---

## How it works

The lifecycle follows a lease-based model, similar to mDNS registrations:

1. **Bind** - request a host UDP port. Koi opens a real `UdpSocket` on the host and returns a binding ID.
2. **Receive** - subscribe to an SSE stream that delivers incoming datagrams as base64-encoded JSON events.
3. **Send** - POST a base64-encoded payload with a destination address. Koi sends it through the bound socket.
4. **Heartbeat** - extend the lease. Without heartbeats, the binding expires and the socket is closed.
5. **Unbind** - explicitly release the binding and close the socket.

This is entirely HTTP-based. Any language with an HTTP client and SSE support can use it - Python, Go, Node.js, shell scripts. No special SDK, no Unix sockets, no shared memory.

---

## Getting started

UDP bridging is available through the HTTP API when the daemon (or embedded HTTP adapter) is running. The examples below use `curl`, but any HTTP client works.

### Bind a port

```bash
curl -X POST http://localhost:5641/v1/udp/bind \
  -H "Content-Type: application/json" \
  -d '{"port": 7184, "addr": "0.0.0.0", "lease_secs": 300}'
```

```json
{
  "id": "01958f2a-...",
  "local_addr": "0.0.0.0:7184",
  "created_at": "2026-02-16T12:00:00Z",
  "last_heartbeat": "2026-02-16T12:00:00Z",
  "lease_secs": 300
}
```

Use `"port": 0` for an OS-assigned ephemeral port - useful when you just need a socket and don't care which port it lands on.

### Receive datagrams (SSE)

```bash
curl -N http://localhost:5641/v1/udp/recv/01958f2a-...
```

```
event: datagram
data: {"binding_id":"01958f2a-...","src":"192.168.1.42:7184","payload":"eyJ0eXBl...","received_at":"2026-02-16T12:00:05Z"}

event: datagram
data: {"binding_id":"01958f2a-...","src":"192.168.1.103:7184","payload":"eyJ0eXBl...","received_at":"2026-02-16T12:00:10Z"}
```

The `payload` field is base64-encoded. Decode it to get the raw datagram bytes. The `src` field tells you who sent it.

### Send a datagram

```bash
curl -X POST http://localhost:5641/v1/udp/send/01958f2a-... \
  -H "Content-Type: application/json" \
  -d '{"dest": "192.168.1.255:9", "payload": "//8AAAAAAADI..."}'
```

```json
{ "bytes_sent": 102 }
```

The payload is base64-encoded. The datagram is sent from the bound socket, so the source address will be the binding's local address.

### Heartbeat

```bash
curl -X POST http://localhost:5641/v1/udp/heartbeat/01958f2a-...
```

```json
{ "status": "ok" }
```

Send heartbeats at roughly half the lease interval. If you set `lease_secs: 300`, heartbeat every ~150 seconds.

### Check status

```bash
curl http://localhost:5641/v1/udp/status
```

```json
{
  "bindings": [
    {
      "id": "01958f2a-...",
      "local_addr": "0.0.0.0:7184",
      "created_at": "2026-02-16T12:00:00Z",
      "last_heartbeat": "2026-02-16T12:05:00Z",
      "lease_secs": 300
    }
  ]
}
```

### Unbind

```bash
curl -X DELETE http://localhost:5641/v1/udp/bind/01958f2a-...
```

```json
{ "status": "unbound" }
```

The socket is closed immediately and the relay task stops.

---

## HTTP API

All UDP endpoints live under `/v1/udp/`:

| Method   | Path                     | Purpose                               |
| -------- | ------------------------ | ------------------------------------- |
| `POST`   | `/v1/udp/bind`           | Create a new UDP binding              |
| `DELETE` | `/v1/udp/bind/{id}`      | Remove a binding and close the socket |
| `GET`    | `/v1/udp/recv/{id}`      | SSE stream of incoming datagrams      |
| `POST`   | `/v1/udp/send/{id}`      | Send a datagram through a binding     |
| `GET`    | `/v1/udp/status`         | List all active bindings              |
| `POST`   | `/v1/udp/heartbeat/{id}` | Extend a binding's lease              |

### Bind request body

```json
{
  "port": 7184,
  "addr": "0.0.0.0",
  "lease_secs": 300
}
```

| Field        | Type   | Default     | Description                         |
| ------------ | ------ | ----------- | ----------------------------------- |
| `port`       | u16    | `0`         | Host port to bind (0 = OS-assigned) |
| `addr`       | string | `"0.0.0.0"` | Bind address                        |
| `lease_secs` | u64    | `300`       | Lease duration in seconds           |

### Send request body

```json
{
  "dest": "192.168.1.42:7184",
  "payload": "aGVsbG8="
}
```

| Field     | Type   | Description                     |
| --------- | ------ | ------------------------------- |
| `dest`    | string | Destination in `host:port` form |
| `payload` | string | Base64-encoded datagram payload |

### SSE datagram event

```json
{
  "binding_id": "01958f2a-...",
  "src": "192.168.1.42:7184",
  "payload": "aGVsbG8=",
  "received_at": "2026-02-16T12:00:05Z"
}
```

### Error responses

| Condition             | HTTP status | Response                                     |
| --------------------- | ----------- | -------------------------------------------- |
| Binding not found     | 404         | `{"error": "binding not found: <id>"}`       |
| Invalid bind address  | 400         | `{"error": "invalid address: <detail>"}`     |
| Base64 decode failure | 400         | `{"error": "base64 decode error: <detail>"}` |
| Port already in use   | 400         | `{"error": "io error: <detail>"}`            |

---

## Lease model

Bindings follow a lease-based lifecycle identical in spirit to mDNS registrations:

1. A binding is created with a `lease_secs` duration (default 300 seconds / 5 minutes).
2. The heartbeat timestamp is set to creation time.
3. A background reaper checks every 30 seconds for expired leases.
4. If `now - last_heartbeat > lease_secs`, the binding is reaped - the socket is closed and the relay task is cancelled.
5. Sending a heartbeat (`POST /v1/udp/heartbeat/{id}`) updates the timestamp, extending the lease.

This prevents resource leaks. If a container crashes without unbinding, the socket is automatically reclaimed after the lease expires. No orphaned sockets, no port exhaustion.

---

## Embedded usage

When using `koi-embedded` in a Rust application, enable UDP with the builder:

```rust
use koi_embedded::{Builder, ServiceMode};

let koi = Builder::new()
    .service_mode(ServiceMode::EmbeddedOnly)
    .udp(true)
    .build()?;

let handle = koi.start().await?;
let udp = handle.udp()?;
```

### Bind and receive programmatically

```rust
let info = udp.bind(koi_udp::UdpBindRequest {
    port: 0,
    addr: "127.0.0.1".to_string(),
    lease_secs: 300,
}).await?;

// Subscribe to incoming datagrams
let mut rx = udp.subscribe(&info.id).await?;

tokio::spawn(async move {
    while let Ok(datagram) = rx.recv().await {
        println!("from {}: {} bytes", datagram.src, datagram.payload.len());
    }
});
```

### Send programmatically

```rust
use base64::Engine;

let bytes_sent = udp.send(&info.id, koi_udp::UdpSendRequest {
    dest: "192.168.1.42:7184".to_string(),
    payload: base64::engine::general_purpose::STANDARD.encode(b"hello"),
}).await?;
```

### With HTTP adapter

Enable both UDP and the embedded HTTP adapter to expose UDP endpoints over HTTP:

```rust
let koi = Builder::new()
    .service_mode(ServiceMode::EmbeddedOnly)
    .udp(true)
    .http(true)
    .http_port(5641)
    .build()?;
```

Now containers and external clients can reach `/v1/udp/*` on port 5641.

---

## Design scope

UDP bridging is for **control-plane and discovery traffic** - small, infrequent datagrams where the HTTP/SSE overhead is negligible:

| Use case                             | Fits | Why                                |
| ------------------------------------ | ---- | ---------------------------------- |
| Garden mesh chirps/beacons (`:7184`) | Yes  | ~3 KB datagrams, 10–30s intervals  |
| SSDP/UPnP discovery                  | Yes  | Small, infrequent                  |
| Wake-on-LAN                          | Yes  | Fire-and-forget sends              |
| CoAP (IoT)                           | Yes  | Small datagrams                    |
| Syslog (UDP)                         | Yes  | Log forwarding                     |
| Video/audio streaming                | No   | Too much throughput for SSE bridge |
| Game servers                         | No   | Latency-sensitive                  |

Base64 encoding adds ~33% size overhead. For a 3 KB control-plane datagram, that's ~4 KB in the SSE event - well within HTTP throughput for periodic traffic.

---

## Troubleshooting

### Port bind failure

The most common issue. The host port is already in use:

```powershell
# Windows
netstat -ano | findstr :7184

# Linux
ss -ulnp | grep 7184
```

Either stop the conflicting process or use `"port": 0` for an OS-assigned port.

### No datagrams arriving on SSE stream

Check that traffic is actually reaching the bound port. Use a second terminal to send a test datagram:

```bash
echo -n "test" | nc -u -w1 127.0.0.1 <port>
```

If traffic is arriving but the SSE stream shows nothing, verify you're subscribed to the correct binding ID. Each binding has its own SSE endpoint.

### Binding disappeared unexpectedly

The lease expired. The default is 300 seconds (5 minutes). If your client doesn't heartbeat, the reaper closes the socket after the lease runs out. Increase `lease_secs` or implement a heartbeat loop at half the interval.

### Base64 decode errors on send

The `payload` field must be valid standard base64 (RFC 4648, with `+/` alphabet and `=` padding). URL-safe base64 (`-_` alphabet) will produce decode errors. Most language standard libraries default to the correct encoding.
