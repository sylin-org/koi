# Defensive Patent Publication

## UDP Datagram Bridging Over HTTP and Server-Sent Events with Lease-Based Binding Management

**Publication Date:** 2026-03-24
**Inventor:** Leo Botinelly (Leonardo Milson Botinelly Soares)
**Publication Type:** Defensive Patent Publication (voluntary prior art disclosure)
**Implementation:** Koi v0.2 -- cross-platform local network service daemon (Rust)

---

## Field of Invention

Network bridging; Container networking; Protocol adaptation; Lease-based resource management; Server-Sent Events.

## Keywords

UDP, HTTP, SSE, Server-Sent Events, datagram, container networking, lease management, heartbeat, binding lifecycle, protocol bridging, socket proxy, resource reaping, base64 encoding, broadcast channel, on-demand binding.

---

## Background and Problem Statement

### The Container-to-Host UDP Socket Problem

Containers (Docker, Kubernetes pods, LXC, systemd-nspawn) run in isolated network namespaces. A network namespace provides a container with its own set of network interfaces, routing tables, and socket bindings, separate from the host's network namespace. This isolation is fundamental to container security and multi-tenancy.

For TCP services, container networking provides well-established port mapping mechanisms. Docker's `-p` flag (`docker run -p 8080:80`) creates iptables rules (or equivalent) that forward TCP connections from a host port to a container port. Kubernetes Services provide similar TCP load balancing. TCP port mapping is configured at container creation time and remains static for the container's lifetime.

UDP socket binding presents fundamentally different challenges:

1. **Static configuration at creation time.** Docker's `-p` flag supports UDP (`-p 5000:5000/udp`), but the mapping must be specified when the container is created. An application that discovers it needs a UDP socket at runtime (e.g., a game server that allocates UDP ports for individual game sessions, an IoT gateway that binds to different multicast groups based on discovered devices, or a VoIP application that negotiates UDP media ports via SIP signaling) cannot request new host UDP sockets without container reconfiguration.

2. **Bind-to-all-interfaces limitation.** Docker's UDP mapping binds to all host interfaces (or a single specified IP) at a single port. An application that needs to bind to a specific interface dynamically, or that needs to bind and release ports frequently, cannot do so through Docker's static mapping.

3. **No lifecycle management.** If a container process crashes or is killed, the port mapping persists until the container is removed. For UDP, this means the host port remains allocated (though the receiving socket in the container namespace is gone), potentially causing resource exhaustion if containers are created and destroyed frequently.

4. **Kubernetes NetworkPolicy limitations.** Kubernetes NetworkPolicies can restrict UDP traffic between pods but do not provide a mechanism for a pod to dynamically bind to host UDP sockets. HostPort in Kubernetes is available but limited (binds to a specific node, no load balancing, conflicts with other pods requesting the same host port).

### Use Cases Requiring Dynamic UDP Binding

- **Game servers**: A game server process running in a container needs to allocate a dedicated UDP socket for each game session. The number of sessions (and therefore required sockets) varies at runtime.
- **IoT gateways**: An IoT gateway in a container discovers devices via mDNS and needs to bind host UDP sockets for CoAP (Constrained Application Protocol, which runs over UDP) communication with each device.
- **VoIP/SIP**: SIP (Session Initiation Protocol) negotiates UDP media ports dynamically via SDP (Session Description Protocol). The media ports must be reachable from the network, requiring host-level UDP sockets.
- **DNS forwarders**: A containerized DNS resolver needs to bind to host UDP port 53. If the container is restarted, the new instance must re-bind.
- **TFTP servers**: TFTP (Trivial File Transfer Protocol) uses a well-known port (69) for initial contact but allocates a random ephemeral UDP port for each transfer session.
- **Custom UDP protocols**: Any application-specific UDP protocol where the container needs to send and receive datagrams on the host network.

### Existing Approaches and Their Limitations

#### 1. TURN (Traversal Using Relays around NAT, RFC 5766)

TURN provides relay services for UDP and TCP when direct peer-to-peer communication is impossible due to NAT. A TURN client allocates a relayed transport address on a TURN server, and the server relays datagrams between the client and peers.

TURN is:

- **Designed for NAT traversal**, not container-to-host bridging. TURN servers are deployed on the public internet or in DMZ zones, not on the same host as the application.
- **Uses the STUN binary protocol** (RFC 5389) for allocation, refresh, and data indication. STUN messages are binary TLV (Type-Length-Value) encoded, not HTTP/JSON. This requires a STUN client library in the container.
- **Has its own allocation lifetime mechanism** using STUN Refresh requests (not HTTP heartbeats). The default lifetime is 10 minutes (RFC 5766 Section 2.2). Refreshes use STUN messages, not HTTP PUT.
- **Authentication uses long-term credentials** (RFC 5389 Section 10) with HMAC-SHA1 message integrity. This is a fundamentally different auth model than API keys or tokens.
- **Complex channel binding and permission model**: TURN requires creating permissions for each peer address and optionally binding channels for efficiency. This complexity is necessary for internet-scale NAT traversal but unnecessary for same-host container bridging.
- **Does not provide SSE-based datagram delivery**: TURN delivers relayed data through the STUN data indication mechanism or through ChannelData messages, both binary formats. There is no web-friendly event stream interface.

In summary, TURN solves a different problem (NAT traversal) with a different protocol (STUN binary) in a different network context (internet-scale) than the container-to-host bridging described here.

#### 2. wstunnel (WebSocket Tunnel)

wstunnel is an open-source tool that tunnels TCP and UDP over WebSocket or HTTP/2 connections. It operates as a client-server pair:

- The server runs on the host and listens for WebSocket connections
- The client runs in the container and creates local sockets that tunnel through the WebSocket connection to the server

wstunnel:

- **Requires WebSocket protocol support** in both client and server environments. Not all HTTP proxies, load balancers, or corporate firewalls support WebSocket upgrade.
- **Uses persistent connections**: A single WebSocket connection carries all tunneled traffic. Connection drop requires reconnection and re-establishment of all tunnels.
- **No lease-based lifecycle management**: Tunnels exist for the duration of the WebSocket connection. There is no independent lease per tunnel with heartbeat renewal.
- **Point-to-point architecture**: Each wstunnel client-server pair creates a single tunnel. There is no API for dynamically creating and destroying multiple UDP bindings.
- **No HTTP API**: Tunnel configuration is done via command-line arguments at startup, not through runtime API calls.

#### 3. Docker Port Mapping (`-p`)

Docker's `-p` flag creates static port mappings at container creation time:

```
docker run -p 5000:5000/udp myimage
```

Limitations:

- **Static**: Cannot add or remove port mappings after container creation. Requires stopping, removing, and recreating the container.
- **All-or-nothing interface binding**: Binds to `0.0.0.0` (all interfaces) or a single specified IP. No per-binding interface selection at runtime.
- **No lifecycle management**: The mapping exists for the container's lifetime, regardless of whether the application inside is actually using the port.
- **No heartbeat/lease**: If the application inside the container stops listening, the port mapping remains, occupying the host port.
- **No send-through-binding**: Docker port mapping only forwards incoming traffic to the container. An application that needs to send UDP datagrams from a specific host port (e.g., for NAT hole punching or source-port-dependent protocols) cannot use Docker port mapping for outbound traffic with a controlled source port.

#### 4. WebRTC Data Channels

WebRTC provides peer-to-peer communication with DTLS/SCEP transport, including unreliable (UDP-like) data channels:

- **Vastly more complex than needed**: WebRTC requires ICE negotiation (STUN binding, TURN allocation, connectivity checks), DTLS handshake, SCTP association setup, and SDP offer/answer exchange. This infrastructure is designed for browser-to-browser communication.
- **Requires signaling server**: WebRTC peers exchange SDP offers/answers through an external signaling mechanism (typically WebSocket + a signaling server).
- **No raw UDP access**: WebRTC data channels provide an abstraction over UDP, not direct access to a host UDP socket. The application cannot control source ports, bind addresses, or send to arbitrary destinations.
- **Designed for peer-to-peer**: Not for container-to-host socket delegation.

#### 5. socat / netcat

Unix command-line tools that can relay data between different network socket types:

```
socat UDP-LISTEN:5000,fork TCP:localhost:6000
```

- **Point-to-point relay**: Each socat instance handles one socket pair. Managing N UDP bindings requires N socat processes.
- **No API**: Configuration is via command-line arguments. No runtime binding creation/destruction.
- **No lifecycle management**: No lease, no heartbeat, no automatic cleanup.
- **No structured datagram delivery**: socat passes raw bytes, not structured messages with metadata (source address, timestamp).
- **No multiplexing**: Each binding requires a separate process, each with its own memory footprint and process management overhead.

#### 6. Host Networking Mode

Docker and Kubernetes support "host network mode" where the container shares the host's network namespace:

```
docker run --network=host myimage
```

- **Eliminates isolation**: The container can bind any host port directly, but also sees all host network interfaces, routes, and other sockets. This defeats the purpose of container network isolation.
- **Security concern**: A compromised container with host networking has full network access to the host and all other containers.
- **Single-tenant only**: Only one container can use host networking effectively (port conflicts between containers).
- **Not available in all environments**: Kubernetes restricts host networking through PodSecurityPolicies/PodSecurityStandards. Many managed Kubernetes providers (EKS Fargate, Cloud Run) do not support host networking.

### The Gap

No existing system provides:

1. An HTTP API for on-demand creation and destruction of host UDP socket bindings from within a container
2. Server-Sent Events (SSE) delivery of incoming datagrams with structured metadata (source address, base64-encoded payload, timestamp)
3. HTTP-based outbound datagram sending through a specific binding
4. Lease-based lifecycle management with heartbeat renewal and automatic reaping of expired bindings
5. Multiple concurrent bindings managed through a single API endpoint
6. No container reconfiguration required -- bindings are created at application runtime

The invention described herein fills this gap.

---

## Detailed Technical Description

### 1. System Architecture

The system is a service running on the host machine (not inside a container). It exposes an HTTP API that containers (or any HTTP client) use to create, manage, and communicate through host UDP sockets. The service is implemented as a domain crate (`koi-udp`) within a larger daemon, but the UDP bridging functionality is architecturally independent and can operate standalone.

#### 1.1. Component Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        Host Machine                              │
│                                                                  │
│  ┌──────────────────────┐        ┌───────────────────────────┐   │
│  │   Container A        │        │   UDP Runtime Service     │   │
│  │                      │  HTTP  │                           │   │
│  │  Application ───────────────> │  Binding Manager          │   │
│  │  (HTTP client)       │        │    ├─ Binding "abc123"    │   │
│  │                      │        │    │   ├─ UdpSocket       │   │
│  └──────────────────────┘        │    │   ├─ Relay Task      │   │
│                                  │    │   ├─ Broadcast Chan   │   │
│  ┌──────────────────────┐        │    │   └─ Lease State     │   │
│  │   Container B        │        │    ├─ Binding "def456"    │   │
│  │                      │  HTTP  │    │   ├─ UdpSocket       │   │
│  │  Application ───────────────> │    │   ├─ Relay Task      │   │
│  │  (HTTP client)       │        │    │   ├─ Broadcast Chan   │   │
│  │                      │        │    │   └─ Lease State     │   │
│  └──────────────────────┘        │    └─ ...                 │   │
│                                  │                           │   │
│                                  │  Reaper Task (30s loop)   │   │
│                                  │    └─ Closes expired      │   │
│                                  │       bindings            │   │
│                                  └────────────┬──────────────┘   │
│                                               │                  │
│                                    ┌──────────┴──────────┐       │
│                                    │   Host Network      │       │
│                                    │   Interfaces         │       │
│                                    │   (eth0, wlan0, etc)│       │
│                                    └─────────────────────┘       │
└──────────────────────────────────────────────────────────────────┘
```

#### 1.2. Core Data Structures

**UdpRuntime**: The top-level manager. Contains:
- `bindings`: A concurrent map (`Arc<RwLock<HashMap<String, ActiveBinding>>>`) from binding ID to active binding
- `cancel`: A `CancellationToken` for graceful shutdown
- `_reaper_handle`: The background reaper task handle

**ActiveBinding**: Represents a single host UDP socket binding. Contains:
- `id`: Unique binding identifier (UUIDv7 string)
- `local_addr`: The actual bound socket address (`SocketAddr`)
- `created_at`: Creation timestamp (`DateTime<Utc>`)
- `lease_secs`: Lease duration in seconds
- `last_heartbeat`: Last heartbeat timestamp (`Arc<RwLock<DateTime<Utc>>>`)
- `tx`: Broadcast channel sender for incoming datagrams
- `socket`: Shared reference to the UDP socket (`Arc<UdpSocket>`)
- `binding_cancel`: Child cancellation token for this binding's relay task
- `relay_handle`: Handle to the background relay task

**UdpDatagram**: A received datagram, relayed to subscribers. Contains:
- `binding_id`: Which binding received the datagram
- `src`: Source address as string (e.g., "192.168.1.50:9090")
- `payload`: Base64-encoded datagram payload
- `received_at`: Timestamp when the datagram was received

**UdpBindRequest**: Request to create a binding. Contains:
- `port`: Port to bind (0 = OS-assigned ephemeral port)
- `addr`: Bind address (default "0.0.0.0")
- `lease_secs`: Lease duration (default 300 seconds, capped at 86400)

**UdpSendRequest**: Request to send a datagram. Contains:
- `dest`: Destination address as string (e.g., "192.168.1.50:9090")
- `payload`: Base64-encoded datagram payload

**BindingInfo**: Status information for a binding. Contains:
- `id`: Binding identifier
- `local_addr`: Bound socket address
- `created_at`: Creation timestamp
- `last_heartbeat`: Last heartbeat timestamp
- `lease_secs`: Lease duration

### 2. HTTP API Specification

The API is served under the `/v1/udp/` prefix. All request and response bodies are JSON. Error responses use a consistent envelope with `error_code` and `message` fields.

#### 2.1. Create Binding -- `POST /v1/udp/bind`

**Purpose:** Create a new host UDP socket binding.

**Request body:**
```json
{
  "port": 5000,
  "addr": "0.0.0.0",
  "lease_secs": 3600
}
```

All fields are optional:
- `port`: Default 0 (OS-assigned ephemeral port). If non-zero, the service attempts to bind to this exact port. If the port is already in use, the bind fails with an IO error.
- `addr`: Default "0.0.0.0" (all IPv4 interfaces). Can be set to a specific interface address (e.g., "192.168.1.10") or "::0" for all IPv6 interfaces.
- `lease_secs`: Default 300 (5 minutes). Capped at `MAX_LEASE_SECS` (86400 = 24 hours). Values above the cap are silently reduced to the cap.

**Processing:**
1. Parse the bind address from the `addr` and `port` fields into a `SocketAddr`. If parsing fails, return HTTP 400 with `InvalidPayload` error code.
2. Call `tokio::net::UdpSocket::bind(addr)` to create and bind a UDP socket in the host's network namespace. If binding fails (port in use, permission denied, address not available), return HTTP 500 with `IoError` error code.
3. Retrieve the actual local address from the socket (via `socket.local_addr()`). This is important when `port` is 0 -- the OS assigns an ephemeral port, and the actual port must be communicated back to the caller.
4. Generate a unique binding ID using UUIDv7 (`uuid::Uuid::now_v7().to_string()`). UUIDv7 is time-ordered, which provides natural chronological sorting of binding IDs.
5. Create an `ActiveBinding` with the socket, ID, timestamps, lease duration, broadcast channel (capacity 512), and spawn the relay task (described in Section 3).
6. Insert the binding into the `bindings` map under a write lock.

**Response (HTTP 201 Created):**
```json
{
  "id": "019503a1-7c00-7def-8000-1a2b3c4d5e6f",
  "local_addr": "0.0.0.0:5000",
  "created_at": "2026-03-24T12:00:00Z",
  "last_heartbeat": "2026-03-24T12:00:00Z",
  "lease_secs": 3600
}
```

#### 2.2. Close Binding -- `DELETE /v1/udp/bind/{id}`

**Purpose:** Close a UDP binding and release the socket.

**Path parameter:** `id` -- the binding ID returned by the bind operation.

**Processing:**
1. Acquire a write lock on the `bindings` map.
2. Remove the binding by ID. If not found, return HTTP 404 with `NotFound` error code.
3. Call `binding.shutdown()` which cancels the relay task (via `CancellationToken::cancel()`) and drops the `JoinHandle`.
4. The `UdpSocket` is dropped when the `ActiveBinding` is dropped, which closes the OS socket and releases the port.

**Response (HTTP 200):**
```json
{
  "unbound": "019503a1-7c00-7def-8000-1a2b3c4d5e6f"
}
```

#### 2.3. Receive Datagrams -- `GET /v1/udp/recv/{id}`

**Purpose:** Subscribe to incoming datagrams on a binding via Server-Sent Events.

**Path parameter:** `id` -- the binding ID.

**Query parameters:**
- `idle_for` (optional): Seconds of silence before the SSE stream closes.
  - Absent: Keep open indefinitely (default for UDP streams -- UDP applications typically expect long-lived connections)
  - `0`: Keep open indefinitely (explicit infinite)
  - `N` (positive integer): Close the stream after N seconds of no datagrams

**Processing:**
1. Acquire a read lock on the `bindings` map.
2. Look up the binding by ID. If not found, return HTTP 404.
3. Call `binding.subscribe()` to get a `broadcast::Receiver<UdpDatagram>` from the binding's broadcast channel.
4. Create an SSE stream that:
   a. Waits for the next datagram from the broadcast receiver (with optional idle timeout)
   b. Serializes the `UdpDatagram` to JSON
   c. Yields an SSE `Event` with:
      - `id`: A new UUIDv7 (for SSE event ID, enabling last-event-id reconnection semantics)
      - `event`: "datagram" (SSE event type)
      - `data`: JSON-serialized datagram
   d. If the broadcast receiver reports a lag (too many datagrams buffered, subscriber fell behind), skips the lagged messages and continues
   e. If the broadcast channel is closed (binding removed), ends the stream
   f. If idle timeout fires, ends the stream
5. Return the SSE stream with keep-alive enabled (periodic `:` comments to prevent intermediate proxies from closing idle connections).

**SSE event format:**
```
id: 019503a1-7c01-7abc-8000-aabbccddeeff
event: datagram
data: {"binding_id":"019503a1-7c00-7def-8000-1a2b3c4d5e6f","src":"192.168.1.50:9090","payload":"SGVsbG8gV29ybGQ=","received_at":"2026-03-24T12:00:01Z"}

```

Multiple clients can subscribe to the same binding simultaneously. Each subscriber receives all datagrams (broadcast semantics). The broadcast channel has a capacity of 512 events; if a subscriber falls behind by more than 512 events, it receives a `RecvError::Lagged` which the stream handler skips (continues listening for new events).

#### 2.4. Send Datagram -- `POST /v1/udp/send/{id}`

**Purpose:** Send a UDP datagram through a binding's socket.

**Path parameter:** `id` -- the binding ID.

**Request body:**
```json
{
  "dest": "192.168.1.50:9090",
  "payload": "SGVsbG8gV29ybGQ="
}
```

- `dest`: Destination socket address in `host:port` format. Parsed as `SocketAddr`.
- `payload`: Base64-encoded (standard alphabet, with padding) binary payload.

**Processing:**
1. Parse the destination address. If parsing fails, return HTTP 400 with `InvalidAddr` error.
2. Decode the base64 payload. If decoding fails, return HTTP 400 with `InvalidPayload` error.
3. Acquire a read lock on the `bindings` map.
4. Look up the binding by ID. If not found, return HTTP 404.
5. Call `binding.send_to(&payload, dest)` which calls `socket.send_to(&payload, dest)` on the underlying `UdpSocket`.
6. Return the number of bytes sent.

**Response (HTTP 200):**
```json
{
  "sent": 11
}
```

The sent datagram originates from the binding's local address (the address/port returned in the bind response). This means the destination will see the source address as the host's IP and the bound port, not the container's IP. This is a key feature -- the container can control which host port its outgoing UDP traffic comes from.

#### 2.5. Heartbeat -- `PUT /v1/udp/heartbeat/{id}`

**Purpose:** Renew a binding's lease.

**Path parameter:** `id` -- the binding ID.

**Processing:**
1. Acquire a read lock on the `bindings` map.
2. Look up the binding by ID. If not found, return HTTP 404.
3. Call `binding.touch()` which updates `last_heartbeat` to `Utc::now()` using a `try_write` lock. If the lock is contended (rare -- only contends with the reaper's read), the heartbeat is silently skipped (the next heartbeat will succeed).

**Response (HTTP 200):**
```json
{
  "renewed": "019503a1-7c00-7def-8000-1a2b3c4d5e6f"
}
```

The client should call this endpoint periodically, at an interval shorter than `lease_secs`, to prevent the reaper from closing the binding. A common pattern is to heartbeat at `lease_secs / 2` intervals.

#### 2.6. List Bindings -- `GET /v1/udp/status`

**Purpose:** List all active bindings with their metadata.

**Processing:**
1. Acquire a read lock on the `bindings` map.
2. Iterate over all bindings, collecting `BindingInfo` for each.
3. Return the list.

**Response (HTTP 200):**
```json
{
  "bindings": [
    {
      "id": "019503a1-7c00-7def-8000-1a2b3c4d5e6f",
      "local_addr": "0.0.0.0:5000",
      "created_at": "2026-03-24T12:00:00Z",
      "last_heartbeat": "2026-03-24T12:30:00Z",
      "lease_secs": 3600
    }
  ]
}
```

### 3. Relay Task Architecture

Each binding spawns a dedicated relay task that reads from the UDP socket and broadcasts received datagrams to all subscribers.

#### 3.1. Relay Task Lifecycle

The relay task is a Tokio task spawned during binding creation:

```
Relay Task (per binding):
  Allocate 65535-byte receive buffer (maximum UDP datagram size)
  Loop:
    Select:
      - binding_cancel is cancelled → break (shutdown)
      - socket.recv_from(&mut buf) completes:
          If Ok((len, src)):
            Base64-encode buf[..len]
            Construct UdpDatagram { binding_id, src, payload, received_at }
            Send to broadcast channel (ignore send errors = no subscribers)
          If Err(e):
            Log warning, continue (transient errors, e.g., ICMP port unreachable)
  Log "relay task stopped"
```

Key design decisions:

- **65535-byte buffer**: The maximum size of a UDP datagram (limited by the 16-bit length field in the UDP header). This ensures no incoming datagram is truncated.
- **Broadcast channel**: Uses `tokio::sync::broadcast` with capacity 512. This provides multiple-producer, multiple-consumer semantics where every subscriber receives every message. The capacity of 512 was chosen to balance memory usage with burst tolerance.
- **Transient error handling**: Network errors (e.g., ICMP destination unreachable causing `recv_from` to fail on some OSes) are logged and the task continues. Only cancellation causes the task to exit.
- **No subscriber required**: If no subscribers are connected (no SSE streams open), the broadcast channel's `send()` returns an error (no active receivers). This error is intentionally ignored -- datagrams are simply dropped when no one is listening. This prevents unbounded memory growth.

#### 3.2. Cancellation

The relay task holds a child `CancellationToken` derived from the binding's token:

```
parent_cancel (UdpRuntime) → child (binding_cancel)
```

Cancellation occurs in three scenarios:
1. **Explicit unbind**: `DELETE /v1/udp/bind/{id}` calls `binding.shutdown()` which cancels the binding token
2. **Lease expiry**: The reaper removes the binding from the map and calls `binding.shutdown()`
3. **Runtime shutdown**: The parent token is cancelled, which cancels all child tokens

### 4. Lease-Based Lifecycle Management

#### 4.1. Lease Semantics

Each binding has a lease defined by two parameters:
- `lease_secs`: The lease duration, set at bind time, capped at `MAX_LEASE_SECS` (86400 seconds = 24 hours)
- `last_heartbeat`: The timestamp of the most recent heartbeat (or creation time if no heartbeat has been received)

A binding is considered **expired** when:
```
now - last_heartbeat > lease_secs
```

The lease is extended by calling `PUT /v1/udp/heartbeat/{id}`, which updates `last_heartbeat` to the current time.

#### 4.2. Reaper Task

The `UdpRuntime` spawns a background reaper task at creation:

```
Reaper Task:
  Create 30-second interval timer
  Loop:
    Select:
      - runtime_cancel is cancelled → break (shutdown)
      - interval.tick() fires:
          Acquire write lock on bindings map
          Identify all expired bindings:
            For each (id, binding) in map:
              elapsed = now - binding.last_heartbeat
              If elapsed > binding.lease_secs:
                Mark as expired
          Remove expired bindings from map
          For each removed binding:
            Call binding.shutdown() (cancels relay task)
            Log "Reaped expired UDP binding"
```

The reaper runs every 30 seconds. This means a binding may persist up to 30 seconds past its lease expiration. This granularity is acceptable because:
- UDP applications are inherently tolerant of timing imprecision
- The 30-second sweep interval minimizes lock contention (the write lock is held once per sweep, not per heartbeat)
- Expired-but-not-yet-reaped bindings continue to function normally (the socket is still open, datagrams still flow)

#### 4.3. Resource Leak Prevention

The lease mechanism prevents resource leaks in several scenarios:

- **Container crash**: If the container process dies without explicitly unbinding, the lease expires naturally after `lease_secs` with no heartbeats. The reaper closes the socket and frees the port.
- **Network partition**: If the container loses HTTP connectivity to the host service, heartbeats stop arriving. The lease expires and the binding is reaped.
- **Application bug**: If the application forgets to unbind or heartbeat, the lease provides a safety net.
- **Maximum lease cap**: The 86400-second (24-hour) cap prevents a client from requesting an indefinitely long lease, which would effectively disable the reaper for that binding.

### 5. Data Encoding

#### 5.1. Base64 Encoding

UDP datagrams carry arbitrary binary data. Since the HTTP API uses JSON for request and response bodies, and JSON does not natively support binary data, datagram payloads are encoded as Base64 strings.

The encoding uses the **standard Base64 alphabet** (RFC 4648, Table 1) with **padding** (`=`). The standard alphabet uses characters A-Z, a-z, 0-9, +, /. Padding ensures the encoded string length is always a multiple of 4.

Encoding is performed on the host side:
- **Incoming datagrams**: The relay task encodes the raw bytes received from `recv_from` using `base64::engine::general_purpose::STANDARD.encode(&buf[..len])`
- **Outgoing datagrams**: The send handler decodes the base64 payload from the request using `base64::engine::general_purpose::STANDARD.decode(&req.payload)`

Base64 encoding expands the payload by approximately 33% (3 bytes become 4 characters). For a maximum UDP datagram of 65535 bytes, the base64 representation is approximately 87380 characters, well within JSON string limits.

#### 5.2. Address Encoding

Socket addresses (`SocketAddr`) are encoded as strings in `host:port` format:
- IPv4: `"192.168.1.50:9090"`
- IPv6: `"[::1]:9090"` (with brackets per RFC 2732)

This format is human-readable and parseable by standard libraries in all major programming languages.

### 6. Concurrency Model

#### 6.1. Binding Map

The `bindings` map uses `Arc<RwLock<HashMap<String, ActiveBinding>>>`:

- **Arc**: Shared ownership between the runtime, reaper task, and HTTP handlers
- **RwLock**: Multiple concurrent readers (HTTP GET handlers) with exclusive write access (bind, unbind, reaper)
- **HashMap**: O(1) lookup by binding ID

Read operations (subscribe, send, heartbeat, status) acquire a read lock and can execute concurrently. Write operations (bind, unbind, reaper) acquire a write lock and are serialized.

#### 6.2. Heartbeat Timestamp

The `last_heartbeat` field uses `Arc<RwLock<DateTime<Utc>>>` with non-blocking access:

- **Heartbeat update**: Uses `try_write()`. If the lock is contended (e.g., the reaper is reading), the update is silently skipped. This is safe because:
  - The next heartbeat (seconds later) will succeed
  - Missing a single heartbeat update shortens the effective lease by at most one heartbeat interval, not by the full lease duration
- **Reaper read**: Uses `try_read()` with a fallback to `created_at`. If the lock is contended (e.g., a heartbeat is being written), the reaper uses the creation time as a conservative estimate. This may cause premature reaping in rare cases, but the binding would need to be within seconds of expiration for this to matter.

This design avoids blocking the reaper (which holds a write lock on the entire binding map) on individual heartbeat timestamps.

#### 6.3. Broadcast Channel

The `tokio::sync::broadcast` channel provides:
- **Multiple subscribers**: Each `GET /v1/udp/recv/{id}` call creates a new subscriber
- **Bounded buffer**: Capacity 512. If a subscriber falls behind by more than 512 messages, it receives a `Lagged` error and skips to the latest message.
- **Automatic cleanup**: When a subscriber (SSE stream) disconnects, its receiver is dropped. When the last subscriber disconnects, subsequent `send()` calls return an error (no receivers), and the relay task ignores this error.
- **Send is non-blocking**: `tx.send()` never blocks the relay task, even if subscribers are slow. Slow subscribers experience lag, not backpressure.

### 7. Complete Data Flow Examples

#### 7.1. Game Server Session

```
1. Game server in container starts
2. POST /v1/udp/bind {"port": 0, "lease_secs": 7200}
   → Response: {"id": "abc", "local_addr": "0.0.0.0:49152", "lease_secs": 7200}
3. Game server advertises port 49152 to game clients
4. GET /v1/udp/recv/abc (SSE stream opens)
5. Game client sends UDP datagram to host:49152
6. SSE event: {"binding_id":"abc","src":"10.0.0.5:12345","payload":"...","received_at":"..."}
7. Game server processes datagram
8. POST /v1/udp/send/abc {"dest":"10.0.0.5:12345","payload":"..."}
   → Datagram sent from host:49152 to 10.0.0.5:12345
9. [Every 3600s] PUT /v1/udp/heartbeat/abc
10. Game session ends
11. DELETE /v1/udp/bind/abc
```

#### 7.2. Container Crash Recovery

```
1. Container A binds: POST /v1/udp/bind {"port": 5000, "lease_secs": 300}
   → Binding "abc" created
2. Container A crashes (no unbind, no heartbeat)
3. [After 300s + up to 30s reaper delay] Reaper closes binding "abc", port 5000 released
4. Container A restarts
5. POST /v1/udp/bind {"port": 5000, "lease_secs": 300}
   → New binding "def" created on port 5000 (now available)
```

#### 7.3. Multiple Subscribers

```
1. POST /v1/udp/bind {"port": 5000}
   → Binding "abc" created
2. Client X: GET /v1/udp/recv/abc (SSE stream 1)
3. Client Y: GET /v1/udp/recv/abc (SSE stream 2)
4. External host sends UDP datagram to port 5000
5. Both streams receive: SSE event with the datagram
6. Client X disconnects
7. External host sends another datagram
8. Only Client Y receives the event
```

### 8. Error Handling

#### 8.1. Error Types

| Error | HTTP Status | Error Code | Cause |
|-------|-------------|------------|-------|
| `NotFound` | 404 | `not_found` | Binding ID not in the map (expired, never existed, or already unbound) |
| `InvalidAddr` | 400 | `invalid_payload` | Address string cannot be parsed as `SocketAddr` |
| `Io` | 500 | `io_error` | OS-level socket error (bind failed, send failed) |
| `Base64` | 400 | `invalid_payload` | Payload string is not valid base64 |

#### 8.2. Partial Failure Scenarios

- **Bind fails (port in use)**: HTTP 500 returned. No binding created. Client should retry with a different port or port 0.
- **Send fails (network unreachable)**: HTTP 500 returned. The binding remains active. The client can retry the send.
- **Heartbeat on expired binding**: HTTP 404 returned. The client should create a new binding.
- **Receive on expired binding**: If the binding expires while an SSE stream is open, the broadcast channel is closed (sender dropped), and the stream ends naturally. The client observes the stream closing.

### 9. Security Considerations

#### 9.1. Port Binding Authorization

In the current implementation, any HTTP client that can reach the API can create bindings on any port. For production deployments, access control should be implemented at the HTTP layer:

- Restrict access to localhost (127.0.0.1) to limit binding creation to same-host containers
- Use authentication tokens for binding operations
- Rate-limit binding creation to prevent port exhaustion
- Restrict which ports can be bound (e.g., only ephemeral ports > 1024)

#### 9.2. Resource Exhaustion

Potential resource exhaustion vectors and mitigations:

- **Port exhaustion**: Each binding consumes one host UDP port. The reaper with `MAX_LEASE_SECS` (24 hours) ensures abandoned bindings are eventually released. A per-client binding limit could be added.
- **Memory exhaustion**: Each binding spawns a relay task with a 65535-byte buffer. For 1000 concurrent bindings, this is ~64 MB of buffer space. The broadcast channel adds 512 * sizeof(UdpDatagram) per binding.
- **File descriptor exhaustion**: Each binding consumes one UDP socket file descriptor. The OS file descriptor limit (typically 1024 or 65536) bounds the number of concurrent bindings.

#### 9.3. Datagram Spoofing

The `src` field in `UdpDatagram` reflects the source address reported by `recv_from()`. UDP source addresses can be spoofed. The system faithfully reports what the OS reports and does not attempt to validate source addresses.

### 10. Platform-Specific Behavior

#### 10.1. Socket Options

The `UdpSocket` is created with Tokio's async UDP socket, which uses `socket2` under the hood. Default socket options apply:

- **SO_REUSEADDR**: Not explicitly set. Two bindings to the same port will fail with EADDRINUSE.
- **SO_REUSEPORT**: Not explicitly set. On Linux, this could be enabled to allow multiple sockets on the same port for load balancing.
- **IP_PKTINFO**: Not used. The system reports the socket's `local_addr`, not the specific interface that received the datagram.

#### 10.2. Windows Considerations

On Windows, `UdpSocket::bind("0.0.0.0:0")` binds to all IPv4 interfaces. Windows Firewall may block incoming UDP traffic on dynamically bound ports. The host service may need to be added to the Windows Firewall allow list.

#### 10.3. macOS Considerations

macOS limits the range of ephemeral ports (typically 49152-65535). Binding to privileged ports (< 1024) requires root/admin privileges.

### 11. Variants and Alternative Embodiments

#### 11.1. WebSocket Instead of SSE

The receive mechanism could use WebSocket instead of SSE:
- **Bidirectional**: WebSocket allows both receiving and sending on the same connection, potentially combining the recv and send operations.
- **Binary framing**: WebSocket supports binary frames, eliminating the need for base64 encoding.
- **Connection overhead**: WebSocket requires an HTTP upgrade handshake and maintains a persistent TCP connection. SSE works over standard HTTP and is naturally supported by HTTP proxies.
- **Reconnection**: SSE has built-in reconnection semantics (Last-Event-ID header). WebSocket requires application-level reconnection logic.

The primary embodiment uses SSE because it is simpler, works with all HTTP proxies, and provides built-in reconnection.

#### 11.2. Hex Encoding Instead of Base64

Datagram payloads could be hex-encoded instead of base64:
- Hex is simpler (no padding, no alphabet variants)
- Hex expands by 100% (compared to base64's 33%)
- For large datagrams, base64 is more efficient

#### 11.3. Multicast Group Membership

Bindings could support joining multicast groups:
- `POST /v1/udp/bind` with `multicast_groups: ["239.1.2.3"]`
- The service calls `socket.join_multicast_v4()` for each group
- A corresponding `leave_multicast` operation

This would enable containerized applications to participate in multicast protocols (mDNS, SSDP, CoAP multicast) through the host's network.

#### 11.4. Source Address Filtering

Bindings could filter incoming datagrams by source address:
- `POST /v1/udp/bind` with `allow_sources: ["192.168.1.0/24"]`
- The relay task checks the source address against the allow list before broadcasting

#### 11.5. Persistent Bindings

Bindings could be persisted to disk and restored across service restarts:
- On service shutdown, serialize all binding metadata (port, address, lease)
- On service startup, re-bind the same ports and resume heartbeat tracking
- This would prevent port-change disruptions during service upgrades

#### 11.6. Binding Transfer

A binding could be "transferred" from one container to another:
- Container A creates binding "abc"
- Container B calls `POST /v1/udp/transfer/abc` with a token from Container A
- Ownership transfers: Container B now heartbeats and receives

#### 11.7. Rate Limiting Per Binding

Send and receive rates could be limited per binding:
- `POST /v1/udp/bind` with `max_send_rate: 1000, max_recv_rate: 5000` (datagrams per second)
- The relay task and send handler enforce the rate limits
- Excess datagrams are dropped with appropriate error responses

#### 11.8. QoS / DSCP Marking

Outgoing datagrams could have DSCP (Differentiated Services Code Point) values set:
- `POST /v1/udp/send/{id}` with `dscp: 46` (Expedited Forwarding for VoIP)
- The service sets `IP_TOS` socket option before sending

### 12. Comparison with Related Work

| Feature | UDP-HTTP-SSE Bridge | TURN (RFC 5766) | wstunnel | Docker -p | socat |
|---------|-------------------|-----------------|----------|-----------|-------|
| Protocol | HTTP + SSE (JSON) | STUN binary | WebSocket | iptables | Raw streams |
| On-demand binding | Yes (runtime API) | Yes (Allocate) | No (startup config) | No (creation time) | No (startup) |
| Lease management | HTTP heartbeat | STUN Refresh | Connection-based | Container lifetime | None |
| Multiple bindings | Single API | Multiple allocations | Multiple tunnels | Multiple -p flags | Multiple processes |
| Datagram metadata | src, timestamp, id | Limited | None | None | None |
| Auto-reaping | Yes (30s sweep) | Yes (allocation timeout) | Connection close | Container removal | Manual |
| Scope | Container-to-host | NAT traversal | Point-to-point tunnel | Port forwarding | Point-to-point |
| Infrastructure | Same-host service | Dedicated TURN server | Client+server pair | Docker daemon | CLI tool |

---

## Implementation Evidence

The following source files in the Koi v0.2 codebase implement this invention:

- `crates/koi-udp/src/lib.rs` -- `UdpRuntime` struct, `bind()`, `unbind()`, `subscribe()`, `send()`, `heartbeat()`, `status()`, reaper loop, `MAX_LEASE_SECS` constant, public types (`UdpDatagram`, `UdpBindRequest`, `UdpSendRequest`, `BindingInfo`, `UdpError`)
- `crates/koi-udp/src/binding.rs` -- `ActiveBinding` struct, relay task implementation, broadcast channel management, `shutdown()`, `touch()`, `send_to()`
- `crates/koi-udp/src/http.rs` -- HTTP route handlers (`bind_handler`, `unbind_handler`, `recv_handler`, `send_handler`, `status_handler`, `heartbeat_handler`), SSE stream construction, `idle_duration()` helper, OpenAPI schema, route path constants
- `crates/koi/src/adapters/http.rs` -- Routes mounted at `/v1/udp/`
- `crates/koi/src/main.rs` -- `UdpRuntime` creation in daemon mode with `CancellationToken`
- `crates/koi/src/commands/udp.rs` -- CLI commands for bind, unbind, send, status, heartbeat

Unit tests:
- `idle_duration_absent_returns_none_infinite` -- verifies default idle behavior for UDP SSE streams
- `idle_duration_zero_returns_none_infinite` -- verifies explicit infinite idle
- `idle_duration_explicit_value` -- verifies numeric idle timeout parsing

---

## Claims-Style Disclosures

1. A method for bridging UDP datagrams between containerized applications and host network interfaces using an HTTP API, comprising: (a) creating a host-side UDP socket binding via an HTTP POST request specifying port, bind address, and lease duration; (b) spawning a per-binding relay task that reads incoming datagrams from the host socket and broadcasts them through a multi-subscriber channel; (c) delivering incoming datagrams to one or more subscribers via Server-Sent Events streams, with each datagram encoded as a JSON object containing the source address, base64-encoded payload, and reception timestamp; (d) sending outgoing datagrams through the bound socket via HTTP POST with base64-encoded payload and destination address; wherein the binding exists in the host's network namespace (not the container's), all control and data operations use standard HTTP (not STUN binary, WebSocket, or custom protocols), and multiple concurrent bindings are managed through a single API endpoint, distinct from TURN (which uses STUN binary protocol for internet-scale NAT traversal), wstunnel (which uses WebSocket with persistent connections), and Docker port mapping (which is static at container creation time).

2. A method for lease-based UDP socket lifecycle management comprising: (a) associating each UDP binding with a configurable lease duration and a last-heartbeat timestamp; (b) providing an HTTP PUT endpoint for heartbeat renewal that updates the last-heartbeat timestamp; (c) enforcing a maximum lease duration cap (86400 seconds) to prevent indefinite resource retention; (d) running a background reaper task that periodically (every 30 seconds) identifies bindings where the elapsed time since last heartbeat exceeds the lease duration, closes the UDP socket, and removes the binding; wherein expired bindings are automatically cleaned up without client cooperation, preventing resource leaks from crashed containers, network partitions, or application bugs.

3. A system for on-demand host UDP socket binding from containerized environments, comprising: an HTTP-accessible runtime service on the host that maintains a concurrent map of active UDP bindings, each binding comprising a host UDP socket, a relay task broadcasting received datagrams to subscribers via a bounded broadcast channel, a lease with heartbeat renewal, and a cancellation token for orderly shutdown; wherein the system provides six HTTP operations (bind, unbind, receive via SSE, send, heartbeat, status), all operations are identified by a unique binding ID, multiple subscribers can receive datagrams from the same binding simultaneously via broadcast semantics, the relay task handles transient socket errors without termination, and the entire binding lifecycle (creation, datagram relay, heartbeat, expiration, cleanup) is managed through the HTTP API without requiring container reconfiguration, host network mode, or privileged container capabilities.

---

## Antagonist Review Log

### Round 1

**Antagonist:**

1. **Prior art weakness -- no mention of `slirp4netns` or `rootlesskit`.** These tools provide user-mode networking for rootless containers, including UDP port forwarding. The disclosure should address them.

2. **Abstraction gap -- the broadcast channel capacity of 512 is stated but not justified.** Why 512? What happens under sustained high-throughput UDP traffic (e.g., a game server receiving 10,000 datagrams/second)?

3. **Scope hole -- the disclosure does not address IPv6 dual-stack behavior.** Can a binding be created on `[::]` and receive both IPv4 and IPv6 datagrams? What about IPv4-mapped IPv6 addresses?

4. **Reproducibility gap -- the exact UUIDv7 generation method matters for binding ID uniqueness guarantees.** The disclosure says "UUIDv7" but does not specify the randomness source for the random bits in UUIDv7.

5. **Missing edge case -- what if two containers try to bind the same port simultaneously?** The HashMap write lock serializes the bind operations, but two `UdpSocket::bind()` calls to the same port would race at the OS level.

6. **Section 101 exposure -- is "UDP over HTTP" an abstract idea?** The disclosure should emphasize the specific technical combination, not just the concept of protocol bridging.

**Author Revisions:**

1. Added to Section "Existing Approaches":

> **7. slirp4netns / rootlesskit**
>
> These tools provide user-mode networking for rootless (unprivileged) containers. `slirp4netns` implements a user-mode TCP/IP stack (based on libslirp) that translates between the container's TAP device and the host's network stack. `rootlesskit` wraps container runtimes and uses `slirp4netns` as a network driver.
>
> `slirp4netns` supports port forwarding (including UDP) via its `api.sock` Unix socket or the `--port-driver=builtin` option. However:
> - Port forwarding must be configured at container startup or through the management socket (not a standard HTTP API)
> - Uses a user-mode TCP/IP stack, which introduces performance overhead (all packets are processed in userspace)
> - No lease-based lifecycle management -- port forwards persist until explicitly removed or the slirp process exits
> - No structured datagram delivery -- raw packet forwarding, not JSON-encoded events
> - No multi-subscriber semantics -- one consumer per forwarded port
> - Primarily designed for rootless container networking, not as a general-purpose UDP bridging API

2. Expanded Section 3.1 with broadcast channel justification:

> The broadcast channel capacity of 512 is chosen to balance memory usage with burst tolerance. At 512 events, assuming an average `UdpDatagram` size of approximately 1 KB (binding_id + src string + base64 of a 500-byte payload + timestamp), the buffer consumes approximately 512 KB per binding. For 100 concurrent bindings, this is ~50 MB.
>
> Under sustained high throughput (e.g., 10,000 datagrams/second), a subscriber that processes events slower than the arrival rate will lag. After falling 512 events behind, the subscriber receives a `Lagged` error and skips to the latest event. The relay task is never blocked -- it always processes incoming datagrams regardless of subscriber speed. This design prioritizes relay task throughput over subscriber completeness: it is better to drop stale events than to slow down socket reads (which could cause OS socket buffer overflow and kernel-level datagram drops).
>
> For applications requiring guaranteed delivery, the subscriber should process events as fast as they arrive or acknowledge that UDP itself does not guarantee delivery. The broadcast channel's bounded buffer mirrors UDP's inherent best-effort semantics.

3. Added Section 10.4 (IPv6 dual-stack):

> **10.4. IPv6 Dual-Stack Behavior**
>
> When binding to `[::]` (all IPv6 interfaces), behavior depends on the OS:
> - **Linux**: By default, a socket bound to `[::]` receives both IPv6 and IPv4-mapped IPv6 traffic (dual-stack). The `IPV6_V6ONLY` socket option is `0` by default on Linux. IPv4 senders appear as `::ffff:192.168.1.50` in the `src` field.
> - **Windows**: Dual-stack is enabled by default. Same behavior as Linux.
> - **macOS/BSD**: `IPV6_V6ONLY` defaults to `1` -- a socket bound to `[::]` receives only IPv6 traffic. To receive IPv4, a separate binding to `0.0.0.0` is needed.
>
> The system does not explicitly set `IPV6_V6ONLY`. Applications requiring dual-stack on macOS should create two bindings (one IPv4, one IPv6).

4. Clarified UUIDv7 in Section 2.1: "Generate a unique binding ID using UUIDv7 (`uuid::Uuid::now_v7().to_string()`). The `uuid` crate's `now_v7()` uses the current system time for the 48-bit timestamp component and the system's CSPRNG (via `getrandom`) for the random bits, providing collision resistance of 2^74 for IDs generated within the same millisecond."

5. Added Section 9.3 (concurrent bind to same port):

> **9.3. Concurrent Bind to Same Port**
>
> If two containers simultaneously request a binding on the same port (e.g., both POST `{"port": 5000}`), the operations are serialized as follows:
> 1. Both HTTP handlers execute concurrently up to the `UdpSocket::bind()` call
> 2. The first `bind()` succeeds and acquires the OS port
> 3. The second `bind()` fails with `EADDRINUSE` (address already in use)
> 4. The first handler acquires the write lock on the bindings map and inserts its binding
> 5. The second handler returns HTTP 500 with an IO error
>
> There is no TOCTOU race because the OS enforces exclusive port binding. The HashMap write lock serializes the map insertion (not the socket bind), so two bindings with different IDs but the same port cannot both exist in the map.

6. The disclosure emphasizes specific technical implementation throughout (specific data structures, concurrency primitives, channel semantics, reaper algorithm, SSE event format). The combination of HTTP-based binding creation + SSE datagram delivery + lease-based reaping + broadcast multi-subscriber channels is the specific technical contribution, not the abstract concept of "UDP over HTTP."

### Round 2

**Antagonist:**

1. **Missing edge case -- what happens to in-flight SSE events when a binding is reaped?** If a subscriber is connected to `GET /recv/{id}` and the binding is reaped (removed from the map), does the SSE stream receive a termination event or just silently close?

2. **Prior art gap -- `sozu` (Clever Cloud's reverse proxy) supports UDP.** Should be evaluated.

3. **Terminology drift -- "binding" vs "allocation" vs "mapping".** The disclosure uses "binding" consistently, but TURN uses "allocation" and Docker uses "mapping." The relationship between these terms should be explicit.

**Author Revisions:**

1. Added to Section 8.2:

> **Binding reaped during active SSE stream**: When the reaper removes a binding, it calls `binding.shutdown()` which drops the `ActiveBinding` struct. This drops the `broadcast::Sender<UdpDatagram>`, closing the broadcast channel. All active `broadcast::Receiver` instances (held by SSE stream handlers) will receive `None` on their next `recv()` call (channel closed), causing the SSE stream's `async_stream` generator to break out of its loop and end the stream. The client observes the SSE connection closing (TCP FIN). No explicit termination event is sent -- the stream simply ends. The client can distinguish between idle timeout (if `idle_for` was set) and binding removal by calling `GET /v1/udp/status` to check if the binding still exists.

2. Evaluated `sozu`:

> **8. Sozu (Clever Cloud reverse proxy)**
>
> Sozu is an HTTP reverse proxy written in Rust that supports hot configuration reloading. While Sozu can proxy HTTP and HTTPS traffic, it does not provide UDP socket binding or datagram relay capabilities. Sozu's architecture is designed for HTTP request routing (load balancing, TLS termination, virtual hosting), not for creating arbitrary UDP sockets on demand. Sozu does not have a mechanism for containerized applications to request host UDP sockets.

3. Added terminology note to Section 1:

> **Terminology note**: This disclosure uses "binding" to mean the creation and ownership of a host UDP socket. In TURN (RFC 5766), the equivalent concept is an "allocation" -- a relayed transport address allocated on the TURN server. In Docker, the equivalent concept is a "port mapping" -- an iptables rule forwarding host port traffic to a container port. The term "binding" is chosen because it directly corresponds to the OS-level `bind()` system call that creates the socket.

### Round 3

**Antagonist:**

No further objections -- this disclosure is sufficient to block patent claims on the described invention. The disclosure thoroughly describes the architecture, API, relay mechanism, lease lifecycle, concurrency model, data encoding, error handling, security considerations, platform-specific behavior, and variants. Prior art analysis covers TURN, wstunnel, Docker, WebRTC, socat, host networking, and slirp4netns. The claims-style disclosures identify the specific combination of features that distinguishes this system from prior art.
