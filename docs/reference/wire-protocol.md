# mDNS JSON and local IPC

Koi's discovery interfaces share service-record vocabulary. HTTP uses route-specific payloads; local IPC uses newline-delimited JSON commands. The small versioned local-control requests are an additional authenticated IPC contract, not HTTP commands.

## mDNS requests

Each line is one complete JSON request:

```jsonl
{"browse":"_http._tcp"}
{"register":{"name":"My App","type":"_http._tcp","port":8080}}
{"unregister":"a1b2c3d4"}
{"resolve":"My App._http._tcp.local."}
{"subscribe":"_http._tcp"}
{"heartbeat":"a1b2c3d4"}
```

Successful messages use operation-specific fields such as `found`, `registered`, `resolved`, `unregistered` and `renewed`. Errors contain `error` and `message`. Streaming requests keep the connection open and emit individual records/events; clients must parse framing rather than treating a whole stream as one JSON document.

## Service record

| Field | Meaning |
| --- | --- |
| `name` | Human-readable instance label |
| `type` | Canonical DNS-SD type such as `_http._tcp` |
| `host` | Resolved hostname when known |
| `ip` | Address when known |
| `port` | Port when known |
| `txt` | Key/value metadata |

Early `found` observations can be incomplete; `resolved` adds endpoint facts, and `removed` withdraws an observed service. Unresolved data must not be rendered as a verified reachable endpoint. mDNS names and TXT are untrusted observations.

Type input normalization accepts shorthand such as `http` or `_http`, supplies `._tcp` when missing, and handles trailing dot/`.local.`. Output uses canonical DNS-SD forms. Instance/service identity and display text must remain distinct.

## Registration lifetime

HTTP announcements use heartbeat leases (default 90 seconds, with a 30-second grace); the daemon-backed CLI renews while its announcement command remains alive. IPC registrations are session-scoped, with connection loss initiating grace. Explicit standalone announcement owns its local registration until its session ends.

Use the returned ID/lease facts for heartbeat and release. A disconnected observer is not authority to remove another owner's registration. See [HTTP API](http-api.md) for the corresponding routes.

## Authenticated local transport

| Platform | Default endpoint |
| --- | --- |
| Windows | `\\\\.\\pipe\\koi` |
| Linux/macOS | `$XDG_RUNTIME_DIR/koi.sock`, otherwise `/var/run/koi.sock` |

The installed service verifies the recorded operator through the OS peer identity before parsing/returning access information. Version 1 supports:

```jsonl
{"request":"access","version":1}
{"request":"info","version":1}
```

`access` returns the running daemon's matching HTTP endpoint/token and optional resolved data root; HTTP-disabled state produces `http_disabled`. `info` returns non-secret resolved data/configuration paths even when HTTP is disabled. These facts are local-only; they are not exported through public HTTP/Pond.

Windows combines a protected DACL with exact recorded-operator SID verification. Unix admits root and the recorded UID. Clients then use the supplied endpoint/DAT for catalog and preference HTTP operations; these do not introduce another IPC dialect. Treat returned access bytes as credentials.

For identity messages use the separate [trust protocol](trust-protocol.md). For supported-versus-certified workflow evidence use [launch readiness](../launch/README.md).
