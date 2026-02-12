# Koi Embedded Integration Guide (Rust)

This guide shows how to integrate the `koi-embedded` facade into a Rust app, how to exercise the full capability surface in-process, and how to validate HTTP/IPC surfaces without spawning the `koi` binary.

## Quick Start

Add the crate from the workspace:

```rust
use koi_embedded::Builder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let koi = Builder::new().build()?;
    let handle = koi.start().await?;

    // Your app logic here.

    handle.shutdown().await?;
    Ok(())
}
```

## Capability Integration (Direct API)

Each domain is exposed as a handle. Use these for in-process control with typed APIs.

```rust
let handle = koi.start().await?;

// mDNS
let mdns = handle.mdns()?;
let browse = mdns.browse("_koi._tcp").await?;
let _registration = mdns.register(koi_mdns::protocol::RegisterPayload {
    name: "my-service".to_string(),
    service_type: "_koi._tcp".to_string(),
    port: 51515,
    ip: Some("127.0.0.1".to_string()),
    lease_secs: Some(30),
    txt: Default::default(),
})?;

// DNS
let dns = handle.dns()?;
let _ = dns.add_entry(koi_config::state::DnsEntry {
    name: "my-service.lan".to_string(),
    ip: "127.0.0.1".to_string(),
    ttl: None,
})?;

// Health
let health = handle.health()?;
health
    .add_check(koi_health::HealthCheck {
        name: "my-tcp".to_string(),
        kind: koi_health::ServiceCheckKind::Tcp,
        target: "127.0.0.1:1234".to_string(),
        interval_secs: 5,
        timeout_secs: 2,
    })
    .await?;

// Proxy
let proxy = handle.proxy()?;
let _ = proxy.upsert(koi_proxy::ProxyEntry {
    name: "my-proxy".to_string(),
    listen_port: 18080,
    backend: "http://127.0.0.1:18081".to_string(),
    allow_remote: false,
})
.await?;
```

## Events (Stream + Push)

You can observe events as a stream or register a push handler.

```rust
let koi = koi_embedded::Builder::new()
    .events(|event| println!("event: {event:?}"))
    .build()?;

let handle = koi.start().await?;
let mut stream = handle.events();
while let Some(Ok(event)) = stream.next().await {
    println!("stream: {event:?}");
}
```

## In-Process HTTP + IPC Surfaces

The embedded integration binary wires the HTTP and IPC adapters in-process and exercises the same surface that `tests/integration.ps1` covers, without spawning the `koi` binary. This is the fastest path to validate that your embedded integration also satisfies adapter contracts.

Run the integration example:

```bash
cargo run -p koi-embedded --example embedded-integration
```

What it covers:
- Embedded API (mdns/dns/health/certmesh/proxy + event stream)
- HTTP routes for mdns/dns/health/certmesh/proxy, including SSE events
- IPC (named pipe on Windows) for mdns request/response flows

## Certmesh Notes

Certmesh create/destroy touches the trust store and may require elevated permissions on some platforms. The embedded integration example runs certmesh by default. If you embed certmesh in production, ensure your process has the right privileges and the data directory is isolated per environment.

## Tips for Production Integration

- Set `data_dir` to isolate state per process or environment.
- Keep `event_poll_interval_secs` small if you need rapid state updates.
- On startup, explicitly enable/disable capabilities to match your deployment.

## Example Integration Checklist

- `Builder::new().build()` succeeds with defaults
- mDNS register + browse + resolve
- DNS add/lookup/list/remove
- Health add/remove checks + snapshot
- Proxy upsert/list/remove
- Certmesh create/status/enrollment/policy/rotate/destroy
- HTTP surface validation (including SSE)
- IPC surface validation (Windows pipe)

## See Also

- `koi-embedded` example: `crates/koi-embedded/examples/embedded-integration.rs`
- Quickstart: `docs/embedded-quickstart.md`
