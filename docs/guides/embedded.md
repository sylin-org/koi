# Embedded Integration

Use `koi-embedded` to run Koi in-process — no daemon, no IPC, no binary dependency. This is the right choice when your Rust application needs mDNS, DNS, health checks, or certmesh as a library rather than an external service.

---

## Quick start

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

That gives you all capabilities with sane defaults. For selective capabilities:

```rust
let koi = Builder::new()
    .mdns(true)
    .dns_enabled(true)
    .health(false)
    .certmesh(false)
    .proxy(false)
    .build()?;
```

---

## DNS configuration

```rust
let koi = Builder::new()
    .dns(|cfg| cfg.zone("lan").port(5353))
    .dns_auto_start(true)
    .build()?;
```

---

## Capability handles

Each domain is exposed as a typed handle. Use these for in-process control without HTTP round-trips.

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

---

## Events

Events are push-based via broadcast channels — no polling. You can register a handler or consume as a stream:

```rust
let koi = Builder::new()
    .events(|event| println!("event: {event:?}"))
    .build()?;

let handle = koi.start().await?;
let mut stream = handle.events();
while let Some(Ok(event)) = stream.next().await {
    println!("stream: {event:?}");
}
```

---

## In-process adapter validation

The embedded integration example wires HTTP and IPC adapters in-process, exercising the same surface as `tests/integration.ps1` without spawning the binary:

```bash
cargo run -p koi-embedded --example embedded-integration
```

This validates: mDNS, DNS, health, certmesh, and proxy HTTP routes (including SSE), plus IPC flows on Windows.

---

## Certmesh notes

Certmesh create/destroy touches the trust store and may require elevated permissions. Certmesh initialization checks disk state on startup: no CA → `CertmeshCore::uninitialized()`; roster exists but key not decrypted → `CertmeshCore::locked()`. Use the ceremony protocol to create or unlock.

---

## Production tips

- Set `data_dir` to isolate state per process or environment
- Events are zero-latency broadcast channels — no file polling
- Explicitly enable/disable capabilities to match your deployment
- The facade contains zero domain logic — it composes existing crates

---

## Re-exported types

`koi-embedded` re-exports key types for convenience:

- `KoiConfig`, `ServiceMode`, `DnsConfigBuilder` from `koi-config`
- `KoiEvent` from `koi-embedded::events`
- `KoiHandle`, `MdnsHandle`, `DnsHandle`, `HealthHandle`, `CertmeshHandle`, `ProxyHandle`

---

## Integration checklist

- [ ] `Builder::new().build()` succeeds with defaults
- [ ] mDNS register + browse + resolve
- [ ] DNS add/lookup/list/remove
- [ ] Health add/remove checks + snapshot
- [ ] Proxy upsert/list/remove
- [ ] Certmesh create/status/enrollment/policy/rotate/destroy
- [ ] HTTP surface validation (including SSE)
- [ ] IPC surface validation (Windows pipe)

See also: `crates/koi-embedded/examples/embedded-integration.rs`
