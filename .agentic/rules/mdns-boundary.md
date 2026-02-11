---
globs: src/core/daemon.rs
alwaysApply: false
---
# mdns-sd Boundary Rules

## The Single Import Rule (CRITICAL)
`core/daemon.rs` is the ONLY file that may import from the `mdns-sd` crate.

### Rules
- NEVER import `mdns_sd::*` in any other file
- NEVER expose mdns-sd types (ServiceDaemon, ServiceInfo, ServiceEvent, ResolvedService) in public APIs
- ALWAYS convert mdns-sd types to Koi protocol types at the boundary

### Worker Thread Pattern
MdnsDaemon serializes all mdns-sd operations through a dedicated thread:

```rust
// All operations go through MdnsOp enum → worker thread
enum MdnsOp {
    Register(Box<ServiceInfo>),
    Unregister(String),
    Browse { service_type, reply },
    StopBrowse(String),
    Shutdown { reply },
}
```

- Fire-and-forget ops (register, unregister, stop_browse): enqueue and return
- Reply ops (browse, shutdown): use oneshot channel for response
- The worker runs on `std::thread` (named `koi-mdns-ops`), not tokio

### Type Conversion
```rust
// mdns-sd → Koi (happens ONLY in daemon.rs)
fn resolved_to_record(resolved: &ResolvedService) -> ServiceRecord {
    // Convert addresses: ScopedIp → IpAddr via .to_ip_addr()
    // Use ty_domain field (not get_type())
    // Map properties to txt HashMap
}
```

### Key mdns-sd API Notes
- `ServiceEvent::ServiceResolved` contains `Box<ResolvedService>`, NOT `ServiceInfo`
- `ResolvedService::get_addresses()` returns `HashSet<ScopedIp>`
- `ServiceDaemon::browse()` returns `Receiver<ServiceEvent>` (flume)
- `ServiceDaemon::shutdown()` returns `Result<Receiver<DaemonStatus>>`
