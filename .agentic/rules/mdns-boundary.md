---
globs: crates/koi-mdns/src/daemon.rs
alwaysApply: false
---
# mdns-sd Boundary Rules

## The Single Import Rule (CRITICAL)
`crates/koi-mdns/src/daemon.rs` is the ONLY file that may import from the `mdns-sd` crate.
This is enforced by the `no_mdns_sd_outside_daemon_rs` unit test (in `daemon.rs`), which
greps every other `src/*.rs` for `mdns_sd` and fails the build if any appears.

### Rules
- NEVER import `mdns_sd::*` in any other file
- NEVER expose mdns-sd types (ServiceDaemon, ServiceInfo, ServiceEvent, ResolvedService) in public APIs
- ALWAYS convert mdns-sd types to Koi types at the boundary

### Browse Multiplexing (CRITICAL)
mdns-sd keeps exactly **one querier per service type**: a second `browse` of a type
overwrites the first's listener, and `stop_browse` removes the querier *and clears its
cache*. So Koi must never open two raw browses for the same type. The hub inside
`MdnsDaemon` enforces this:

- `subscribe_type(key, is_meta) -> BrowseSubscription` shares **one** real browse per
  canonical type key across N subscribers via a per-type `tokio::sync::broadcast`. The
  first subscriber starts the browse (a pump task owns the single mdns-sd receiver and
  translates events to Koi types); the last drop stops it (refcount + `TypeGuard`).
- Always derive the key with `daemon::canonical_key` (`ServiceType::parse(..).as_str()`,
  or `META_QUERY` for the meta query) so `discover` and `resolve` map to the same browse.
- `resolve()` is a temporary subscription (cache-checked) — it never calls `stop_browse`
  and so can never terminate concurrent subscribers.
- `BrowseSubscription` carries Koi `MdnsEvent`s only; `mdns_sd` types never escape.

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
