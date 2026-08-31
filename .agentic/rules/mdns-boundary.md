---
globs: crates/koi-mdns/src/{provider,native,avahi,daemon}.rs,crates/koi-compose/src/mdns.rs
alwaysApply: false
---
# mDNS Provider Boundary Rules

## The Single Import Rule (CRITICAL)
`crates/koi-mdns/src/native.rs` is the ONLY file that may import from the `mdns-sd` crate.
This is enforced by `mdns_sd_is_isolated_to_the_native_adapter`, which scans every
other Rust source file and fails the build if `mdns_sd` appears.
`crates/koi-mdns/src/avahi.rs` likewise owns all Avahi `zbus`/D-Bus types.

### Rules
- NEVER import `mdns_sd::*` in any other file
- NEVER expose mdns-sd types (ServiceDaemon, ServiceInfo, ServiceEvent, ResolvedService) in public APIs
- ALWAYS convert mdns-sd types to provider-neutral values inside `native.rs`
- `MdnsCore` and `MdnsDaemon` depend only on the `MdnsProvider` port
- `koi-compose/src/mdns.rs` probes once and injects exactly one provider
- A present-but-broken Avahi is an error, never permission to arm native beside it
- Provider recovery stays inside the selected adapter; selection changes only on Koi restart

### Browse Multiplexing (CRITICAL)
The native mdns-sd provider keeps exactly **one querier per service type**: a second `browse` of a type
overwrites the first's listener, and `stop_browse` removes the querier *and clears its
cache*. So Koi must never open two raw browses for the same type. The hub inside
`MdnsDaemon` enforces this:

- `subscribe_type(key, is_meta) -> BrowseSubscription` shares **one** real browse per
  canonical type key across N subscribers via a per-type `tokio::sync::broadcast`. The
  first subscriber starts the browse (a pump task owns the single provider receiver and
  translates observations to Koi types); the last drop stops it (refcount + `TypeGuard`).
- Always derive the key with `daemon::canonical_key` (`ServiceType::parse(..).as_str()`,
  or `META_QUERY` for the meta query) so `discover` and `resolve` map to the same browse.
- `resolve()` is a temporary subscription (cache-checked) — it never calls `stop_browse`
  and so can never terminate concurrent subscribers.
- `BrowseSubscription` carries Koi `MdnsEvent`s only; provider-library types never escape.

### Native Worker Thread Pattern
`NativeMdnsProvider` serializes all mdns-sd operations through a dedicated thread:

```rust
// All operations go through NativeOp enum → worker thread
enum NativeOp {
    Register(Box<ServiceInfo>),
    Unregister(String),
    Browse { service_type, reply },
    StopBrowse(String),
    Shutdown { reply },
}
```

- Fire-and-forget ops (register, unregister, stop_browse): enqueue and return
- Reply ops (browse, shutdown): use oneshot channel for response
- The worker runs on `std::thread` (named `koi-mdns-native`), not tokio

### Type Conversion
```rust
// mdns-sd → provider-neutral observation (happens ONLY in native.rs)
fn resolved_to_service(resolved: &ResolvedService) -> ProviderService {
    // Retain every address plus its interface identity.
}
```

The provider-neutral hub in `daemon.rs` makes the compatibility projection to
`ServiceRecord` (currently one preferred IPv4/IPv6 address).

### Key mdns-sd API Notes
- `ServiceEvent::ServiceResolved` contains `Box<ResolvedService>`, NOT `ServiceInfo`
- `ResolvedService::get_addresses()` returns `HashSet<ScopedIp>`
- `ServiceDaemon::browse()` returns `Receiver<ServiceEvent>` (flume)
- `ServiceDaemon::shutdown()` returns `Result<Receiver<DaemonStatus>>`
