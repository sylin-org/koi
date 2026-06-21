# Embedded Integration

Use `koi-embedded` to run Koi in-process - no daemon, no IPC, no binary dependency. This is the right choice when your Rust application needs mDNS, DNS, health checks, or certmesh as a library rather than an external service.

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
    .udp(false)
    .build()?;
```

---

## Cargo features: lean builds

There are **two independent axes** for trimming Koi, and they do different things:

- **Runtime toggles** (the `Builder` above) decide which capabilities *run*. Everything
  is still *compiled* — you just don't start it.
- **Cargo features** (this section) decide which optional, heavy, version-locked
  *dependencies* are *compiled at all*. Use these to shrink build time and the dependency
  closure for a deployment that will never use a given backend.

Three dependencies are gated behind **default-on** features, so a default
`koi-embedded = "0.4"` is identical to before — you only opt *out*:

| Feature | Default | Compiles in | With it **off** |
| --- | --- | --- | --- |
| `docker` | on | `bollard` Docker/Podman client (and its `=`-pinned `bollard-stubs`) | the runtime adapter is present, but the Docker/Podman/Auto backend resolves to `BackendUnavailable` |
| `keyring` | on | OS credential store (Keychain / Windows Cred Manager / Linux **Secret Service + D-Bus**) | the vault uses its passphrase backend; certmesh CA-key sealing and TOTP unlock slots fall back to passphrase |
| `qr` | on | `qrcode` + the `image` PNG codec (enrollment QR rendering) | QR renderers return the `otpauth://` URI as text (still scannable / typeable) |

`full = ["docker", "keyring", "qr"]` is a convenience umbrella for "everything".

### Recipes

```toml
# Default — every backend (unchanged; the batteries-included path)
koi-embedded = "0.4"

# Lean — drop bollard, the OS-keychain / Secret-Service / D-Bus stack, and the image
# codec. Ideal for a headless container that only needs discovery / DNS / health.
koi-embedded = { version = "0.4", default-features = false }

# À la carte — start lean and re-arm only what you need
koi-embedded = { version = "0.4", default-features = false, features = ["docker"] }

# Everything, explicitly
koi-embedded = { version = "0.4", features = ["full"] }
```

A common reason to go lean is the **bollard version lock**: `bollard-stubs` pins with an
exact `=` version, so if *your* app also uses `bollard` and the defaults compile koi's
copy, you are pinned to koi's bollard line. `default-features = false` removes koi's
bollard entirely so you own your version; add `features = ["docker"]` back only if you
want koi's Docker backend too (and can share the version).

### What a feature-off build does at runtime

No call sites change — the APIs stay; only the behavior degrades gracefully:

- **`docker` off** — if you enabled the runtime adapter (`Builder::runtime_auto()` /
  `.runtime(kind)`), starting it yields a `RuntimeError::BackendUnavailable` whose message
  names the missing `docker` feature. Runtime is opt-in at runtime anyway
  (`KoiConfig.runtime_enabled` defaults to `false`), so a build that never enables it is
  unaffected.
- **`keyring` off** — `handle.vault()` still opens, using its passphrase backend; no OS
  keychain is touched. Certmesh CA-key sealing and TOTP unlock slots fall back to
  passphrase unlock.
- **`qr` off** — certmesh enrollment returns the `otpauth://` URI as text instead of a
  rendered QR (still scannable / typeable into an authenticator app).

### Verify your build is lean

From your own crate:

```bash
cargo tree -e normal | grep -E ' (bollard|keyring|image|qrcode) '   # empty == lean
```

> The standalone `koi` binary always ships every backend — these features are a
> `koi-embedded` (library) concern only. See
> [ADR-014](../adr/014-optional-backend-features.md) for the design and the full list of
> behavioral trade-offs.

---

## DNS configuration

```rust
let koi = Builder::new()
    .dns(|cfg| cfg.zone("internal").port(5353))
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

// UDP
let udp = handle.udp()?;
let binding = udp.bind(koi_udp::UdpBindRequest {
    port: 9999,
    addr: "0.0.0.0".to_string(),
    lease_secs: 300,
}).await?;
let _bytes_sent = udp.send(&binding.id, koi_udp::UdpSendRequest {
    dest: "127.0.0.1:9998".to_string(),
    payload: base64::engine::general_purpose::STANDARD.encode(b"hello"),
}).await?;
udp.unbind(&binding.id).await?;
```

---

## Events

Events are push-based via broadcast channels - no polling. You can register a handler or consume as a stream:

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

Certmesh create/destroy touches the trust store and may require elevated permissions. On startup the core resolves disk state automatically (`koi_compose::cores::init_certmesh_core`): no CA → an uninitialized core; a CA on disk that isn't decrypted → a locked core (machine-bound auto-unlock, or call `core.unlock(passphrase)`).

`koi-embedded` exposes the **full `CertmeshCore`** via `handle.certmesh()?.core()?` (create, invite, join, renew, revoke, trust-bundle, status, …) plus the plain-HTTP routes; the mTLS inter-node listener and the lifecycle background loops are yours to compose. For embedding a mesh **member** or a **CA host** — the auto-wired-vs-you-wire matrix, working code, the renewal options, and the auth caveat (embedded HTTP has no DAT token gate) — see **[Embedding certmesh](certmesh-embedded.md)**.

---

## Production tips

- Set `data_dir` to isolate state per process or environment
- Events are zero-latency broadcast channels - no file polling
- Explicitly enable/disable capabilities to match your deployment
- The facade contains zero domain logic - it composes existing crates

---

## Re-exported types

`koi-embedded` re-exports key types for convenience:

- `KoiConfig`, `ServiceMode`, `DnsConfigBuilder` from `koi-config`
- `KoiEvent` from `koi-embedded::events`
- `KoiHandle`, `MdnsHandle`, `DnsHandle`, `HealthHandle`, `CertmeshHandle`, `ProxyHandle`, `UdpHandle`

---

## Integration checklist

- [ ] `Builder::new().build()` succeeds with defaults
- [ ] mDNS register + browse + resolve
- [ ] DNS add/lookup/list/remove
- [ ] Health add/remove checks + snapshot
- [ ] Proxy upsert/list/remove
- [ ] UDP bind/send/recv/heartbeat/unbind
- [ ] Certmesh create/status/enrollment/policy/rotate/destroy
- [ ] HTTP surface validation (including SSE)
- [ ] IPC surface validation (Windows pipe)

See also: `crates/koi-embedded/examples/embedded-integration.rs`

---

## Unit tests

The crate includes 56 unit tests covering the testable surface that doesn't require a runtime:

- **`config.rs`** — `KoiConfig` defaults, `firewall_ports()` deduplication and capability-awareness, `DnsConfigBuilder` fluent API, `ServiceMode` variants
- **`events.rs`** — all `KoiEvent` variant construction, Clone preservation, Debug formatting
- **`lib.rs`** — `KoiError` Display and From impls, all 5 event mapping functions (`map_mdns_event`, `map_health_event`, `map_dns_event`, `map_certmesh_event`, `map_proxy_event`), `Builder` defaults and fluent overrides

Integration tests requiring the tokio runtime (startup, shutdown, domain handle operations, HTTP surface) are exercised via the example binary and the integration checklist above.
