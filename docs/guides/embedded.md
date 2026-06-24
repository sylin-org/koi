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
    // 0.0.0.0 is non-loopback, so this is required; loopback binds default to false.
    allow_remote: true,
}).await?;
let _bytes_sent = udp.send(&binding.id, koi_udp::UdpSendRequest {
    dest: "127.0.0.1:9998".to_string(),
    payload: base64::engine::general_purpose::STANDARD.encode(b"hello"),
}).await?;
udp.unbind(&binding.id).await?;
```

---

## HTTP adapter (optional)

The embedded HTTP adapter is **off by default** (`http(false)`); a library normally
drives the cores directly via the typed handles above. Turn it on with `.http(true)` to
serve the same `koi-serve` router the daemon uses — `/v1/status`, the domain routes, and
(when enabled) the dashboard and OpenAPI docs.

```rust
let koi = Builder::new()
    .http(true)
    .http_port(8080)        // fixed port; pass 0 for an OS-assigned ephemeral one
    .dashboard(true)        // GET /            embedded HTML dashboard
    .mdns_browser(true)     // GET /mdns-browser network browser (requires mDNS)
    .api_docs(true)         // GET /docs        Scalar UI + /openapi.json
    .build()?;
let handle = koi.start().await?;
```

### Ephemeral (free) port

Pass `http_port(0)` and Koi binds an OS-assigned free port. Read the actual port back from
the handle after `start()` — this is the supported way to run on a free port without
racing to pick one yourself:

```rust
let koi = Builder::new().http(true).http_port(0).build()?;
let handle = koi.start().await?;

let port = handle.bound_http_port().expect("HTTP enabled");   // u16
let addr = handle.http_addr().expect("HTTP enabled");         // SocketAddr
```

Both return `None` when HTTP is disabled or the handle is in remote mode.

### Secure by default

The HTTP adapter binds **loopback (`127.0.0.1`) by default**, so only local processes
reach it and mutations need no token. Exposing it to the LAN is an explicit, fail-closed
opt-in:

- `announce_http(true)` advertises this host's `_http._tcp` record and therefore binds
  `0.0.0.0` (all interfaces).
- A `0.0.0.0` bind **requires** a token: `start()` returns
  `KoiError::InsecureConfig` if `announce_http` is set without `http_token(..)` — it fails
  before any core or socket is created.
- `http_token(token)` requires the `x-koi-token` header on every mutation (parity with the
  daemon's DAT). It works on a loopback bind too if you want authenticated local mutations.

```rust
let koi = Builder::new()
    .http(true)
    .announce_http(true)            // binds 0.0.0.0
    .http_token("a-strong-secret")  // required, or start() fails closed
    .build()?;
let handle = koi.start().await?;
```

> The loopback default is the only configuration where embedded HTTP mutations are
> unauthenticated. The moment you set `http_token`, the `x-koi-token` gate is in force.

---

## Trusted services (ADR-020 same-port dial)

A `KoiHandle` whose certmesh capability is enabled can serve your own `axum::Router` with
the posture-adaptive same-port dial: plain HTTP while this node is **Open**, mTLS once it
is **Authenticated**, flipping live with **no dropped connections** as the posture changes.
You write one `serve` call and never branch on posture.

```rust
let koi = Builder::new().certmesh(true).build()?;
let handle = koi.start().await?;

let router = axum::Router::new()
    .route("/ping", axum::routing::get(|| async { "pong" }));
let addr = "0.0.0.0:8443".parse()?;
let cancel = tokio_util::sync::CancellationToken::new();

// Identity + posture-stamped mDNS announce + same-port serve in one call:
let _server = handle.participate(router, addr, "_my-svc._tcp", cancel).await?;
```

- `participate(router, addr, service_type, cancel)` acquires/maintains this node's identity
  (best-effort), announces `service_type` with the posture stamped into the TXT and kept
  current across flips, and serves with the same-port dial.
- `serve(router, addr, cancel)` is the serve step alone (no announce) if you do not want
  mDNS advertisement.
- The lower-level `serve_adaptive(core, router, addr, cancel)` is re-exported for direct use.
- Both are **embedded only** — a remote handle has no local identity to serve mTLS with and
  returns `KoiError::DisabledCapability`.

Certificate *renewal* is handled by the certmesh background loops — enable them with
`Builder::certmesh_background(true)` on a long-running host.

### Trust primitives

The certmesh handle exposes the mode-transparent trust primitives directly — identical call
sites whether the node is Open or Authenticated:

```rust
let cm = handle.certmesh()?;
let posture = cm.posture()?;                       // the mode oracle
let env = cm.sign(b"payload").await?;              // freshness-stamped Open, ES256 secure
let assurance = cm.verify(&env).await?;            // Assurance::identity() if trusted
let peers = handle.mdns()?.discover("_my-svc._tcp").await?;  // each peer carries its posture hint
let diag = cm.diagnose().await?;                   // trust-doctor TrustDiagnosis
```

`sign`/`verify` are also available **directly on the handle** as a symmetric pair, so you
don't unwrap the certmesh sub-handle for the common envelope round-trip:

```rust
let env = handle.sign(b"payload").await?;          // = handle.certmesh()?.sign(..)
let assurance = handle.verify(&env).await?;        // = handle.certmesh()?.verify(..)
```

A member node can read its own leaf's expiry to drive a "renews in N days" display or its
own renewal timer. Prefer `handle.certmesh()?.core()?.local_identity().await` →
`Identity::renewal` (cert-derived; works whether or not `member.json` is armed). The
`member_cert_expiry()` convenience returns the raw `Option<DateTime<Utc>>` but is
`member.json`-gated, so it is `None` for a node that never armed member state.

**Authorizing a request from an envelope** — use the request-bound door, not bare
`identity()`. `verify()` attests the *signer*, decoupled from the payload, so
`if a.identity().is_some() { authorize(req) }` would accept a captured envelope replayed
against a *different* request. `Assurance::identity_for(env, expected)` returns the CN only
when the signer signed *these* bytes:

```rust
let assurance = cm.verify(&env).await?;
let canonical = my_canonical_request_bytes(&req);   // your canonicalization (often a body hash)
match assurance.identity_for(&env, &canonical) {
    Some(cn) => authorize(cn, &req),                // signer signed THIS request
    None => reject(),                               // anonymous, stale, rejected, or wrong payload
}
```

This pairs exactly with CA-side renewal: `verify → identity_for(env, csr_bytes) → renew_member(cn, csr)`.

---

## Vault

`handle.vault()` opens an encrypted key-value store for general-purpose secret storage. It
uses platform credential binding (keyring) when available with a machine-bound fallback,
and requires a `data_dir` (it returns `KoiError::DisabledCapability` otherwise).

```rust
let koi = Builder::new().data_dir("/var/lib/my-app").build()?;
let handle = koi.start().await?;
let vault = handle.vault()?;
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

## Testing with `testkit`

`koi_embedded::testkit` spins a real embedded node in a known posture for your own
integration tests — no Docker, no daemon. It is a normal module (no feature flag), so a
test only needs a `koi-embedded` dev-dependency. Each node runs with mDNS off (CI has no
multicast) and exercises the trust primitives.

```rust
use koi_embedded::testkit;

// open()    → an Open node (no CA, no identity; sign() is a freshness-stamped passthrough)
// secured() → an Authenticated node (a CA is created; sign() is ES256-signed)
let node = testkit::open().await;       // TestNode derefs to KoiHandle
let cm = node.certmesh().unwrap();
let env = cm.sign(b"hello").await.unwrap();
assert!(!cm.verify(&env).await.unwrap().is_rejected());
node.shutdown().await;                   // tears down + wipes the isolated data dir
```

`TestNode` derefs to `KoiHandle`, so call any handle method on it directly. The "same code,
both postures" acceptance gate is simply to run one consumer code path against
`[testkit::open().await, testkit::secured().await]` — if the body ever needs an
`if secure { … } else { … }`, a primitive is missing.

---

## Certmesh notes

Certmesh create/destroy touches the trust store and may require elevated permissions. On startup the core resolves disk state automatically (`koi_compose::cores::init_certmesh_core`): no CA → an uninitialized core; a CA on disk that isn't decrypted → a locked core (machine-bound auto-unlock, or call `core.unlock(passphrase)`).

`koi-embedded` exposes the **full `CertmeshCore`** via `handle.certmesh()?.core()?` (create, invite, join, renew, revoke, trust-bundle, status, …) plus the plain-HTTP routes; the mTLS inter-node listener and the lifecycle background loops are yours to compose. The embedded HTTP adapter is loopback-only and token-free **by default** — set `http_token(..)` to require the `x-koi-token` gate on mutations (mandatory once you expose it via `announce_http`; see [HTTP adapter](#http-adapter-optional)). For embedding a mesh **member** or a **CA host** — the auto-wired-vs-you-wire matrix, working code, and the renewal options — see **[Embedding certmesh](certmesh-embedded.md)**.

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
- `KoiHandle`, `MdnsHandle`, `DnsHandle`, `HealthHandle`, `CertmeshHandle`, `ProxyHandle`
- Trust primitives (ADR-020): `Peer`, `Posture`, `PostureLevel`, `PeerClient`, `Sealed`/`Opened`/`Confidentiality`, `TrustDiagnosis`, and `serve_adaptive`
- `Vault`, `VaultError` from `koi-crypto` (for `handle.vault()`)

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
