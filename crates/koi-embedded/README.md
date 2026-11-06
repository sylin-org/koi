# koi-embedded

Run selected Koi capabilities inside a Rust application using the same composition and serving layers as the host daemon. `Builder::build()` creates the configuration; async `start()` returns typed handles and lifecycle ownership.

Embedding is an advanced integration surface. The initial product journey uses the installed Koi service; embedding does not bypass network, trust-store or listener requirements. Managed Certmesh renewal/bundle maintenance is enabled by default. Embedded HTTP defaults to loopback with optional token authentication; exposing it through `announce_http` requires `http_token` and otherwise fails before startup. It does not automatically mount the daemon's authority mTLS/ACME supervisor or MCP HTTP surface.

## Source example

```rust
use koi_embedded::{Builder, RegisterPayload};

let koi = Builder::new().mdns(true).build()?.start().await?;
koi.mdns()?.register(RegisterPayload {
    name: "My Service".to_string(),
    service_type: "_http._tcp".to_string(),
    port: 8080,
    ip: None,
    lease_secs: None,
    txt: Default::default(),
}).await?;
```

The surrounding application supplies an async runtime, error handling and shutdown. Consult the workspace examples for complete programs. Do not announce a port before the application is listening on the intended interface.

## Optional dependencies

| Feature | Default | Effect when omitted |
| --- | --- | --- |
| `docker` | Enabled | Docker/Podman runtime backend reports unavailable |
| `keyring` | Enabled | Use the passphrase backend instead of platform credential storage |
| `qr` | Enabled | Enrollment can expose the provisioning URI as text |

Disable default features and re-enable the subset needed by the application. Runtime Builder toggles are distinct: they select which compiled capabilities start. The current workspace version is authoritative in `Cargo.toml`; use a matching published version only after confirming its availability.

See [embedded usage](../../docs/guides/embedded.md), [architecture](../../docs/reference/architecture.md) and [launch readiness](../../docs/launch/README.md).
