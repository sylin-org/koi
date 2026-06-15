# koi-embedded

[![Crates.io](https://img.shields.io/crates/v/koi-embedded.svg)](https://crates.io/crates/koi-embedded)
[![Docs.rs](https://docs.rs/koi-embedded/badge.svg)](https://docs.rs/koi-embedded)
[![License](https://img.shields.io/crates/l/koi-embedded.svg)](https://github.com/sylin-org/koi#license)

Embed local network discovery, DNS, health, and TLS directly in your Rust application.

## Overview

`koi-embedded` lets you embed the full Koi stack — mDNS discovery, DNS
resolution, health monitoring, TLS proxy, certmesh, and UDP bridging — inside
your own Rust application. It provides a `Builder` for configuration and
returns typed handles (`MdnsHandle`, `DnsHandle`, `HealthHandle`, etc.) for
interacting with each capability, plus a `KoiEvent` broadcast stream for
reacting to system-wide events.

## Usage

```rust
use koi_embedded::{Builder, RegisterPayload};

// Build the embedded stack, then start it. `build()` is sync and returns a
// `KoiEmbedded`; `start()` is async and returns the running `KoiHandle`.
let koi = Builder::new()
    .mdns(true)
    .build()?
    .start()
    .await?;

// Register a service through the mDNS handle (`mdns()` returns a `Result`;
// `register` is synchronous).
koi.mdns()?.register(RegisterPayload {
    name: "My Service".to_string(),
    service_type: "_http._tcp".to_string(),
    port: 8080,
    ip: None,
    lease_secs: None,
    txt: Default::default(),
})?;

// Subscribe to the system-wide event stream.
let mut rx = koi.subscribe();
while let Ok(event) = rx.recv().await {
    println!("{event:?}");
}
```

## Cargo features (lean builds)

Three heavy, version-locking backends are gated behind **default-on** features. A default
dependency is unchanged; a lean consumer opts out, and re-arms à la carte:

| Feature | Default | Compiles in | Off → fallback |
| --- | --- | --- | --- |
| `docker` | on | `bollard` Docker/Podman client (`=`-pinned stubs) | runtime backend → `BackendUnavailable` |
| `keyring` | on | OS keychain / Secret Service / D-Bus | vault uses its passphrase backend |
| `qr` | on | `qrcode` + `image` PNG codec | enrollment returns the `otpauth://` URI text |

```toml
# default — everything
koi-embedded = "0.4"
# lean — no bollard, no OS-keychain/D-Bus, no image codec
koi-embedded = { version = "0.4", default-features = false }
# à la carte (also: features = ["full"])
koi-embedded = { version = "0.4", default-features = false, features = ["docker"] }
```

These are compile-time choices, distinct from the runtime capability toggles on
`Builder` (which compile everything and just don't start it). See the
[embedded guide](https://github.com/sylin-org/koi/blob/main/docs/guides/embedded.md)
and [ADR-014](https://github.com/sylin-org/koi/blob/main/docs/adr/014-optional-backend-features.md).

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details and the full crate inventory.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
