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
use koi_embedded::{Builder, ServiceMode};

let koi = Builder::new()
    .mode(ServiceMode::Standalone)
    .build()
    .await?;

// Register a service
koi.mdns().register(payload).await?;

// Subscribe to events
let mut rx = koi.subscribe();
while let Ok(event) = rx.recv().await {
    println!("{event:?}");
}
```

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details and the full crate inventory.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
