# koi-client

[![Crates.io](https://img.shields.io/crates/v/koi-client.svg)](https://crates.io/crates/koi-client)
[![Docs.rs](https://docs.rs/koi-client/badge.svg)](https://docs.rs/koi-client)
[![License](https://img.shields.io/crates/l/koi-client.svg)](https://github.com/sylin-org/koi#license)

HTTP client for the Koi daemon.

## Overview

`koi-client` provides `KoiClient`, a blocking HTTP client (built on `ureq`)
for communicating with a running Koi daemon. It covers all daemon API
endpoints — mDNS operations, admin commands, certmesh, DNS, health, and
proxy — and is used by the CLI in client mode and by background tasks that
need to call the daemon from `spawn_blocking`.

## Usage

```rust
use koi_client::KoiClient;

let client = KoiClient::new("http://127.0.0.1:5641");
let status = client.status()?;
```

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
