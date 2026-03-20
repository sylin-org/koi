# koi-mdns

[![Crates.io](https://img.shields.io/crates/v/koi-mdns.svg)](https://crates.io/crates/koi-mdns)
[![Docs.rs](https://docs.rs/koi-mdns/badge.svg)](https://docs.rs/koi-mdns)
[![License](https://img.shields.io/crates/l/koi-mdns.svg)](https://github.com/sylin-org/koi#license)

mDNS/DNS-SD service discovery and registration for the local network.

## Overview

`koi-mdns` provides a high-level domain facade (`MdnsCore`) for multicast DNS
service discovery and registration. It wraps the `mdns-sd` crate behind an
opaque boundary, manages service lifecycles with session/heartbeat/permanent
lease modes, and exposes both programmatic commands and HTTP routes (via axum)
for browsing, registering, resolving, and subscribing to service events.

## Features

- Browse and resolve services by type (`_http._tcp`, `_ssh._tcp`, etc.)
- Register services with session, heartbeat, or permanent leases
- Subscribe to real-time lifecycle events (found, resolved, removed)
- Built-in HTTP API with SSE streaming
- Thread-safe registry with automatic lease reaping

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
