# koi-mdns

[![Crates.io](https://img.shields.io/crates/v/koi-mdns.svg)](https://crates.io/crates/koi-mdns)
[![Docs.rs](https://docs.rs/koi-mdns/badge.svg)](https://docs.rs/koi-mdns)
[![License](https://img.shields.io/crates/l/koi-mdns.svg)](https://github.com/sylin-org/koi#license)

mDNS/DNS-SD service discovery and registration for the local network.

## Overview

`koi-mdns` provides a high-level domain facade (`MdnsCore`) for multicast DNS
service discovery and registration. A provider port isolates platform engines
from the domain, shared browse hub, and public transports. The built-in native
adapter wraps `mdns-sd`; platform adapters can supply the same real DNS-SD
capabilities without leaking their API types into Koi's domain model.

At runtime, `MdnsControlPlane` asks every platform adapter for live evidence and
routes each capability to the best provider that actually implements it. On Linux
that catalog contains Avahi, systemd-resolved, and native Koi. A complete provider
such as Avahi can own every route; otherwise complementary providers can own
distinct routes without duplicate publication or browsing. Native Koi is always
catalogued as the lowest-priority complete provider. Stateful provider sessions
own their native resources and recovery, while structured status names the active
routes, provider evidence, session state, and publication synchronization.
Provider evidence includes the calling service's real non-interactive authority:
on Linux, a user-scoped Koi can therefore use resolve1 for resolution while
native Koi supplies publication when polkit does not grant `RegisterService`.

The core manages service lifecycles with session/heartbeat/permanent lease
modes and exposes both programmatic commands and HTTP routes (via axum) for
browsing, registering, resolving, and subscribing to service events.

## Features

- Browse and resolve services by type (`_http._tcp`, `_ssh._tcp`, etc.)
- Register services with session, heartbeat, or permanent leases
- Subscribe to real-time lifecycle events (found, resolved, removed)
- Capability-aware runtime provider selection and non-overlapping composition
- Built-in HTTP API with SSE streaming
- Thread-safe registry with automatic lease reaping

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
