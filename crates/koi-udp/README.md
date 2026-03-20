# koi-udp

[![Crates.io](https://img.shields.io/crates/v/koi-udp.svg)](https://crates.io/crates/koi-udp)
[![Docs.rs](https://docs.rs/koi-udp/badge.svg)](https://docs.rs/koi-udp)
[![License](https://img.shields.io/crates/l/koi-udp.svg)](https://github.com/sylin-org/koi#license)

UDP datagram bridging over HTTP/SSE for containerized workloads.

## Overview

`koi-udp` bridges host UDP sockets to HTTP clients via Server-Sent Events.
This is useful for containerized workloads that need UDP access without host
networking. Bindings are leased with heartbeat renewal, and datagrams are
base64-encoded for transport over the HTTP API.

## Features

- Bind host UDP ports with lease-based lifecycle
- Receive datagrams via SSE stream
- Send datagrams via HTTP POST
- Heartbeat-based lease renewal
- Base64 payload encoding

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
