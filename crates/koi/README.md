# koi-net

[![Crates.io](https://img.shields.io/crates/v/koi-net.svg)](https://crates.io/crates/koi-net)
[![Docs.rs](https://docs.rs/koi-net/badge.svg)](https://docs.rs/koi-net)
[![License](https://img.shields.io/crates/l/koi-net.svg)](https://github.com/sylin-org/koi#license)

Local network toolkit: service discovery, DNS, health monitoring, TLS proxy, and certificate mesh.

## Overview

`koi-net` is the CLI binary for the Koi local network toolkit. It provides a
single daemon that combines mDNS/DNS-SD service discovery, a local DNS resolver,
HTTP/TCP health monitoring, a TLS-terminating reverse proxy, UDP datagram
bridging, and a zero-config private CA — all controllable via CLI commands or a
built-in HTTP API with an embedded dashboard.

## Install

```sh
cargo install koi-net
```

## Usage

```sh
# Start the daemon (all capabilities enabled by default)
koi

# Discover services on the network
koi mdns discover

# Register a service
koi mdns announce --name "My App" --type _http._tcp --port 8080

# Initialize a private CA
koi certmesh create

# Start the local DNS resolver
koi dns serve

# Open the web dashboard
koi launch
```

Run `koi --help` for the full command reference.

## Part of Koi

This is the binary crate of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details and the full crate inventory.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
