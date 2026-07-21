# koi-net

[![Crates.io](https://img.shields.io/crates/v/koi-net.svg)](https://crates.io/crates/koi-net)
[![Docs.rs](https://docs.rs/koi-net/badge.svg)](https://docs.rs/koi-net)
[![License](https://img.shields.io/crates/l/koi-net.svg)](https://github.com/sylin-org/koi#license)

Let everything local find, trust, and talk.

## Overview

`koi-net` is the CLI binary for Koi, an open-source local connectivity substrate.
It makes containers, applications, and devices discoverable, secure, and
interconnected by composing mDNS/DNS-SD, local DNS, container lifecycle, health,
TLS and UDP bridging, and a private CA behind one daemon. The same capabilities
are available through CLI commands, an HTTP API, and an embedded dashboard.

## Install

Download the prebuilt binaries from [GitHub Releases](https://github.com/sylin-org/koi/releases) for your platform, or build from source in the main workspace repository.

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

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or
[MIT License](../../LICENSE-MIT) at your option.
