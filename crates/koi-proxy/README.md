# koi-proxy

[![Crates.io](https://img.shields.io/crates/v/koi-proxy.svg)](https://crates.io/crates/koi-proxy)
[![Docs.rs](https://docs.rs/koi-proxy/badge.svg)](https://docs.rs/koi-proxy)
[![License](https://img.shields.io/crates/l/koi-proxy.svg)](https://github.com/sylin-org/koi#license)

TLS-terminating reverse proxy with automatic certificate management.

## Overview

`koi-proxy` provides a reverse proxy that terminates TLS using certificates
managed by Koi's certmesh CA. It watches for certificate changes on disk and
hot-reloads TLS configuration without restarting. Each proxy entry maps a
listen port to a backend address and can be restricted to local-only or allow
remote connections.

## Features

- TLS termination with automatic certificate reload
- File-system watching for cert/key changes
- Per-entry listen port and backend routing
- Local-only or remote access control
- HTTP API for add/remove/list/status operations
- Persistent configuration across restarts

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
