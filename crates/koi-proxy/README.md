# koi-proxy

[![Crates.io](https://img.shields.io/crates/v/koi-proxy.svg)](https://crates.io/crates/koi-proxy)
[![Docs.rs](https://docs.rs/koi-proxy/badge.svg)](https://docs.rs/koi-proxy)
[![License](https://img.shields.io/crates/l/koi-proxy.svg)](https://github.com/sylin-org/koi#license)

TLS-terminating TCP passthrough with automatic certificate management.

## Overview

`koi-proxy` is the pre-wired TLS endpoint for certmesh certificates. Each entry binds
a listen port, terminates TLS with a certmesh-issued certificate (or a generated
self-signed one when none is on disk), and pipes raw bytes to a plaintext TCP backend
with `tokio::io::copy_bidirectional`. Because forwarding is at the byte level,
WebSockets and any other bidirectional/upgraded protocol pass through transparently.

It watches the cert directory and hot-reloads the certificate on the next handshake
with no restart. It is **passthrough only** — there is no HTTP layer, so no path
routing, header injection, or rewrites. For L7 routing, point this proxy at
Caddy/Traefik/nginx.

## Features

- TLS termination → byte-level TCP passthrough (WebSocket-safe)
- Certificate resolution: per-entry dir → host cert → generated self-signed
- Hot certificate reload via `ResolvesServerCert` (free per-handshake swap)
- Per-entry listen port and backend; non-loopback backend gated by `allow_remote`
- Real listener state (running / error with detail) surfaced through status
- HTTP API for add/remove/list/status operations
- Persistent configuration across restarts

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
