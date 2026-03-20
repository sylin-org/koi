# koi-truststore

[![Crates.io](https://img.shields.io/crates/v/koi-truststore.svg)](https://crates.io/crates/koi-truststore)
[![Docs.rs](https://docs.rs/koi-truststore/badge.svg)](https://docs.rs/koi-truststore)
[![License](https://img.shields.io/crates/l/koi-truststore.svg)](https://github.com/sylin-org/koi#license)

Platform trust store integration for installing and removing local CA certificates.

## Overview

`koi-truststore` provides a cross-platform abstraction for installing and
removing CA certificates in the operating system's trust store. On Windows it
uses `certutil`, on macOS it uses the System Keychain via `security`, and on
Linux it writes to the system certificate directory and runs `update-ca-certificates`
or `update-ca-trust`.

## Supported Platforms

- **Windows** — `certutil -addstore` / `certutil -delstore`
- **macOS** — `security add-trusted-cert` / `security remove-trusted-cert`
- **Linux** — `/usr/local/share/ca-certificates/` + `update-ca-certificates`

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
