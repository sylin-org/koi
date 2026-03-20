# koi-common

[![Crates.io](https://img.shields.io/crates/v/koi-common.svg)](https://crates.io/crates/koi-common)
[![Docs.rs](https://docs.rs/koi-common/badge.svg)](https://docs.rs/koi-common)
[![License](https://img.shields.io/crates/l/koi-common.svg)](https://github.com/sylin-org/koi#license)

Shared types, traits, and utilities for the Koi local network toolkit.

## Overview

`koi-common` is the shared kernel of the Koi workspace. It provides the
foundational types used across all domain crates: `ServiceRecord`, `ErrorCode`,
`PipelineResponse`, session ID generation, data directory paths, ceremony
protocol, and capability gating. Domain crates depend on `koi-common` but never
on each other.

## Key Types

- **`ServiceRecord`** — core service data (name, type, host, ip, port, txt)
- **`PipelineResponse<B>`** — generic wire envelope with status/warning fields
- **`ErrorCode`** — wire error codes with HTTP status mapping
- **`generate_short_id()`** — UUID v4 prefix for registration IDs

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
It is a transitive dependency of all Koi domain crates and is not typically
used directly by end users.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
