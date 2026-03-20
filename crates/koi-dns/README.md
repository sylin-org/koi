# koi-dns

[![Crates.io](https://img.shields.io/crates/v/koi-dns.svg)](https://crates.io/crates/koi-dns)
[![Docs.rs](https://docs.rs/koi-dns/badge.svg)](https://docs.rs/koi-dns)
[![License](https://img.shields.io/crates/l/koi-dns.svg)](https://github.com/sylin-org/koi#license)

Local DNS resolver with mDNS, certmesh, and static record integration.

## Overview

`koi-dns` runs a local DNS server (built on Hickory DNS) that resolves names
from multiple sources: static entries, certmesh-enrolled hosts, and mDNS
discovered services. It supports configurable zones, per-query rate limiting,
upstream forwarding for non-local names, and an HTTP API for managing entries
at runtime.

## Features

- Local DNS server with configurable zone (e.g. `.koi`)
- Static, certmesh, and mDNS record sources
- Per-query rate limiting
- Upstream DNS forwarding for external names
- HTTP API for add/remove/lookup/list operations

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
