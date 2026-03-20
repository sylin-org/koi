# koi-config

[![Crates.io](https://img.shields.io/crates/v/koi-config.svg)](https://crates.io/crates/koi-config)
[![Docs.rs](https://docs.rs/koi-config/badge.svg)](https://docs.rs/koi-config)
[![License](https://img.shields.io/crates/l/koi-config.svg)](https://github.com/sylin-org/koi#license)

Configuration, breadcrumb discovery, and state persistence for Koi.

## Overview

`koi-config` handles runtime configuration and daemon discovery for the Koi
toolkit. It manages the breadcrumb file that lets CLI clients auto-discover a
running daemon, persists DNS entries and proxy state to disk, and provides the
configuration types shared across the workspace.

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
