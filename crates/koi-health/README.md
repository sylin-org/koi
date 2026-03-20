# koi-health

[![Crates.io](https://img.shields.io/crates/v/koi-health.svg)](https://crates.io/crates/koi-health)
[![Docs.rs](https://docs.rs/koi-health/badge.svg)](https://docs.rs/koi-health)
[![License](https://img.shields.io/crates/l/koi-health.svg)](https://github.com/sylin-org/koi#license)

Machine and service health monitoring for the local network.

## Overview

`koi-health` provides HTTP and TCP health checks for services on your local
network. It runs periodic probes with configurable intervals and timeouts,
tracks status transitions (Up/Down/Unknown) with timestamps, broadcasts
state-change events, and exposes an HTTP API for managing checks and querying
current health snapshots.

## Features

- HTTP and TCP health check probes
- Configurable check intervals and timeouts
- Status transition tracking with event broadcast
- Machine-level health aggregation
- HTTP API for check management and status queries

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
