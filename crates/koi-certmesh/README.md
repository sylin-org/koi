# koi-certmesh

[![Crates.io](https://img.shields.io/crates/v/koi-certmesh.svg)](https://crates.io/crates/koi-certmesh)
[![Docs.rs](https://docs.rs/koi-certmesh/badge.svg)](https://docs.rs/koi-certmesh)
[![License](https://img.shields.io/crates/l/koi-certmesh.svg)](https://github.com/sylin-org/koi#license)

Zero-config private CA, certificate enrollment, and mesh trust for the local network.

## Overview

`koi-certmesh` implements a lightweight private Certificate Authority that runs
on your LAN. It handles CA creation with passphrase-protected keys, TOTP-based
enrollment authentication, automatic certificate issuance and renewal, roster
management with signed manifests, primary/standby failover, encrypted backups,
and a full audit log. Enrollment scope can be constrained by domain suffix or
CIDR subnet.

## Features

- Private CA with envelope-encrypted key (AES-256-GCM + Argon2id)
- TOTP-based enrollment authentication
- Automatic certificate renewal with configurable thresholds
- Primary/standby failover with signed roster manifests
- Enrollment windows with deadline auto-close
- Domain and subnet scope constraints
- Encrypted backup and restore
- HTTP API with axum routes

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
