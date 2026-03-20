# koi-crypto

[![Crates.io](https://img.shields.io/crates/v/koi-crypto.svg)](https://crates.io/crates/koi-crypto)
[![Docs.rs](https://docs.rs/koi-crypto/badge.svg)](https://docs.rs/koi-crypto)
[![License](https://img.shields.io/crates/l/koi-crypto.svg)](https://github.com/sylin-org/koi#license)

Key management, TOTP, signing, and encryption primitives for local network trust.

## Overview

`koi-crypto` provides the cryptographic building blocks used by Koi's
certificate mesh. It includes ECDSA P-256 key generation and signing, TOTP
secret management with QR code generation, AES-256-GCM envelope encryption
with Argon2id key derivation, X25519 key agreement for CA key transfer, and
platform credential store integration (macOS Keychain, Windows Credential
Manager, Linux Secret Service).

## Features

- ECDSA P-256 key pair generation, signing, and verification
- TOTP secret creation and validation with QR code rendering
- AES-256-GCM authenticated encryption
- Argon2id passphrase-based key derivation
- X25519 Diffie-Hellman key agreement
- Platform credential store abstraction (keyring)

## Part of Koi

This crate is part of the [Koi](https://github.com/sylin-org/koi) workspace.
See the main repository for architecture details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
