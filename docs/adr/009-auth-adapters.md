# ADR-009: Pluggable Auth Adapters

**Status:** Accepted  
**Date:** 2025-12-15  

## Context

Certmesh enrollment authentication was hard-wired to TOTP, which is the right default for containers and cloud deployments but excludes hardware security keys (YubiKey, Titan, SoloKey) that offer phishing-resistant auth with better UX. The system needed to support multiple auth methods without branching the enrollment/promote/rotate flows per method. Additionally, USB-based FIDO2 requires HID access only available in the CLI binary, while the daemon should perform pure cryptographic verification without physical device dependencies.

## Decision

An `AuthAdapter` trait with `challenge()` and `verify()` methods replaces the hard-wired TOTP calls. Auth credentials, challenges, and responses are serde-tagged enums (`AuthCredential`, `AuthChallenge`, `AuthResponse`) that transport method-specific data without the flow logic caring which method is active. Adapter resolution is a function: `adapter_for(&credential) -> Box<dyn AuthAdapter>`.

TOTP and FIDO2 ship as the first two adapters. USB HID communication (`ctap-hid-fido2`) lives exclusively in the CLI binary; the daemon uses `p256` for ECDSA signature verification only. The auth method is mutable on a live CA via `koi certmesh rotate-auth`.

## Consequences

- Adding a future auth method requires adding enum variants, writing an adapter struct, and adding match arms to `adapter_for()`. No flow changes or protocol rework.
- The CLI/daemon split means FIDO2 cannot work in headless/containerized environments. TOTP remains the default there.
- Auth is implemented as a single `auth.rs` file in `koi-crypto`, not a directory of adapter modules — simplicity was preferred over premature structural separation.
- The `ctap-hid-fido2` crate is a CLI-only dependency, keeping the daemon's dependency tree lighter.
