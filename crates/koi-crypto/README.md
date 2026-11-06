# koi-crypto

Cryptographic primitives for Koi: P-256 keys/signatures, authenticated encryption, key agreement, pinning, TOTP, envelope unlock slots and platform credential storage.

CA authorization and enrollment policy belong to `koi-certmesh`. Cryptographic helpers do not establish an independent identity or permission policy. Optional `keyring` and `qr` features control platform-secret and QR dependencies.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-crypto --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
