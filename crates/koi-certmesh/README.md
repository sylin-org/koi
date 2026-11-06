# koi-certmesh

Private CA and mesh identity domain: CA creation/unlock, CSR-based enrollment, single-use invitations, member renewal, signed trust bundles, revocation metadata, encrypted backup/restore and manual authority promotion.

Enrollment uses open/closed and approval-required state. It does not provide timed enrollment windows, CIDR/domain enrollment restrictions or automatic CA election.

The domain also implements exact service-name grants and a restricted ACME server. The public workflow that creates those grants and binds exact service certificates to listeners is incomplete. Ordinary TLS clients do not consume Koi's revocation metadata through CRL/OCSP.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-certmesh --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
