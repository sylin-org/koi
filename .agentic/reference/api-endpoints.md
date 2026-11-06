# API source of truth

Use the [HTTP reference](../../docs/reference/http-api.md),
[route/auth matrix](../../docs/reference/http-route-auth-matrix.md) and
[security model](../../docs/reference/security-model.md).

The source owner is crates/koi-serve/src/http.rs plus domain-owned route modules.
The CLI grammar is crates/koi/src/cli.rs; the daemon-backed HTTP client lives in
crates/koi-client/src/lib.rs. The authenticated local IPC wire contract is
documented in [wire protocol](../../docs/reference/wire-protocol.md).

Do not infer an endpoint from a planned UI operation or old example. Confirm the
route, request type, auth class, failure response and tests before documenting it.
Use the running artifact's API docs only for that artifact's actual version.
