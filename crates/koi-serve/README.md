# koi-serve

Transport adapters over Koi's shared composition: HTTP/OpenAPI, authenticated local IPC, MCP, inter-node mTLS, ACME, and operator/browser views.

Serving code enforces authentication, exposes accepted domain state and owns listener tasks through the common lifecycle owner. It must not create independent copies of domain truth. The default management HTTP bind is loopback.

When DAT authentication is configured, `/ui` loads the shared Services interface.
Its memory-only token transport requests `/v1/ui/shell` with bounded view queries;
Rust owns filtering, sorting and details. The HTML endpoint requires the token
for every peer, including loopback. `/` and `/mdns-browser` lead to this
interface; Koi ships no second dashboard HTML application. Browser Favorite and friendly names use the typed
preferences API only when that core is mounted and the request peer is loopback;
conflicts stay visible for retry. A transient catalog failure retains the last
view and memory-only session for explicit Refresh. Pond renders the same built-in
interface against an mDNS-only, preference-free public projection and has no UI
publication or mutation route.

## Development

Read [architecture](../../docs/reference/architecture.md) for ownership boundaries and [launch readiness](../../docs/launch/README.md) for the supported-versus-tested journey matrix. This README describes repository source; it does not assert package publication or physical acceptance.

```sh
cargo test -p koi-serve --locked
```

Platform-dependent tests can require explicit facilities or remain ignored in ordinary runs. See [validation](../../docs/qa/validation-suite.md) before interpreting a green result.

Licensed under Apache-2.0 OR MIT; see the workspace license files.
