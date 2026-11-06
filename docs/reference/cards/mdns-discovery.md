# mDNS discovery

Browse DNS-SD services through the running daemon with `koi mdns discover _http._tcp`. Publish an already-listening application with `koi mdns announce "My App" _http._tcp 8080`.

## Use and verify

Use `koi mdns subscribe _http._tcp` to observe changes. Daemon-backed announcement renews an HTTP lease while the client is alive; explicit standalone operation owns a temporary local composition.

## Boundaries

mDNS is link-local and advertisements are unauthenticated discovery hints. Provider capabilities vary by OS/session. Validate on another physical device; local discovery and self-publication are insufficient.

See [the capability guide](../../guides/mdns.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
