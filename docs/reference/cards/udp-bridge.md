# UDP bridge

Koi can own leased host UDP sockets while an HTTP client receives datagrams through SSE and sends through the API.

## Use and verify

Use the [UDP guide](../../guides/udp.md) for the binding/heartbeat/send/receive sequence. Release bindings when the client finishes; leases provide cleanup when it disappears.

## Boundaries

The whole UDP API requires a token. Destination/bind safeguards and explicit remote opt-ins apply. This is not a general multicast reflector, subnet tunnel or appropriate default for high-volume media.

See [the capability guide](../../guides/udp.md), [security model](../security-model.md) and [launch readiness](../../launch/README.md). Current acceptance evidence belongs in the launch ledger; this reference card does not inherit proof from an older build.
