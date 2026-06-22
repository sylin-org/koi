# koi-serve

The **serving layer** of [Koi](https://github.com/sylin-org/koi): it exposes the composed
domain cores over the network.

koi-serve owns Koi's transport adapters — the HTTP/OpenAPI router, IPC and piped-stdio
NDJSON, the in-process MCP HTTP transport, the inter-node mTLS and ACME (RFC 8555)
listeners, Prometheus service discovery, and the dashboard/browser wiring — plus the
posture-reactive **trust-plane** supervisor.

It sits one layer above [`koi-compose`](../koi-compose) (which *constructs* the cores) and
is consumed by the two top-level hosts: the `koi` binary and `koi-embedded`. Nothing
depends on koi-serve except those consumers, so the kernel and domain closures stay clean.

Not a general-purpose library; the surface tracks Koi's needs and may change between
releases.
