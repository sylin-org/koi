# koi-dashboard

Presentation layer for the [Koi](https://github.com/sylin-org/koi) local-network
toolkit. Hosts the two single-file, zero-build HTML surfaces and their backing
endpoints:

- **Dashboard** (`GET /`, `/v1/dashboard/snapshot`, `/v1/dashboard/events`) — system
  overview with a live SSE activity feed.
- **mDNS browser** (`GET /mdns-browser`, `/v1/mdns/browser/snapshot`,
  `/v1/mdns/browser/events`) — live LAN service-discovery explorer.

This is a **composition crate**, not a domain crate: it depends on the event-bearing
domain crates so it can host a single event forwarder and a single mDNS browse adapter.
Nothing else in the workspace depends on it, so the `koi-common` kernel and the domain
crates keep clean dependency closures.

Rendering is done with DOM construction (`createElement` + `textContent`/`dataset`),
never HTML-string concatenation of dynamic values, and launch links are restricted to an
`http`/`https` scheme allowlist — closing the LAN-attacker XSS class structurally.

The LAN-wide meta-browse that populates the browser cache is **lazy**: it starts on the
first browser request and idles out after inactivity (`koi status` reports whether it is
active).
