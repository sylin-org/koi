# Listeners and firewall

Reachability depends on a real listener, a usable route and firewall policy. Discovery is a separate fact. The preview tests the actual application on a second device; exposing Koi's management API is not that application test.

| Port | Transport and purpose | Default bind / condition |
| --- | --- | --- |
| 5641 | HTTP management API, dashboard, MCP HTTP | `127.0.0.1`; unless HTTP disabled |
| 5642 | Certmesh inter-node mTLS, optional remote MCP | `0.0.0.0`; unlocked local authority with usable identity |
| 5643 | ACME server-auth TLS | `0.0.0.0`; usable authority plus DNS and ACME enabled |
| HTTP port + 3 (normally 5644) | Pond reduced read-only browser/API surface | IPv4 all interfaces; only while enabled and its listener is live |
| 53 UDP/TCP | Local DNS resolver | All IPv4 interfaces when resolver starts; private clients by default |
| 5353 UDP | mDNS multicast | Provider-managed multicast sockets |
| Per proxy entry | TLS termination to backend | Entry's configured port; check live status and firewall |
| Per UDP binding | Leased datagram socket | Loopback unless explicitly allowed otherwise |

Local IPC is a Unix domain socket or Windows named pipe, not a network port.

## Configuration

`--port`, `--mtls-port`, `--acme-port` and `--dns-port` change the corresponding ports. Their environment variables are `KOI_PORT`, `KOI_MTLS_PORT`, `KOI_ACME_PORT` and `KOI_DNS_PORT`. Pond uses the resolved HTTP port plus three.

`--http-bind` / `KOI_HTTP_BIND` selects `loopback`, `bridge`, an IP address or `0.0.0.0`. Bridge access and Docker Desktop host access depend on the actual runtime/network; verify from the intended container rather than assuming a hostname bypasses a loopback bind.

`--announce-http` publishes a discovery record without changing HTTP exposure. Do not advertise a loopback-only management endpoint as remotely reachable. An mDNS announcement may carry posture/fingerprint/expiry hints; clients must verify identity independently.

## Authority listeners

Authenticated members use the authority plane as clients. Merely holding a member certificate does not start the local authority listeners. The supervisor withdraws listeners when authority/identity state becomes unusable and retries eligible startup failures. Enrollment bootstrap uses the authority's reachable HTTP route; established member operations use mTLS.

ACME's separate protocol port is not a complete integration recipe. Clients need exact service grants and a dns-01 provider. See [ACME](../guides/acme.md).

## Firewall ownership

Windows installation snapshots and manages its program-scoped rules transactionally with the service installation. Relevant rules cover enabled mDNS/DNS, exposed management HTTP and the optional Pond port. Firewall setup is part of installation verification/rollback, not an unconditional best-effort success.

Authority and per-proxy listener exposure requires explicit firewall configuration where not covered by the installer. Linux/macOS firewall policy remains operator-owned. Never open every capability port as a prerequisite for the container preview; open the application and discovery paths the selected scenario requires.

Check [installation](../guides/install-and-service.md) and [the fleet contract](../../fleet/CONTRACT.md) before changing an existing host. A rule existing does not prove a listener is live, and a listener does not prove another device can reach it. Authentication rules are in [the route matrix](http-route-auth-matrix.md).
