# DNS - Local Resolver

Koi DNS provides a lightweight local resolver for a private zone (default: `.lan`).
It combines three sources:

1. Static entries you add with `koi dns add`.
2. Certmesh SANs (aliases added to member certificates).
3. mDNS aliases derived from discovered services.

Requests outside the local zone forward to the system upstream resolver.

---

## Quick start

Start the resolver in the foreground:

```
koi dns serve
```

Add a static entry:

```
koi dns add grafana 10.0.0.42
```

Query it:

```
koi dns lookup grafana
```

List all local names:

```
koi dns list
```

Stop the resolver (daemon mode only):

```
koi dns stop --endpoint http://localhost:5641
```

---

## CLI commands

```
koi dns serve
koi dns stop
koi dns status
koi dns lookup NAME [--record-type A|AAAA|ANY]
koi dns add NAME IP [--ttl SECS]
koi dns remove NAME
koi dns list
```

Notes:
- `dns stop` is only available when the daemon is running.
- `dns lookup` defaults to `A` records; use `--record-type AAAA` for IPv6.

---

## HTTP API (daemon)

When the daemon is running, DNS endpoints live under `/v1/dns`:

- `GET /v1/dns/status`
- `GET /v1/dns/lookup?name=grafana&type=A`
- `GET /v1/dns/list`
- `GET /v1/dns/entries`
- `POST /v1/dns/entries` (JSON body: `{ "name": "grafana", "ip": "10.0.0.42" }`)
- `DELETE /v1/dns/entries/{name}`
- `POST /v1/dns/admin/start`
- `POST /v1/dns/admin/stop`

---

## Configuration

Koi DNS is configurable via flags or environment variables:

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--dns-port` | `KOI_DNS_PORT` | `53` | DNS server port |
| `--dns-zone` | `KOI_DNS_ZONE` | `lan` | Local DNS zone suffix |
| `--dns-public` | `KOI_DNS_PUBLIC` | `false` | Allow queries from non-private clients |
| `--no-dns` | `KOI_NO_DNS` | `false` | Disable DNS capability |

Examples:

```
# Run on a high port (no admin privileges required)
koi --dns-port 15353

# Use a custom zone suffix
koi --dns-zone corp

# Allow non-private clients (not recommended on open networks)
koi --dns-public
```

---

## Safety and behavior

- Local-zone names only resolve to private or link-local IPs.
- By default, Koi only answers queries from private address ranges.
- It forwards non-local names to your system-configured upstream resolver.

---

## Troubleshooting

### Port 53 bind failure

On many systems, binding to port 53 requires elevated privileges. Use a high port for testing:

```
koi --dns-port 15353
```

### No results for `.lan` names

Check that the DNS capability is enabled and the resolver is running:

```
koi dns status
```

If the daemon is running, use:

```
koi dns status --endpoint http://localhost:5641
```
