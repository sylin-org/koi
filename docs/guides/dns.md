# DNS - Local Resolver

Names matter. Typing `grafana.lan` into a browser is a fundamentally different experience from typing `10.0.0.42:3000`. Names are how humans think about services. DNS is how computers translate that thinking into addresses.

But on a private network, DNS is usually an afterthought. You hard-code IPs in config files, add entries to `/etc/hosts` on each machine, or run a full-blown BIND instance that nobody wants to maintain. Koi's DNS capability fills the gap: a lightweight local resolver that answers queries for your private zone and forwards everything else to the system upstream.

**When to use Koi DNS**: You have services on your LAN that you want to reach by name. You're tired of editing hosts files. You want certmesh SANs and mDNS discoveries to automatically become resolvable DNS names. You need split-horizon behavior where `.lan` names resolve locally but everything else goes to your normal resolver.

---

## The three record sources

This is the key design insight. Koi DNS doesn't just serve a static zone file - it merges three sources into a single consistent view:

1. **Static entries** you add with `koi dns add`. These are your manually declared names - the equivalent of hosts file entries, but centralized.
2. **Certmesh SANs**. When a certmesh member has Subject Alternative Names on its certificate, those SANs become DNS entries automatically. No extra configuration.
3. **mDNS aliases**. Services discovered via mDNS get DNS entries too. If `grafana._http._tcp` appears on the network, `grafana.lan` becomes resolvable.

This layering is deliberate. Static entries give you explicit control. Certmesh SANs ensure TLS names are always resolvable. mDNS aliases mean discovered services "just work" in DNS too. The result is a local zone that stays accurate without constant maintenance.

Anything outside the local zone (`.lan` by default) is forwarded to your system's upstream resolver. Koi doesn't try to be a general-purpose recursive resolver - it stays in its lane.

---

## Getting started

Start the resolver:

```
koi dns serve
```

Add a static name:

```
koi dns add grafana 10.0.0.42
```

Look it up:

```
koi dns lookup grafana
```

See everything in the zone:

```
koi dns list
```

That's the whole cycle: serve, add, query, list. The resolver runs until you stop it or the daemon shuts down.

---

## CLI commands

```
koi dns serve           # Start the resolver
koi dns stop            # Stop the resolver (daemon mode)
koi dns status          # Check resolver state
koi dns lookup NAME     # Query a name (default: A record)
koi dns add NAME IP     # Add a static entry
koi dns remove NAME     # Remove a static entry
koi dns list            # List all entries from all sources
```

`dns lookup` defaults to `A` records. Use `--record-type AAAA` for IPv6 or `--record-type ANY` to see everything. `dns stop` only works when the daemon is running - in foreground mode, just use Ctrl+C.

---

## HTTP API

When the daemon is running, DNS endpoints live under `/v1/dns/`:

| Method   | Path                                 | Purpose                      |
| -------- | ------------------------------------ | ---------------------------- |
| `GET`    | `/v1/dns/status`                     | Resolver state               |
| `GET`    | `/v1/dns/lookup?name=grafana&type=A` | Query a name                 |
| `GET`    | `/v1/dns/list`                       | All entries from all sources |
| `GET`    | `/v1/dns/entries`                    | Static entries only          |
| `POST`   | `/v1/dns/add`                        | Add a static entry           |
| `DELETE` | `/v1/dns/remove/{name}`              | Remove a static entry        |
| `POST`   | `/v1/dns/serve`                      | Start the resolver           |
| `POST`   | `/v1/dns/stop`                       | Stop the resolver            |

### Add example

```
POST /v1/dns/add
Content-Type: application/json

{"name": "grafana", "ip": "10.0.0.42"}
```

---

## Configuration

| Flag           | Env var          | Default | Description                              |
| -------------- | ---------------- | ------- | ---------------------------------------- |
| `--dns-port`   | `KOI_DNS_PORT`   | `53`    | DNS server port                          |
| `--dns-zone`   | `KOI_DNS_ZONE`   | `lan`   | Local DNS zone suffix                    |
| `--dns-public` | `KOI_DNS_PUBLIC` | `false` | Allow queries from non-private IP ranges |
| `--no-dns`     | `KOI_NO_DNS`     | `false` | Disable DNS capability entirely          |

The zone suffix determines what names the resolver claims authority over. The default `.lan` is a good choice for most environments - it's not a real TLD, so there's no collision risk. But if you prefer `.corp` or `.home`, change it:

```
koi --dns-zone corp
```

Port 53 is the standard DNS port, but it requires elevated privileges on most systems. For development and testing, use a high port:

```
koi --dns-port 15353
```

The `--dns-public` flag relaxes the client filter. By default, Koi only answers queries from private address ranges (RFC 1918, link-local). Enabling public mode lets any client query your resolver. This is almost never what you want on an open network - it's there for specific environments where the network topology demands it.

---

## Safety model

Koi DNS is conservative by design:

- **Private IPs only**: Local-zone names only resolve to private or link-local addresses. You can't accidentally create a DNS entry that points external traffic somewhere unexpected.
- **Private clients only**: By default, only clients on private IP ranges can query the resolver. This prevents your local zone from leaking to the internet.
- **Forwarding, not recursion**: Names outside the local zone are forwarded to the system upstream resolver. Koi doesn't recurse - it delegates.

These constraints mean Koi DNS can safely run alongside your existing DNS infrastructure. It doesn't interfere with public resolution, and it doesn't answer queries it shouldn't.

---

## Troubleshooting

### Port 53 bind failure

This is the most common issue. Port 53 requires root/admin privileges. Two options:

1. Run Koi with elevated privileges (suitable for production daemon mode)
2. Use a high port for testing: `koi --dns-port 15353`

On Linux, you may also need to contend with `systemd-resolved` which holds port 53. Either disable it or configure Koi on an alternate port.

### No results for `.lan` names

First, check that the resolver is actually running:

```
koi dns status
```

If the daemon is running:

```
koi dns status --endpoint http://localhost:5641
```

If the resolver is running but names aren't resolving, make sure your system is configured to use Koi as a resolver. For quick testing, you can query it directly with `dig` or `nslookup` pointed at the correct port.

### Names from certmesh or mDNS not appearing

These sources only populate when their respective capabilities are enabled and active. Check that mDNS discovery is running (`koi mdns status`) or that certmesh members have SANs on their certificates (`koi certmesh status`).
