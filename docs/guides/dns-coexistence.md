# DNS coexistence — running Koi alongside your resolver

Koi's resolver does **not** want to replace the DNS server you already run. The
collaboration pattern (Charter principle 10) is **conditional forwarding**: your
incumbent resolver stays authoritative for everything, and forwards just the Koi
zone (`lab.internal` in the examples below) to Koi. Stop forwarding and nothing
breaks — Koi is purely additive.

Koi's DNS resolver listens on `0.0.0.0:53` by default and is authoritative for its
zone (default `internal`; the examples use `lab.internal` — set it with `--dns-zone`).
Replace `<koi-ip>` with the host running Koi.

You can also pull a snapshot of the zone for resolvers that prefer a static file:

```sh
TOKEN=$(koi token show)   # run on the Koi host; or `koi token write <path>` for a 0600 file
curl -s -H "x-koi-token: $TOKEN" "http://<koi-ip>:5641/v1/dns/zone?format=hosts"    # <ip> <name> lines
curl -s -H "x-koi-token: $TOKEN" "http://<koi-ip>:5641/v1/dns/zone?format=dnsmasq"  # address=/<name>/<ip> lines
```

> **Auth note.** `/v1/dns/zone` (and `/v1/dns/list`, `/v1/dns/entries`) is
> token-gated for **non-loopback** callers — so a `curl` run *from another host*
> (the resolver box) must pass `-H "x-koi-token: $TOKEN"` or it gets a `401`.
> Read the token with `koi token show` on the Koi host (`koi token write <path>`
> writes a 0600 file for containers/scripts). A `curl` run **on the Koi host
> itself** (loopback) needs no token.

Each recipe below ends with a `dig` test you can run from any client of that
resolver.

---

## AdGuard Home (v0.107.x)

**Settings → DNS settings → Upstream DNS servers**, add a zone-scoped upstream:

```
[/lab.internal/]<koi-ip>:53
```

The `[/zone/]` prefix routes only `*.lab.internal` queries to `<koi-ip>:53`; all
other names use AdGuard's normal upstreams. Click **Apply**.

```sh
dig @<adguard-ip> grafana.lab.internal
```

---

## Pi-hole v6 (FTL v6)

Pi-hole v6 manages dnsmasq through its own config. Add the forward rule under
**Settings → All settings → Misc → `misc.dnsmasq_lines`**:

```
server=/lab.internal/<koi-ip>#53
```

(`#53` is dnsmasq's port separator, not `:53`.) Save and let FTL reload.

> **v6 gotcha:** Pi-hole v6 ignores drop-in files in `/etc/dnsmasq.d/*.conf` by
> default. Either use the `misc.dnsmasq_lines` setting above, or first enable
> `misc.etc_dnsmasq_d=true` (Settings → All settings → Misc) before relying on
> drop-in files.

```sh
dig @<pihole-ip> grafana.lab.internal
```

---

## dnsmasq (2.92)

Drop a file in `/etc/dnsmasq.d/` (e.g. `koi.conf`):

```
server=/lab.internal/<koi-ip>#53
```

Reload: `sudo systemctl reload dnsmasq` (or send `SIGHUP`).

```sh
dig @<dnsmasq-ip> grafana.lab.internal
```

---

## Unbound (1.25)

Add a `forward-zone` clause (e.g. in `/etc/unbound/unbound.conf.d/koi.conf`):

```
forward-zone:
    name: "lab.internal"
    forward-addr: <koi-ip>@53
```

(Unbound uses `@53` for the port.) Reload: `sudo unbound-control reload` (or
restart the service).

```sh
dig @<unbound-ip> grafana.lab.internal
```

---

## Technitium (v15)

In the web console, **Zones → Add Zone**:

- **Zone:** `lab.internal`
- **Type:** Conditional Forwarder
- **Forwarder Protocol:** `Udp`
- **Forwarder:** `<koi-ip>:53`

Save the zone.

```sh
dig @<technitium-ip> grafana.lab.internal
```

---

## Push adapters (follow-up)

The recipes above are **pull/forward** integrations — the incumbent forwards live
queries to Koi, so Koi's records are always current with zero sync. *Push*
adapters that write Koi's records *into* another resolver (e.g. the Pi-hole admin
API, or RFC 2136 dynamic DNS updates) are an explicit follow-up and not yet
provided. For static imports today, poll `GET /v1/dns/zone?format=hosts` (or
`dnsmasq`) on a timer and feed the file to your resolver — pass
`-H "x-koi-token: $TOKEN"` when polling from a remote host (see the auth note above).
