# Integrations

Koi is the substrate *under* the tools you already run. It speaks **their** formats
so you never have to teach those tools that Koi exists — point them at a Koi
endpoint or hand them a file in the shape they expect, and they work. Every door
here has an easy exit: stop pointing the tool at Koi and nothing breaks.

- [Prometheus](#prometheus) — scrape Koi-managed services via HTTP service discovery.
- [Traefik & Caddy labels](#traefik--caddy-labels) — Koi reads the routing labels you
  already wrote.
- [Trust (root distribution)](#trust-root-distribution) — install any CA root into
  the OS trust store, and export the certmesh root for ACME bootstrap.
- [Traefik & Caddy labels](#traefik--caddy-labels) — Koi reads the routing labels
  you already wrote for your reverse proxy.

---

## Prometheus

Koi exposes a [Prometheus HTTP service discovery](https://prometheus.io/docs/prometheus/latest/http_sd/)
endpoint at `GET /v1/sd/prometheus`. Prometheus polls it, Koi answers with the
current set of targets — no exporter sidecar, no per-service scrape config, no Koi
plugin on the Prometheus side.

### `prometheus.yml`

```yaml
scrape_configs:
  - job_name: koi-lan
    http_sd_configs:
      - url: "http://127.0.0.1:5641/v1/sd/prometheus"
```

That is the entire integration. Prometheus re-polls on its `refresh_interval`
(default 60s) and always receives the full target list (it does not diff). On a
fresh daemon the endpoint returns `[]`.

To also scrape services Koi merely *discovered* on the LAN (mDNS `_http._tcp`),
not just the ones it manages, add the query parameter:

```yaml
      - url: "http://127.0.0.1:5641/v1/sd/prometheus?include=discovered"
```

### What gets exported

- **Default (Koi-managed):** every health-checked service and every runtime
  (container) instance that publishes a port. These are the services *you* told
  Koi about.
- **`?include=discovered`:** additionally, LAN-discovered `_http._tcp` mDNS records.

A target with no recoverable `host:port` is silently skipped rather than emitted
broken.

### Labels

Each target group carries `__meta_koi_*` labels. Like all `__meta_*` labels they
exist only during the relabel phase — use `relabel_configs` to promote the ones
you want onto the final series.

| Label                          | Meaning                                                        |
| ------------------------------ | -------------------------------------------------------------- |
| `__meta_koi_name`              | Service name (label/announce name, else the instance name).    |
| `__meta_koi_source`            | `health`, `runtime`, or `mdns` — where Koi learned the target. |
| `__meta_koi_service_type`      | mDNS service type (e.g. `_http._tcp`) when known.              |
| `__meta_koi_health`            | `up`, `down`, or `unknown` (health-checked targets only).      |
| `__meta_koi_cert_expiry_days`  | Days until the certmesh cert for this name expires.            |

`__meta_koi_cert_expiry_days` is **unique to Koi** — no other LAN service-discovery
source (Consul, Docker, file SD, …) knows your private-CA certificate lifetimes.
It is attached only when the target's name matches an active certmesh member with a
known expiry, and omitted otherwise. It lets you alert on soon-to-expire mesh certs
straight from Prometheus:

```yaml
    relabel_configs:
      - source_labels: [__meta_koi_cert_expiry_days]
        target_label: koi_cert_expiry_days
```

```promql
# Members whose Koi mesh cert expires within a week.
min_over_time(koi_cert_expiry_days[1h]) < 7
```

---

## Trust (root distribution)

`koi trust` installs CA roots into the operating system's trust store and exports
the certmesh root — so the tools you already use to make local TLS (step-ca,
mkcert, Caddy's internal CA, a corporate root) become trusted system-wide with one
command, and so Koi's own mesh root can seed those same tools.

Koi tracks only the roots **it** installed (in `state/trust.json`); `list` and
`remove` never enumerate or touch the rest of your OS store.

### Install any root

```sh
# Trust a step-ca root system-wide (browsers, curl, language runtimes).
koi trust install ./step-ca-root.pem

# Trust mkcert's local CA, or Caddy's internal root, the same way:
koi trust install "$(mkcert -CAROOT)/rootCA.pem"
koi trust list
koi trust remove koi-step-ca-root   # untrust later — every door has an exit
```

`install` validates the input: it must be a real X.509 **CA** certificate. A
server/leaf certificate is rejected (`not a CA certificate`), so you cannot
accidentally install the wrong PEM as a root.

### Export the certmesh root (ACME bootstrap)

```sh
koi trust export --ca > koi-root.pem
```

This prints the certmesh root CA (PEM) to stdout. Use it to bootstrap trust in
clients that won't read the OS store — for example seeding an ACME client's CA
bundle so it trusts Koi's ACME directory. See the
[ACME guide](./acme.md) for where this fits the bootstrap flow.

### Using Koi trust with step-ca / Caddy / mkcert

- **step-ca** — `step ca root root.pem` writes the root; `koi trust install
  root.pem` makes the whole machine trust it. Now any service step-ca issues for
  is trusted without per-app `--cacert`.
- **Caddy** — Caddy's automatic-HTTPS internal issuer writes a root at
  `$XDG_DATA_HOME/caddy/pki/authorities/local/root.crt`; install that with
  `koi trust install` to trust Caddy-issued local certs.
- **mkcert** — `mkcert -install` already trusts its root; to push that same root
  to *other* machines, copy `$(mkcert -CAROOT)/rootCA.pem` over and run
  `koi trust install rootCA.pem` there.

---

## Traefik & Caddy labels

If you already label your containers for Traefik or Caddy, Koi reads those labels
and gives the service a local DNS name and a proxy port — no extra `koi.*` labels
required. The labels you wrote for your reverse proxy do double duty.

This is passive and safe (Koi only *reads* labels you already wrote), so it is on
by default. Opt a container out with `koi.enable=false`.

**Precedence:** explicit `koi.*` labels win, then Traefik/Caddy-derived values,
then port heuristics. `koi.enable=false` overrides everything.

### Traefik (v3)

Koi reads the **first** ``Host(`…`)`` from any
`traefik.http.routers.<r>.rule` and the
`traefik.http.services.<s>.loadbalancer.server.port`. Containers with
`traefik.enable=false` are ignored.

```yaml
services:
  grafana:
    image: grafana/grafana
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.grafana.rule=Host(`grafana.lab.internal`)"
      - "traefik.http.services.grafana.loadbalancer.server.port=3000"
```

```sh
koi dns lookup grafana.lab.internal     # resolves to the container — no koi.* labels
```

`Host(...)` is matched on the rule value only — the arbitrary `<r>`/`<s>` segment
names are never used as the hostname. `&&`, `||`, and `PathPrefix(...)` are
tolerated; the first `Host` wins; a rule with no `Host` contributes no name.

### Caddy (caddy-docker-proxy)

Koi reads the **first** comma-separated entry of the `caddy` label as the
hostname, and the numeric port from `caddy.reverse_proxy`'s
`{{upstreams …}}` directive.

```yaml
services:
  grafana:
    image: grafana/grafana
    labels:
      caddy: grafana.lab.internal
      caddy.reverse_proxy: "{{upstreams 3000}}"
```

```sh
koi dns lookup grafana.lab.internal
```

`{{upstreams https}}` (no port) contributes a hostname but no port; `{{upstreams
http 8080}}` and `{{upstreams 8080}}` both contribute port `8080`.

The inventory marks these instances with `source: traefik-labels` /
`caddy-labels` so you can see where the routing came from
(`GET /v1/runtime/instances`).
