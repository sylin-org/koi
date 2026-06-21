# P13 — Ecosystem Doors — Plan

> Branch: `dev` (autonomous). Four INDEPENDENT doors, commit each separately. Charter
> principle 10 (collaboration: their formats, their configs — never require Koi knowledge).
> Research: repo-side mapped + Prometheus http_sd verified (Prometheus 3.12; http_sd since
> 2.28). Traefik/Caddy label + DNS-forwarding syntax to be web-verified during implementation.

## Door 1 — Prometheus HTTP SD — `GET /v1/sd/prometheus`
Contract (verified): JSON array of `{targets:["host:port"], labels:{__meta_*}}`; **200 +
`Content-Type: application/json`**; full list every poll; empty = `[]`; `__meta_*` are
relabel-phase only. Mount in `crates/koi/src/adapters/http.rs::start()` as a top-level route
BEFORE the auth layer (GET is already auth-exempt) — unauthenticated like the rest.
Default slice = **Koi-managed** (announced/labeled/health-checked); `?include=discovered` adds
LAN-discovered `_http._tcp`. Sources: `HealthCore::snapshot()` (name, target, Up/Down),
`RuntimeCore::list_instances()` (host_port/host_ip), `MdnsSnapshot::cached_records()`,
**`CertmeshSnapshot::active_members()` → `cert_expires`** → the differentiator label
`__meta_koi_cert_expiry_days = (cert_expires - now).num_days()`. Labels: `__meta_koi_name`,
`__meta_koi_source` (runtime|health|mdns|labeled), `__meta_koi_service_type`,
`__meta_koi_health` (up|down|unknown), `__meta_koi_cert_expiry_days`. Test: shape + content-type
+ empty-list-on-nothing. Doc in `docs/guides/integrations.md` with the `prometheus.yml` snippet
(`http_sd_configs: [{ url: ".../v1/sd/prometheus" }]`).

## Door 2 — Traefik/Caddy label ingestion (koi-runtime)
Extend `crates/koi-runtime/src/instance.rs::KoiMetadata::from_labels_and_env`. **GOTCHA:** the
raw labels map is consumed in `docker.rs:116` and NOT stored on Instance — parse traefik/caddy
INSIDE `from_labels_and_env` (it receives the full map). Precedence (extend the existing):
explicit `koi.*` > **traefik/caddy-derived** > port heuristics; `koi.enable=false` wins over all.
Extract (web-verify exact syntax): traefik `traefik.enable=true`, the FIRST `` Host(`name.domain`) ``
from `traefik.http.routers.<r>.rule` (tolerate `||`/`PathPrefix`/malformed — never panic),
`traefik.http.services.<s>.loadbalancer.server.port`; caddy-docker-proxy `caddy=<host>` +
`caddy.reverse_proxy` upstream port. Derived → the service's dns_name + service_type; inventory
marks `source: traefik-labels`/`caddy-labels`. Passive/safe → **on by default with opt-out**.
Tests: 10+ extraction/precedence cases incl. malformed rules (no panic). Guide section + the
compose example. Inventory source marker.

## Door 3 — DNS coexistence + zone export
1. `GET /v1/dns/zone?format=hosts|dnsmasq|json` in koi-dns http.rs. Sources: `DnsCore::snapshot()`
   → `RecordsSnapshot{static/certmesh/mdns entries}` (name→IPs). **GOTCHA:** names are FQDN with
   trailing dot — strip for hosts/dnsmasq. hosts = `<ip> <name>`; dnsmasq = `address=/<name>/<ip>`;
   json = the record set. Tests: each format + empty. (koi-dns default bind `0.0.0.0:53`, zone `lan`.)
2. `docs/guides/dns-coexistence.md`: one copy-paste conditional-forwarding recipe per incumbent
   (web-verify current syntax + versions): AdGuard Home (`[/lab/]ip:port` upstream), Pi-hole v6
   (`server=/lab/ip#port` dnsmasq conf), dnsmasq, Unbound (`forward-zone:`), Technitium — each with
   a `dig @<resolver> name.lab` test. Push adapters out of scope (note follow-up).

## Door 4 — `koi trust` (generic root distribution)
`koi trust install <pem> | list | remove <name> | export --ca`. koi-truststore has
`install_ca_cert(pem, name)` + `is_ca_installed`; **ADD a per-platform `remove_ca_cert(name)`**
(Linux rm `/usr/local/share/ca-certificates/<name>.crt` + `update-ca-certificates --fresh`;
Windows `certutil -delstore Root <name>`; macOS `security delete-certificate`). **ADD CA-cert
validation** (gap): parse PEM (`pem` crate), reject garbage; check the cert is a CA
(BasicConstraints IsCa via x509-parser) — reject non-CA + give a clear error; fingerprint via
`koi_crypto::pinning`. Track Koi-installed roots in `state/trust.json` (koi-config persist
pattern) so list/remove only manage Koi roots (never enumerate the OS store). `export --ca`
reads `CertmeshPaths::ca_cert_path()` (`data_dir/certmesh/ca/ca-cert.pem`) — for the P12 bootstrap
recipes. Scope: local machine only (roster-wide trust = follow-up). CLI = a new top-level
`koi trust` moniker (cli.rs + dispatch + commands/trust.rs + help/meta). Tests: parse + CA-cert
rejection (non-CA + garbage) + a `#[ignore]` install/remove round-trip (needs admin).
`docs/guides/integrations.md` section: "Koi trust with step-ca/Caddy/mkcert".

## Sequence
Door per commit. Each updates guide + catalog (+ OpenAPI for the endpoints). Doors 1+4 share
`integrations.md` (Door 1 creates it; Door 4 appends). Do 1 → 4 → 2 → 3 to manage the shared
guide cleanly. Workspace green per charter.
