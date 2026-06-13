# P13 — Ecosystem Doors (feeders pack)

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M (four independent doors — commit each separately; any subset is a valid
> session) · Prereqs: P03 · Read `docs/prompts/CHARTER.md` first — principle 10
> (collaboration doctrine) is the spec.
> Strategy basis: docs/assessment/research/collaboration-strategy-2026.md §7–§13.

## Mission

Open four cheap, high-leverage doors that let Koi *feed* the tools users already run —
export in their formats, consume what users already wrote, never require
rip-and-replace. Each door is small precisely because the knowledge it exports (the
LAN inventory: discovered services + names + cert state + health + instances) already
exists in Koi.

---

## Door 1 — Prometheus HTTP service discovery

**Research:** Prometheus `http_sd_config` contract (GET → JSON array of
`{targets, labels}` groups; 200 + `Content-Type: application/json`; full list every
poll; `__meta_*` label conventions). Decide which inventory slices become target
groups (health-checked HTTP services, runtime instances with ports, mDNS-discovered
`_http._tcp`?) and the opt-in/scrape-safety semantics — recommended: only services Koi
*manages* (announced/labeled/health-checked) by default; LAN-discovered third parties
behind `?include=discovered`.

**Target shape:**

```jsonc
// GET /v1/sd/prometheus            (unauthenticated GET, like the rest)
[{ "targets": ["192.168.1.42:3000"],
   "labels": { "__meta_koi_name": "grafana", "__meta_koi_source": "runtime",
               "__meta_koi_service_type": "_http._tcp",
               "__meta_koi_health": "up",
               "__meta_koi_cert_expiry_days": "23" } }]
```

```yaml
# prometheus.yml — the entire integration:
scrape_configs:
  - job_name: koi-lan
    http_sd_configs: [{ url: "http://127.0.0.1:5641/v1/sd/prometheus" }]
```

`__meta_koi_cert_expiry_days` is the differentiator — nobody else exports per-service
cert expiry into Prometheus. Acceptance: endpoint conforms to the contract (test:
shape + content-type + empty-list-on-nothing); documented in a new
`docs/guides/integrations.md` with the YAML above.

---

## Door 2 — Traefik/Caddy label ingestion (consume what users already wrote)

**Research:** the `traefik.*` label conventions actually present on real compose
stacks — minimum viable extraction: service name from router rule
`` Host(`name.domain`) `` patterns, port from
`traefik.http.services.<n>.loadbalancer.server.port`, enablement from
`traefik.enable`. Also `caddy` / `caddy.reverse_proxy` labels (caddy-docker-proxy).
Map the precedence: explicit `koi.*` labels > traefik/caddy-derived > heuristics
(current `instance.rs` precedence logic is the model — extend it).

**Target behavior:** a container labeled only for Traefik gets a Koi DNS name and
appears in the inventory with **zero** relabeling:

```yaml
services:
  grafana:
    labels:
      - traefik.enable=true
      - traefik.http.routers.grafana.rule=Host(`grafana.lab.internal`)
      - traefik.http.services.grafana.loadbalancer.server.port=3000
# → koi dns lookup grafana.lab.internal → container IP; inventory shows source: traefik-labels
```

Opt-out flag (`koi.enable=false` wins over everything). Acceptance: unit tests for the
extraction/precedence matrix in `koi-runtime/src/instance.rs`-land (10+ cases incl.
malformed rules — never panic on a weird label); guide section with the example above;
inventory marks the source.

---

## Door 3 — DNS coexistence recipes + zone export

**Research:** verify each incumbent's conditional-forwarding syntax from current docs:
AdGuard Home (`[/lab.internal/]192.168.1.10:5354` upstream syntax), Pi-hole v6
(misc.dnsmasq config / `server=/lab.internal/...`), dnsmasq, Unbound
(`forward-zone:`), Technitium (conditional forwarder app). Verify koi-dns's actual
listen port/address story for being a forward target.

**Deliverables (mostly docs, one tiny endpoint):**

1. `docs/guides/dns-coexistence.md` — "keep your ad-blocker" recipes, one per
   incumbent, each a copy-paste block with its verified syntax + a test command
   (`dig @pihole grafana.lab.internal`).
2. `GET /v1/dns/zone?format=hosts|dnsmasq|json` — export the current record set in
   hosts-file and dnsmasq `address=/.../...` formats, for tools/users that prefer
   static sync over forwarding. (Push adapters — Pi-hole API/RFC 2136 — are out of
   scope; note as follow-up.)

Acceptance: endpoint with format tests; the guide's recipes carry exact version-pinned
syntax with sources.

---

## Door 4 — `koi trust`: generic root distribution

**Research:** confirm `koi-truststore`'s API (306 lines: install + per-platform
modules + name validation) and what certmesh passes it today. CLI moniker fit per
charter principle 1.

**Target shape:**

```console
$ koi trust install ./step-ca-root.pem      # ANY CA's root — not just certmesh's
✓ installed "step-ca-root" into the system trust store (requires admin)
$ koi trust list                            # roots Koi has installed (tracked in state)
NAME            INSTALLED    FINGERPRINT
koi-pond        2026-03-02   a1b2…
step-ca-root    2026-06-12   c3d4…
$ koi trust remove step-ca-root
$ koi trust export --ca > koi-root.pem      # certmesh root, for P12 bootstrap recipes
```

Scope fence: local machine only (roster-wide "which machines trust X" needs daemon
RPC — note as follow-up). Track installs in a state file so `list`/`remove` only
manage Koi-installed roots (never enumerate/touch the OS store wholesale). Acceptance:
subcommands + catalog entries + parse tests; install/remove round-trip integration
test gated `#[ignore]` (needs admin); fingerprint validation rejects non-CA certs and
garbage PEM with clear errors; `docs/guides/integrations.md` section: "using Koi trust
with step-ca/Caddy/mkcert".

---

## Session protocol

Per charter: research each door's external contract from primary docs (record sources
in the plan file), plan all four (or the chosen subset), implement door-per-commit.
Every door updates: guide, catalog, OpenAPI where applicable.

## Overall acceptance

- [ ] Each implemented door has its tests, docs with copy-paste-verified snippets, and
      catalog/OpenAPI entries.
- [ ] No door requires the partner tool to know Koi exists (their formats, their
      configs) — doctrine check.
- [ ] Workspace green per charter commands.

## Do NOT

- Build push adapters (Pi-hole API writes, RFC 2136), `koi dns adopt` (OS split-DNS),
  HA add-on packaging, or the Traefik provider plugin — all noted follow-ups with
  their own future prompts.
- Make any door default-on if it changes network behavior (Door 2 extraction is
  passive/safe → on by default with opt-out; justify any deviation).
