# Collaboration & Differentiation Strategy — Expanding the Opportunity Map

> Companion to [landscape-2026.md](landscape-2026.md) and
> [trends-opportunities-2026.md](trends-opportunities-2026.md), extending the
> [maturity assessment](../2026-06-maturity-assessment.md) §7. Written 2026-06-11.
> Integration mechanisms marked ✓ were verified against current vendor docs.

## The integration paradox — and the posture that resolves it

Koi's breadth is its biggest strategic liability when framed as competition: seven
capabilities invite "Koi vs X" comparisons against seven mature incumbents (Pi-hole,
Caddy, Traefik, step-ca, Uptime Kuma, Tailscale, Avahi), and Koi loses every
feature-by-feature comparison. The landscape research already concluded "the wiring is
the product." This document develops the consequence: **Koi should operate in two
postures from the same core**:

1. **Koi-as-authority** — the standalone stack for greenfield/simple environments: one
   binary gives names, certs, TLS, health. (The current product.)
2. **Koi-as-feeder** — the *discovery-and-trust substrate* that exports its knowledge
   into the tools people already run, in *their* native formats. (Almost entirely
   absent today, and where most of the unclaimed value sits.)

The homelab audience has already chosen its DNS ad-blocker, reverse proxy, and
dashboard. They will not rip those out for a young project. But **nobody owns the layer
underneath them** — the real-time knowledge of *what exists on this network, what it's
called, whether it's trusted, and whether it's alive*. Every incumbent wants that data
and has a documented ingestion interface for it. Koi uniquely *produces* it.

---

## New strategic opportunities (continuing §7's numbering)

### 6. ACME facade for certmesh — the single highest-leverage collaboration move

Expose certmesh as an **ACME server endpoint** (`/acme/directory`), the way step-ca
does. ✓ The pattern is established: Caddy and Traefik consume private ACME CAs today via
one config line (`caServer = "https://…/acme/acme/directory"`,
[smallstep's private ACME server](https://smallstep.com/blog/private-acme-server/),
[Traefik ACME resolver docs](https://doc.traefik.io/traefik/https/acme/),
[worked example](https://github.com/dogukancagatay/step-ca-example)) — as do
cert-manager, lego, acme.sh, NPM, and every other ACME client.

Why this transforms certmesh's position:

- It converts certmesh from *"a PKI you must adopt"* (proprietary join ceremony,
  Koi-side renewal, reload hooks) into *"a local Let's Encrypt your existing stack
  already speaks."* Users keep Caddy/Traefik; Koi just signs. The "trust a young
  project for PKI" objection shrinks to "trust it to sign," with no workflow lock-in.
- **Koi has a structural advantage no other private ACME CA has: it owns the local DNS
  zone.** DNS-01 challenges can be self-served internally (the CA writes the TXT record
  into koi-dns and validates it in-process) — no public domain, no DNS-provider API
  keys, no propagation delays. step-ca cannot do this without an external DNS server;
  for Koi it is one internal function call. This makes *wildcard and offline issuance*
  trivially automatable on a LAN — a genuinely unique capability.
- It composes with the existing differentiators: ACME issues the cert, koi-truststore
  distributes the root, the roster tracks who holds what. step-ca offers none of the
  last two.

Cost: an ACME server implementation (directory, nonce, order, authz, DNS-01/TLS-ALPN-01)
is real work — the one significant *build* recommendation in this document. It is also
the best candidate to *replace* shed certmesh surface (enrollment windows, scope
policies, compliance) rather than add to it: ACME's account model can subsume much of
the bespoke enrollment machinery for the service-cert use case, with the TOTP ceremony
reserved for *machine* (roster) enrollment.

### 7. "Sync engine" mode — push names into the DNS users already run

People will not drop Pi-hole/AdGuard (their ad-blocking lives there). Koi should feed
them instead, in two tiers:

- **Tier 1 (docs only, days):** conditional-forwarding recipes. Pi-hole, AdGuard Home
  (`[/lab.internal/]<koi-ip>` upstream syntax), Technitium, dnsmasq, and Unbound all
  support per-domain forwarding — delegate `lab.internal` (or the user's chosen zone)
  to koi-dns. Koi stays authoritative for its zone; the incumbent stays the household
  resolver. Zero code.
- **Tier 2 (small adapters):** active push. Koi already maintains the record set
  (mDNS-derived aliases + certmesh SANs + container names); export it *into* the
  incumbent: Pi-hole's custom-DNS API, AdGuard's rewrites API, **RFC 2136 dynamic
  updates** for Technitium/BIND/Windows DNS Server. Each adapter is a thin
  one-direction sync loop. Koi becomes *the discovery-to-DNS bridge* — the wiring that
  today exists only as hand-edited zone files — without serving a single user query
  itself if the user prefers.

This also reframes koi-dns's defensibility honestly: it can't beat Technitium as a DNS
server, but as the *dynamic record source* for Technitium it has no competitor.

### 8. OS-resolver adoption — `koi dns adopt`

The #1 friction of any local DNS solution is "now repoint your devices' DNS." The
collaboration answer is to integrate with the **OS resolver's split-DNS facilities**
instead of replacing the resolver: `resolvectl domain`/`dns` per-link routing on
systemd-resolved, `/etc/resolver/<domain>` files on macOS, NRPT rules on Windows. A
`koi dns adopt` command that registers Koi as the resolver *for its zone only* — and
`koi dns abandon` to undo it — gives MagicDNS-grade UX without touching global DNS.
This is precisely how Tailscale integrates, and it is the missing last mile for
opportunities 6 and 7.

### 9. Tailnet coexistence — "Koi for the LAN, Tailscale for the WAN"

Don't fight the gravity well; dock with it. ✓ Tailscale's **restricted nameservers
(split DNS)** let an admin route one domain to a custom DNS server for every tailnet
client ([DNS in Tailscale](https://tailscale.com/docs/reference/dns-in-tailscale),
[split-DNS overview](https://tailscale.com/learn/why-split-dns)). Point `lab.internal`
at koi-dns and **remote tailnet devices resolve Koi names** — Koi's zone becomes
reachable from anywhere, while Koi keeps serving the devices Tailscale can't (printers,
TVs, guests, IoT — anything not in the tailnet). The same recipe works for NetBird
(DNS groups/match-domains). Deliverable: a documented pattern + a `koi status` hint
when a tailnet interface is detected. The division of labor is clean and honest:
Tailscale owns remote access and WAN identity; Koi owns LAN-local naming, discovery,
and trust for *all* devices.

### 10. Observability feeds — turn koi-health from product into supply chain

The assessment already demotes koi-health (commodity vs Uptime Kuma/Gatus). The
collaboration version turns Koi's *discovery* into the thing monitoring tools lack:

- **Prometheus HTTP service discovery** ✓ — `http_sd_config` polls a JSON endpoint for
  scrape targets ([Prometheus HTTP SD](https://prometheus.io/docs/prometheus/latest/http_sd/)).
  A `/v1/sd/prometheus` endpoint mapping discovered/labeled services (with
  `__meta_koi_*` labels for type, instance, cert expiry) is ~a day of work and makes
  Koi the auto-population source for every homelab Prometheus/Grafana stack.
- **Gatus/Uptime Kuma config export** — generate monitor definitions from the same
  inventory (both tools are config/API-driven).
- **Dashboard widgets** — Homepage/Homarr/Dashy auto-populated "what's on my network"
  via Koi's HTTP API; these dashboards are the homelab's front page and a free
  discovery channel for Koi itself.
- Bonus metric nobody else has: **per-service certificate expiry from the roster**,
  exported as Prometheus metrics — directly feeds the cert-automation anxiety the
  47-day-lifetime mandate created.

### 11. Reverse-proxy collaboration — three rungs, no replacement

- **Rung 1 (free, now):** certmesh cert files + the existing reload hooks, documented
  for Caddy/NPM/Traefik file-provider users.
- **Rung 2 (the ACME facade, #6):** proxies obtain and renew certs themselves; Koi is
  just their CA. This alone makes koi-proxy optional for everyone who has a proxy.
- **Rung 3 (targeted build):** a **Traefik provider plugin** ✓ — Traefik's yaegi plugin
  system supports custom *provider* plugins that feed routers/services from external
  discovery (precedent: the Service Fabric provider —
  [Traefik plugin catalog](https://plugins.traefik.io/plugins),
  [extend docs](https://doc.traefik.io/traefik/extend/extend-traefik/)). A `koi`
  provider would let Traefik route to anything Koi discovers — containers *and*
  bare-metal LAN services, which Traefik's Docker provider can't see.

And one **zero-effort-for-users** move with outsized charm: **read the labels users
already wrote.** Millions of containers already carry `traefik.http.routers.*` /
caddy-docker-proxy labels. koi-runtime can derive names, ports, and TLS intent from
those *existing* labels (in addition to its own `koi.*` namespace) — instant value on
day one, no relabeling, and a wedge into every Traefik-labeled compose stack.

### 12. The Home Assistant channel

HA (2M+ installs) sits at the center of the audience and has Koi's exact pains
documented: mDNS discovery broken in containers, TLS-for-the-dashboard friction. Two
cheap plays: package Koi as a **Supervisor add-on** (an add-on is just a managed
container — Koi's host-daemon role maps cleanly, and solves HA's zeroconf-in-Docker
problem via HTTP instead of host networking), and a small **HACS integration** exposing
Koi-discovered services/health as HA entities. This is distribution strategy more than
engineering: the add-on store is how this audience installs infrastructure.

### 13. Generic truststore service — `koi trust`

koi-truststore (306 lines, the assessment's "model small crate") solves the one problem
*every* private-CA approach shares — root distribution — and currently hides it behind
certmesh. Decouple it: `koi trust install <root.pem>`, `koi trust list`,
`koi trust verify <name>` work with **any** CA — step-ca, Caddy's local CA, mkcert,
corporate roots. Combined with the roster, Koi can answer "which of my machines trust
this root?" — visibility nothing else on the market offers. This makes Koi valuable
even to users who keep their existing CA, and it is the lowest-cost item in this
document (the crate already exists; this is CLI surface + docs).

### 14. Runtime backend pull — Proxmox before Kubernetes

The assessment recommends deleting the Systemd/Incus/Kubernetes stub variants. When a
second backend is ever justified by demand, the evidence points to **Proxmox** (45% of
homelabs per selfh.st 2025; the stubs cover none of it): VM/LXC metadata → the same
name+cert+health pipeline. Strictly demand-pulled — noted here so the next backend
decision starts from audience data rather than enterprise reflexes.

---

## Sharpened differentiation axes (the "how else" answers)

Beyond the four positions already established (cross-platform mDNS daemon with HTTP
API; container mDNS without host networking; the integrated pipeline; Windows
first-class), the comparison work surfaces five more axes worth owning explicitly:

1. **Lifecycle correctness — "no stale services."** Koi's lease engine
   (session/heartbeat/permanent, ALIVE→DRAINING→EXPIRED, transport-adaptive defaults)
   is its most under-marketed invention (it has a defensive publication but zero
   README presence). Avahi ghosts and half-dead registrations are a familiar annoyance;
   "services that vanish actually disappear" is a crisp, demonstrable promise no
   incumbent makes.
2. **Offline-first / airgapped-first.** Everything in Koi works with zero internet: no
   SaaS account (vs Tailscale's coordination server), no public domain or CT logs (vs
   Let's Encrypt flows), no external dependencies (vs Avahi's D-Bus). Ships, labs, OT
   networks, field deployments, and privacy-motivated homelabs are a real and growing
   segment — and "the LAN toolkit that works when the WAN doesn't" is a position no
   competitor can chase without redesign.
3. **The LAN inventory API.** Discovery + DNS + roster + health + runtime as one
   queryable, real-time, OpenAPI-documented source of truth about the local network.
   Individually each datum exists somewhere; *joined*, they exist nowhere else. This is
   the substrate that #10 (observability), #12 (HA), and the MCP opportunity all draw
   from — and it's already built.
4. **API-first among its peers.** Koi is the only tool in its category with a
   Scalar-documented REST surface; Avahi has D-Bus, step-ca has a CLI-first story,
   Pi-hole's API is an afterthought. For scripters and AI agents, this is the
   adoption-deciding feature.
5. **Integration-readiness as the differentiator itself.** If §6–§11 land, Koi speaks
   *every lingua franca of local infrastructure*: ACME to proxies, HTTP-SD to
   Prometheus, RFC 2136 to DNS servers, split-DNS to tailnets and OS resolvers, labels
   to container stacks, MCP to agents. None of these interfaces is individually novel —
   *being the one tool that speaks all of them from a single binary* is.

## Rules of engagement (the collaboration doctrine)

Worth encoding in the project's philosophy docs, alongside "the boundary is the local
network":

1. **Export in their formats; never require import in ours.** Koi adapts to the
   incumbent's interface (ACME, http_sd, RFC 2136, rewrites API), not vice versa.
2. **Consume what users already wrote.** Existing traefik/caddy labels, existing
   compose files, existing roots — meet the environment as-is.
3. **Be the substrate, not the surface.** The user's dashboard stays Homepage/Grafana;
   the user's proxy stays Caddy; Koi supplies the knowledge and trust underneath. The
   built-in dashboard/proxy remain the zero-config fallback, never the pitch.
4. **Every capability needs an exit.** Conditional forwarding instead of resolver
   replacement; `dns abandon` to undo `dns adopt`; ACME so certs outlive Koi adoption.
   Tools that are easy to *stop* using are easy to *start* using.
5. **Degrade gracefully when a layer is owned.** Detect Pi-hole/Traefik/Tailscale and
   offer the feeder posture instead of competing (`koi status` should say "AdGuard
   detected — see the sync guide", not silently double-serve DNS).

## Priority and cost

| Opportunity | Cost | Leverage | When (roadmap stage) |
|---|---|---|---|
| 13. `koi trust` generic truststore | Trivial (exists) | Medium-high | Stage 2 (falls out of consolidation) |
| 7. Tier-1 DNS forwarding recipes + 9. tailnet split-DNS docs | Docs only | High | Stage 0–1 |
| 10. Prometheus http_sd endpoint | ~Days | High | Stage 3–4 |
| 11. Read traefik/caddy labels | Small | High | Stage 2 (runtime adapter work) |
| 8. `koi dns adopt` (OS split-DNS) | Moderate (3 platforms) | High | Stage 4 |
| 7. Tier-2 push adapters (Pi-hole/AdGuard/RFC2136) | Moderate | High | Stage 4 |
| 12. HA add-on + HACS integration | Moderate (packaging) | High (channel) | Stage 4 |
| 6. ACME facade | Significant | **Transformative** | Stage 4–5, after the certmesh diet |
| 11. Traefik provider plugin | Moderate (Go/yaegi) | Medium | Demand-pulled |
| 14. Proxmox backend | Significant | Medium | Demand-pulled only |

The pattern across the table: **the collaboration strategy is mostly cheap.** Six of
ten items are docs, small endpoints, or surface over existing code — consistent with
the assessment's "less but more meaningful parts": Koi doesn't need more domains; it
needs more *doors*.

## Unchanged anti-goals

Everything in this document stays inside the established fence: no ad-blocking, no
proxy feature wars, no tunneling, no overlay networking, no enterprise PKI, no
monitoring product, no Matter controller. Collaboration interfaces are doors through
the fence, not extensions of it.

---

### Sources (verified June 2026)

- Traefik provider plugins: [plugin catalog](https://plugins.traefik.io/plugins),
  [Extend Traefik](https://doc.traefik.io/traefik/extend/extend-traefik/),
  [providers overview](https://doc.traefik.io/traefik/providers/overview/)
- Private ACME pattern: [smallstep private ACME server](https://smallstep.com/blog/private-acme-server/),
  [ACME clients with step-ca](https://smallstep.com/docs/tutorials/acme-protocol-acme-clients/),
  [Traefik ACME](https://doc.traefik.io/traefik/https/acme/),
  [step-ca + Traefik example](https://github.com/dogukancagatay/step-ca-example),
  [homelab DNS-01 + Traefik writeup](https://www.garrettlaman.com/Homelab/Automating-internal-certificate-management-with-ACME-DNS%E2%80%9101-and-Traefik)
- Prometheus HTTP SD: [writing HTTP SD](https://prometheus.io/docs/prometheus/latest/http_sd/),
  [configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- Tailscale split DNS: [DNS in Tailscale](https://tailscale.com/docs/reference/dns-in-tailscale),
  [why split DNS](https://tailscale.com/learn/why-split-dns),
  [homelab split-DNS pattern](https://aottr.dev/posts/2024/08/homelab-using-the-same-local-domain-to-access-my-services-via-tailscale-vpn/)
