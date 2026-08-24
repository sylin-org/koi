# What is Koi, and is it for you?

This page is orientation, not instructions. It explains what Koi is, the problem it
solves, who it's for, and — just as importantly — when you should reach for something
else. If you already know you want it, skip to [where to go next](#where-to-go-next).

---

## The promise

> **Let everything local find, trust, and talk.**

Koi is an open-source local connectivity substrate that makes containers,
applications, and devices delightfully discoverable, secure, and interconnected.
It runs as one cross-platform binary, has no hosted control plane, and continues to
work when the internet does not.

A local network gives participants addresses, but very little shared context. Devices
may advertise over mDNS while bridge-networked containers cannot hear them. Applications
accumulate IP addresses and ports in configuration. Private services need useful names,
yet those names still produce certificate warnings unless every machine shares a trust
root. Each layer has a point solution; the boundaries between them become repeated work.

Koi owns that connective tissue.

## How Koi grew

Koi began as a host-side mDNS bridge for containers. The host could participate in
multicast while isolated workloads used ordinary HTTP, preserving container network
isolation without making every image carry platform-specific discovery machinery.

Making containers first-class network citizens revealed the adjacent gaps. Something
that arrives needs a name. Something found needs a reliable way to be reached. A name
needs identity before people and applications can trust it. Health and lifecycle must
keep the entire picture honest when the participant changes or leaves.

Those are not unrelated features. They are the missing seams in one local-participation
lifecycle:

`arrive → receive a name → be discovered → be reached → be trusted → report health → change → leave cleanly`

## Find. Trust. Connect.

### Find

Koi speaks mDNS/DNS-SD, gives services meaningful names in a local DNS zone
(`.internal` by default), observes container runtime events, and maintains leases so
departed services disappear instead of becoming stale ghosts. A participant can be
found whether it began as a device announcement, a container label, a static record,
or a certificate identity.

### Trust

Koi provides a private certificate authority, guided enrollment, automatic renewal,
OS trust-store installation, mTLS, signing and verification, and a trust doctor that
makes failures explicit. The result is locally governed identity and warning-free HTTPS
for in-zone services without pretending that an unverified discovery announcement is
proof. Security is one pillar of Koi, not its entire identity.

### Connect

Koi bridges the boundaries that normally keep local participants apart. Containers can
announce, discover, and watch mDNS without host networking; applications can use the
CLI, HTTP, IPC, or an embedded Rust API; UDP can cross a container bridge; and existing
proxies, resolvers, monitoring systems, runtimes, and agents can consume standard
interfaces. This is bidirectional participation, not merely an inbound route.

The familiar `discover → name → trust → serve → watch` pipeline remains one useful
end-to-end journey beneath these outcomes. It is evidence that Koi's capabilities
compose, not the boundary of what Koi enables.

## Who it's for

Koi is built for people who own the network they run on:

- **Homelabbers and self-hosters** who want `https://grafana.internal` to just work.
- **Developers on a LAN** who need services to find each other and carry trusted certs
  without a public DNS name or a Let's Encrypt round-trip.
- **Small teams** running a handful of machines who want naming and trust without standing
  up enterprise DNS or PKI.
- **Container hosts**, where bridge networks cannot carry multicast — the host daemon
  lets workloads announce, discover, and watch the LAN through ordinary interfaces.

## Works with the stack you already have

Koi is connective infrastructure, not a demand to replace working tools:

- Keep Pi-hole, AdGuard, dnsmasq, or Unbound and delegate only the Koi zone.
- Keep Caddy, Traefik, or another reverse proxy and let its ACME client obtain local
  certificates from Koi.
- Keep Tailscale or another overlay and route `.internal` lookups to Koi through its
  split-DNS mechanism.
- Keep Docker or Podman labels, Prometheus service discovery, and MCP clients; Koi
  consumes or exports the formats those tools already speak.

Koi can be the authority for a small greenfield network or the feeder beneath an
existing stack. Every capability can be disabled independently.

## Ways to use it

The same binary supports four access modes:

- **Daemon** — `koi --daemon` (or installed as a service). The composed capabilities,
  HTTP API on `127.0.0.1:5641`, dashboard, and trust plane.
- **Standalone** — `koi mdns discover` with no daemon running does the work directly and
  exits. Instant, zero config.
- **Client** — the same command *with* a daemon running talks to it over HTTP instead.
- **Embedded** — `koi-embedded` is a Rust library that puts the same cores inside your own
  application, no separate process.

You don't pick a mode; Koi detects it. Bare `koi` shows live status and the command
catalog.

## The trust boundary

Koi's threat model is simple and worth stating plainly: **Koi is a LAN tool operated by
the machine's owner.** That single sentence is the boundary.

- **Loopback by default.** The HTTP API binds `127.0.0.1:5641`. Other machines and
  bridge-networked containers on native Linux can't reach it until you expose it
  deliberately with `--http-bind` (`bridge`, `<ip>`, or `0.0.0.0`).
- **Mutations require a token.** Every non-`GET` request carries the daemon access token
  (`x-koi-token`); the CLI handles this for you. Exposing the API never relaxes that.
  Reads are open on loopback by design — local processes are trusted readers.
- **Between nodes it's mTLS.** Certmesh inter-node traffic runs on a separate mutually
  authenticated listener (`5642`), with client certificates and CN-based authorization.

The full, exact rules — every carve-out, every bind value — live in the
[security model](reference/security-model.md).

## When *not* to use it

Koi is honest about its edges. Reach for something else when:

- **You're on the public internet / WAN.** Koi is a LAN substrate. It is not a
  public-facing edge, and its private CA is not a public CA. Use real public DNS and a
  public ACME CA (Let's Encrypt) for anything internet-facing.
- **You need an overlay network or application traffic policy.** Koi does not create
  routes between subnets, encrypt arbitrary host traffic, inject sidecars, or manage
  application-level routing. Keep Tailscale, WireGuard, Cilium, or a service mesh for
  those responsibilities and integrate Koi where local discovery, identity, or naming
  is useful.
- **You need enterprise PKI or DNS at scale.** One token per daemon, one CA, no per-client
  accounts or scopes. For org-wide identity, RBAC, and large authoritative DNS, use the
  tools built for that.
- **The host is untrusted or multi-tenant.** Koi treats every local process as a trusted
  reader and assumes the machine owner runs it. It does not defend against a hostile
  process already running as your user, or against other tenants on a shared box.
- **You need certificate revocation that TLS verifiers honor.** Revocation in Koi is
  **roster-level**: revoking a member stops Koi-mediated renewal and enrollment and is
  enforced at Koi's own boundaries, but it does **not** invalidate an already-issued
  certificate for generic TLS verifiers. There is no CRL or OCSP distribution. Instead Koi
  bounds the exposure by default: new meshes issue **7-day leaves renewed automatically at
  3 days remaining**, so a revoked leaf's residual validity is ≤ 8 days (ADR-027). If
  real-time revocation is a requirement, Koi's CA is the wrong tool.

Koi is also pre-1.0 and consolidating — play with it, but don't run it as load-bearing
infrastructure yet.

A note on destructive commands, since the boundary above is about protecting state:
`koi certmesh destroy` (requires typing `DESTROY`) tears down certmesh state, and
`koi factory-reset` deletes the **entire** data directory — CA keys, certs, the audit log,
DNS entries, all of it — irreversibly. Back up first with `koi certmesh backup` if you
might want any of it again.

## Where to go next

- **Just want to see it?** [Getting started](tutorials/getting-started.md) — install to a
  visible result in about a minute.
- **The headline journey:** [Trusted HTTPS across two machines](tutorials/trusted-https.md)
  — zero to a green `https://`, no public CA.
- **Know what you want?** The [capability cards](reference/cards/index.md) are one-screen
  maps of a single capability.
- **Have a specific goal?** The [by-goal table](index.md#by-goal) routes you straight to
  the right guide.

The positioning and product-boundary decision behind this model is recorded in
[ADR-024: Public Identity — Find, Trust, Connect](adr/024-public-identity-find-trust-connect.md).
