# What is Koi, and is it for you?

This page is orientation, not instructions. It explains what Koi is, the problem it
solves, who it's for, and — just as importantly — when you should reach for something
else. If you already know you want it, skip to [where to go next](#where-to-go-next).

---

## The problem

A local network ships with almost nothing. Plug in machines and containers and you get
IP addresses and a lot of manual work. Out of the box your LAN has no usable service
discovery you can drive from code, no way to give a host a stable name without editing a
zone file somewhere, no trusted HTTPS for private addresses (public CAs won't sign
`.internal` names or RFC-1918 IPs — by rule), and no quick way to put a TLS endpoint in
front of a plain service.

Each of those has a point solution. The pain is the *wiring between them*: discovery is
useless until things have names, names are half a solution until the certs behind them are
trusted, and certs only matter once something terminates TLS. Stitching that together by
hand — Avahi here, a dnsmasq zone there, a hand-rolled CA, a reverse proxy config — is the
job nobody wants. **That wiring is what Koi is.**

## Koi's model: discover → name → trust → serve

Koi is one static binary that runs as a small daemon on each machine and gives the network
the four things it never gets, wired together as one pipeline:

1. **Discover** — mDNS/DNS-SD service discovery with a real lifecycle. Services that go
   away actually disappear (leases, not stale ghosts).
2. **Name** — a local DNS zone (`.internal` by default) where names appear automatically:
   from discovery, from containers, from issued certificates. No zone-file editing.
3. **Trust** — a private certificate authority with guided enrollment and OS trust-store
   installation, so `https://` on the LAN is green in the browser without a public CA.
4. **Serve** — a zero-config TLS endpoint for those certificates, plus health checks to
   watch the whole thing.

Label a container and the pipeline runs end to end — announced, named, certified, watched —
without touching the image. There are no accounts and no cloud; it works when the internet
doesn't.

## Who it's for

Koi is built for people who own the network they run on:

- **Homelabbers and self-hosters** who want `https://grafana.internal` to just work.
- **Developers on a LAN** who need services to find each other and carry trusted certs
  without a public DNS name or a Let's Encrypt round-trip.
- **Small teams** running a handful of machines who want naming and trust without standing
  up enterprise DNS or PKI.
- **Container hosts**, where bridge networks can't do multicast — the host daemon speaks
  mDNS, containers speak plain HTTP to it.

## Four ways to run it

The same binary is four things depending on how you call it:

- **Daemon** — `koi --daemon` (or installed as a service). All capabilities, the HTTP API
  on `127.0.0.1:5641`, the dashboard, and the trust plane. This is the full toolbox.
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
- **You need enterprise PKI or DNS at scale.** One token per daemon, one CA, no per-client
  accounts or scopes. For org-wide identity, RBAC, and large authoritative DNS, use the
  tools built for that.
- **The host is untrusted or multi-tenant.** Koi treats every local process as a trusted
  reader and assumes the machine owner runs it. It does not defend against a hostile
  process already running as your user, or against other tenants on a shared box.
- **You need certificate revocation that TLS verifiers honor.** Revocation in Koi is
  **roster-level**: revoking a member stops Koi-mediated renewal and enrollment, but it
  does **not** invalidate an already-issued certificate until it expires (90 days). There
  is no CRL or OCSP distribution. If real-time revocation is a requirement, Koi's CA is the
  wrong tool.

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
