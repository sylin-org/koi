# Ports & firewall

> Precise technician voice: this page is the single authoritative list of every
> port Koi can listen on. For *who is allowed to call* a port (the token, CORS,
> loopback carve-outs), defer to [security-model.md](security-model.md). For how
> the installed service opens firewall rules, defer to
> [install-and-service.md](../guides/install-and-service.md).

---

## The ports

| Port | Purpose | Bind default | Change it with | `--no-*` gate | When it starts | Firewall (Windows `koi install`) |
| ---- | ------- | ------------ | -------------- | ------------- | -------------- | -------------------------------- |
| **5641** | HTTP API + dashboard + in-process MCP — all `/v1/*`, `/`, `/mdns-browser`, `/docs`, `/v1/mcp` | `127.0.0.1` (loopback) | `--port` / `KOI_PORT`; bind with `--http-bind` / `KOI_HTTP_BIND` | `--no-http` / `KOI_NO_HTTP` (whole adapter) | Always (unless gated off) | Rule **only when exposed** off-loopback; loopback stays closed |
| **5642** | Inter-node mTLS — certmesh enrollment sync, roster, promotion. Client cert required; CN-authorized | `0.0.0.0` | `--mtls-port` / `KOI_MTLS_PORT` | (none — gated by certmesh state, not a flag) | Conditional: once a CA exists **and** is unlocked (posture-reactive — comes up/withdraws as posture flips) | **Not opened** — open it yourself for a CA / standby node |
| **5643** | ACME (RFC 8555) server — lets standard ACME clients (Caddy, Traefik, lego, certbot) get certs from the CA. Server-auth TLS, dns-01 only | `0.0.0.0` | `--acme-port` / `KOI_ACME_PORT` | `--no-acme` / `KOI_NO_ACME` | Conditional: CA initialized **and** unlocked **and** DNS enabled | **Not opened** — open it yourself if ACME clients are off-box |
| **53** | Local DNS resolver — `koi dns serve`. Answers in-zone + static names | `0.0.0.0`, but replies to **private clients only** unless `--dns-public` | `--dns-port` / `KOI_DNS_PORT`; rate `--dns-qps` / `KOI_DNS_QPS` (default 200 q/s per source IP); zone `--dns-zone` / `KOI_DNS_ZONE` | `--no-dns` / `KOI_NO_DNS` | Conditional: when the DNS resolver is started | Rule opened (UDP **and** TCP on the DNS port) when DNS is enabled |
| **per-proxy** | TLS-terminating reverse proxy listeners — one per entry | `0.0.0.0` on the entry's listen port | `koi proxy add --listen <port>` (per entry) | `--no-proxy` / `KOI_NO_PROXY` | Conditional: per configured proxy entry | **Not opened** — open each proxy listen port yourself |

Also listening, but not TCP/UDP ports: the **mDNS** capability uses multicast
UDP **5353** (the standard mDNS port — `koi install` opens a UDP 5353 rule when
mDNS is enabled), and the **IPC** adapter uses a local named pipe (Windows) or
Unix domain socket, never a network port.

Notes on the conditional listeners:

- **5642 / 5643 are posture-reactive.** They are not behind their own boot flag —
  they come up the moment the certmesh CA becomes usable (initialized + unlocked,
  and for ACME, DNS also enabled), and withdraw if posture changes. A fresh node
  with no CA never opens either. `koi certmesh unlock` is what brings them up after
  a locked boot.
- **53 answers private clients only** by default. It binds `0.0.0.0` so LAN hosts
  can query it, but a query from a non-private source address is refused unless you
  pass `--dns-public`. It is also rate-limited per source IP (`--dns-qps`, default
  200 q/s).

---

## Loopback by default

The **HTTP API binds `127.0.0.1`** out of the box. Only processes on the same
machine reach it; other hosts and (on native Linux) bridge-networked containers
cannot. Expose it deliberately with `--http-bind` (env `KOI_HTTP_BIND`):

| Value | Binds | Use |
| ----- | ----- | --- |
| `loopback` (default) | `127.0.0.1` | Local processes only — quiet |
| `bridge` | the docker/podman bridge IPv4 (e.g. `172.17.0.1`) | Bridge-networked containers on native Linux |
| `<ip>` | that interface | A specific NIC |
| `0.0.0.0` | all interfaces | Whole LAN — loudest startup warning |

Non-loopback binds log a warning at startup and surface in `koi status`
(`Bind:` line / `http_bind` JSON field). **Exposing the port does not relax
authentication** — mutations still require the daemon token regardless of bind
address, and `0.0.0.0` leaves `GET` endpoints readable by any device on the
network. See [security-model.md](security-model.md) for the full token and
read-exemption rules.

## Advertising on the LAN — `--announce-http`

`--announce-http` (env `KOI_ANNOUNCE_HTTP`) publishes this host's `_http._tcp`
record over mDNS so other machines can *discover* the dashboard / API. It is a
discovery advertisement only — **it does not change the bind address.** Pair it
with a non-loopback `--http-bind` (e.g. `--http-bind 0.0.0.0`): advertising a
loopback-only API to the LAN points peers at an address they cannot reach.

The `_http._tcp` record carries an ADR-020 posture stamp (`posture=` / `fp=` /
`expires=`) and is re-announced automatically when the node's trust posture
changes — no restart needed. It is withdrawn on shutdown.

## The Windows firewall rule

On Windows, `koi install` manages inbound firewall rules with `netsh advfirewall`
(best-effort — install never aborts if a rule fails). It opens rules **only for
ports that are actually reachable from off-box**:

- **mDNS** (UDP 5353) and **DNS** (UDP + TCP on the DNS port) — when those
  capabilities are enabled, since they bind broadly.
- **The HTTP API port — only when exposed.** Loopback traffic never crosses the
  firewall, so no HTTP rule is created at the default bind; a rule is added only
  when you bind off-loopback (`--http-bind bridge` / `<ip>` / `0.0.0.0`).

`koi install` does **not** open 5642 (mTLS), 5643 (ACME), or any per-proxy listen
port — those are conditional listeners whose exposure you opt into. If you run a
CA / standby node, an ACME endpoint, or a proxy that off-box clients must reach,
open those ports with your firewall tooling yourself. `koi uninstall` removes only
the rules Koi created. Linux and macOS do not auto-manage the firewall. The full
rule lifecycle is in
[install-and-service.md](../guides/install-and-service.md#the-windows-firewall-rule).

## What to open: member node vs CA node

- **Member node** (joins a mesh, runs services, gets certs): nothing inbound is
  required just to participate — it *reaches out* to the CA over 5642. Open the
  HTTP API only if remote tools/containers must call this node, and open any
  per-proxy listen port it serves.
- **CA node** (ran `koi certmesh create`, or a promoted standby): open **5642**
  so members can sync enrollment / roster. Open **5643** as well if you want
  standard ACME clients to fetch certs from it (5643 needs DNS enabled too). The
  HTTP API and its `--http-bind` exposure follow the same rules as any node —
  members discover and enroll over mDNS + 5642, not via the loopback HTTP API.
