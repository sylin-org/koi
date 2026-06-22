# Networking & Security Model

> Precise technician voice: this page describes the binary as it ships today.
> Every other document (README, GUIDE, CONTAINERS, guides) defers to this page for
> bind addresses, authentication, and CORS behavior.

---

## Listeners

| Listener | Bind | Purpose |
| -------- | ---- | ------- |
| HTTP API + dashboard | `127.0.0.1:5641` (default; see `--http-bind`) | All `/v1/*` endpoints, dashboard (`/`), mDNS browser (`/mdns-browser`), OpenAPI (`/docs`) |
| mTLS plane | `0.0.0.0:5642` | Certmesh inter-node traffic only (enrollment sync, roster, promotion). Client certificates required; CN-based authorization |
| DNS resolver (if started) | `0.0.0.0:53` (configurable) | `koi dns serve` — rate-limited, private-client-only by default |

**The HTTP API is loopback-only by default.** Processes on the same machine can
reach it; other machines and (on native Linux) containers on bridge networks cannot.
On Docker Desktop (Windows/macOS), `host.docker.internal` proxies into the host's
loopback, so container access works there with no extra flags.

To reach the daemon from a container on native Linux — or from elsewhere on the LAN —
expose it deliberately with `--http-bind` (env `KOI_HTTP_BIND`):

| Value | Binds | Use |
| ----- | ----- | --- |
| `loopback` (default) | `127.0.0.1` | Local processes only — quiet |
| `bridge` | the docker/podman bridge IPv4 (e.g. `172.17.0.1`) | Bridge-networked containers on native Linux |
| `<ip>` | that interface | A specific NIC |
| `0.0.0.0` | all interfaces | Whole LAN — loudest warning |

Non-loopback binds log a warning at startup and surface in `koi status` (`Bind:`
line / `http_bind` JSON field) and the breadcrumb. **Exposure does not relax auth** —
mutations still require the token; on Windows the exposed HTTP port also gets a
firewall rule. `0.0.0.0` exposes `GET` endpoints to any device on the network.

## The daemon access token (DAT)

Every daemon start generates a fresh random token. **All HTTP requests except
`GET`/`HEAD`/`OPTIONS` must carry it** in the `x-koi-token` header, or they receive
`401 {"error": "unauthorized", ...}`. Comparison is constant-time. The header value is
the **bare token** — the breadcrumb file stores it with a `dat:` line prefix, but that
prefix is not part of the header value.

Carve-outs to that rule:

- **`/v1/mcp`** (the in-process MCP transport) requires the token on *every* method —
  including its `GET` server→client SSE stream, which is a live channel, not a read.
- **`/v1/certmesh/log`** (the CA audit log) requires the token on *every* method. The
  log narrates the full trust history — member joins/revocations, auth rotations, failed
  unlock attempts, backup/restore — so reading it is not read-safe.
- **The whole `/v1/udp/*` surface** requires the token on *every* method. `GET
  /v1/udp/status` enumerates every binding's id and `GET /v1/udp/recv/{id}` streams a
  binding's inbound datagrams — both expose other token-holders' bindings.
- **`/v1/certmesh/diagnose` and `/v1/dns/{list,zone,entries}`** are token-free for a
  **loopback** peer (local tooling, the CLI, the dashboard) but require the token from a
  **non-loopback** peer — the trust-doctor report and the full DNS zone are fine to read
  locally but not safe to leave world-readable once the adapter is bound to a routable
  address. When the peer address is unknown, these fail closed (token required).
- **`/v1/certmesh/status` and `/v1/certmesh/trust-bundle` stay open on every peer** — by
  design. They are load-bearing in the *unauthenticated* cross-host protocol: a joining
  node reads `status.ca_fingerprint` to pin the CA before it holds any credential, and
  members pull the trust-bundle (an ES256-signed, self-verifying document) over plain
  HTTP. Gating either would break enrollment and sync.
- **`POST /v1/certmesh/join`** does *not* require the token. A node enrolling against a
  remote CA has no way to know that host's local token, so enrollment is authorized by
  the TOTP code in the request body instead — the join handler verifies it along with
  the open/closed enrollment policy and rate limiting. This is the one mutation the DAT
  layer deliberately lets through.

`OPTIONS` is always let through (a CORS preflight carries no credentials and returns
only CORS headers, never a resource body).

The token is distributed via the **breadcrumb file**, written at daemon startup
(owner-only permissions on Unix):

| Platform | Breadcrumb path |
| -------- | --------------- |
| Windows | `%ProgramData%\koi\koi.endpoint` |
| Linux/macOS | `$XDG_RUNTIME_DIR/koi.endpoint`, fallback `/var/run/koi.endpoint` |

Format — two lines: the endpoint URL, then the token prefixed with `dat:`:

```
http://localhost:5641
dat:8a31…base64url…
```

### Worked example

```bash
# Linux/macOS
BC="${XDG_RUNTIME_DIR:-/var/run}/koi.endpoint"
TOKEN=$(sed -n 's/^dat://p' "$BC")

# Reads work without a token:
curl "http://localhost:5641/v1/mdns/discover?type=_http._tcp"

# Writes require it:
curl -X POST -H "x-koi-token: $TOKEN" \
  http://localhost:5641/v1/mdns/announce \
  -d '{"name": "My App", "type": "_http._tcp", "port": 8080}'
```

```powershell
# Windows
$token = (Get-Content "$env:ProgramData\koi\koi.endpoint")[1] -replace '^dat:', ''
Invoke-RestMethod -Method Post -Uri http://localhost:5641/v1/mdns/announce `
  -Headers @{ 'x-koi-token' = $token } `
  -Body '{"name":"My App","type":"_http._tcp","port":8080}'
```

The `koi` CLI handles all of this automatically: it reads the breadcrumb, attaches
the token, and falls back to standalone mode when no daemon is running.

To hand the token to another process or container, use `koi token` instead of
parsing the breadcrumb by hand:

```bash
koi token show                 # print the token (tty only; --force to pipe)
koi token write /run/koi/token # write a 0600 file to mount as a container secret
```

## CORS

Browser requests are accepted only from `http://localhost` / `http://127.0.0.1`
origins (any port). The API is **not** open to arbitrary web origins.

## What is *not* protected

Be aware of the trade-offs in the current model:

- **Most `GET` endpoints are unauthenticated on loopback.** Any local process (or any
  localhost-origin web page, via CORS) can read daemon status, discovered services, and
  certmesh status. Treat local processes as trusted readers; if that doesn't fit your
  machine, don't run the daemon there. The audit log (`/v1/certmesh/log`) and the
  `/v1/udp/*` surface are the exception — they require the token even on loopback (see
  the carve-outs above), and the DNS zone / diagnose reads require it from a remote peer.
- **The token authorizes writes, not identities.** There is one token per daemon —
  no per-client accounts or scopes.
- **Certificate revocation is roster-level.** Revoking a member stops Koi-mediated
  renewal and enrollment; it does not invalidate the already-issued certificate for
  TLS verifiers until its (90-day) expiry. There is no CRL/OCSP distribution.

## DNS rate limiting

The resolver rate-limits queries **per source IP**: each client gets its own
per-second budget (`--dns-qps`, env `KOI_DNS_QPS`, default 200), so one noisy or hostile
LAN peer can't starve resolution for everyone else. A whole-resolver backstop
(`10 ×` the per-client budget) caps aggregate load — the only meaningful guard against
spoofed-source floods — and the tracked-client map is hard-bounded so a burst of distinct
source IPs can't grow it without limit. Shed queries return `REFUSED` (not `SERVFAIL`,
which would invite immediate retries and amplify a flood).

## Supply chain

Every release archive **and** the GHCR image (`ghcr.io/sylin-org/koi`) carry a signed
build-provenance attestation (GitHub Artifact Attestations / Sigstore, keyless) proving
the artifact was built by this repository's release workflow. The container image also
ships an SBOM. Verify before trusting:

```bash
gh attestation verify koi-<target>.tar.gz --repo sylin-org/koi
gh attestation verify oci://ghcr.io/sylin-org/koi:<version> --repo sylin-org/koi
```

## Threat-model summary

Koi is a **LAN tool operated by the machine's owner**. It defends against: remote
networks (loopback-only API), unauthorized local writes (DAT), passive theft of the
CA key at rest (envelope encryption — see
[envelope-encryption.md](envelope-encryption.md)), and rogue enrollment (TOTP
ceremony + rate limiting). It does not defend against: a hostile process already
running as your user, a hostile LAN device intercepting *reads* of mDNS (mDNS is
public by design), or a compromised machine that holds an issued certificate.
