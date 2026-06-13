# Networking & Security Model

> Precise technician voice: this page describes the binary as it ships today.
> Every other document (README, GUIDE, CONTAINERS, guides) defers to this page for
> bind addresses, authentication, and CORS behavior.

---

## Listeners

| Listener | Bind | Purpose |
| -------- | ---- | ------- |
| HTTP API + dashboard | `127.0.0.1:5641` | All `/v1/*` endpoints, dashboard (`/`), mDNS browser (`/mdns-browser`), OpenAPI (`/docs`) |
| mTLS plane | `0.0.0.0:5642` | Certmesh inter-node traffic only (enrollment sync, roster, promotion). Client certificates required; CN-based authorization |
| DNS resolver (if started) | `0.0.0.0:53` (configurable) | `koi dns serve` — rate-limited, private-client-only by default |

**The HTTP API is loopback-only.** Processes on the same machine can reach it;
other machines and (on native Linux) containers on bridge networks cannot. There is
currently no flag to change the HTTP bind address — LAN/container exposure of the
HTTP API is a roadmap item (see `docs/prompts/P03-container-access.md`). On Docker
Desktop (Windows/macOS), `host.docker.internal` proxies into the host's loopback, so
container access works there; on native Linux Docker it does not.

## The daemon access token (DAT)

Every daemon start generates a fresh random token. **All HTTP requests except
`GET`/`HEAD`/`OPTIONS` must carry it** in the `x-koi-token` header, or they receive
`401 {"error": "unauthorized", ...}`. Comparison is constant-time.

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

## CORS

Browser requests are accepted only from `http://localhost` / `http://127.0.0.1`
origins (any port). The API is **not** open to arbitrary web origins.

## What is *not* protected

Be aware of the trade-offs in the current model:

- **`GET` endpoints are unauthenticated on loopback.** Any local process (or any
  localhost-origin web page, via CORS) can read daemon status, discovered services,
  DNS entries, certmesh status, the roster, and the audit log. Treat local processes
  as trusted readers; if that doesn't fit your machine, don't run the daemon there.
- **The token authorizes writes, not identities.** There is one token per daemon —
  no per-client accounts or scopes.
- **Certificate revocation is roster-level.** Revoking a member stops Koi-mediated
  renewal and enrollment; it does not invalidate the already-issued certificate for
  TLS verifiers until its (30-day) expiry. There is no CRL/OCSP distribution.

## Threat-model summary

Koi is a **LAN tool operated by the machine's owner**. It defends against: remote
networks (loopback-only API), unauthorized local writes (DAT), passive theft of the
CA key at rest (envelope encryption — see
[envelope-encryption.md](envelope-encryption.md)), and rogue enrollment (TOTP
ceremony + rate limiting). It does not defend against: a hostile process already
running as your user, a hostile LAN device intercepting *reads* of mDNS (mDNS is
public by design), or a compromised machine that holds an issued certificate.
