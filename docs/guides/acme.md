# ACME — Get Certs from Koi's CA with Any Standard Client

Here's the problem: you already run Caddy, Traefik, or `lego`. They know how to get
certificates over **ACME** (RFC 8555). Koi has a private CA (the certmesh) that the rest
of your network already trusts. Wouldn't it be nice if those tools could just *ask Koi* for
a certificate the same way they ask Let's Encrypt — no plugin, no Koi-specific config,
no rip-and-replace?

That is exactly what the ACME facade does. Koi runs a small **RFC 8555 server** in front of
its CA. Point any standard ACME client at Koi's directory URL, have it trust the CA root
once, and it gets certificates for names inside your Koi DNS zone — automatically renewed,
with zero Koi knowledge on the client side.

This is the collaboration doctrine in action: Koi is the substrate under the tools you
already run. You keep Caddy/Traefik; Koi is just the CA they talk to.

---

## Scope (what this is, and isn't)

- **dns-01 only.** Koi serves the `dns-01` challenge and solves it **in-process** via its
  own DNS resolver — there is no DNS propagation wait, and **wildcards + offline issuance
  work**. `http-01` and `tls-alpn-01` are out of scope (a possible follow-up).
- **EC / ES256 only (v1).** Account keys must be P-256 ECDSA. `RS256` is rejected with
  `badSignatureAlgorithm`. (Most modern ACME clients default to or support EC keys.)
- **In-zone names only.** Koi issues **only** for identifiers inside your Koi DNS zone
  (default `lan`). An order for `evil.example.com` is rejected with `rejectedIdentifier`.
  The wildcard `*.<zone>` is allowed.
- **No OCSP, no CT, no pre-authorization.** This is a homelab/LAN CA facade, not a public CA.
- **CA-admin ops stay off ACME.** ACME issues leaf certs; it never touches CA creation,
  unlock, enrollment policy, backup, or revoke-the-CA. Those remain `koi certmesh …`.

---

## How it works

1. The daemon runs a dedicated **server-auth TLS listener** (default port **5643**) mounting
   `/acme/{directory, new-nonce, new-account, new-order, authz, chall, order/finalize, cert,
   revoke-cert}`.
2. The listener's own certificate is a daemon leaf issued by your certmesh CA. Because it
   chains to the CA root, a client that trusts the root trusts the listener.
3. A client registers an account (its EC public key), creates an order for a name in your
   zone, and is handed a `dns-01` challenge.
4. The client writes the challenge TXT — and because Koi *is* the DNS resolver for the zone,
   it reads the value straight back in-process and marks the challenge valid. No waiting.
5. The client finalizes with a CSR. Koi signs **only** the order's authorized names — any
   extra SAN snuck into the CSR is rejected (`badCSR`). The issued leaf + CA chain is
   returned.
6. The issued cert is recorded in the certmesh roster (`source: acme`), so it shows up in
   `koi certmesh status` and renewal accounting alongside TOTP-enrolled members.

The server starts automatically with the daemon when the CA is **initialized + unlocked**.
Disable it with `--no-acme` / `KOI_NO_ACME=1`. It needs the DNS capability (the dns-01
solver writes into the DNS core); with `--no-dns` it is skipped.

---

## Quick start

```bash
# 1. Have a CA (once).
koi certmesh create

# 2. See the directory URL + bootstrap recipe.
koi certmesh acme enable
#   Directory URL : https://<daemon-host>:5643/acme/directory
#   CA root cert  : <data-dir>/certmesh/ca/ca-cert.pem
#   ...

# 3. Check it's serving.
koi certmesh acme status
```

The **one-time bootstrap** every client needs: distribute the CA root certificate
(`<data-dir>/certmesh/ca/ca-cert.pem`) and configure the client to trust it for ACME. The
ACME listener's leaf chains to that root, so once a client trusts the root, it trusts Koi's
ACME endpoint. (You may already have installed the root via `koi`'s truststore integration;
the same root is used here.)

---

## Client recipes

In every recipe below, replace `<dir>` with your directory URL
(`https://<daemon-host>:5643/acme/directory`) and `<ca-root>` with the path to the CA root
PEM (`<data-dir>/certmesh/ca/ca-cert.pem`).

### Caddy

Caddy points at a custom ACME CA with `acme_ca`, and trusts its root with `acme_ca_root`:

```caddyfile
{
    # Global options
    acme_ca         <dir>
    acme_ca_root    <ca-root>
}

grafana.lan {
    reverse_proxy localhost:3000
}
```

Caddy will request `grafana.lan` from Koi over ACME, solve the dns-01 challenge, and renew
automatically. (Caddy's internal issuer also accepts `dir`/`trusted_roots_pem_files` under
`tls { issuer acme { … } }` for per-site control.)

### Traefik

Traefik configures a custom CA server with `caServer`, pins the root with `caCertificates`,
and needs a dns-01 **provider**:

```yaml
certificatesResolvers:
  koi:
    acme:
      caServer: <dir>
      caCertificates: <ca-root>
      email: you@example.invalid
      storage: /etc/traefik/acme.json
      dnsChallenge:
        # Traefik's dns-01 needs a provider to WRITE the TXT record. Use an
        # `exec`/`httpreq` provider that writes into Koi's DNS, or run the client
        # on the Koi host so the TXT lands in the same resolver. (Koi reads the
        # TXT back in-process to validate.)
        provider: exec
```

> Note: Traefik (like lego) needs a dns-01 provider to publish the TXT record. Koi solves
> the challenge in-process, but the *client* still has to put the value somewhere Koi's
> resolver can see it — point the provider at Koi's DNS (`koi dns add` / the DNS API) or run
> the client where it can write into the same zone.

### lego

`lego` points at a custom server with `--server`, trusts the root via
`LEGO_CA_CERTIFICATES`, and uses a dns-01 provider (`exec` is the simplest to wire to Koi):

```bash
export LEGO_CA_CERTIFICATES=<ca-root>
export EXEC_PATH=/path/to/koi-dns-hook.sh   # writes the TXT into Koi's DNS

lego \
  --server <dir> \
  --email you@example.invalid \
  --dns exec \
  --domains grafana.lan \
  run
```

The `koi-dns-hook.sh` script `lego` calls (with `present`/`cleanup` + the FQDN + value)
writes the TXT into Koi's resolver, e.g. via the DNS API. Koi then reads it back in-process.

---

## Open vs. closed enrollment

The ACME server mirrors the certmesh enrollment posture:

- **Open** (`koi certmesh open-enrollment`): `new-account` is free — any client can register
  and order in-zone names. This is the homelab default ("Just Me").
- **Closed**: the directory advertises `externalAccountRequired`, and `new-account` without
  an External Account Binding (EAB) is rejected with `externalAccountRequired`. EAB ties new
  ACME accounts to a certmesh-minted credential. Use this for shared/team meshes.

---

## Security model

- Every ACME request is a signed JWS; the signature is verified against the account's EC
  key. A request signed with the wrong key is rejected (`unauthorized`).
- Every response carries a fresh `Replay-Nonce`; a reused nonce is rejected (`badNonce`)
  **with a fresh nonce** so the client recovers.
- The protected-header `url` must equal the request URL.
- Identifiers are constrained to the Koi DNS zone (`rejectedIdentifier` otherwise).
- At finalize, **every CSR SAN must be an authorized identifier of the order** — the CA
  issues a cert bearing only the authorized names, never the CSR's embedded extras.
- Errors are RFC 8555 `application/problem+json` (`urn:ietf:params:acme:error:*`), not the
  flat Koi `{error,message}` shape.

These properties are enforced by the security-gate tests in
`crates/koi-certmesh/tests/acme.rs`, alongside an `instant-acme` conformance test that
issues a real certificate end-to-end via dns-01.

---

## Commands & endpoints

| Command | Purpose |
|---|---|
| `koi certmesh acme enable` | Print the directory URL + the client bootstrap recipe |
| `koi certmesh acme status` | Show whether the ACME server is serving + the directory URL |

The ACME protocol endpoints live under `/acme/` on the **dedicated TLS port (5643)**, *not*
the main HTTP adapter:

| Endpoint | Purpose |
|---|---|
| `GET  /acme/directory` | Directory (endpoint URLs + meta) |
| `HEAD/GET /acme/new-nonce` | Fresh replay nonce |
| `POST /acme/new-account` | Register an account (JWS + jwk; EAB in closed mode) |
| `POST /acme/new-order` | Create an order (in-zone identifiers only) |
| `POST /acme/authz/{id}` | Authorization (POST-as-GET) |
| `POST /acme/chall/{id}` | Trigger dns-01 validation |
| `POST /acme/order/{id}/finalize` | Submit CSR → issue |
| `POST /acme/cert/{id}` | Download the leaf + CA chain (POST-as-GET) |
| `POST /acme/revoke-cert` | Revoke an issued certificate |

---

## See also

- [certmesh.md](certmesh.md) — the private CA the ACME server issues from.
- [proxy.md](proxy.md) — Koi's built-in TLS endpoint, *or* bring your own proxy via ACME.
