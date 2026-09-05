# ACME — Get certs from Koi's CA with dns-01 clients

Here's the problem: you already run Caddy, Traefik, or `lego`. They know how to get
certificates over **ACME** (RFC 8555). Koi has a private CA (the certmesh) that the rest
of your network already trusts. Wouldn't it be nice if those tools could just *ask Koi* for
a certificate through their existing ACME support, without replacing the proxy?

That is exactly what the ACME facade does. Koi runs a small **RFC 8555 server** in front of
its CA. Point an ACME client at Koi's directory URL, have it trust the CA root once, and
connect its dns-01 provider to Koi's two-command TXT interface. It can then obtain and
renew certificates for names inside your Koi DNS zone.

You keep Caddy/Traefik, but this is not zero-configuration interoperability: the
client must support P-256 ACME accounts, a private CA root, and a dns-01 provider
that maps present/cleanup to Koi's TXT operations. The recipes below state those
requirements instead of implying every stock client works unchanged.

---

## Scope (what this is, and isn't)

- **dns-01 only.** The client's provider publishes through `koi dns txt set`; Koi validates
  against its own DNS resolver. There is no public-DNS propagation wait, and **wildcards +
  offline issuance work**. `http-01` and `tls-alpn-01` are out of scope.
- **EC / ES256 only (v1).** Account keys must be P-256 ECDSA. `RS256` is rejected with
  `badSignatureAlgorithm`. (Most modern ACME clients default to or support EC keys.)
- **In-zone names only.** Koi issues **only** for identifiers inside your Koi DNS zone
  (default `internal`). An order for `evil.example.com` is rejected with `rejectedIdentifier`.
  The wildcard `*.<zone>` is allowed.
- **No OCSP, no CT, no pre-authorization.** This is a homelab/LAN CA facade, not a public CA.
- **Revocation is Koi metadata, not public-PKI status.** `revoke-cert` updates the
  certmesh roster and signed trust bundle. Koi-aware verification consumes that
  metadata; ordinary TLS clients do not receive CRL/OCSP and may accept the leaf
  until its own expiry.
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
4. The client's provider calls `koi dns txt set <name> <value>`. Koi serves that ephemeral
   value over DNS and the ACME validator reads it through the same DNS core.
5. The client finalizes with a CSR. Koi signs **only** the order's authorized names — any
   extra SAN snuck into the CSR is rejected (`badCSR`). The issued leaf + CA chain is
   returned.
6. The issued cert is recorded in the certmesh roster (`source: acme`), so it shows up in
   `koi certmesh status` and renewal accounting alongside TOTP-enrolled members.

The server starts automatically with the daemon when the CA is **initialized + unlocked**.
Disable it with `--no-acme` / `KOI_NO_ACME=1`. It needs the DNS capability; with
`--no-dns` it is skipped.

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
ACME endpoint. Installing the root in the OS store is not proof that a particular ACME
client reads that store; prefer its explicit private-CA option where available.

---

## Client recipes

In every recipe below, replace `<dir>` with your directory URL
(`https://<daemon-host>:5643/acme/directory`) and `<ca-root>` with the path to the CA root
PEM (`<data-dir>/certmesh/ca/ca-cert.pem`).

### Provider hook

Every client needs a dns-01 provider. The provider has exactly two Koi operations:

```bash
# present
koi dns txt set _acme-challenge.app.internal "$VALUE"

# cleanup — removes only this value, preserving concurrent challenges
koi dns txt clear _acme-challenge.app.internal "$VALUE"
```

Both commands require the daemon access token, just like other DNS mutations. Run the hook
where `koi` can read the daemon breadcrumb, or pass the normal `--endpoint` and `--token`
options. Values are memory-only and are not written to Koi's persistent DNS state.

### Caddy

Caddy can point its ACME issuer at `<dir>` and trust `<ca-root>`, but Koi offers dns-01
only. A stock Caddy build without a DNS provider cannot complete this flow. Use a Caddy
build/provider module that can invoke the two operations above; then configure the site
issuer with Koi's directory and root. This limitation is explicit: Koi does not pretend
that `acme_ca` alone supplies a dns-01 provider.

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
        # Use an exec/HTTP provider that maps present and cleanup to
        # `koi dns txt set` and `koi dns txt clear`.
        provider: exec
```

`koi dns add` creates address records and is deliberately not used for ACME challenges.
Provider hooks must use `koi dns txt set/clear` or `PUT/DELETE /v1/dns/txt`.

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
  --domains grafana.internal \
  run
```

The `koi-dns-hook.sh` script maps `present` to `koi dns txt set` and `cleanup` to
`koi dns txt clear`, passing the challenge FQDN and exact value supplied by the provider.

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
| `koi dns txt set <name> <value>` | Publish one ephemeral dns-01 value |
| `koi dns txt clear <name> <value>` | Remove that exact value |

The corresponding authenticated DNS API uses `PUT /v1/dns/txt` and
`DELETE /v1/dns/txt`, both with `{"name":"…","value":"…"}`.

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
