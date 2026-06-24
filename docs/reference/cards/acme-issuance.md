---
type: REF
domain: certmesh
title: "ACME issuance (RFC 8555) for Caddy / Traefik / lego"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.7.0
validation:
  date_last_tested: 2026-06-22
  status: verified
  scope: "integration: crates/koi-certmesh/tests/acme.rs — raw-JWS security gates (zone boundary, wrong-key, nonce-replay, out-of-zone rejectedIdentifier, wildcard-in-zone, unauthorized-SAN finalize) AND the instant-acme conformance test (conformance_issues_cert_via_dns01: real ACME client over TLS, newAccount→order→dns-01→finalize→download, chains to the Koi CA)"
---

# ACME issuance (RFC 8555) for Caddy / Traefik / lego

> One-screen map of Koi's RFC 8555 facade — point a standard ACME client at your LAN CA. Full recipes: [acme.md](../../guides/acme.md) · wire shapes: [http-api.md](../http-api.md). Names must be in-zone: [internal-zone.md](./internal-zone.md).

**What it does** — Koi puts an **RFC 8555 ACME server in front of the certmesh CA**, so any existing ACME client (Caddy, Traefik, lego, certbot) gets certificates from your private LAN CA with no Koi-specific code. It is deliberately narrow: **dns-01 only** (solved **in-process** — the daemon writes the `_acme-challenge` TXT into its own DNS core and reads it back, so there's no propagation wait, and **wildcards** work), **EC / ES256 only** (the JWS `alg` allow-list is `ES256`; JWKs must be `EC` `P-256`), and **in-zone names only** (every order identifier must fall inside the Koi DNS zone — an out-of-zone name is `rejectedIdentifier`). It runs on a **separate server-auth TLS listener (port 5643)**, distinct from the daemon HTTP port (5641) and inter-node mTLS (5642). The server starts **automatically** with the daemon once the CA is initialized + unlocked and the DNS capability is on — no command turns it on.

## The one canonical pattern

`koi certmesh acme enable` does **not** start a server — it prints the directory URL + a client bootstrap recipe (the daemon already serves ACME once the CA is up). Trust the CA root once, then point the client at the directory.

```bash
# On the CA host: surface the connection details + the one-time trust step.
koi certmesh acme enable
#   Directory URL : https://ca-host:5643/acme/directory
#   CA root cert  : /var/lib/koi/certmesh/ca/ca-cert.pem
#   CA fingerprint: 714cad…

# In your ACME client, trust that CA root, then aim at the directory:
#   Caddy   : tls { issuer acme { dir https://ca-host:5643/acme/directory } }
#   Traefik : certificatesResolvers.koi.acme.caServer=https://ca-host:5643/acme/directory
#   lego    : LEGO_CA_CERTIFICATES=/var/lib/koi/certmesh/ca/ca-cert.pem \
#             lego --server https://ca-host:5643/acme/directory ...
```

Order an **in-zone** name (e.g. `grafana.internal`) and the CA issues a real, browser-trusted leaf — provided the client trusts the printed CA root.

## Commands & flags you'll use

| Command / flag | What it does |
|---|---|
| `koi certmesh acme enable` | Print the directory URL + Caddy/Traefik/lego recipe + CA-root trust step. Does **not** start a server. |
| `koi certmesh acme status` | Show whether the server is serving (CA initialized + unlocked), the directory URL, and the open/closed account mode. |
| `--no-acme` (`KOI_NO_ACME`) | Disable the ACME listener entirely. |
| `--acme-port <n>` (`KOI_ACME_PORT`) | ACME server-auth TLS port. **Default `5643`.** |
| `GET /acme/directory` | RFC 8555 directory (the URL clients consume). Full endpoint set: [http-api.md](../http-api.md). |

## The escape hatch & limits

The facade is intentionally minimal — it is **not** a general ACME server. dns-01 is the **only** challenge type (no http-01/tls-alpn-01); **ES256/P-256** is the **only** key type; only **in-zone** identifiers issue (anything else → `rejectedIdentifier`); ACME-issued leaves are **30-day** (renewal is the client's job — Caddy/Traefik/lego renew automatically). To turn the server off, set `--no-acme` / `KOI_NO_ACME`. In **closed** enrollment the directory advertises `externalAccountRequired` and `newAccount` is refused (Koi has no EAB key store yet, so it fails closed rather than admit unverified accounts); run `koi certmesh open-enrollment` to accept new ACME accounts.

## The proof it works

Integration: `crates/koi-certmesh/tests/acme.rs` is the acceptance gate. Raw-JWS handler tests prove the zone boundary, wrong-key rejection, nonce-replay (`badNonce`), the out-of-zone `rejectedIdentifier`, wildcard-in-zone acceptance, and the unauthorized-SAN finalize rejection. `conformance_issues_cert_via_dns01` drives the **full RFC 8555 flow with the `instant-acme` client over TLS** — newAccount → order → dns-01 → finalize → download — and verifies the issued cert chains to the Koi CA.
