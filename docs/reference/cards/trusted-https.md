---
type: REF
domain: certmesh
title: "Trusted HTTPS on the LAN (private CA)"
audience: [operators, developers, ai-agents]
status: current
last_updated: 2026-06-22
koi_version: v0.5.0
validation:
  date_last_tested: 2026-06-22
  status: verified
  scope: "integration (acme::raw_out_of_zone_identifier_is_rejected, raw_wildcard_in_zone_order_succeeds, and the in-process newAccount→order→dns-01→finalize→download issuance act in crates/koi-certmesh/tests/acme.rs); cert policy unit (roster::CertPolicy::default = 90/30/14); enroll→renew→revoke guarded by the ADR-018 cross-participant suite; create→enroll→serve exercised on the two-box integration host (scripts/integration/cross-host-test.sh)"
---

# Trusted HTTPS on the LAN (private CA)

> One-screen map of the **discover → name → trust → serve** pipeline: a private CA issues browser-warning-free certs for in-zone names. Full flow: [certmesh.md](../../guides/certmesh.md) · trust-store distribution: [trust.md](../../guides/trust.md) · walkthrough: [trusted-https.md](../../tutorials/trusted-https.md) · names: [internal-zone.md](./internal-zone.md) · enrollment: [certmesh-invite.md](./certmesh-invite.md).

**What it does** — Koi turns a LAN name into a **trusted** `https://` URL with no browser warning and no public CA. One host runs `koi certmesh create` to stand up a private ECDSA P-256 CA; other hosts enroll (keeping their own private key — see [certmesh-invite.md](./certmesh-invite.md)) and get a CA-signed leaf, either by **member enrollment** or by pointing a standard ACME client (Caddy, Traefik, lego) at Koi's RFC 8555 facade. Issuance is restricted to **in-zone** names (`web.internal`; see [internal-zone.md](./internal-zone.md)) — that's the integral guarantee: the name Koi's DNS resolves is exactly the name its CA will sign. The last mile is one-time: clients trust the CA root with `koi trust install`, and every mesh cert is then warning-free.

## The one canonical pattern

CA host stands up the CA; each serving host gets a cert (member or ACME); each client trusts the root once.

```bash
# 1. CA host — stand up the private CA (interactive ceremony; --json for headless):
koi certmesh create --profile just-me
koi certmesh open-enrollment            # required before any host can join

# 2. Serving host — enroll (key stays local) OR use ACME. Member route:
koi certmesh invite web-01              # on the CA host: mint a single-use invite
koi certmesh join http://ca-host:5641 --invite <code>   # on web-01
#   → key + CA-signed leaf land in /var/lib/koi/certs/web-01
# ACME route (for Caddy/Traefik/lego): see the directory URL + recipe:
koi certmesh acme enable               # → https://ca-host:5643/acme/directory

# 3. Name it + trust the root once per client:
koi dns add web 10.0.0.5               # → web.internal A 10.0.0.5
koi trust export --ca > koi-ca.pem     # hand this root to each client
koi trust install koi-ca.pem           # now https://web.internal is warning-free
```

## Commands & flags you'll use

| Command / flag | What it does |
|---|---|
| `koi certmesh create --profile <just-me\|team\|organization>` | Initialize the private CA (`--operator` required for team/org; `--passphrase`/`--json` for headless). |
| `koi certmesh open-enrollment` | Open the window — required for **any** join to be accepted. |
| `koi certmesh join <ca-endpoint> --invite <code>` | Enroll a host; the local daemon keeps the key (see [certmesh-invite.md](./certmesh-invite.md)). |
| `koi certmesh acme enable` | Print the ACME directory URL (port **5643**) + the Caddy/Traefik/lego bootstrap recipe. |
| `koi trust export --ca` / `koi trust install <pem>` | Export the mesh root / install a CA root into the OS trust store. |
| `koi trust diagnose [--fix]` | Trust-doctor: posture, renewal health, CA-trust install (`--fix` installs the mesh root). |

## Limits & the escape hatch

**In-zone names only.** ACME issues only for names inside the Koi DNS zone (default `.internal`); an out-of-zone identifier is rejected `rejectedIdentifier`, and at finalize every CSR SAN must be authorized. dns-01 is the only challenge type; EC/ES256 keys only; the wildcard `*.<zone>` is allowed. **Cert lifecycle is a CA-held policy: 90-day leaves, renew at 30 days remaining, 14-day post-expiry grace** (`CertPolicy`, applied at both enrollment and renewal; members pull-renew over mTLS before expiry — see [certmesh-invite.md](./certmesh-invite.md)). Escape hatch: the CA is not a lock-in — `koi trust install` takes *any* root (step-ca, mkcert, Caddy's local CA), so you can distribute a different CA's root the same way ([trust.md](../../guides/trust.md)).

## The proof it works

Integration: `crates/koi-certmesh/tests/acme.rs` deterministically gates the ACME facade — `raw_out_of_zone_identifier_is_rejected` (the in-zone guarantee), `raw_wildcard_in_zone_order_succeeds`, an unauthorized-SAN finalize rejection, and a full in-process `newAccount → order → dns-01 → finalize → download` that issues a real cert. The 90/30/14 policy is unit-pinned in `roster::CertPolicy::default`. The enroll → renew → revoke exchange is guarded end-to-end by the ADR-018 cross-participant suite, and the create → enroll → serve pipeline is exercised on the two-box integration host (`scripts/integration/cross-host-test.sh`).
