# P12 — ACME Facade for Certmesh

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: L (phased; checkpoint after the directory/order skeleton) · Prereqs: P08
> (certmesh diet) · Read `docs/prompts/CHARTER.md` first.
> Strategy basis: docs/assessment/research/collaboration-strategy-2026.md §6 — the
> single highest-leverage collaboration move.

## Mission

Expose certmesh as an **ACME server** so every existing ACME client — Caddy, Traefik,
NPM, lego, acme.sh, cert-manager — can obtain certificates from Koi's CA with one
config line and *zero knowledge of Koi*. This converts certmesh from "a PKI you must
adopt" into "a local Let's Encrypt your stack already speaks." Koi's structural edge:
it **owns the local DNS zone**, so DNS-01 challenges are self-served in-process — no
public domain, no provider API keys, no propagation waits. Wildcards and fully-offline
issuance become trivial. This is the one big *build* in the stash; treat scope
discipline as a feature.

## Load context first

1. `docs/prompts/CHARTER.md`
2. `docs/assessment/research/collaboration-strategy-2026.md` §6 and its sources
   (smallstep's private-ACME pattern; Traefik's `caServer` config)
3. Post-diet certmesh: `crates/koi-certmesh/src/` (ca.rs issuance path, roster,
   enrollment booleans), `koi-dns` (`DnsCore` record API — where the TXT challenge
   record will go), the mTLS/http adapters (where the ACME endpoint mounts)
4. RFC 8555 (ACME). Read it for real — the subset below is your scope fence.

## Research phase

- **Crate survey first** (charter: research-and-reuse): evaluate existing Rust ACME
  *server-side* implementations and RFC 8555 primitives (JWS verification: `josekit`
  or hand-rolled over `ring`? `rcgen`'s CSR parsing — certmesh currently has *no* CSR
  path; ACME requires accepting CSRs — `x509-parser`/`rcgen` support). Building on
  proven JWS/CSR parsing is mandatory; hand-rolling crypto plumbing is not acceptable.
- The RFC 8555 **minimum viable subset**: directory, newNonce, newAccount (EAB
  optional — see below), newOrder, authz/challenge (dns-01 first; http-01 optional
  later), finalize (CSR → cert), certificate download, revokeCert. No
  pre-authorization, no external account *requirement*, no OCSP.
- Client validation matrix: how Caddy (`acme_ca`), Traefik (`caServer`), and lego
  validate — TLS of the ACME endpoint itself (the bootstrap problem: clients need the
  CA root trusted *before* talking to it, or `--ca-bundle`-style flags; document the
  bootstrap recipe per client).
- Authorization policy: who may get certs? Tie to certmesh's post-diet booleans —
  recommended: orders are allowed for names within the Koi zone when
  `enrollment_open`, plus an optional EAB (external account binding) keyed from a
  certmesh-issued credential for closed mode. Decide and justify.

## Target experience (north star)

```console
$ koi certmesh acme enable
ACME directory: https://koi.internal:5643/acme/directory     # own port or mTLS-adjacent — research
  dns-01: self-served via koi-dns (wildcards OK)
  bootstrap: clients must trust the Koi root — `koi trust export --ca > koi-root.pem`
```

```caddy
# Caddyfile — the entire integration:
{ acme_ca https://koi.internal:5643/acme/directory
  acme_ca_root /etc/koi/koi-root.pem }
grafana.lab.internal { reverse_proxy 127.0.0.1:3000 }
```

```yaml
# traefik.yml
certificatesResolvers:
  koi:
    acme:
      caServer: https://koi.internal:5643/acme/directory
      dnsChallenge: { provider: ... }   # research: Traefik needs a provider even for
                                        # custom CAs — document the working recipe
```

The dns-01 self-serve loop (the differentiator — make this a sequence test):

```
client newOrder grafana.lab.internal
  → koi creates challenge, writes _acme-challenge.grafana.lab.internal TXT into koi-dns
  → koi validates against ITS OWN resolver state (in-process; no network race)
  → client finalizes with CSR → certmesh signs (existing issuance path, now CSR-based)
  → TXT record cleaned up
```

Issued-via-ACME certs appear in the roster (`source: acme`, account binding) so
`koi certmesh status` and renewals-due reporting stay the one pane of glass.

## Plan, then implement (phased — commit per phase)

1. Design note in the plan file: endpoint placement + TLS bootstrap story, account
   policy, crate choices. **Stop and surface the plan before coding** (charter §6) —
   this prompt's choices are architecture.
2. CSR issuance path in certmesh core (`sign_csr(csr, validity) -> cert`) + tests —
   independent of ACME, fixes the assessment's "no CSR flow" finding.
3. ACME skeleton: directory/nonce/account/order state machine (persisted in the data
   dir), JWS verification, hard input validation at every boundary.
4. dns-01 via a new `koi_common::integration` trait implemented by koi-dns
   (domain-isolation rule: certmesh must not import koi-dns).
5. finalize/cert/revoke + roster integration.
6. Client conformance: scripted lego (or acme.sh) run against a test daemon as an
   integration test; Caddy + Traefik recipes verified manually and documented in
   `docs/guides/acme.md`.

## Acceptance criteria

- [ ] `lego --server <koi>/acme/directory ... run` obtains a cert for a zone name
      end-to-end via dns-01, in an automated integration test.
- [ ] Wildcard order (`*.lab.internal`) succeeds; out-of-zone order is rejected with
      a correct ACME problem document (`urn:ietf:params:acme:error:rejectedIdentifier`).
- [ ] All ACME errors are RFC-compliant problem+json; nonce replay rejected; JWS with
      wrong key rejected (tests for each).
- [ ] ACME-issued certs visible in roster/status; revokeCert works and is reflected.
- [ ] Closed-enrollment mode enforces EAB (or the documented chosen policy).
- [ ] `docs/guides/acme.md` with working Caddy/Traefik/lego recipes incl. root
      bootstrap; catalog + OpenAPI updated; certmesh guide cross-links.
- [ ] Charter principle 10 honored: koi-proxy docs now present "bring your own proxy
      via ACME" as a first-class path.
- [ ] Workspace green per charter commands.

## Do NOT

- Implement http-01/tls-alpn-01 in v1 (note as follow-up), OCSP, CT, or
  pre-authorization.
- Accept identifiers outside the Koi DNS zone (no public-name issuance, ever — this
  is a private CA).
- Roll your own JWS/CSR parsing primitives, or weaken any existing enrollment path —
  ACME is additive alongside the TOTP machine-join, not a replacement for it.
