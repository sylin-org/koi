# P12 — ACME Facade for Certmesh — Design Plan (architecture-surfacing)

> Branch: `dev` (autonomous). The prompt flags its choices as architecture ("stop and surface
> the plan before coding"). The user authorized the whole sequence asleep, so this plan is
> committed to dev (visible for review) and the build is gated on the security + conformance
> tests below. Research (web + compiled primitives) archived in the run transcript.

## What ships (RFC 8555 MVP, dns-01 only)

`koi certmesh acme enable` → a dedicated **server-auth TLS listener on :5643** mounting
`/acme/{directory,new-nonce,new-account,new-order,authz,chall,order/finalize,cert,revoke-cert}`.
Existing ACME clients (Caddy `acme_ca`+`acme_ca_root`, Traefik `caServer`+`caCertificates`, lego
`--server`+`LEGO_CA_CERTIFICATES`) get certs from Koi's CA with zero Koi knowledge. dns-01 is
**self-served in-process** via koi-dns (no propagation wait); wildcards + offline issuance work.

## Architecture decisions (made; justified)

1. **Crates (no new crypto plumbing):** JWS verify is *assembled* from existing `p256`+`sha2`+
   `base64` (josekit = OpenSSL DLL → rejected; jsonwebtoken = compact-only → rejected). ES256
   sig is **raw 64-byte R‖S** (`Signature::from_slice`, NOT der — the gotcha vs certmesh's
   manifest verify). **EC-only (ES256) v1**; RS256 → `badSignatureAlgorithm`. CSR via `rcgen`
   0.13.2 `CertificateSigningRequestParams::from_pem` (parses + verifies self-sig) +
   `signed_by(&ca_cert, &ca_key)` (the 0.13 2-arg form) — add rcgen features `["pem","x509-parser"]`.
   base64url = `URL_SAFE_NO_PAD`. EAB MAC = `hmac` + `subtle` (const-time). Conformance driver =
   **`instant-acme` 0.8.5** in `cargo test` (`Account::builder_with_root(ca_pem)` — in-process, no Go/lego).
2. **Endpoint placement:** new dedicated TLS listener (server-auth only — a near-clone of
   `adapters/mtls.rs` minus the client-cert verifier; cert = a daemon self-issued leaf from the
   CA, SAN = daemon FQDN/IP). Plain-HTTP adapter (wrong scheme/auth) and mTLS adapter (clients
   have no cert yet) are both wrong. Gate `--no-acme` / `KOI_NO_ACME`; start only when the CA is
   initialized + unlocked. Bootstrap: the operator distributes the CA root once
   (`koi certmesh export-ca` / `koi trust export`) — the ACME leaf chains to it.
3. **Account/authorization policy** (post-P08 booleans): **open mode** (`enrollment_open`) → free
   newAccount, orders allowed **only for identifiers inside the Koi DNS zone** (the critical
   boundary; out-of-zone → `rejectedIdentifier`). **Closed mode** → `meta.externalAccountRequired`
   + EAB (HMAC-signed JWS in newAccount, kid+secret minted from a certmesh credential like
   rotate-auth). `requires_approval` held-order gate is post-v1.
4. **dns-01 + the TXT gap:** DnsCore is IP-only today. Add an ephemeral TXT store
   (`HashMap<String, Vec<String>>` scoped to `_acme-challenge.*`) + `RecordType::TXT` handling +
   `add_txt/remove_txt/get_txt`. **Domain isolation:** a new `koi_common::integration::AcmeDnsSolver`
   trait (`set_txt/clear_txt/get_txt`) that **koi-dns implements** (bridge wired in the binary);
   certmesh's ACME module holds `Arc<dyn AcmeDnsSolver>` and never imports koi-dns.
5. **Roster integration:** ACME-issued certs land in the roster (`source: acme`, account binding)
   so `koi certmesh status` + renewals-due stay one pane of glass. revokeCert reflects there.

## Security gate (these tests are the objective acceptance — not optional)

- JWS verified over `b64url(protected).b64url(payload)`; wrong-key JWS → rejected (test).
- Nonce single-use, fresh `Replay-Nonce` in every response, reuse → `badNonce` (test, concurrency-safe).
- protected-header `url` must equal the request URL → else `malformed` (test).
- **Zone restriction:** out-of-zone identifier → `rejectedIdentifier` (test). Wildcard in-zone OK (test).
- CSR self-sig verified by `from_pem`; **every CSR SAN must be an authorized identifier of the
  order** before signing → else `badCSR`/`unauthorized` (test — don't sign snuck-in names).
- EAB HMAC const-time compare; inner JWK == outer account JWK (test for closed mode).
- All errors are RFC 8555 `application/problem+json` `urn:ietf:params:acme:error:*` (dedicated
  responder, NOT the flat `{error,message}` shape).

## Phases (commit per phase; verify each)

1. Design (this file) — committed.
2. **CSR issuance in certmesh core** `sign_csr(csr_pem, validity) -> cert_pem` + tests — independent
   of ACME, fixes the assessment's "no CSR flow" finding. (Low risk; lands first.)
3. **koi-dns TXT support** + the `AcmeDnsSolver` integration trait + koi-dns bridge + binary wiring.
4. **ACME skeleton:** directory/new-nonce/new-account/new-order + JWS verify (assembled) + the
   nonce store + problem+json responder + the persisted order/account state (in the data dir).
5. **dns-01 authz/challenge** (write TXT → validate in-process → clear) + **finalize** (CSR → zone
   + SAN-authorization check → `sign_csr`) + **cert download** + **revokeCert** + roster integration.
6. **Conformance + docs:** the `instant-acme` end-to-end test (newAccount → order a zone name →
   dns-01 via writing TXT into the test DnsCore → finalize → assert the chain validates to the CA;
   wildcard; out-of-zone rejected; wrong-key/nonce-replay) — in `cargo test`. `koi certmesh acme
   enable`/`status` CLI + catalog/OpenAPI. `docs/guides/acme.md` (Caddy/Traefik/lego recipes +
   root bootstrap); koi-proxy docs gain "bring your own proxy via ACME"; certmesh guide cross-link.

## Do NOT (scope fence)

http-01/tls-alpn-01 (note as follow-up), OCSP, CT, pre-authorization; NEVER issue for names
outside the Koi DNS zone; never roll JWS/CSR primitives by hand (assemble from p256/rcgen);
ACME is additive alongside the TOTP machine-join, not a replacement.

## Autonomous-mode note

This is the security-sensitive "one big build". It lands on `dev` (not released) behind the
security gate above + the instant-acme conformance test. The architecture decisions here are
recorded for the operator to ratify on review; if any phase cannot be completed AND verified
(security tests green), it is landed partial with an explicit ledger flag rather than shipped
unverified.
