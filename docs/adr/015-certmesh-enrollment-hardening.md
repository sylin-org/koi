# ADR-015: Certmesh Enrollment Hardening

**Status:** Partially Implemented / Superseded — **F1** (CSR-based enrollment) and **F2** (single-use invite tokens) are **Implemented** (2026-06-18, shipped on `dev`, security-reviewed, live-verified). The remaining work — phases 3–4 (F3, F4, F5, F6, F7, F9, F11, F12, F14, F16) and the unfinished phase-1 hygiene items (F10, F13, F15) — is **superseded by [ADR-017](017-certmesh-trust-lifecycle.md)**, which rebuilds them around a unified trust-ledger / CSR-only-issuance / anchor-lifecycle backbone. This document is retained for the threat analysis and the F1/F2 design of record.
**Date:** 2026-06-18
**Amends:** ADR-009 (Auth Adapters — the dead FIDO2 enrollment path is retired)
**Relates to:** ADR-004 (Ceremony Engine — the invite/join ceremony is expressed through it)
**Depends on:** ADR-011 (Security Architecture Overhaul — dual-port 5641 HTTP+DAT / 5642 mTLS; unchanged here), ADR-003 (Envelope Encryption)
**Constrained by:** STACK-0001 (K2 consumer-neutrality, K3 frozen HKDF labels, D7 contract surface)

---

## Context

A full audit of the certmesh enrollment lifecycle (CA genesis → unlock → discovery → join → issuance → renewal/health/revocation) surfaced one structural fault and a long tail of weaknesses, standards deviations, and operability gaps. They cluster around four root causes:

1. **The CA is a key custodian.** `ca::issue_certificate` ([ca.rs:279-338](../../crates/koi-certmesh/src/ca.rs#L279)) *generates* each member's private key on the CA, writes it to the CA's disk as plaintext PEM ([certfiles.rs:22-51](../../crates/koi-certmesh/src/certfiles.rs#L22)), and ships it back in the join response ([enrollment.rs:130-137](../../crates/koi-certmesh/src/enrollment.rs#L130)). A CA compromise therefore yields *every member's identity*, and the private key crosses the network.

2. **The enrollment trust anchor is weak and shared.** A single mesh-wide TOTP secret ([lib.rs:342-355](../../crates/koi-certmesh/src/lib.rs#L342)) is the only credential; it authorizes *any* hostname; the join runs over plain HTTP with the code in cleartext; and there is no out-of-band verification of the CA's identity, so a spoofed CA (fake mDNS / endpoint) is trusted on first contact.

3. **Revocation does not propagate.** It is roster-local only ([roster.rs:207-230](../../crates/koi-certmesh/src/roster.rs#L207)); neither the health endpoint nor the mTLS handler checks it, so a revoked-but-valid certificate keeps working on any node that has not re-synced.

4. **Operational correctness gaps:** push-only renewal that strands offline members, a global in-memory rate limiter that is a trivial DoS lever, a roster persisted asynchronously *after* the success response, non-idempotent joins, success-only audit logging, loose certificate profiles, and a non-functional mDNS discovery path.

This ADR decides the end-state for **every** finding, including the operability tail, and specifies how each is **tested** — unit, integration, and on real cross-platform deployments (the Windows development host plus Linux servers).

### Scope and non-goals

- **In scope:** the certmesh enrollment/issuance/renewal/revocation/identity path and its bootstrap trust.
- **Out of scope (separate future ADR):** the stack-wide *dual-mode transport* (open HTTP vs. pond HTTPS, same-port flip). This ADR makes enrollment **cryptographically safe independent of transport**, and recommends TLS-on-join as defense-in-depth to be realized when that ADR lands. The ADR-011 port model (5641 HTTP+DAT, 5642 mTLS) is unchanged, as is the separate ACME listener (5643).
- **Explicitly rejected as over-scoped for Koi's deployment context** (homelab → small org): HSM/KMS integration, X.509 CRL/OCSP responders, certificate-transparency logs, and multi-party promotion quorums. We choose lighter, equivalent-strength mechanisms (a CA-signed trust bundle, short-lived certs, single-use bound tokens).

---

## Decision

The redesign is anchored by a single consolidating move: **the member's private key is born on the member and never leaves it; the CA only ever signs CSRs and publishes signed truth.** Most of the critical findings collapse into that, plus per-join authorization and a signed trust bundle.

Sixteen features (F1–F16) are decided below, grouped. Each lists the decision, the reused primitive, and the precise touchpoints. None renames a frozen HKDF label (K3); none names a consumer (K2).

### Group A — Trust, custody, and bootstrap

**F1. CSR-based enrollment (the keystone).** The joining machine's local daemon generates its own P-256 keypair and a CSR; the join request carries the **CSR**, never expecting a key back. The CA verifies authorization, calls `csr::sign_csr` ([csr.rs:39-76](../../crates/koi-certmesh/src/csr.rs#L39) — already verifies CSR self-signature and substitutes the CA-authorized SAN set), and returns **only** the leaf + chain. The CA never generates, stores, or transmits a member private key.
- *Wire:* `JoinRequest` gains `csr_pem: String`; `JoinResponse` **drops `service_key`** ([protocol.rs:17-37](../../crates/koi-certmesh/src/protocol.rs#L17)).
- *Server:* `enroll`/`process_enrollment` swap `ca::issue_certificate` → `csr::sign_csr` with `authorized_sans = [hostname, hostname.local]` ([enrollment.rs:29-140](../../crates/koi-certmesh/src/enrollment.rs#L29)). The CA writes **no** `key.pem`.
- *Client:* a new `csr::generate_keypair_and_csr(hostname, sans)` helper (rcgen `KeyPair::generate()` + `CertificateParams::serialize_request`, the pattern already in csr.rs tests); the member daemon persists the key locally (0600 / platform-sealed), the CLI never sees it.
- *Resolves:* W1, W3, D1, D2. Reuses csr.rs + rcgen 0.13 (P-256/ES256, consistent with the stack).

**F2. Per-join, single-use, hostname-bound invite tokens** replace the mesh-wide enrollment TOTP. `koi certmesh invite <hostname>` mints a high-entropy token bound to that hostname, with a short TTL (default 1h) and single-use semantics; the token is stored **hashed** at rest. Join requires a valid token; the CA checks: not expired, unused, and the requested hostname (CSR CN/SAN) equals the token's hostname.
- *Replaces:* the mesh-wide TOTP enrollment secret ([lib.rs:342-355](../../crates/koi-certmesh/src/lib.rs#L342)). The **unlock** TOTP slot machinery and its frozen label `b"pond-unlock-slot-totp-v1"` are untouched (K3).
- *New:* a persisted token store (JSON in the certmesh data dir, 0600). The roster posture booleans still gate: `enrollment_open` = invites are accepted now; `requires_approval` = a valid invite still needs operator approval. No `TrustProfile` reintroduced.
- *Automation (the driver):* the old credential is the mesh-wide TOTP rendered **QR-only** — there is no pasteable secret, so enrollment cannot be scripted (confirmed live: `create`/`rotate-auth --json` never emit the secret/URI). The invite token is a copy-pasteable string, so both ends are non-interactive: `koi certmesh invite <hostname> [--ttl <mins>]` mints it; `koi certmesh join <endpoint> --token <T>` consumes it. (`certmesh create` is already non-interactive via `--profile`/`--passphrase`/`--json`.)
- *Rejected alternative — a reusable enrollment passphrase (mesh-wide PSK):* automatable, but it re-creates the mesh-TOTP blast radius (one leak → unlimited enrollment as any host). The invite token has identical ergonomics with single-use + host-binding, so the shared secret stays dead.
- *Resolves:* W4 (no shared secret), W5 (hostname is authorized at mint time, not claimed by the joiner), and the **enrollment-automation gap** (QR-only credential).

**F3. Pinned-CA-fingerprint bootstrap; the invite carries the fingerprint.** The invite token is an opaque artifact encoding `{secret, ca_fingerprint, optional endpoint}`. The joiner verifies the CA's presented certificate fingerprint against the value in the invite **before** sending the CSR. mDNS / a passed endpoint is treated as an untrusted hint only. This defeats CA *spoofing* (a fake CA fails the fingerprint check) and removes private-key exposure entirely (F1). It does **not** make a plain-HTTP join leak-proof: the invite is a bearer secret, so an on-path attacker who captures it can race the legitimate joiner to spend it — single-use + short TTL + hostname-binding bound that to one wrongly-issued cert *for an already-authorized hostname*, and the legitimate joiner's failed attempt is audited (F9), making the race detectable. See *Accepted residual risks*.
- *Client:* `discover_ca` ([commands/certmesh.rs:1070](../../crates/koi/src/commands/certmesh.rs#L1070)) becomes hint-only; add a preflight `GET /v1/certmesh/status` fingerprint compare and a `--ca-fingerprint` override; consume the fingerprint from the invite when present.
- *Defense-in-depth:* TLS-for-join (future dual-mode transport ADR) closes the capture-race entirely and is recommended; it is **not** the trust anchor here.
- *Resolves:* W2 (CA-spoofing/TOFU); the token-capture race is a documented accepted residual until TLS-for-join.

**F4. CA-signed trust bundle + revocation propagation and enforcement.** The CA publishes a **signed** roster/trust bundle (reusing `koi_crypto::signing::{sign_bytes, verify_signature}`, P-256 — [signing.rs:15-36](../../crates/koi-crypto/src/signing.rs#L15)) at `GET /v1/certmesh/trust-bundle`. It carries the member set, their cert fingerprints, the revocation list, the current CA fingerprint, and a **monotonic sequence number + `issued_at`**. Members verify the signature against the pinned CA public key and enforce **freshness/anti-rollback**: reject any bundle whose sequence is lower than the highest already seen (a replayed pre-revocation bundle), and treat a bundle older than a `max_age` as stale and re-fetch. **Revocation is enforced**: the mTLS handler ([mtls.rs:95-174](../../crates/koi-certmesh/src/mtls.rs#L95)) rejects a peer whose CN is revoked in the current bundle, and `health_handler` ([http.rs:706-767](../../crates/koi-certmesh/src/http.rs#L706)) rejects revoked members. This is the "verify against signed truth, don't trust the wire" model; the sequence + `max_age` give it CRL-grade freshness without an OCSP responder.
- *Resolves:* W6, D6 (revocation deviation), and the stale-bundle-hides-revocation rollback risk. Reuses existing roster-manifest signing.

**F5. Fingerprint refresh on renewal/rotation.** `RenewResponse` ([protocol.rs:282-287](../../crates/koi-certmesh/src/protocol.rs#L282)) gains `ca_fingerprint`; the member updates its pin when it differs. The signed bundle (F4) also carries the current fingerprint. This fixes the post-promotion breakage where members pin a stale CA fingerprint forever.
- *Resolves:* W10.

**F14. `self_enroll` audited + hostname-pinned; promotion validates the received key.** `self_enroll` ([lib.rs:606-738](../../crates/koi-certmesh/src/lib.rs#L606)) emits a distinct audit event and pins the daemon CN to the system hostname (re-enrollment with a different CN is refused + audited). The promote handler ([http.rs:533-621](../../crates/koi-certmesh/src/http.rs#L533)) verifies that the decrypted CA key's public half matches the expected CA cert fingerprint before adopting it.
- *Resolves:* D4 and the promote-key-validation finding.

### Group B — Operability and correctness

**F6. Pull-based renewal + grace; longer lifetime.** Add `GET /v1/certmesh/renew` (member-initiated): the member submits a fresh CSR and pulls a re-signed cert, so offline members recover on reconnect rather than silently expiring. Cert lifetime moves to **90 days**, renewal threshold to **30 days**, with a **7-day post-expiry grace** in which a member may still renew. Renewal is CSR-based too (consistent with F1), so the renewed key never leaves the member and the legacy push path that shipped `key_pem` is removed. Renewal re-applies join's SAN authorization (the CA re-derives the authorized SANs; CSR SANs are not trusted) and is authorized by the member's own mTLS identity (a member renews only its own hostname). The renew endpoint accepts a member cert that is **expired but still within the grace window**, so an offline member can recover; past grace the cert is refused and re-enrollment via a fresh invite is required.
- *Touch:* [lifecycle.rs:25-150](../../crates/koi-certmesh/src/lifecycle.rs#L25), constants `CERT_LIFETIME_DAYS`/`RENEWAL_THRESHOLD_DAYS`, new pull handler in [http.rs](../../crates/koi-certmesh/src/http.rs).
- *Resolves:* W9, D-lifetime.

**F7. Fail-closed, scoped, persisted rate limiting.** Persist the `RateLimiter` ([totp.rs:210-288](../../crates/koi-crypto/src/totp.rs#L210)) to disk so a restart cannot reset it; on load failure, start **locked** (fail-closed). Replace the single global counter with **per-source** counters so failures cannot lock out all enrollment for everyone (the current global-counter DoS lever). Because F2 makes the credential a high-entropy single-use token, brute force is largely moot; rate limiting now guards token-guessing per source.
- *Resolves:* W8.

**F8. Atomic, ordered roster commit + idempotent join + dedup persistence.** Persist the roster (and cert files) **before** returning 200, in a defined order (journal the roster entry, then write cert files via temp-file + atomic rename), so a crash cannot leave issued-but-unrecorded state. Join becomes **idempotent**, keyed by the invite token **bound to the first CSR's public key**: a retry carrying the *same* token and *same* CSR returns the cached cert (so a lost response is recoverable), while a *different* CSR under an already-spent token is rejected (one invite never yields two identities). Consolidate the ~12 duplicated roster-persist sites into one helper.
- *Touch:* `enroll`/`persist_roster` ([lib.rs:521-600](../../crates/koi-certmesh/src/lib.rs#L521), [roster.rs:296-307](../../crates/koi-certmesh/src/roster.rs#L296)).
- *Resolves:* W11, W12 (idempotency).

**F9. Full-coverage security audit logging.** Audit **failures**, not only successes ([audit.rs:15-41](../../crates/koi-certmesh/src/audit.rs#L15)): add `enroll_auth_failed`, `enroll_revoked_attempt`, `enroll_approval_denied`, `enroll_token_invalid`, `enroll_token_reused`, `roster_persist_failed`. Every gate in `process_enrollment` logs before returning `Err`.
- *Resolves:* W12 (audit).

### Group C — PKI profile and hygiene

**F10. Certificate profile hardening.** Leaf certs set `KeyUsage = [DigitalSignature, KeyEncipherment]` and `ExtendedKeyUsage = [ServerAuth, ClientAuth]` (members act as both in mTLS); leaves are explicitly `is_ca = false`. The CA cert's `BasicConstraints` becomes `Constrained(0)` (no sub-CA delegation) ([ca.rs:67-87, 282-338](../../crates/koi-certmesh/src/ca.rs#L67)). rcgen 0.13 supports `KeyUsagePurpose`/`ExtendedKeyUsagePurpose` directly; if a needed EKU is unavailable, fall back to x509 post-processing.
- *Resolves:* D3.

**F11. Auto-unlock custody hardening + machine-change detection.** Auto-unlock backed only by a *machine-derived* vault key (no TPM/keyring) is refused by default (loud opt-out), because a VM clone/snapshot recovers it ([vault.rs:64-150](../../crates/koi-crypto/src/vault.rs#L64)). At CA creation, record a machine-binding fingerprint; at boot, if it changed, refuse auto-unlock and audit. Document the TPM threat model honestly (defends disk theft / snapshot, **not** local code execution).
- *Resolves:* W7.

**F12. mDNS self-advertise (hint-only, fingerprint in TXT).** Resolve the dead discovery path by **advertising** `_certmesh._tcp` at daemon startup after `self_enroll`, with the CA fingerprint in a TXT record, and deregistering on shutdown ([CERTMESH_SERVICE_TYPE lib.rs:46](../../crates/koi-certmesh/src/lib.rs#L46)). The TXT fingerprint is a **convenience hint** the joiner cross-checks against the invite (F3) — never a trust source.
- *Resolves:* D5 (and the operability complaint that discovery is non-functional).

**F13. Stop serializing `cert_path`.** Mark `RosterMember.cert_path` `#[serde(skip)]` (or store relative) so the roster/status JSON no longer leaks the operator's home directory ([roster.rs:107](../../crates/koi-certmesh/src/roster.rs#L107)).
- *Resolves:* W12 (path leak).

**F15. RFC 1123 hostname validation.** Replace the length/null/space check ([lib.rs:526-534](../../crates/koi-certmesh/src/lib.rs#L526)) with full label validation (1–63 chars, alphanumeric+hyphen, no leading/trailing hyphen), and reject IP-literals and reserved names in the hostname field.
- *Resolves:* the RFC1123 finding.

**F16. Remove the FIDO2 dead path; K2 vocabulary scrub.** Remove the insecure, callerless FIDO2 enrollment path (narrowing ADR-009). The label `b"pond-fido2-storage-key-v1"` is **reserved in STACK-0001 (K3) but not present in code today** — it is neither introduced nor renamed here; it remains reserved in canon for a future FIDO2 slot. Scrub consumer names from **enrollment** vocabulary: the TOTP issuer string `"ZenGarden"` ([pond_ceremony.rs](../../crates/koi-certmesh/src/pond_ceremony.rs)) and the `"Non-Moss client (e.g. Rake)"` comment ([roster.rs:62](../../crates/koi-certmesh/src/roster.rs#L62)) become neutral, satisfying the `scripts/check-doc-leaks.sh` / `surfaces` CI gate. (The broader consumer-name cleanup in koi-dns and koi-embedded is the STACK-0001 de-consumerization effort, not duplicated here.)
- *Resolves:* the FIDO2 dead-end and K2 leakage in the enrollment path.

---

## Accepted residual risks

These follow from Koi's deployment context (homelab → small org) and are deliberately accepted rather than engineered away — each is stated so the decision is explicit:

- **The trust root is the out-of-band delivery of the invite.** The invite carries the CA fingerprint, so a compromised *network* cannot MITM enrollment — but a compromised *invite-delivery channel* can. This is the irreducible "one trusted bit" of any bootstrap; the operator must deliver the invite over a channel they trust.
- **The invite token is a bearer secret on the wire (plain-HTTP join).** CSR-based enrollment means the private key never travels, but an on-path attacker who captures the token can race the legitimate joiner to spend it. Single-use + short TTL + hostname-binding bound the damage to one wrongly-issued cert for an already-authorized hostname, and the loser's failed attempt is audited (F9), so the race is detectable. **TLS-for-join (future dual-mode ADR) closes this entirely;** until then, prefer short invite TTLs.
- **One online CA: single signer, single-step promotion.** No offline root, HSM, or multi-party quorum. A CA-host compromise lets an attacker issue certs (but, post-F1, **not** steal existing member private keys). An offline-root hierarchy remains a documented future option, not built here.
- **Source-based rate limiting is best-effort.** Source IPs are spoofable on a LAN; the real brute-force defense is the high-entropy single-use token (F2). F7's per-token + per-source limiting is DoS dampening, not the primary credential guard.
- **Machine-change detection fails safe, not silent.** A legitimate VM migration/restore trips it; the consequence is a refused *auto*-unlock requiring a one-time manual passphrase + operator re-bind — never silent admission. This false-positive is the intended, safe behavior (F11).
- **Token-store / roster compromise.** The invite store holds only salted hashes of high-entropy tokens (not reversible); the roster/bundle are integrity-protected by the CA signature + sequence (F4). Both live on the CA host, whose compromise is already terminal for the mesh.

## Test & Verification Strategy

**Principle:** every feature F1–F16 has (a) in-crate unit tests, (b) an integration test in `crates/koi-certmesh/tests/`, and (c) a place in the cross-platform validation. CI already runs the `test` job on **ubuntu-latest, windows-latest, macos-latest** ([.github/workflows/ci.yml](../../.github/workflows/ci.yml)), so (a) and (b) are validated on all three OSes automatically. (c) adds a true multi-machine deployment pass that CI cannot perform.

### Levels

1. **Unit (`#[cfg(test)]` in source).** Serde round-trips for the changed wire types (`JoinRequest` with `csr_pem`, `JoinResponse` without `service_key`, `RenewResponse` with `ca_fingerprint`, the invite token, the signed bundle); token TTL/single-use/hostname-binding logic; rate-limiter fail-closed + per-source + persistence; RFC1123 validator; cert-profile assertions (parse issued leaf with x509-parser, assert KeyUsage/EKU/`is_ca=false`, CA `pathlen=0`); machine-change detection. Use `koi_common::test::ensure_data_dir` + `CertmeshPaths::with_data_dir(tempdir)` for isolation.

2. **Integration (`crates/koi-certmesh/tests/enrollment.rs`, new).** Mirror the proven two-tier `acme.rs` shape:
   - **Raw handler security gates** (axum `ServiceExt::oneshot` over plain HTTP on `127.0.0.1:0`): CA never returns a private key; a join with no/expired/used/wrong-hostname token is rejected; a CSR whose CN ≠ token hostname is rejected; SANs in the CSR that exceed the authorized set are dropped; a revoked member is rejected at health and (with a crafted bundle) at mTLS; a replayed lower-sequence trust bundle is rejected (anti-rollback); a *different* CSR under a spent token is rejected while the *same* CSR returns the cached cert (idempotency); audit log contains the failure events.
   - **Full CSR enrollment end-to-end:** generate keypair+CSR client-side, mint invite, enroll, assert the returned chain verifies to the CA. Assert key-custody **mechanically**: `JoinResponse` carries no key field at the type level (compile-time), and a regression test scans the raw response bytes for any `PRIVATE KEY` PEM marker and fails if one is present. Then pull-renew and assert the pin refreshes (`RenewResponse.ca_fingerprint` / bundle); then revoke and assert the signed bundle's sequence increments and enforcement rejects.
   - **Renewal (pull) — custody, scope, grace, authorization:** a member submits a fresh CSR to the renew endpoint and gets a re-signed cert; assert the response carries **no `PRIVATE KEY`** bytes (same mechanical scan as join) and the renewed cert keeps exactly the authorized SAN set (a renewal CSR requesting an extra SAN has it dropped); a member attempting to renew a *different* hostname is rejected (CN-authorization); a clock-advanced member **within** the grace window renews successfully (its expired-but-in-grace cert is accepted on the renew path), while **past** grace it is refused and must re-enroll; after a simulated CA re-key, `RenewResponse.ca_fingerprint` differs and the member updates its pin (F5).
   - Serialize with `--test-threads=1` (as acme.rs documents) where global state is touched.

3. **Local multi-instance E2E (CI-able).** Extend `crates/koi-embedded/examples/embedded-integration.rs` (or a sibling example) to run **two daemons in one host** with distinct `KOI_DATA_DIR` and ports (CA on 5641/5642, joiner on 5651/5652), driving create → invite → CSR-join → mTLS handshake → revoke → bundle-resync → rejection. Runnable as `cargo run -p koi-embedded --example enrollment-e2e`, and added as an `#[ignore]`-gated integration test so it can run on each CI OS on demand without requiring separate machines.

### Cross-platform deployment validation (Windows host + Linux servers)

CI cannot span physical machines, so this is a **documented, repeatable runbook** (also captured as an `#[ignore]` checklist test à la `docker_integration.rs`). Hosts: **W** = this Windows host, **L1/L2** = Linux servers. Data dirs default per platform (`%ProgramData%\koi\`, `/var/lib/koi/`); ports 5641/5642/5643; mDNS 5353. On Linux open the relevant ports (ufw/firewalld); on Windows `koi install` writes the netsh rules.

| Step | Where | Command (sketch) | Asserts |
|---|---|---|---|
| Install | W, L1, L2 | `koi install` (admin/root) | service runs `koi --daemon` |
| Create CA | L1 | `koi certmesh create` | prints CA fingerprint; `certs/<l1>/key.pem` exists **only on L1** |
| Advertise | L1 | (automatic, F12) | `_certmesh._tcp` resolvable with fingerprint TXT |
| Invite | L1 | `koi certmesh invite windows-host` | prints a single-use token carrying the fingerprint |
| Join (discover) | W | `koi certmesh join --invite <token>` | keypair+CSR generated locally; fingerprint verified from token; **no key in any response**; `%ProgramData%\koi\certs\windows-host\key.pem` present locally, **absent on L1** |
| Join (explicit) | L2 | `koi certmesh join --invite <token2> --endpoint https://l1:5641` | same custody assertions on L2 |
| mTLS | W↔L1↔L2 | inter-node health on 5642 | handshake succeeds for enrolled members |
| Revoke + propagate | L1 then L2/W | `koi certmesh revoke windows-host` | after bundle resync, L2 and L1 **reject** windows-host on mTLS and health |
| Renewal pull | W (clock-advanced or short-lifetime build) | member pull-renew | new cert; pin refreshes via `ca_fingerprint` |
| Offline grace | L2 (stop, restart inside the grace window) | pull-renew | recovers; renewed key stays on L2 (no key in response) |
| Past-grace expiry | L2 (stay down beyond grace) | pull-renew | **refused**; re-enroll via fresh invite required |
| Negative: spoofed CA | W | point at a rogue endpoint with wrong fingerprint | join **refused** before sending CSR |
| Negative: token replay | W | re-use a spent token | **rejected**; `enroll_token_reused` audited |
| Negative: wire capture | W | capture the plain-HTTP join | captured bytes are **useless** (single-use token, no key) |

Per-platform service specifics validated incidentally: Windows SCM + netsh firewall + `%ProgramData%` ACLs; Linux systemd `Type=notify` + `/var/lib/koi`; (macOS launchd path exercised by CI unit/integration on `macos-latest`). Auto-unlock custody (F11) is validated by: enable auto-unlock on L1 *with* keyring → boots unlocked; clone L1's data dir to L2 *without* keyring → boot **refuses** auto-unlock + audits a machine-change.

### CI changes

- Add `crates/koi-certmesh/tests/enrollment.rs` (runs in the existing 3-OS `test` matrix).
- Keep the `surfaces` job green: the K2 vocabulary scrub (F16) must pass `scripts/check-doc-leaks.sh`.
- Update [docs/SURFACES.md](../../docs/SURFACES.md) certmesh row: bump `Last exercised` and record the new enrollment guard (per the rotation contract). Note revocation is now propagated via a signed bundle (not "roster-only").

### Requirements → test traceability

| Feature | Unit | Integration (`enrollment.rs`) | Deployment / E2E |
|---|---|---|---|
| F1 CSR enrollment | wire serde; no-key invariant | "CA never returns a key"; chain verifies | custody asserts on W/L1/L2 |
| F2 invite tokens | TTL/single-use/binding | invalid/expired/used/wrong-host rejected | invite + replay negative |
| F3 fingerprint bootstrap | invite decode | preflight mismatch bails | spoofed-CA negative |
| F4 signed bundle + revocation | bundle sign/verify + anti-rollback (seq) | revoked rejected (health+mTLS); stale/replayed bundle rejected | revoke + propagate |
| F5 fingerprint refresh | `RenewResponse` serde (+`ca_fingerprint`) | pin updates after CA re-key | renewal pull |
| F6 pull renewal + grace | lifetime/threshold/grace consts | renew custody (no key) + SAN no-escalation + CN-authz; within-grace ok, past-grace refused | offline grace + past-grace re-enroll |
| F7 rate limiter | fail-closed/per-source/persist | lockout survives reload | (covered by negative) |
| F8 atomic + idempotent | ordered-write helper | idempotent re-submit | crash-retry on a host |
| F9 audit failures | audit format | failure events present | audit inspected post-run |
| F10 cert profile | x509 KeyUsage/EKU/pathlen | issued leaf parsed | mTLS still validates |
| F11 auto-unlock custody | machine-change detect | (n/a) | clone-without-keyring refuses |
| F12 mDNS advertise | TXT build | discover hint-only | discover join on W |
| F13 cert_path skip | serde omits path | status has no path | (inspect JSON) |
| F14 self_enroll/promote | CN pin; key match | promote wrong-key rejected | promote on L2 |
| F15 RFC1123 | validator cases | bad hostnames rejected | (covered) |
| F16 FIDO2 removal + K2 | (compile) | no FIDO2 route | `check-doc-leaks.sh` green |

---

## Rollout / phasing

Greenfield, pre-1.0, **no compatibility shims** (STACK-0001). Land in dependency order so each phase is independently testable and the gate (`cargo test && cargo clippy -- -D warnings && cargo fmt --check`) stays green:

1. **F1 + F8 + F10 + F13 + F15** — CSR enrollment with atomic/idempotent commit, hardened profile, hygiene. (Biggest blast-radius reduction; reuses csr.rs.)
2. **F2 + F3** — invite tokens + pinned-fingerprint bootstrap (retires the mesh-wide TOTP).
3. **F4 + F5 + F14** — signed trust bundle, revocation enforcement, fingerprint refresh, identity-transfer integrity.
4. **F6 + F7 + F9 + F11 + F12 + F16** — operability/custody tail and the vocabulary scrub.

Each phase ships its unit + integration tests; the cross-platform runbook is executed at the end of phase 1 (custody) and again after phase 3 (revocation/renewal).

---

## Consequences

### Positive
- CA compromise no longer yields member private keys; keys never traverse the network — closes the audit's only critical-structural fault.
- Enrollment is safe even over plain HTTP (bound single-use token + fingerprint pin + CSR PoP), decoupling enrollment security from the unresolved dual-mode transport decision.
- Revocation actually takes effect mesh-wide via signed truth that members verify; no trust in unauthenticated discovery.
- Offline members recover (pull renewal + grace); operations stop silently expiring.
- Standards-aligned: proper CSR flow, leaf profiles, non-delegating CA, full audit, hostname validation.

### Negative
- **UX change:** adding a machine now requires the operator to mint a per-host invite (one command) instead of sharing one TOTP. Mitigation: the invite is a single copy-paste/QR artifact that also carries the CA fingerprint, so it is no harder than the TOTP and strictly safer.
- More moving parts (token store, signed bundle, machine-binding record) — each is small and individually tested.
- A re-keyed CA (promotion/rotation) forces a fingerprint refresh; F5 automates it, but a member offline across a rotation must pull-renew to recover.

### Risk mitigation
- The riskiest change (F1) reuses already-tested csr.rs/rcgen and is covered by a "CA never emits a private key" invariant test plus the cross-platform custody asserts.
- Fail-closed defaults (F7, F11) ensure that a load/parse failure denies rather than admits.
- Frozen HKDF labels (K3) are never touched; the FIDO2 reserved label is preserved though its dead code path is removed.
- The cross-platform runbook exercises the genuinely-distributed behaviors (custody, revocation propagation, renewal, auto-unlock cloning) that single-host CI cannot.

---

## References
- Audit findings (this conversation's enrollment-lifecycle map + threat/PKI/architecture critique).
- ADR-011 (dual-port security architecture), ADR-003 (envelope encryption), ADR-004 (ceremony), ADR-009 (auth adapters), STACK-0001 (stack canon: K2/K3/D7).
- Reused primitives: `csr::sign_csr`, `koi_crypto::signing`, `koi_crypto::pinning`, `koi_crypto::key_agreement`, `koi_crypto::vault`/`tpm`, rcgen 0.13 (P-256/ES256).
