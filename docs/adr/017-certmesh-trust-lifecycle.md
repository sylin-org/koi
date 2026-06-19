# ADR-017: Certmesh Trust Ledger, CSR-Only Issuance, and Anchor Lifecycle

**Status:** Accepted — **Phases 1–3 Implemented** (1a cert profiles + CA-held policy; 1b member-pull rotate-key renewal; 2 signed monotonic trust bundle + sequenced single-writer roster + boundary revocation; 3 pinned-fingerprint bootstrap + mDNS fp advertise + anchor self-heal). Phase 4 pending. (operator-ratified key decisions 2026-06-18)
**Date:** 2026-06-18
**Builds on:** ADR-015 (Certmesh Enrollment Hardening) — **F1** (CSR-based enrollment) and **F2** (single-use invite tokens) are **Implemented**; this ADR supersedes ADR-015's **phases 3–4** (F3, F4, F5, F6, F7, F9, F11, F12, F14, F16) and the completion of the phase-1 hygiene items not yet finished (F10 cert profile, F13 cert_path, F15 RFC1123).
**Constrained by:** STACK-0001 (K2 consumer-neutrality, K3 frozen HKDF labels, D7 contract surface). The bundle/policy signing uses the CA's P-256 key — **not** HKDF — so the frozen K3 labels are untouched. No consumer names are introduced.
**Relates to:** ADR-011 (Security Architecture — dual-port 5641 HTTP+DAT / 5642 mTLS), ADR-003 (Envelope Encryption), ADR-016 (Strategic Realignment — Koi as the node trust plane).

---

## Context

ADR-015 enumerated sixteen enrollment-hardening features. F1 (the joiner keeps its own key; the CA signs a CSR) and F2 (per-host single-use invite tokens) shipped, were security-reviewed, and were live-verified. A ground-truth audit of the remaining work found that the unbuilt features are **not independent** — implemented feature-by-feature they would produce an incoherent system. They share three structural roots:

- **R1 — Mesh state has no integrity, version, or atomicity.** `roster.json` is plain unsigned JSON with no sequence counter, written non-atomically by several concurrent writers (enroll, revoke, the live renewal loop, the live health loop each `clone → drop lock → spawn_blocking write`). So revocation is **CA-local only** — never propagated to members and **not enforced at the mTLS/health boundary** (only checked at enroll/receive_renewal); there is **no anti-rollback**; and concurrent writes can silently lose updates.
- **R2 — The trust anchor has no lifecycle.** A joiner never pins the CA fingerprint *before* it sends its CSR (`discover_ca` trusts plain-HTTP mDNS); the pin is never refreshed when the CA re-keys; and the CA never advertises itself.
- **R3 — Issuance is split and still key-leaky.** Enrollment is CSR-based (F1), but the **renewal loop is wired and live** and calls `ca::issue_certificate`, which **regenerates a member keypair on the CA each cycle** and is built to ship it in `RenewRequest.key_pem`. There is no single cert profile (leaves carry no KeyUsage / no EKU; the CA cert has no path-length limit), and the at-rest CA key is machine-derived with **no clone/snapshot detection**.

Cross-cutting: failure paths are not audited and `self_enroll` emits no audit event; `RosterMember.cert_path` leaks home directories into JSON; hostname validation is not full RFC 1123; the legacy term "pond" lingers in a module name and the `pond_initialized` audit event (no FIDO2 *code* exists — only a research note).

This ADR rebuilds certmesh around three backbone primitives from which the remaining features follow. Greenfield, pre-1.0, **no compatibility shims** (STACK-0001); the wire and on-disk formats may change.

---

## Decision

### Backbone P1 — The signed, monotonic Trust Bundle is the single source of mesh truth

A canonical, CA-signed document is the authority on membership, revocation, the CA identity, and the lifecycle policy:

```jsonc
// GET /v1/certmesh/trust-bundle  -> { "bundle": <TrustBundle>, "signature": <base64 P-256/ES256 over canonical bundle bytes> }
TrustBundle {
  seq:            u64,            // monotonic; bumped on every roster mutation
  issued_at:      RFC3339,
  ca_fingerprint: String,        // sha256 of ca_cert DER
  ca_cert_pem:    String,
  policy:         CertPolicy,     // CA-held lifecycle policy (below)
  members:  [ { hostname, cert_fingerprint, not_after: RFC3339, status: "active"|"revoked" } ],
  revoked:  [ { hostname, cert_fingerprint, revoked_at: RFC3339 } ]
}
```

- **Signature:** detached ES256 over the canonical (sorted-key, no-whitespace) bundle bytes, produced by the CA key. Verifiable offline by anyone holding the (pinned) CA cert.
- **Served** at `GET /v1/certmesh/trust-bundle` (DAT-exempt read — it is integrity-protected by its own signature, like a CRL).
- **Pulled** by members on an interval; each member verifies the signature chains to its **pinned** CA fingerprint and rejects any bundle with `seq ≤ last_seen` (**anti-rollback**).
- **Enforced** at the boundary: the mTLS layer and the `/health` handler reject peers whose `(hostname, cert_fingerprint)` is in `revoked` or absent from `members` — revocation now actually takes effect mesh-wide, not just at enroll time.
- The local `roster.json` becomes the CA's **private superset** (operator names, reload hooks, invite store stay CA-side); the bundle is its public, integrity-protected **projection**.

Resolves **F4** (signed bundle + revocation propagation + anti-rollback) and **F5** (the bundle carries the live `ca_fingerprint`; see anchor lifecycle). Feeds **F12** (the mDNS TXT advertises the same fingerprint).

### Backbone P2 — A single-writer RosterStore with atomic, sequence-bumping commits

Every roster mutation (enroll, revoke, renew, touch-last-seen, role change) goes through one `RosterStore` that:

1. holds the lock for the **entire** read-modify-write (no more `clone → drop → write` races),
2. bumps `seq`,
3. writes atomically (temp file → `fsync` → `rename`),
4. re-signs and caches the trust bundle (P1 is a pure projection of the store).

Enrollment commit is **ordered and idempotent**: an idempotency key of `(hostname, CSR public-key fingerprint)` makes a retried join return the same result instead of double-enrolling. Resolves **F8** (atomic/idempotent commit) and supplies the monotonic `seq` P1/P4 require.

### Backbone P3 — One CSR-only issuance pipeline with one cert profile

Collapse enrollment and renewal onto a single signing path:

- `csr::sign_csr` is the **only** issuance entry point for members, applying a shared `leaf_profile()`. `ca::issue_certificate` (which key-gens) survives **only** for the CA's own `self_enroll` (the CA's own identity, generated locally).
- **Renewal becomes member-initiated pull.** The member's renewal loop, when a cert is within the CA's `renew_threshold_days`, **generates a fresh keypair + CSR** (rotate-on-renewal — operator-ratified) and calls `/v1/certmesh/renew` over mTLS with the CSR; the CA signs and returns the leaf; the member installs it locally next to its new key. `RenewRequest.key_pem` is **deleted** — the CA never generates or transmits member keys, on enroll *or* renew.
- **Cert profiles** (applied by both `sign_csr` and the CA self-enroll leaf):
  - Leaf: `KeyUsage = [DigitalSignature, KeyEncipherment]`, `ExtendedKeyUsage = [ServerAuth, ClientAuth]`, `BasicConstraints: is_ca = false`.
  - CA: `BasicConstraints: is_ca = true, path_len = 0` (the CA may sign leaves but not sub-CAs).

Completes **F1**, fixes **F6** (key custody preserved across renewal; member-pull; grace), and centralizes **F10**.

### CA-held lifecycle policy (operator-ratified: 90 / 30 / 14, configurable)

```rust
CertPolicy { leaf_lifetime_days: u32, renew_threshold_days: u32, grace_days: u32 } // default 90 / 30 / 14
```

- **CA-owned.** Stored in `RosterMetadata`, set at `certmesh create` (CLI flags / ceremony), defaulting to 90/30/14. The CA applies `leaf_lifetime_days` when signing.
- **Distributed in the signed bundle** so members drive their pull-renewal loop on the CA's schedule (`renew_threshold_days`) and know how long past `not_after` they may still pull-renew before they must re-enroll (`grace_days`).
- **Grace state machine (member side):** `valid` → (within `renew_threshold`) `renewing` → on success back to `valid`; if `not_after` passes, `grace` (mTLS may still be accepted by peers for `grace_days`, and the member keeps trying to pull-renew); past grace → `expired` → must re-enroll via a fresh invite.

### Supporting layers

- **Bootstrap & refresh (F3, F5, F12).** The invite carries the CA fingerprint; `koi certmesh join --invite <token>` pins it and **preflights** (`GET /status` or `/trust-bundle`), aborting **before** sending the CSR on mismatch. The daemon advertises `_certmesh._tcp` at startup with `fp=<ca_fingerprint>` in TXT — a convenience hint the joiner cross-checks against the invite, never a trust source. The pin is refreshed only from a bundle whose signature verifies against the **currently pinned** CA (normal re-key) or via a promotion-signed transition.
- **Custody (F11).** Record a machine-binding fingerprint at CA create; at boot, if it changed, **refuse auto-unlock and audit** (a VM clone/restore trips it — the safe failure). A machine-derived-only vault key (no platform keystore/TPM) is refused by default with a loud opt-out.
- **Observability (F9, F14).** Audit **every** trust decision, including failures, *before* returning `Err`: `enroll_auth_failed`, `enroll_revoked_attempt`, `enroll_approval_denied`, `enroll_token_invalid`, `enroll_token_reused`, `enroll_no_csr`, `roster_persist_failed`, `renewal_failed`, `unlock_failed`, `auto_unlock_refused_machine_changed`, `bundle_rollback_rejected`, `mtls_revoked_rejected`. Audit `self_enroll`. The promote handler verifies the decrypted CA key's public key matches the expected fingerprint (F14).
- **Hygiene (F13, F15, F16).** `#[serde(skip)]` on `RosterMember.cert_path` (or store relative); one shared full **RFC 1123** hostname validator (≤63/label, alphanumeric+hyphen, no leading/trailing hyphen) used everywhere a hostname becomes a SAN or a directory; retire "pond" from the public/audit surface (`pond_initialized → ca_initialized`, `pond_ceremony → init_ceremony`); confirm FIDO2 remains docs-only.
- **Rate limiting (F7).** The TOTP enrollment path keeps a **fail-closed**, per-source + per-token limiter, persisted so a restart can't reset a lockout. Invite tokens are deliberately unthrottled (single-use, high-entropy).

---

## Protocol surface (net change)

| Method | Path | Change | Auth |
|---|---|---|---|
| GET | `/v1/certmesh/trust-bundle` | **new** — signed bundle (P1) | exempt (self-verifying) |
| POST | `/v1/certmesh/renew` | **changed** — body is now `{hostname, csr}`; response has **no** key | mTLS |
| POST | `/v1/certmesh/member-csr` · `/member-cert` | reused for renewal (rotate-key) | DAT (local) |
| GET | `/v1/certmesh/status` | adds `policy` + `seq` + `ca_fingerprint` (for preflight) | exempt (GET) |

mDNS: `_certmesh._tcp` is now **advertised** by the daemon with `fp=` TXT (was browse-only).

---

## Phased plan (each phase independently testable; the gate `cargo fmt --check && cargo clippy -- -D warnings && cargo test` stays green; each phase is security-reviewed and live-verified on the test host before the next)

1. **Issuance unification. ✅ Implemented (1a + 1b).** P3 + `leaf_profile`/`ca_profile` (F10) + `CertPolicy` (CA-held, 90/30/14) + member-pull rotate-key renewal (F6); deleted CA-side member key-gen on renewal and `RenewRequest.key_pem` (the request is now `{hostname, csr}`). `/renew` is mTLS-only; members persist `certmesh/member.json` (CA host + pinned fp + policy) and pull a rotated leaf before expiry; the CA self-renews its own leaf at restart. *Closed the live key-custody regression first.*
2. **Trust ledger. ✅ Implemented.** P2 single-writer sequenced commit (`commit_roster`/`touch_roster` hold the lock across an atomic write + bump `seq` on membership changes — F8) → P1 signed `TrustBundle` at `GET /v1/certmesh/trust-bundle` (ES256 by the CA key over canonical bytes; self-verifying, DAT-exempt) + member pull with pin-check + anti-rollback (`seq` floor) + policy refresh + self-revocation detection; boundary revocation enforced at the mTLS `/renew` + `/health` handlers (F4). `/status` surfaces `seq` + `policy`. *Idempotency-key dedup of retried joins (F8) deferred to a follow-up — the atomic single-writer commit is in place.*
3. **Anchor lifecycle. ✅ Implemented.** F3 pinned-fingerprint bootstrap: the invite is now a `<secret>.<ca_fingerprint>` code; `join --invite` pins the embedded fingerprint and **preflights** (`GET /status`), aborting *before* sending its CSR on mismatch, and `install_member_cert` **hard-fails** unless the installed CA cert matches the out-of-band pin (closing the join-MITM vector for invite joins; the TOTP join stays TOFU). F12 the daemon **advertises** `_certmesh._tcp` with `fp=<ca_fingerprint>` in TXT, which `join` cross-checks as a hint. F5 the member **self-heals** its on-disk `ca.pem` from each verified bundle, and a bundle whose fingerprint differs from the pin is **rejected fail-safe** (the pin is invariant — promotion transfers the same key; an intentional CA replacement is recovered by re-enrolling with a fresh invite). *A signed live re-key transition is deferred (no CA re-key path exists today; the fail-safe + re-enroll recovery is the secure interim).*
4. **Custody, observability, hygiene.** F11 machine-binding + clone detection; F9/F14 full failure audit incl. `self_enroll`; F13/F15/F16 hygiene; F7 persisted fail-closed rate limiter.

### Hole → phase map

| Hole | Phase | Hole | Phase |
|---|---|---|---|
| F6 pull renewal + grace | 1 | F5 fingerprint refresh | 3 |
| F10 cert profile | 1 | F12 mDNS advertise | 3 |
| CA-held cert policy | 1 | F11 custody machine-binding | 4 |
| F8 atomic/idempotent commit | 2 | F9 failure audit | 4 |
| F4 signed bundle + revocation + anti-rollback | 2 | F14 self_enroll audit + promote pubkey check | 4 |
| F3 pinned bootstrap | 3 | F13/F15/F16 hygiene; F7 rate limiter | 4 |

---

## Consequences

**Positive.** One integrity-protected source of truth (the signed, monotonic bundle) replaces an unsigned racy JSON blob; revocation actually propagates and is enforced at the boundary; the member private key never exists on the CA, on enroll *or* renew; certs carry least-privilege profiles; the CA identity is pinned at bootstrap and safely refreshed; custody fails safe on machine change; every trust decision is audited. The certmesh domain is organized around three primitives instead of sixteen patches.

**Negative / cost.** A larger rebuild touching `roster.rs`, `lifecycle.rs`, `ca.rs`, `csr.rs`, `enrollment.rs`, `http.rs`, the compose background loops, and the binary join/renew flows. On-disk and wire formats change (acceptable pre-1.0; no shims). Rotate-on-renewal means a member's cert fingerprint changes each cycle — the bundle/roster already track it, but anything that pinned a *leaf* fingerprint (not the CA) must follow the bundle.

**Accepted residual risks (carried from ADR-015).** The trust root is the out-of-band delivery of the invite (a compromised invite-delivery channel can MITM enrollment). One online CA: single signer, single-step promotion, no offline root/HSM/quorum. Source-based rate limiting is best-effort on a LAN; the real brute-force defense is the high-entropy single-use token. Machine-change detection fails safe (a legitimate migration trips it → one-time manual passphrase + re-bind). Plain-HTTP join remains until a TLS-for-join transport ADR; the pinned fingerprint (F3) closes the CA-spoofing vector, leaving only a token-capture race as documented.

## Decisions recorded (2026-06-18)

- **Cert lifetimes:** 90 / 30 / 14 days, as a **CA-held configurable policy** distributed in the signed bundle.
- **Renewal:** member **rotates** to a fresh keypair each renewal.
- **Recording:** this new ADR-017 supersedes ADR-015 phases 3–4; ADR-015 F1/F2 stand as Implemented.
