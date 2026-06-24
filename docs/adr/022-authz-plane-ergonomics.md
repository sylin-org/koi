# ADR-022: Authorization-Plane Ergonomics — Request Binding, Reject Attribution, Policy Propagation

**Status:** Accepted (operator-ratified 2026-06-24)
**Date:** 2026-06-24
**Builds on:** ADR-020 (mode-transparent trust primitives), ADR-021 (transport-agnostic CA-side renewal), ADR-017 (certmesh trust lifecycle)
**Constrained by:** STACK-0001 (K2 consumer-neutrality, K3 frozen HKDF labels)

---

## Context

After ADR-020/ADR-021 shipped (0.6.0), an embedded consumer building a dual-mode
authorization plane on the `Envelope` primitive — and a renewal loop over its own
clear+signed channel — filed a round-2 wishlist. Per K2 the consumer is unnamed here.

The headline of the filing: **there is no blocker**. 0.6.0 has every primitive the plane
needs (`sign`/`verify` → `Envelope`/`Assurance`, `Assurance::identity()` as the one trust
door, `renew_member` taking a pre-authenticated CN, `local_identity().renewal` for
cert-derived expiry, the reactive events). This ADR covers the *ergonomics and footgun*
findings from wiring it up — "make the secure path the easy path" + observability. Every
item is additive or a small contract extension.

### The footgun: `verify()` attests the signer, not the request

`verify(&Envelope) -> Assurance` deliberately attests only the **signer**, decoupled from
the payload — correct, because Koi cannot know a consumer's request canonicalization. But
that leaves the obvious code silently vulnerable:

```rust
if core.verify(&env).await.identity().is_some() { authorize(request) }   // VULNERABLE
```

This authorizes a *captured* envelope replayed against a *different* request. The sharp
edge is concrete on a CA-side renewal endpoint: an attacker who captures **any** signed
envelope from member-A can POST it with their **own** CSR and — because `renew_member`
signs whatever CSR with A's authorized SANs — obtain a cert for A's identity bound to a
key they hold. Full impersonation, unless the verifier *also* checks the envelope's signed
payload equals the canonical bytes of *this* request (which embed a hash of the body / the
CSR). A consumer can do this by hand (decode `env.payload`, compare), and the failure is
silent if they forget.

### Secondary findings

- A `Rejected` verdict drops the signer's identity, even when the carried leaf parsed and
  chained — so a CA cannot log *who* failed, and a consumer cannot greet a returning member
  by name ("your identity expired — rejoin").
- `leaf_not_after_utc` and CN-from-PEM are crate-private; a consumer occasionally needs to
  read an *arbitrary* leaf (a discovered peer's cert, an operator-pasted cert) without a
  full verify.
- A member that intentionally does not arm `member.json` (the EmbeddedOnly cornerstone — it
  serves no mTLS pull-renewal authority) gets a *default* `renew_threshold_days`, so the
  threshold-derived `RenewalHealth.next_renewal_at` can drift from the CA's actual policy.
  (The expiry/`expired` facts are cert-derived and correct; only the threshold field drifts.)
- `member_cert_expiry()` (0.6.0) is `member.json`-gated, so it returns `None` for that same
  consumer — which partly defeats its own intent and briefly misled the consumer, who then
  found `local_identity().renewal` (the right call).

---

## Decision

### 1. `Assurance::identity_for(env, expected)` — fold request-binding into the door (M1)

```rust
impl Assurance {
    /// `Some(cn)` iff the envelope is Authenticated **and** Fresh **and** its signed
    /// payload equals `expected`. The safe door for *request* authorization.
    pub fn identity_for(&self, env: &Envelope, expected: &[u8]) -> Option<&str>;
}
```

Keeps Koi payload-agnostic (the consumer supplies the bytes it expected to be signed) and
preserves the existing **one identity door** philosophy (envelope.rs §13) — it just extends
it to the request-binding dimension, the one most likely to be gotten wrong and where the
failure is silent. `identity()` stays the signer-only door; `identity_for` is the
request-bound door.

**Why `identity_for`, not `verify_bound`:** the operator chose the method-on-`Assurance`
shape. It is purely additive (no new `RejectReason`, no change to the verdict the verifier
produces), composes with the existing `verify()` call the consumer already makes, and
matches the shape the consumer sketched. A `verify_bound` single-call would need a new
`PayloadMismatch` verdict — a contract addition we avoid. The payload comparison is a plain
equality check (the payload was already cryptographically authenticated by `verify`; it is
not a secret, so constant-time is unnecessary).

### 2. `Assurance::Rejected { reason, signer_cn }` — attribute the stale (N1)

```rust
Rejected { reason: RejectReason, signer_cn: Option<String> }
```

`signer_cn` is `Some(cn)` **only** when the carried leaf chained to the verifier's pinned CA
and the rejection is `Expired` or `Revoked` — i.e. a *known* member whose cert is merely
stale, where the CN is **authoritative**. It is `None` for `Malformed`, `UnsupportedVersion`,
`BadSignature`, and `UnknownSigner`, because in those cases the CN is either unparseable or an
**attacker-controllable claim** (anyone can attach a public leaf with a bad signature, or a
leaf that does not chain). This makes `signer_cn` a *trusted* attribution or nothing — never
a vector for log-spoofing — while still serving the audit + warm-rejoin use case.

`signer_cn` serializes with `skip_serializing_if = "Option::is_none"`, so the JSON wire shape
is unchanged for the common (`None`) case; trust-protocol.md §2 documents the field and its
trusted-only semantics. This is a minor breaking change for Rust code that exhaustively
matches `Rejected { reason }` (add `, ..`); no change for JSON readers.

### 3. Public stateless leaf parsers (N3)

```rust
pub fn leaf_not_after_utc(cert_pem: &str) -> Option<DateTime<Utc>>;
pub fn leaf_cn(cert_pem: &str) -> Option<String>;
```

Re-exported from `koi_certmesh`. `leaf_not_after_utc` is promoted from crate-private;
`leaf_cn` wraps PEM parsing over the existing DER `mtls::extract_cn`. Pure, no trust
inputs — for reading an arbitrary leaf's facts without a full verify.

### 4. `policy` on `RenewResponse` (N4)

`RenewResponse` gains `policy: CertPolicy`, populated by `renew_member` from the CA's roster
metadata — symmetric with `JoinResponse.policy`. A member (even one without `member.json`)
can then compute an accurate renewal schedule from the renew response. Additive wire field.

### 5. `member_cert_expiry()` doc steer (N5)

A doc line on `member_cert_expiry()` steering a consumer to `local_identity().renewal` for
own-leaf expiry **independent of member state**. We keep `member_cert_expiry()`
`member.json`-gated (changing it to fall back would make it `async` — a breaking 0.6.0 API
change for no gain, since `local_identity().renewal` already covers the need).

---

## Consequences

**Good:**
- The safe request-authorization path is now a one-liner (`identity_for`), not a hand-rolled
  decode-and-compare every consumer can forget.
- A CA can audit *who* failed and a consumer can greet a returning member by name — without
  ever trusting an attacker-supplied CN.
- Reading arbitrary leaf facts no longer needs a fork of Koi's parsers.
- A policy-accurate "renews in N days" line for members that drive their own renewal.

**Watch out for:**
- `identity_for` must compare against the **same** `env` that produced the `Assurance`;
  the doc makes this explicit. (A `verify_bound` would remove that footgun but at the cost of
  a new verdict — the deliberate trade.)
- `signer_cn` must never be populated for `UnknownSigner`/`BadSignature` — that would
  reintroduce an attacker-controllable identity claim into the verdict. The unit tests pin
  the trusted-only semantics.

## Out of scope

- **`verify_single_use` / a koi-owned nonce cache** (wishlist N2) — adds replay *state* to a
  deliberately stateless verifier. The consumer will build a bounded single-use set itself;
  Koi owning it is a larger decision deferred to its own ADR if a second consumer needs it.
- **Confidentiality / `seal`** — the consumer wants authenticity, not secrecy, on the LAN
  plane; the sign-only path is sufficient and unchanged.
- **Koi's mTLS pull-renewal loop** (`renew_self_if_due`, `certmesh_background`) — explicitly
  not used by the EmbeddedOnly consumer; `local_identity().renewal` + `renew_member` are the
  only renewal surfaces it needs.
