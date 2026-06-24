# Koi 0.7 — Authz-plane ergonomics (round 2)

> A round-2 wishlist from an embedded consumer building a dual-mode authorization plane on
> the ADR-020 `Envelope` primitive + a renewal loop over its own clear+signed channel,
> filed against 0.6.0. **No blocker** — 0.6.0 has the surface; this round is "make the
> secure path the easy path" + observability. Decisions ratified 2026-06-24.
>
> **K2 gate**: generic, consumer-neutral vocabulary only. Run `scripts/check-doc-leaks.sh`
> after any doc change.

## Architecture Decision

**ADR-022** (`docs/adr/022-authz-plane-ergonomics.md`) covers the contract-affecting
decisions: the request-binding door (M1), reject attribution (N1), and policy propagation
(N4). Read it first.

## Scope (0.7.0) — ratified "everything except N2"

| # | Item | Wire contract? | Status |
|---|------|----------------|--------|
| **M1** | `Assurance::identity_for(env, expected)` — request-binding door (the silent-impersonation fix; "if only one lands, this is it") | No (additive method) | — |
| **N1** | `Assurance::Rejected { reason, signer_cn }` — trusted-only signer attribution (Expired/Revoked only) | Yes (Assurance shape; minor Rust-breaking via `..`; trust-protocol §2) | — |
| **N3** | public `leaf_not_after_utc` / `leaf_cn` (PEM) | No | — |
| **N4** | `policy: CertPolicy` on `RenewResponse` (symmetric with `JoinResponse.policy`) | Yes (additive field) | — |
| **N5** | doc steer: `member_cert_expiry()` → `local_identity().renewal` | No (doc) | — |

**M1 shape ratified:** `Assurance::identity_for(env, expected)` (method on `Assurance`,
additive, preserves the one-door philosophy) — not `verify_bound` (which would need a new
`PayloadMismatch` verdict).

## Deferred / non-asks

- **N2 `verify_single_use` / koi-owned nonce cache** — adds replay state to a deliberately
  stateless verifier; the consumer builds its own bounded single-use set. Own ADR if a
  second consumer needs it.
- **Confidentiality / `seal`** — consumer wants authenticity, not secrecy; sign-only path
  unchanged.
- **mTLS pull-renewal loop** (`renew_self_if_due`, `certmesh_background`) — not used;
  `local_identity().renewal` + `renew_member` are the only renewal surfaces needed.

## Release shape

0.7.0 = M1 + N1 + N3 + N4 + N5. N1 is the reason for the minor bump (it changes the
serialized `Assurance` contract). Two-box hardware gate applies (N4 touches the renewal
response path). Verify gate per commit: `cargo check --workspace`, `cargo test --workspace
--locked`, `cargo clippy -- -D warnings`, `cargo fmt --check`, `scripts/check-doc-leaks.sh`.
