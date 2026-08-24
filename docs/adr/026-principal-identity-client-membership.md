# ADR-026: Principal Identity — Client-Role Mesh Membership for Non-Human Callers

**Status:** Accepted (operator-ratified 2026-08-23)
**Date:** 2026-08-23
**Builds on:** ADR-017 (CSR-only issuance, single-use invites, roster roles, boundary revocation), ADR-020 (Posture/Assurance/RejectReason, `ClientCn` extraction, same-port posture dial), ADR-011 (port model), ADR-015 (enrollment constraints)
**Constrained by:** STACK-0001 (K2 consumer-neutrality — no agent/product names enter Koi; K3 frozen HKDF labels — no new derivations introduced)
**Amends:** the ADR-024 honest-limits wording "one token per daemon … no per-client accounts" — see Consequences.

---

## Context

Every mutating request to the daemon authenticates with the single shared DAT token
(`x-koi-token`). That is correct for the loopback owner model and must not change locally — but
it makes every non-human caller *indistinguishable*: the audit trail records the token, not the
actor; compromise of one consumer's copy of the token compromises all of them; and revocation
is all-or-nothing (rotate the token, breaking every caller at once). ADR-024 recorded "one
token per daemon, no per-client accounts or scopes" as a limit. Non-human callers — scripts,
automation, AI agents reaching Koi through the MCP door — are becoming primary LAN
participants, which turns that incidental limit into a strategic gap: **Find. Trust. Connect.
must apply to them too.**

### Substrate audit (2026-08-23)

The gap is smaller than it looks; most of the substrate exists:

| Capability | Status today | Location |
|---|---|---|
| Roster role `Client` | **EXISTS** | `RosterMember.role` (Primary/Standby/Member/Client) |
| CSR-only issuance (caller keeps its key) | **EXISTS** | `csr::sign_csr` — ADR-017 P3 |
| Single-use invite tokens | **EXISTS** | ADR-015 F2 / ADR-017 bootstrap |
| RFC 1123 name validator | **EXISTS** | ADR-017 F15 shared validator |
| Client-certificate CN extraction | **EXISTS** | `ClientCn` extension, `koi_certmesh::mtls` |
| Boundary revocation enforcement | **EXISTS** | trust-bundle check at mTLS/health boundary (ADR-017 P1) |
| ClientAuth-only leaf-profile variant | **ABSENT** | `leaf_profile()` issues `[ServerAuth, ClientAuth]` uniformly |
| Wire-enrollment path usable without a full daemon install | **ABSENT** | join presumes the installed CLI/daemon |
| Management-plane CN authorization | **ABSENT** | mTLS listener serves only certmesh inter-node routes |
| Per-actor audit attribution | **ABSENT** | audit entries record the operation, not the verified caller |

**Conclusion:** the genuinely new work is one leaf-profile variant, a documented wire path for
keyless-install clients, CN-based authorization on an authenticated management transport, and
attribution plumbing into the audit chokepoint.

---

## Decision

### 1. Vocabulary — "principal"

A **principal** is an enrolled non-host participant holding a Client-role membership: it
receives identity and attribution but does not serve TLS, does not hold CA material, cannot
promote, and runs no CA-plane loops. The word is deliberately neutral (K2): Koi documents
*principals*; whether one happens to be an agent, a script, or a phone is invisible here.

### 2. Naming

A principal's roster `hostname` **is** its identity string: one or more RFC 1123 labels under
the configured zone (validated by the existing F15 validator). Default suggestion
`client-<short_id>` (`koi_common::id::generate_short_id()`); the operator may choose the name
at invite time. The roster schema is unchanged — role `Client` is what marks the entry as
non-serving.

### 3. Leaf-profile variant

`apply_leaf_profile()` (`koi_certmesh::ca`, already the single chokepoint applied by both
CA self-enroll and `csr::sign_csr`) gains a role-aware split:

- Host roles (Primary/Standby/Member): unchanged — `[ServerAuth, ClientAuth]`.
- Client role: `ExtendedKeyUsage = [ClientAuth]` only, `KeyUsage = [DigitalSignature]`,
  `BasicConstraints: is_ca = false`.

The CA refuses to issue a ServerAuth EKU to a Client-role CSR (named failure, audited), so a
principal credential can never be presented as a service identity to proxies or browsers.

### 4. Enrollment — custody invariant unchanged, wire path documented

Enrollment reuses ADR-015/017 mechanics verbatim: an operator mints a single-use invite
(`koi certmesh invite --client`); the caller generates its keypair and CSR **locally** (F1 —
the private key never crosses the wire); the CSR + invite token traverse the existing
TOTP/invite-gated enroll pipeline, constrained by the existing time-window/domain/CIDR scopes.

What changes is documentation-first: the enroll request body carries an explicit `"role"`
(`"client"` default `"member"`), and the path is exercised end-to-end by an HTTP client that is
**not** a Koi installation — this is the same surface the SDK betas (V1-11) consume. The CLI
gains a thin `enroll-client` helper form for humans driving a foreign client through the step.

### 5. Management-plane authorization — additive to the loopback model

- **Loopback + DAT is unchanged.** The local trust model ("Koi is a LAN tool operated by the
  machine's owner") stands; local processes remain trusted callers.
- **Any non-loopback management exposure must be mutually authenticated.** Two sanctioned
  shapes, both already precedented: the TLS-proxy front with a client-certificate requirement,
  or a direct mTLS listener in the 5642 style. Plain-HTTP-plus-DAT off-box remains a
  deliberate, discouraged fallback exactly as today.
- On such transports, a caller presenting a certificate chains to the mesh CA is authorized by
  CN → roster lookup: active, not revoked, not expired (the ADR-017 boundary check), else
  rejected with the ADR-020 **named** `RejectReason` vocabulary — never one opaque error.
- **Authorization is coarse for 1.0:** any active principal holds the effective authority of
  the DAT holder **minus the human-only surfaces**. CA administration
  (`create/promote/destroy/unlock`, invite minting) stays CLI/local-DAT only — extending the
  MCP card's exclusion principle from "not exposed to agents" to "not exposed to any
  non-loopback principal." Per-principal scopes/RBAC are explicitly out of scope (a conscious
  1.0 boundary, revisitable post-stable).

### 6. Audit attribution

Audit entries for mutations gain an actor field: `via=dat` for token requests, or the verified
CN for principal-authenticated requests. New named failure events (audited before returning
`Err`, per the ADR-017 discipline): `enroll_client_profile_refused`, `mtls_unknown_cn`,
`mtls_expired_cn` (revoked-CN rejection already exists as `mtls_revoked_rejected` boundary
behavior and is reused, not duplicated).

### 7. Token coexistence

The DAT is **not** removed or deprecated. Principal identity is additive: it upgrades
remote/attribution scenarios without taxing the single-user homelab that never leaves
loopback.

---

## Protocol surface (net change)

| Method | Path | Change | Auth |
|---|---|---|---|
| POST | `/v1/certmesh/enroll` | body gains explicit `role` field; Client-role CSRs get the ClientAuth-only profile | invite + TOTP/scope gates (unchanged) |
| mTLS mgmt transports | existing routes | CN-based principal authorization; named rejections | client certificate chained to mesh CA |
| Audit log | — | entries gain actor attribution (`via=dat` / CN) | local |

No new ports, no new mDNS records, no new HKDF labels (ES256 signing reused; K3 untouched).

---

## Consequences

- **Amended claim:** ADR-024's "when *not* to use" enterprise-PKI bullet is reworded — Koi now
  provides per-caller *identity* (still without per-caller *scopes*). The overview, security
  model, and MCP card are synced when this ADR lands.
- **Revocation pairing:** a revoked principal fails closed at Koi boundaries immediately
  (bundle enforcement); its residual exposure to *generic* TLS verifiers is bounded by
  ADR-027's short leaf lifetimes instead of the current 90 days.
- **Attribution is not yet authorization:** coarse equality with the DAT means a compromised
  principal is as powerful as a leaked token *remotely* — the win is attribution, individual
  revocation, and removal of long-lived bearer copies from consumer machines, not blast-radius
  reduction to zero. Stated plainly to avoid overselling.

## Validation plan

- Unit: profile variants refuse ServerAuth for Client role; F15 validator on principal names;
  audit attribution round-trip.
- Integration (two-daemon harness): a third participant enrolls as Client over raw HTTP with a
  locally generated CSR, presents its certificate to the mTLS management shape, exercises
  `/v1/mcp`, is revoked, and is then rejected with the named reason while a healthy principal
  still passes.
- Physical lane: extends the existing `certmesh-lifecycle` transaction with a client-role
  third participant (Windows↔Linux), reusing the tracked trust-transaction cleanup discipline.
- SURFACES row for the enroll-body change; capability-card updates for certmesh + MCP.
