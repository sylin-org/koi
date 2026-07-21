# ADR-023: Delightful Trust — Membership-Intrinsic Self-Management

**Status:** Accepted (operator-ratified 2026-06-24)
**Date:** 2026-06-24
**Builds on:** ADR-017 (certmesh trust lifecycle), ADR-020 (mode-transparent trust primitives), ADR-022 (authz-plane ergonomics)
**Constrained by:** STACK-0001 (K2 consumer-neutrality, K3 frozen HKDF labels)

---

## Context

A downstream embedded consumer filed a wishlist asking Koi for two new public
`CertmeshCore` APIs to make revocation effective fleet-wide: a CA-side
`revoked_fingerprints()` export accessor, and a member-side
`set_revoked(&[String])` ingest. Per K2 the consumer is unnamed here.

Evaluating the wishlist against the code surfaced a deeper truth: **the wishlist is a
bug report about delight.** The consumer did not actually want those APIs — they wanted
*"when I untrust a node, that untrust is real everywhere."* They reached for a bespoke
revocation-distribution plane only because the delightful path either did not exist or
was not reachable. The operator articulated the principle the substrate had drifted from:

> You fire up something — quick, uncomplicated setup. And you're *done*. You never have
> to bother about it again, unless you *want* to know what happened.

Delight for a trust substrate is not a great dashboard (making someone *watch* is just
another way of demanding their attention). It is **earning a place in the operator's
"don't think about it" set and never falling out of it.** Attention is opt-in in *both*
directions: you opt in once, cheaply, at setup; after that the substrate goes quiet
*because it is handling things, not because it is hiding them* — and the proof of that
difference is that you can always open a window (`diagnose`, logs, the dashboard) and get
the whole story. The window is **pull**. It never pushes.

Three concrete deviations from that principle produced the wishlist:

1. **A real defect (the gap).** A joined member already pulls and verifies the CA's
   signed trust bundle on its role loop, but `pull_trust_bundle` read the bundle's
   `revoked` set *only* to check whether **this** node was revoked. It discarded the
   cross-member revocations. `revoked_fingerprints()` (which feeds `verify`/`open`) sourced
   purely from the local roster — empty on a pure member. So a member's `verify()` never
   rejected envelopes from *other* revoked members. Revocation was effective only on the CA.

2. **An opt-in trap.** Honoring revocations — a *safety* property — was bundled, behind a
   default-off `certmesh_background` opt-in (embedded), together with cert renewal, CA
   self-leaf re-issue, and the approval pump. To get the safety a consumer had to discover
   a flag and adopt the lifecycle machinery. Being a member did **not** mean being a
   well-behaved, self-managing member.

3. **A doc that lied.** The role-loop's own comment claimed it *"pick[s] up revocations."*
   It did not. A consumer reading Koi's docs reasonably believed propagation already worked.

Koi already embodies the delight principle where it is at its best: a member silently
self-heals its on-disk CA anchor on every pull, and rotates its own leaf before expiry —
both invisible, both self-correcting, neither requiring operator action. Revocation,
self-stand-down, and the membership default are simply where Koi forgot its own DNA.

---

## Decision

Make trust **self-managing by virtue of membership**, with attention opt-in both ways.
Capability is configured; membership is observed; management is intrinsic to membership;
observability is pull-only.

### 1. Membership is an observable runtime fact — `is_certmesh_member()`

The thing that should gate self-management was never a config flag; it is the runtime
fact of *being a member*. Expose it as a cheap public predicate on `CertmeshCore`:

```rust
/// Whether this node is an active member of a certificate mesh — it holds a usable
/// CA-anchored identity (created a CA, or joined one). A cheap filesystem check
/// (no lock, no network) — the same fact as `posture().signed`.
pub fn is_certmesh_member(&self) -> bool;
```

This is the supported predicate for a **"membership = enforcement"** consumer: gate
enforcement on `is_certmesh_member()` — permissive when `false` (an Open node), require
authenticated envelopes when `true`. Koi keys its *own* self-management on the same fact,
so one cheap check serves both the substrate and the consumer. Unlike the wishlist's
rejected accessors, this is vocabulary-neutral and genuinely load-bearing.

### 2. Self-management is intrinsic to membership (default-on, opt-*out*)

`certmesh(true)` enables the *capability* (passive: status, methods). Whether the node is
a member is then a runtime fact, transitioned only by a deliberate act (`create` / `join`).
A member self-manages by default: it keeps its revocation view fresh, renews its leaf, and
stands down if revoked. The role loop is a no-op until membership appears, so it
self-activates on join with no operator re-engagement and no surprise egress (egress begins
only once you are a member — a state you reached on purpose).

- The **daemon** already did this (`spawn_certmesh_loops` defaults on); unchanged.
- **Embedded** flips to match: the opt-in `certmesh_background(bool)` (default off) is
  replaced by an opt-*out* `certmesh_managed(bool)` (default **on**). The escape hatch is
  for the rare embedder that drives its own lifecycle over its own plane (see §4) —
  `certmesh_managed(false)` — not the default a consumer must discover to be safe.

### 3. A member applies cross-member revocations (the gap, fixed)

`pull_trust_bundle` now applies the bundle's **full** revoked set into a persisted
member-side store that `revoked_fingerprints()` unions in — so a pure member's
`verify`/`open` rejects *other* revoked members, not just itself. Four correctness
requirements (each a real trap):

- **(a) Apply on every verified bundle, including an unchanged `seq`** — mirroring the
  anchor self-heal that runs before the seq short-circuit — so a member already at the
  current seq still materializes the set (the one-time migration / stall case).
- **(b) Collect fingerprints from *both* projections** — `revoked[].cert_fingerprint`
  (`#[serde(default)]`, may be empty) **and** `members[status == "revoked"].cert_fingerprint`
  (always carries the fingerprint). `is_revoked()` is hostname-keyed and unusable here.
- **(c) Full-replace, persisted in one atomic write.** Each accepted bundle is the full
  authoritative projection, so full-replace also clears an un-revoked entry. Safe because
  the existing monotonic `last_bundle_seq` floor already rejects an older/smaller set
  (`bundle::verify` errors before any apply). Store the set in `member.json` alongside
  `last_bundle_seq` so the floor can never advance without the data.

### 4. The seam for self-drivers is the *signed bundle*, never a bare list

A consumer that carries trust over its **own** transport (one plane, no dependency on the
CA's HTTP port) gets a public ingest seam that keeps Koi owning verification:

```rust
/// Verify (pin + ES256 + anti-rollback) and apply a trust bundle the caller obtained
/// over its own transport. The verify+persist core of `pull_trust_bundle`, minus the fetch.
pub async fn apply_trust_bundle(&self, signed: &bundle::SignedBundle)
    -> Result<BundleOutcome, CertmeshError>;
```

`pull_trust_bundle` becomes *fetch → `apply_trust_bundle`*. The wishlist's
`set_revoked(&[String])` is **rejected**: it would be the first unauthenticated mutation
of a Koi trust decision — `verify_envelope` trusts the revoked slice with zero provenance,
making a bare-list ingest a dual **DoS** (inject the CA's own fingerprint → brick the
control plane) and **suppression** (a stale/empty full-replace silently un-revokes a
compromised node) primitive, replicated into every consumer. Ingesting the *signed bundle*
preserves the CA-signature binding and the monotonic anti-rollback floor.

### 5. A revoked node stands itself down (outbound self-gate)

When a node observes its own leaf in the mesh's revoked set, `sign()` and `seal()` stop
minting **authenticated** envelopes and degrade to the Open/unsigned passthrough (a loud,
one-time warning). This closes the hostile-/stale-node window from the *outbound* side that
propagation alone cannot: a revoked node can no longer assert an authenticated identity even
to peers that have not yet pulled the revocation. It is bounded — the node does **not**
delete its on-disk leaf (operator's call) and the process does not exit; it simply stops
claiming an identity. `is_self_revoked()` is exposed for consumers and `diagnose` flags it.

### 6. Observability is pull-only

Untrust is never a push that demands action. The lifecycle is already eventful
(`BundleUpdated { self_revoked }`, `MemberRevoked`, `CertRenewed`), and the story is always
available on demand — `koi trust diagnose`, the audit log, the dashboard. The substrate
never makes "watch me" the operator's job.

---

## Consequences

- **Delight restored.** Enable the capability, join once, done. A member honors mesh
  revocations, renews itself, and stands down if revoked — with no second flag, no
  reachability homework, and no "did it propagate?" anxiety. The window
  (`diagnose`/logs/dashboard) is there if you ever want it.
- **The wishlist dissolves.** The consumer needs neither `revoked_fingerprints()` export nor
  `set_revoked()`: a managed member gets fleet-wide untrust intrinsically; a self-driver uses
  `apply_trust_bundle(&SignedBundle)` on its own plane and cadence.
- **Breaking change (embedded only).** `Builder::certmesh_background(bool)` is removed;
  `Builder::certmesh_managed(bool)` replaces it with an inverted default (**on**). An embedded
  consumer that enabled `certmesh` and drives its own renewal must now call
  `.certmesh_managed(false)` to keep driving — otherwise Koi's role loop runs (it would pull
  the bundle from, and renew against, the CA's ports). The daemon is unchanged. Recorded in
  `CHANGELOG` and `upgrading.md` for the next minor.
- **`member.json` gains `revoked_fingerprints: Vec<String>`** (`#[serde(default)]`,
  back-compatible). One-time materialization on the next verified pull after upgrade.
- **Self-gating is the right aggression.** A node self-revokes only on a CA-signed,
  anti-rollback bundle, so a false positive requires a genuine operator revocation (undone by
  re-enrollment). A revoked node *should* stand down.

---

## Rejected alternatives

- **`revoked_fingerprints()` public export accessor** — redundant and weaker. The signed
  trust bundle already is the authoritative, CA-signed, monotonic, pin-self-verifying CRL; a
  CA-side caller that wants a bare list projects `bundle.revoked[].cert_fingerprint`. Promoting
  the private, best-effort, roster-derived accessor would canonize an empty-on-member footgun.
- **`set_revoked(&[String])` ingest** — see §4: an unauthenticated mutation of a trust
  decision; disqualified regardless of how carefully a consumer verifies.
- **Always-on with no opt-out** — would break a self-driving consumer at runtime (double
  renewal cadence + a CA-port reachability dependency it never provisioned). The opt-out is the
  deliberate exception, not the default.
- **Auto-deleting a revoked node's leaf / exiting the process** — out of scope; standing down
  the identity is sufficient and reversible (the operator owns disk + process lifecycle).

---

## STACK-0001 alignment

No consumer is named or special-cased; every new name (`is_certmesh_member`,
`certmesh_managed`, `apply_trust_bundle`, `is_self_revoked`) is vocabulary-neutral. The
revocation path signs/verifies with the CA's P-256 key, not HKDF, so the frozen K3
domain-separation labels are untouched. The contract surface (mdns/dns/certmesh/udp/truststore)
is unchanged in shape — this ADR finishes a behavior already promised by the trust-bundle
contract.
