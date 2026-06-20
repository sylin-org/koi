# ADR-020: Mode-Transparent Trust Primitives (Posture-Adaptive Substrate API)

**Status:** Accepted (operator-ratified 2026-06-20)
**Date:** 2026-06-20
**Extends:** ADR-016 (Strategic Realignment — these are its named "primary surfaces" made ergonomic)
**Resolves / un-defers:** ADR-015 §"Scope and non-goals" (the parked *stack-wide dual-mode transport, same-port flip*) and ADR-016 §2 (the *startup-gated mTLS listener* fix)
**Builds on:** ADR-017 (trust ledger, CSR-only issuance, mTLS server/client), ADR-011 (port model), ADR-008 (embedded facade), ADR-003 (envelope encryption — the `seal/open` rung)
**Constrained by:** STACK-0001 (K2 consumer-neutrality, K3 frozen HKDF labels, D4 garden-mesh boundary, D7 contract surface)

---

## Context

A downstream consumer of `koi-embedded` (unnamed here per the D1 layering law) surfaced a request for **mode-transparent primitives**: one consumer code path that behaves correctly whether or not the node has a cryptographic identity, with the open-vs-secure branch living *inside* Koi rather than in every consumer. The stated acceptance criterion:

> If a consumer ever has to write `if secure { … } else { … }`, the primitive is missing or wrong.

This is not scope creep. **ADR-016 §2 already names Koi's primary surfaces as "identity custody, sign/verify, trust-resolution, posture (secure/non-secure), HTTPS-when-secure, and `.internal` certificate issuance,"** and declares "Koi provides primitives only." The request is for those exact surfaces, exposed as ergonomic, posture-adaptive primitives. ADR-016 §2 also flagged the bug this ADR's transport mechanism fixes: "the startup-gated mTLS/ACME listeners so the trust plane is live whenever the CA exists."

### What already exists (substrate audit, 2026-06-20)

A code-level audit confirms most of the substrate is built; the gaps are wrappers and one real transport feature:

| Capability | Status today | Location |
|---|---|---|
| ES256 sign / verify | **EXISTS** | `koi_crypto::signing::{sign_bytes,verify_signature}`; `bundle::{sign,verify}` (anti-rollback) |
| mTLS serve *any* axum router + `ClientCn` injection | **EXISTS** | `koi_certmesh::mtls::serve(Router, listener, config, cancel)`; `ClientCn` extension |
| mTLS client (CA-pinned, identity-loaded) | **PARTIAL** | `mtls::{build_client_config,post_json,get}` — no high-level `client_for` |
| Roster membership + revocation + expiry | **EXISTS** | `Roster::{is_enrolled,find_member,is_revoked}`; `RosterMember::cert_expires` |
| Group-key crypto blocks (AES-256-GCM, X25519, HKDF) | **EXISTS** | `koi_crypto::{keys,key_agreement}` (ADR-003) — no `seal/open` API |
| Posture booleans | **PARTIAL** | `CertmeshStatus{ca_initialized,ca_locked,enrollment_open,requires_approval}` — no derived enum |
| Embedded facade + custom-TXT announce | **EXISTS** | `koi-embedded` Builder → KoiHandle → handles; `RegisterPayload.txt` |
| Generic `Envelope` wire type / general freshness window | **ABSENT** | only `SignedBundle` (typed) + ACME nonce store |
| Single `ensure_identity` entrypoint / unified `Identity` type | **ABSENT** | enroll / self_enroll / renew_self_if_due orchestrated piecemeal in `koi-compose` |
| Typed `Peer` from discovery (fp/cn/posture) | **ABSENT** | only `ServiceRecord` + `txt: HashMap` |
| **Same-port open↔mTLS flip + rebind-on-posture-change** | **ABSENT** | HTTP (5641) and mTLS (5642) are separate fixed listeners spawned at boot |

**Conclusion:** ~70% of the request is wrapping existing substrate in a posture-aware facade; the genuinely new work is a generic signed `Envelope`, a `Posture` oracle, an `ensure_identity` lifecycle wrapper, typed peer discovery, the `seal/open` passthrough, and the one heavy item — the **same-port posture dial** (the transport ADR-015 deferred).

---

## Decision

### 1. The posture model — Koi-native vocabulary, not consumer "degree"

Koi's native term is **posture** (ADR-016 §2: "posture (secure/non-secure)"). We extend the single secure/non-secure bit into two orthogonal booleans, surfaced as one enum, in neutral security vocabulary:

```rust
// koi-common (types-only kernel; serde-stable wire type)
pub struct Posture { pub signed: bool, pub encrypted: bool }

pub enum PostureLevel {
    Open,           // { signed:false, encrypted:false } — no identity (today's "non-secure")
    Authenticated,  // { signed:true,  encrypted:false } — has identity; signs / mTLS (today's "secure")
    Confidential,   // { signed:true,  encrypted:true  } — + group-key confidentiality (the future rung)
}
```

This is **backward-compatible**: "secure" ≡ `signed: true`. The two booleans match the consumer's `{signed, encrypted}` request exactly, so a consumer may alias `PostureLevel` as its own "degree" in *its* layer — but the word **"degree" does not enter Koi**, and neither does "pond"/"open mode"/any consumer codename (K2).

The **oracle** (the one thing every primitive below consults):

```rust
fn posture(&self) -> Posture;                 // our node's posture (derived from CertmeshStatus)
fn posture_of(&self, peer: &Peer) -> Posture; // a discovered peer's advertised posture (a hint, see §8)
```

### 2. The mode-transparency contract (the binding discipline)

Every primitive in this ADR is **no-op-in-Open / real-in-secure**, and the switch is keyed off `posture()` *inside* the primitive. The consumer writes one code path. This is enforced by an **acceptance test** (the consumer's "one discipline"): a `koi-embedded` integration test runs an *identical* consumer code path twice — once against an Open daemon, once against an Authenticated (CA-initialized) daemon — and asserts both green. A primitive that requires the consumer to branch on posture fails this gate and is considered unfinished.

### 3. `sign` / `verify` + the `Envelope` wire type

```rust
// Envelope: koi-common (versioned, encryption-ready header)
pub struct Envelope { v, payload, nonce, ts, sig: Option<Sig> }   // sig absent in Open
pub struct Sig { alg, signature, signer_cn, serial }

// logic: koi-certmesh (needs the identity key + roster)
fn sign(&self, bytes: &[u8]) -> Envelope;          // Open: freshness-stamped passthrough; Authenticated: + ES256
fn verify(&self, env: &Envelope) -> Assurance;     // see below

pub enum Assurance {
    Anonymous { freshness: Freshness },              // Open: no identity claim (Fresh|Stale)
    Authenticated { cn: String, freshness: Freshness },// sig valid vs roster + not-revoked + not-expired
    Rejected { reason: RejectReason },               // distinct, named reasons (not one opaque error)
}
impl Assurance { pub fn identity(&self) -> Option<&str> { /* Some ONLY for Authenticated + Fresh */ } }
```

`verify` returns an **assurance level** (not a bool), so a consumer's authorization keys uniformly off "authenticated-as-CN vs. fresh-but-anonymous." **Misuse-resistance (libsodium/age "one success door" principle, §13):** there is exactly one way to extract an identity — `Assurance::identity()`, which returns `Some` *only* for the authenticated-and-fresh case — so the natural `if !rejected { trust }` cannot leak a `Stale` or anonymous message. `freshness` is a *sub-field*, so "authenticated" can't exist without a freshness verdict and "fresh" can't be read without an identity. **`RejectReason` is a named enum** (no-cert / wrong-CA / expired / clock-skew / revoked / name-mismatch / stale), never one opaque error (the Istio-503 lesson, §13). The general **replay/freshness window** defaults to **±300 s** (LAN clocks drift; NTP isn't guaranteed — §13) and reuses the ACME-nonce + bundle anti-rollback pattern. The Envelope's `v` (version) **selects the verification construction from a hard-coded table — never an envelope-declared `alg` field** (the JWT `alg:"none"` / algorithm-confusion class). Key custody is unchanged (ADR-015 F1 / ADR-017 P3): signing uses the member's local key; nothing new crosses the wire.

> **Transport-agnostic by construction.** `sign`/`verify` operate on bytes and know nothing of the carrier. A consumer may apply them to HTTP bodies, its *own* UDP gossip, anything. Koi never references the consumer's UDP mesh (D4): the primitive is generic; the application is the consumer's.

### 4. `seal` / `open` — the confidentiality rung, shipped as passthrough

```rust
fn seal(&self, bytes: &[u8]) -> Sealed;   // Open/Authenticated: signed-not-encrypted passthrough; Confidential: group-key encrypt
fn open(&self, s: &Sealed) -> Result<Vec<u8>>;
```

Ships **today as passthrough** (signed, not encrypted) so consumers code against the final API now; the encryption rung becomes a later Koi-internal upgrade with **zero consumer change**. The crypto blocks exist (AES-256-GCM + X25519 + HKDF, ADR-003).

**Silent passthrough is a built-in downgrade** (the STARTTLS/opportunistic-encryption antipattern, §13) and must be designed against:
- The `Sealed` type is **version-tagged** (`v0-passthrough` / `v1-groupkey`); `open` selects behavior from the version, never guesses. The version byte is part of the AEAD AAD once real sealing lands (else it's a malleable downgrade lever).
- Confidentiality is **type-level**, not vibes: `Sealed::confidentiality() -> Confidentiality::{None, GroupKey}` — passthrough can't be mistaken for encrypted. A `seal()` with no group key in passthrough emits a one-time `tracing::warn!` and the level surfaces as `seal: passthrough|groupkey` on `/v1/status` (observable downgrade, not silent).
- When v1 lands, `open` **refuses a v0 passthrough envelope unless the caller explicitly opts in** (anti-downgrade, small back-compat window).

**K3 compliance:** the new key derivation uses a *new*, distinct, versioned label namespace (e.g. `b"koi-seal-group-v1"`); the frozen `b"pond-unlock-slot-totp-v1"` / `b"pond-fido2-storage-key-v1"` labels are never touched or reused.

### 5. `serve` — the same-port posture dial (the un-deferred transport)

This delivers ADR-015's parked "dual-mode transport, same-port flip" and ADR-016 §2's "fix the startup-gated mTLS listener."

```rust
fn serve(&self, router: Router, port: u16, cancel: CancellationToken);
```

- **Open:** plain HTTP on `port`.
- **Authenticated/Confidential:** mTLS-HTTPS on the **same** `port`, injecting `ClientCn` (reuses `koi_certmesh::mtls::serve`).
- **On posture transition:** the same port **upgrades** plain↔mTLS — no daemon restart, **no dropped connections**.

Mechanism (new): a `tokio::sync::watch<Posture>` published by `CertmeshCore` (derived from existing CA create/unlock/lock/destroy events) drives a **listener supervisor** in `koi-embedded`. **Critically — this is Istio PERMISSIVE mode (§13), so the flip must not be a hard cutover:** during a transition the supervisor runs **dual acceptors on the one socket** (dispatch by TLS-ClientHello detection: plaintext vs. mTLS), and drains plaintext only after identity is confirmed live. A naive close-and-rebind would drop in-flight connections — the exact failure operators fear. The same posture-watch makes Koi's *own* mTLS listener posture-reactive, resolving ADR-016 §2's startup-gating bug. **Per-connection trust state is always loudly observable** (`plaintext | mTLS(cn=…)` on status/dashboard — a "padlock on the wire"); an operator must never `tcpdump` to learn whether traffic is encrypted.

**Port model interaction (sub-decision):** ADR-011's daemon control ports (5641 HTTP+DAT, 5642 mTLS, 5643 ACME) are **retained**; this ADR's dial governs (a) consumer-served routers passed to `serve`, and (b) makes the daemon's 5642 mTLS listener posture-reactive (start when the CA appears). **Collapsing 5641+5642 into one posture-adaptive control port** (DAT-token and mTLS-CN coexisting on one port) is a larger auth-coexistence question — flagged as an Open Question, not decided here.

### 6. `client_for` + `require_auth`

```rust
fn client_for(&self, peer: &Peer) -> Client;        // Open peer: plain http; secure peer: mTLS (our identity + that peer's pinned CA root)
fn require_auth(&self, min: Assurance) -> Layer;     // Open: pass; secure: require CN / signed envelope ≥ min, else 401 (+ optional CN/role hook)
```

`client_for` wraps the existing `mtls::build_client_config` + `post_json/get` into a high-level client that selects protocol and CA pin from the peer's advertised posture+fingerprint — the caller never attaches a cert or chooses http/https. `require_auth` is a no-op layer in Open and the existing `ClientCn`/envelope gate in secure mode; "which routes to gate" collapses to annotating writes once.

### 7. `ensure_identity` + a unified `Identity` type

```rust
pub struct Identity {
    hostname, cert_pem, key_pem, ca_cert_pem, ca_fingerprint,
    not_after,                       // expiry
    renewal_health: RenewalHealth,   // last attempt + outcome + consecutive_failures + next_renewal_at + renew_overdue
}
fn ensure_identity(&self) -> Option<Identity>;  // Open: None; secure: enroll-if-needed / renew-if-due → live identity
```

Composes the existing `self_enroll` / `enroll` / `renew_self_if_due` into one "keep my identity current" call (the orchestration that today lives step-by-step in `koi-compose`), and unifies the fragmented `SelfEnrollment` + `MemberState` into one `Identity`.

**Identity lifecycle must be loud, not silent** (every cert-lifecycle postmortem failed because renewal stopped silently — §13): renew at **2/3 of cert lifetime**, stored as a **percentage** (avoids the short-cert renewal-loop bug), floor 5 min; carry `renewal_health` (not just `not_after`) so a stuck renewal is visible *before* expiry; emit graduated `IdentityExpiringSoon` at **30 d / 14 d / 7 d / 24 h** *and* a louder `RenewalFailed` / `RenewalStuck` event on the **first** failed attempt (otherwise ~45 days of runway is wasted unseen). `ensure_identity`'s reload must verify the **live serving cert == newest issued cert** (the "new cert on disk, old still in memory" footgun, §13).

### 8. `discover` (posture-carrying) + `announce`

```rust
pub struct Peer { addr, posture: Posture, fp: Option<String>, cn: Option<String>, record: ServiceRecord }
fn discover(&self, ty: &str) -> impl Stream<Item = Peer>;
fn announce(&self, …);  // stamps fp= and posture= into the mDNS TXT in secure mode
```

Typed `Peer` (new) is parsed from `ServiceRecord.txt`; in secure posture Koi **stamps `fp=`/`posture=` into its own mDNS announcements** (within the existing mdns contract surface, D7). Per ADR-016 §2, **discovery announcements remain untrusted hints** — `posture_of(peer)` is advisory; trust is still adjudicated by `verify` against the roster ("ask Koi, don't trust the wire").

### 9. Published wire contract (the cross-sibling gap)

Version and publish, as a language-neutral spec under `docs/reference/`, the **`Envelope`**, the **`Posture` descriptor**, and the **same-port dual-mode handshake** so a non-Rust sibling can implement identical primitives. Per D7 + STACK-0001 line 12, **adding these as contracted surfaces is an architect decision** — ratifying this ADR authorizes it, and STACK-0001's D7 surface list should be amended to append: *envelope/posture descriptor + dual-mode transport*. (The existing five surfaces — mdns, dns, certmesh REST, udp bridging, truststore — are unchanged.)

### 10. The Koi / consumer layer line (what stays out)

Per ADR-016 §2 ("never grow a discovery/membership/mesh-gossip protocol; Koi provides primitives only") and D4:

- **Koi owns:** the primitives above (sign/verify, seal/open, serve/client_for, require_auth, ensure_identity, posture oracle, posture-carrying discover) — all transport-agnostic, all in neutral vocabulary.
- **The consumer owns:** the "degree" *naming*, any mesh/membership orchestration, the auto-flip of a whole fabric, and applying `sign()` to its **own** UDP-7184 gossip. Koi never names the consumer, never references UDP-7184, never defines a gossip protocol.

### 11. Crate placement

- `koi-common` — wire types only: `Envelope`, `Sig`, `Posture`, `PostureLevel`, `Sealed` (types-only kernel; serde round-trip tested).
- `koi-certmesh` — logic primitives: `sign`/`verify`/`Assurance`, `seal`/`open`, posture derivation, the posture `watch`, `client_for`, `require_auth`, and the mTLS serve config (extends the existing `mtls` module).
- `koi-embedded` — the ergonomic facade: `ensure_identity`, typed `discover`/`Peer`, and the posture-watching `serve` supervisor (rebind-on-transition). This is where the consumer's single code path lives.

### 12. Phasing

| Phase | Content | Size |
|---|---|---|
| **P1 — Posture + identity** ✅ landed | `Posture`/`PostureLevel` + the `posture()` oracle; unified `Identity` + `RenewalHealth` (derived schedule) + read-only `local_identity()`; idempotent `ensure_identity()`; embedded-facade passthroughs. (`client_for`/`PostureChanged`/`participate()` had forward deps → re-homed to P3/P4; the 2/3-% renewal trigger + graduated/first-failure events land with the renewal loop.) | S–M |
| **P2 — Envelope** | `Envelope` wire type + `sign`/`verify`/`Assurance` (one-identity-door, freshness sub-field, ±300 s window, version-selects-construction); `require_auth` | M |
| **P3 — Discovery + fleet legibility + client_for** | typed `Peer` + `discover` (carries `posture`/`expires_in`); `client_for(&peer)` (high-level plain/mTLS client keyed off the peer's posture+pin); `fp=`/`posture=`/`expires=` mDNS stamping; fleet-wide view | M |
| **P4 — Same-port dial + posture events** | dual-acceptor posture flip (no dropped connections) + loud per-connection state; posture `watch` + `KoiEvent::PostureChanged`; `participate()` one-liner; make daemon mTLS listener posture-reactive (fixes ADR-016 §2) | **L** |
| **P5 — `seal`/`open` passthrough** | version-tagged `Sealed` + type-level confidentiality + `/v1/status` `seal:` + anti-downgrade (new HKDF label) | S–M |
| **P6 — diagnose() + testkit + wire contract** | `diagnose()` (distinct reasons, clock-skew, renewal-health, per-store trust-install, non-zero-on-red, `--fix` LAN-trust propagation); `koi_embedded::testkit` + `#[koi::test]`; conformance vectors; the "same code, both postures" CI gate; STACK-0001 D7 amendment | M–L |
| **P7 — (stretch) deterministic simulator** | sans-IO + `proptest` LAN-trust state machine; doubles as Koi's own trust state-machine test backbone | M |

Each phase ships under the gate (`cargo test && cargo clippy -- -D warnings && cargo fmt --check`) and adds to the posture-transparency acceptance test.

### 13. DX & delight — grounded in prior-art research (2026-06-20)

Six "delight benchmark" lanes were researched against this design: **Tailscale** (zero-config networking), **Caddy / mkcert / step-ca** (auto-TLS + local CA), **Istio / Linkerd / SPIFFE** (transparent mTLS), **libsodium / age / Tink** (misuse-resistant crypto APIs), **certbot / cert-manager / JWT** (cert & token lifecycle), and **sans-IO / wiremock / sqlx::test / Wycheproof** (test harnesses & conformance vectors). Sources are listed in References.

**One finding dominates all six: the category's defining failure is *silence*, not ignorance.** Silent expiry (a documented certbot SEV-1: renewal failed silently for 45 days → 100 % outage, ~$12k), silent downgrade (Istio PERMISSIVE: "organizations believe they have mTLS when PERMISSIVE silently allows plaintext"), opaque failures (the Istio 503 "means a dozen things, the error itself tells you nothing"), and self-only diagnosis (Tailscale can't see a *peer's* expiry; `status` shows `-`, not "expired"). **Koi's delight differentiator is therefore transparency *of trust state*, not just of code: make the real per-connection / per-node / fleet-wide trust state always loud, queryable, and self-diagnosing.** The "for free" delight (mTLS/identity with no app changes) is *table stakes*; legibility is the moat.

**The same-port dial IS Istio PERMISSIVE mode** — the most-loved migration feature *and* the most-notorious footgun in the category. Non-negotiable rules it inherits (folded into §5): dual acceptors during the flip (no dropped connections); per-connection trust state always loudly observable (the "padlock on the wire"); `require_auth` as the antidote to "stuck in PERMISSIVE forever"; and **stay Linkerd-minimal, not Istio-complex** — few knobs, one identity primitive, secure-by-default, no policy matrix that can silently self-conflict (reaffirms ADR-016's shed of trust-profile indirection).

**`diagnose()` / trust-doctor — validated as essential by every lane.** It must:
- Return **distinct, named** failure reasons with **state + cause + exact remediation command** (`miette`-style actionable help) — never one opaque error (the Istio-503 lesson) — and the remedy must be runnable **remotely** (Tailscale's "can't re-auth over SSH" trap).
- **Measure local clock skew vs. peers** and surface it ("peer web-01 is ~3m behind; 4 Envelopes rejected for skew, not tampering") — the check certbot/cert-manager omit that burns everyone.
- Report **renewal health** (last attempt, outcome, consecutive failures, next-renewal, overdue), **live-cert == on-disk-cert**, and **per-store trust-install results** (system / NSS-Firefox / Java / Node = installed | skipped | failed | n/a — never an aggregate "success", the mkcert #182 bug).
- **Return a non-zero exit when anything is RED** — the meta-lesson: the tool itself must fail loud (certbot/cert-manager return success while broken).

**Fleet-wide trust legibility (the unclaimed delight — Tailscale's biggest gap).** `discover` returns each peer's `posture` + `identity_expires_in`; `diagnose` renders the whole mesh ("3 Confidential, 1 Authenticated, web-02 expires in 2 d"). Koi advertises `posture=` / `expires=` alongside the existing `fp=` in its mDNS TXT — turning the posture oracle into a gossiped network-wide trust map nobody else offers (announcements stay *untrusted hints* per ADR-016 §2; `verify` still adjudicates).

**LAN-trust propagation (a Koi-only superpower — Caddy/mkcert's universal unsolved gap).** Every auto-TLS tool installs the root on the issuing machine *only* ("not trusted from another device on the LAN"). Koi owns *both* discovery *and* `os-truststore` on every node: `koi trust accept <ca-fp>` (peer-side, fingerprint-pinned) / `koi trust diagnose --fix` installs the mesh root into a peer's OS + Firefox + Java + Node stores in one step. No incumbent can do this.

**Crypto API correctness (libsodium / age / Tink + the JWT footgun canon)** — folded into §3/§4: the `Assurance` one-identity-door (fixes the "negative-space" trap where `Stale`/anonymous leaks through `if !rejected`), version-selects-construction (no `alg:"none"` class), and `seal/open`'s version-tag + type-level confidentiality + anti-downgrade. The **±300 s** freshness default comes from this research: LAN clocks drift and NTP isn't guaranteed (60 s — Spring's default — would spuriously reject; .NET/PyJWT/Kerberos all cluster at 5 min), and `diagnose()` must *surface* the leeway (the .NET "hidden grace surprises people" lesson).

**Test & verification delight (sans-IO / wiremock / sqlx::test / Wycheproof)** — folded into P6/P7:
- `koi_embedded::testkit` — one-liner `testkit::open()/secured()` (wiremock model) + a `#[koi::test]` attribute injecting **both postures** into the test signature (sqlx::test model), making the "same code, both postures" acceptance test trivial. Ship as a separate crate/module, **not a `cfg(feature)`** (the additive-feature trap). The pitch: real-daemon fidelity **without Docker**.
- **Conformance vectors** follow the age/CCTV + Wycheproof model: **graded `expect` outcomes** (not pass/fail), a `flags` field, schema-first JSON grouped by attribute, round-trip + payload-hash coverage, a generator, identical files distributed per language, feature-skip for gradual sibling adoption.
- **Runtime posture stays a runtime value, not a typestate parameter.** Typestate (`Participant<Open|Secured>`) was considered but *rejected for the transparent surface* — it would force the consumer to know posture at compile time, defeating the one-code-path goal. Typestate is reserved for genuinely posture-exclusive operations. "Zero-cost in Open" is kept as an asserted, tested promise via sans-IO core design.

**`participate()` + posture events (Tailscale's `up`, plus the legibility it lacks)** — folded into P1: `participate()` (`ensure_identity` + `serve` + `announce` + renewal, maintained across flips/renewals/restarts) is the "3-line trusted service." `KoiEvent::PostureChanged { from, to }` makes the live upgrade observable, and the **degrade** direction (identity expiring, fell back to plaintext) must be as loud as the upgrade — exactly where Tailscale's silent expiry/relay-fallback loses people.

---

## Consequences

### Positive
- Delivers ADR-016's stated identity (the trust plane's primary surfaces) as the ergonomic API consumers actually need, without growing a mesh protocol.
- The mode-transparency *property* becomes a Koi guarantee (with a CI gate), not a pile of per-consumer flags.
- Resolves two parked items at once: ADR-015's deferred dual-mode transport and ADR-016 §2's startup-gated listener.
- `seal/open` as passthrough lets consumers code against the final confidential API today; the encryption rung lands later with zero consumer change.
- A published wire contract unblocks non-Rust siblings — mode-transparency stops being Rust-only.

### Negative
- The same-port dial (P4) is genuine new transport machinery (a posture watch + rebinding supervisor) and the riskiest phase; it touches listener lifecycle.
- Adds public surface to `koi-common`/`koi-certmesh`/`koi-embedded` (mitigated: types-only in the kernel; primitives are thin over existing substrate).
- Amends STACK-0001's D7 contract surface — a cross-repo canon change requiring the architect's sign-off.

### Risk mitigation
- The acceptance test (same consumer code green in Open and Authenticated) is the structural guard against re-introducing posture leaks.
- Key custody invariant (ADR-015 F1 / ADR-017 P3) is untouched — no new key ever crosses the wire.
- K3 frozen labels untouched; `seal/open` uses a new, distinct, versioned label namespace.
- P4 rebinds behind the existing `mtls::serve` + plain axum serve (both proven); the new part is only the supervisor + watch.

---

## Canon compliance (STACK-0001)

- **K2 (consumer-neutrality):** no consumer name or codename ("pond", "degree", garden/stone/etc.) enters Koi code, defaults, or doc-comments. Native vocabulary only: *posture / Open / Authenticated / Confidential / Assurance*.
- **K3 (frozen HKDF):** the two `b"pond-…-v1"` labels are never touched; `seal/open` introduces a separate `b"koi-seal-…-v1"` namespace.
- **D4 (garden-mesh boundary):** `sign`/`verify` are transport-agnostic; Koi never references UDP-7184. Applying signing to the consumer's gossip is the consumer's act.
- **D7 (contract surface):** this ADR *proposes* extending the surface (envelope/posture descriptor + dual-mode transport); ratification is the required architect decision. The TLS proxy remains excluded.

## Open questions
1. **Collapse 5641+5642** into one posture-adaptive control port (DAT-token ↔ mTLS-CN coexistence), or keep ADR-011's dual-port control plane? (Deferred; P4 only makes 5642 posture-reactive.)
2. **`posture=` / `expires=` TXT semantics** — advisory hints only (confirmed); do we also offer a *signed* posture attestation for peers that want more than a hint?
3. **Deterministic simulator (P7)** — ship as a consumer-facing tool, or keep it internal-only as Koi's test backbone? (The replay-window default is now decided: **±300 s**, §13.)

## References
- ADR-016 (trust plane; primary surfaces; startup-gating bug), ADR-015 (deferred dual-mode transport; key-custody invariant), ADR-017 (trust ledger, CSR-only issuance, mTLS server/client), ADR-011 (port model), ADR-008 (embedded facade), ADR-003 (envelope encryption).
- STACK-0001 (D1/K2 consumer-neutrality, K3 frozen labels, D4 garden mesh, D7 contract surface, line 12 architect-decision rule).
- Substrate audit 2026-06-20 (this session).
- **Prior-art / delight research 2026-06-20** (§13), developer-sentiment sources: Tailscale (how-tailscale-works; key-expiry UX bug tailscale#4854); Caddy automatic-HTTPS + trust-store gotchas (caddy#4248), mkcert design (Filippo) + partial-install bug (mkcert#182), step-ca renewal (2/3-lifetime); Istio PERMISSIVE false-security + opaque-503, Linkerd minimalism, SPIFFE/SPIRE clock-skew; libsodium secretbox / age / Tink (misuse-resistance), Latacora "cryptographic right answers", Paragonie "against agility", JWT `alg:none`; certbot silent-renewal SEV-1 + cert-manager renewal backoff (#6378) + JWT clock-skew defaults (.NET 300 s / Spring 60 s / Kerberos 5 min); sans-IO (Firezone), wiremock-rs, `#[sqlx::test]`, C2SP/CCTV (age) + Wycheproof conformance-vector models.
