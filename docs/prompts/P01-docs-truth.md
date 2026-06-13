# P01 — Docs Truth Pass

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: M · Prereqs: none · Read `docs/prompts/CHARTER.md` first and follow its
> session protocol (research → written plan → implement → verify).

> **Status note (2026-06):** the entry points were already reworked — README.md,
> GUIDE.md, CONTRIBUTING.md, the CONTAINERS.md banner + binding fix, and
> `docs/reference/security-model.md` now exist and tell the truth. Your remaining
> scope is the **deep sweep**: the nine `docs/guides/*` (e.g. mdns.md's CORS claim,
> system.md's factory-reset contradiction), `docs/reference/*` (envelope-encryption
> crypto claims, architecture.md sizes, http-api.md auth/UDP section), `.agentic/`
> drift, and the ADR hygiene items. Verify the entry points only briefly; don't
> rewrite them.

## Mission

Make every user-facing document describe the binary as it actually ships. A verified
audit (docs/assessment/findings/verification-2026-06.md) found the primary onboarding
docs describe a pre-security-overhaul product: examples that 401, container claims that
are false, reference docs contradicting the code's cryptography. You are not changing
behavior in this session — you are making the documentation honest, and writing the one
missing page (the security model) that everything else can reference.

## Load context first

1. `docs/prompts/CHARTER.md`
2. `docs/assessment/findings/verification-2026-06.md` — claims 2, 3, 8, 13 are your
   work list; treat its file:line citations as leads, then re-verify each against
   current code yourself.
3. Ground truth to verify: `crates/koi/src/adapters/http.rs` (bind address ~line 238,
   DAT middleware ~455–495, CORS ~230), `crates/koi-certmesh/src/ca.rs` (lifetimes),
   `crates/koi-crypto/src/keys.rs` (algorithm), `crates/koi/src/commands/factory_reset.rs`,
   `Cargo.toml` (rust-version), `crates/koi-certmesh/src/profiles.rs`.

## Research phase

For each doc you touch, diff its claims against code. Build a findings table in your
plan file: doc, line, claim, code reality, fix. Known confirmed instances you must
cover (re-verify, don't trust blindly):

- `CONTAINERS.md:31` claims 0.0.0.0 binding; code binds 127.0.0.1 only.
- `README.md:34` and CONTAINERS.md show tokenless POSTs; all non-GET requires
  `x-koi-token`. `docs/reference/http-api.md` never mentions auth and misstates CORS.
- `docs/reference/envelope-encryption.md` claims Ed25519 CA + 90-day certs; code is
  ECDSA P-256 + 30-day.
- `docs/guides/system.md:100` claims factory-reset is unimplemented; it ships.
- `docs/reference/architecture.md` understates crate sizes ~4× and omits
  orchestrator.rs / integrations.rs / mtls.rs; dashboard/browser now live in koi-common.
- README claims Rust 1.75+; workspace pins 1.92.
- Trust-profile defaults told three different ways (certmesh.md vs
  ceremony-protocol.md vs profiles.rs) — profiles.rs wins; fix both docs and consider a
  unit-test-derived table.
- ADR hygiene: ADR-011 status `Proposed` though implemented; ADR-012 §Block-4 falsely
  says cross-domain imports "never existed" (git: they existed at 588b616, removed by
  aa979d4 — cite that); ADRs 001–010 carry pre-repo dates — add a one-line header:
  `> Retrospectively documented 2026-02-15; decision date approximate.`
  Fix the duplicated "### 7.7" in ADR-012.

## Target experience (north star)

A new page `docs/reference/security-model.md`, referenced from README, GUIDE,
CONTAINERS, http-api.md, mdns.md. Shape:

```markdown
# Networking & Security Model
## Listeners            — 127.0.0.1:5641 (HTTP), 0.0.0.0:5642 (mTLS, certmesh only)
## The daemon token     — what x-koi-token is, where the breadcrumb lives per-OS,
                          lifecycle (regenerated per start), which methods need it
## Worked example       — curl with token:
    TOKEN=$(jq -r .token "$KOI_BREADCRUMB_PATH")
    curl -X POST -H "x-koi-token: $TOKEN" http://localhost:5641/v1/mdns/announce -d '...'
## CORS policy          — localhost origins only (quote the actual code behavior)
## What is NOT protected — GETs are unauthenticated on loopback; implications
## Threat model         — what Koi defends against, what it explicitly does not
```

Every curl example in every doc either works as written against a fresh daemon, or sits
under a clearly-labeled "requires the daemon token (see security model)" with the token
header shown.

For CONTAINERS.md: do **not** invent a fix for the reachability gap (that is P03's
job). Quarantine honestly — a banner at top: current builds bind loopback-only;
container access via plain HTTP is broken pending `--http-bind` (link the assessment);
Docker-Desktop-only paths that still work may stay, labeled as such.

## Plan, then implement

Plan file per charter. Group commits: (1) security-model page + README/GUIDE,
(2) CONTAINERS.md quarantine, (3) reference-doc corrections, (4) ADR hygiene.

## Acceptance criteria

- [ ] `docs/reference/security-model.md` exists; ≥5 docs link to it.
- [ ] Zero tokenless mutation examples remain anywhere in docs/ or README
      (verify: grep for `curl -X POST` / `curl -X PUT` / `curl -X DELETE`).
- [ ] CONTAINERS.md carries the honesty banner; no 0.0.0.0 claim remains.
- [ ] envelope-encryption.md, system.md, architecture.md, README MSRV, profile tables
      all match code (cite file:line in commit messages).
- [ ] ADR-011 status corrected; ADR-012 Block-4 note corrected with commit hashes;
      ADRs 001–010 carry the retrospective header; duplicate §7.7 fixed.
- [ ] A drift guard exists: a unit test or CI grep asserting README's MSRV equals
      Cargo.toml's rust-version (cheap, prevents recurrence).

## Verification

`cargo test` (drift guard passes), manual grep sweep for the patterns above, and a
read-through of README top-to-bottom pretending you are a new user: every command you
could copy-paste must be true.

## Do NOT

- Change any runtime behavior, bind addresses, or auth (P03 owns that).
- Rewrite prose voice wholesale — surgical truth fixes; the writing quality is good.
- Touch docs/prior-art/ or docs/archive/ (relocation is a separate decision).
