# P08 — Certmesh Diet

> Paste this entire file as the task for a fresh agent session in the Koi repo.
> Size: L (commit per shed item; checkpoint freely) · Prereqs: P07 helpful (certmesh
> background tasks already relocated) · Read `docs/prompts/CHARTER.md` first.
> Deletion is the deliverable; pre-1.0, no migration paths, no deprecation shims.

## Mission

Certmesh is Koi's claimed invention and its best-tested code — and also ~45% of the
codebase, carrying an enterprise PKI's surface (FIDO2 in three layers, automatic
failover, compliance endpoints, enrollment windows, trust-profile indirection) for an
audience with no evidence of needing it. The killer loop — **create CA → TOTP join →
trusted certs → auto-renew → OS truststore install → encrypted backup → manual
promotion** — must survive untouched and better-factored. Everything else sheds.
Target: 18.6k → ~9k crate LOC with zero loss of the loop.

## Load context first

1. `docs/prompts/CHARTER.md`
2. `docs/assessment/findings/reader-certmesh-deep.md` (the full analysis — your shed
   list with file:line evidence) and `2026-06-maturity-assessment.md` §6 Tier 3
3. The crate: `crates/koi-certmesh/src/` (read lib.rs, http.rs, pond_ceremony.rs,
   failover.rs, profiles.rs, enrollment.rs at minimum), `koi-crypto/src/`
   (auth.rs, unlock_slots.rs), and binary-side `commands/certmesh.rs`, `ceremony_cli.rs`

## Research phase

Re-verify each shed item before deleting (the assessment verified the load-bearing
ones; spot-check the rest): FIDO2's CLI hard-bail (`ceremony_cli.rs:~277`), the
insecure-slot TODO (`unlock_slots.rs:~95`), zero external callers for
`unlock_with_totp`/`unlock_with_fido2`, `cert_lifetime_days()` returning 30 for every
profile, the compliance handler being status+line-count, HOOK_FORBIDDEN defined twice,
the ~12 clone-roster/spawn_blocking/save copies, `eval_init` spanning ~79–835. Check
every deletion's blast radius: protocol types, CLI subcommands, surface entries, HTTP
routes, OpenAPI, guides, koi-client methods, tests.

## The diet (each item = one commit, in this order)

1. **wordlist.rs (−7,784 lines):** replace the const array with
   `include_str!("eff_large_wordlist.txt")` parsed once via `LazyLock<Vec<&str>>`
   (only consumer: entropy.rs). Keep the test that asserts list length and a sample
   word.
2. **FIDO2, all three layers (−~500):** delete `Fido2Adapter`/`Fido2Credential`
   (koi-crypto/auth.rs), `UnlockSlot::Fido2` + unwrap path (unlock_slots.rs),
   `unlock_with_fido2`, protocol variants, ceremony branches, the `fido2-unlock`
   feature gate, and the `p256`/`ctap` deps if now unused. The `AuthAdapter` trait
   stays — that's the documented re-entry path. ADR note: add a line to ADR-012's
   deferred items pointing at this removal.
3. **Automatic failover → manual promotion (−~800):** keep
   `prepare_promotion`/`accept_promotion` and the X25519 transfer (good crypto, keep
   its tests); delete the mDNS absence-watcher, lexicographic tiebreaker, roster-sync
   background loop, and their wiring/protocol surface. `koi certmesh promote` remains
   the documented (manual) story; the guide explains why (30-day certs ⇒ a dead CA
   pauses renewals, it doesn't cause outages).
4. **Compliance endpoint + CLI (−~100):** delete `/v1/certmesh/compliance`,
   `koi certmesh compliance`, protocol types, catalog entry. `/status` and `/log`
   already carry the information.
5. **Trust-profile flattening (−~150):** profiles collapse to the two real booleans
   (`enrollment_open`, `requires_approval`) with named presets in the *ceremony UX
   only* (the wizard can still say "Just me / My team / My organization" — presets
   map to booleans; the roster stores booleans). Delete the Option-dance fallbacks.
6. **Facade restoration:** move CA-creation orchestration from the 230-line HTTP
   `create_handler` into `CertmeshCore::create(req) -> Result<CreateCaResponse>`;
   the handler becomes a thin delegate (the project's own rule). Same for any other
   handler carrying domain logic.
7. **Mechanical dedup:** one `persist_roster()` helper replacing the ~12 copies (pick
   one consistent save-failure policy and document it); HOOK_FORBIDDEN defined once
   with the superset validation (absolute-path check included); split `eval_init`
   into per-step functions ≤50 lines each, matching how join/invite/unlock already
   look.
8. **Sweep:** delete now-dead protocol variants, error variants, tests of deleted
   features; update guides (certmesh.md loses failover-automation and compliance
   sections, gains a "what certmesh deliberately does not do" honesty section — CRL/
   OCSP absence included, per the assessment's revocation finding); catalog + OpenAPI
   regenerate truthfully.

## Target UX after the diet

```console
$ koi certmesh create            # wizard: pond name, preset→booleans, passphrase, TOTP
$ koi certmesh join              # TOTP ceremony, cert lands, truststore installed
$ koi certmesh status            # CA, members, expiries, enrollment open/closed
$ koi certmesh promote <host>    # manual, deliberate, documented
$ koi certmesh backup|restore|revoke|destroy|unlock|set-hook|rotate-auth|log
# gone: compliance, open/close-enrollment-with-deadlines*, set-policy scope CIDRs*
#   (*fold open/close into a simple toggle if the booleans flattening makes them trivial —
#    decide in plan; keep if they're one-line wrappers)
```

## Acceptance criteria

- [ ] Crate src (excl. tests) ≤ ~9k lines; report before/after per item.
- [ ] The killer-loop tests all pass unmodified (create/join/renew/unlock/backup/
      restore/revoke/promote-manual); 263-test count may shrink only by deleted-feature
      tests.
- [ ] Zero `fido2`/`Fido2` identifiers outside ADR/assessment docs; zero compliance
      endpoints; failover background tasks gone while `promote` works.
- [ ] `CertmeshCore::create()` exists; create_handler ≤ ~30 lines; no HTTP handler in
      the crate contains domain orchestration.
- [ ] One persist helper, one HOOK_FORBIDDEN, no function over ~80 lines in
      pond_ceremony.rs.
- [ ] Guides/catalog/OpenAPI truthful; `koi certmesh <deleted-cmd>` is a clap error,
      not a runtime bail.
- [ ] Workspace green: `cargo test && cargo clippy -- -D warnings && cargo fmt --check`.

## Do NOT

- Touch the unlock-slot envelope-encryption design (minus the FIDO2 slot), the TOTP
  ceremony, the X25519 transfer, koi-truststore, or the audit log format.
- Add anything (the ACME facade is P12 — this session only removes and refactors).
- Keep deleted code behind feature flags "just in case" — git history is the archive.
