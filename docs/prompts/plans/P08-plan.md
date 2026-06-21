# P08 — Certmesh Diet — Plan

> Branch: `dev` (autonomous run). Verify after each item: `cargo check` then, before the
> final commit of the prompt, full `cargo test && cargo clippy -- -D warnings && cargo fmt --check`.
> Research evidence: the `p08-certmesh-diet-research` workflow (8 agents) — full per-item
> deletions + blast radius archived in the run transcript. Baseline: **18,698** crate src
> lines (14,019 excl tests); wordlist alone is 7,784.

## Goal

18.6k → ~9k crate src (excl tests) with **zero loss of the killer loop**
(create / TOTP join / renew / unlock / backup / restore / revoke / manual promote).
Removing the wordlist alone lands excl-test src ≈ 6.3k, so the LOC target is easily met —
the real work is removing unneeded *surface/complexity* correctly.

## Killer-loop tests that MUST survive unmodified

init_* ceremony tests, join_collects_code_then_verification, unlock_collects_passphrase_then_completes,
renew_all_due_*, receive_renewal_*, promote_returns_encrypted_material,
promote_response_can_be_accepted_with_dh, auto_unlock_key_round_trips_through_vault.
(accept_roster_sync / ca_announcement / failover / tiebreaker tests are DELETED with their features.)

## Ordered execution (one commit per item)

1. **wordlist → include_str! + LazyLock** — DONE (7784→31; entropy.rs unchanged via deref). ✓
2. **FIDO2, all three layers.** koi-crypto/auth.rs (Fido2Credential, Fido2Adapter,
   store_fido2, verify_fido2_signature, AuthState/Challenge/Response/Setup::Fido2 + tests);
   unlock_slots.rs (UnlockSlot::Fido2 + 6 methods + Fido2SlotInfo + derive_fido2_storage_key
   + tests); koi-certmesh/lib.rs unlock_with_fido2 + rotate_auth FIDO2 arm; pond_ceremony.rs
   token-select/registration/unlock FIDO2 branches; ceremony_cli.rs InputType::Fido2 bail;
   koi-common/ceremony.rs InputType::Fido2 + Prompt::fido2; the `fido2-unlock` feature.
   Blast: AuthState::Fido2 match arms (failover.rs:69, lib.rs backup, commands/certmesh.rs);
   adapter_for/available_methods/adapter_by_name → TOTP-only; remove p256 dep if unused;
   sha2 stays (TOTP uses it); ADR-012 §7.2/§7.5 note the removal. **AuthAdapter trait STAYS.**
3. **Automatic failover → manual promotion.** DELETE in koi-compose/certmesh.rs the
   roster-sync loop + failover-detection loop (→ spawn 2 loops: renewal + heartbeat).
   DELETE in failover.rs: should_promote, tiebreaker_wins, find_active_primary,
   FAILOVER_GRACE_SECS, ROSTER_SYNC_INTERVAL_SECS, build_signed_manifest, verify_manifest +
   their tests. DELETE in lib.rs: standby_hostnames, accept_roster_sync, ca_announcement +
   their tests. DELETE protocol RosterManifest; koi-client get_roster_manifest.
   **KEEP:** prepare_promotion/accept_promotion + X25519 + tests, promote_self_to_primary/
   demote_self_to_standby, node_role, CERTMESH_SERVICE_TYPE, MemberRole::Standby, renewal +
   heartbeat loops, health_heartbeat. Update P07 parity test (4 loops → 2).
4. **Compliance endpoint + CLI.** http.rs paths::COMPLIANCE + route + compliance_handler +
   utoipa; protocol PolicySummary + ComplianceResponse; cli.rs Compliance variant; dispatch
   arm; commands/certmesh.rs compliance(); surface CommandDef + see_also refs; docs
   (certmesh.md, cli.md, http-api.md); integration.ps1 case.
5. **Trust-profile flattening (riskiest).** Delete TrustProfile enum/impl. Roster stores
   `enrollment_open: bool` + `requires_approval: bool` (serde `default`). Presets
   (Just Me / My Team / My Org → bool tuples) live in ceremony/CLI UX only. Delete the
   Option-dance fallbacks, enrollment deadline + CIDR scope (open-enrollment→toggle,
   set-policy removed), enrollment scope validators. Auto-unlock becomes ceremony-driven.
6. **Facade: CertmeshCore::create().** Move the 230-line create_handler orchestration into
   `CertmeshCore::create(req) -> Result<CreateCaResponse, CertmeshError>`; handler ≤30-line
   delegate. (Other fat handlers — set_hook/promote/renew/health — left unless trivial.)
7. **Mechanical dedup.** One `persist_roster(&Roster, &Path) -> Result<(), CertmeshError>`
   (spawn_blocking + clone + save inside) replacing ~19 copies — callers keep their error
   policy via `?` vs `let _ =`/warn. HOOK_FORBIDDEN once (lib.rs) with the superset
   validation incl. absolute-path check; http.rs delegates. Split eval_init (≤842) into
   per-step fns ≤50 lines.
8. **Sweep.** Dead protocol/error variants, tests of deleted features; guides
   (certmesh.md loses failover-automation + compliance; gains "what certmesh deliberately
   does not do" incl. CRL/OCSP absence); catalog + OpenAPI regenerate truthfully.

## Autonomous decisions (→ divergence log)

- **D1 Heartbeat KEPT.** The prompt lists only absence-watcher/tiebreaker/roster-sync for
  deletion; the heartbeat loop is orthogonal member-trust validation. `spawn_certmesh_background_tasks`
  4→2 loops; P07 parity inventory test updated 4→2.
- **D2 Status wire change.** `CertmeshStatus.profile` (enum) → `enrollment_open` +
  `requires_approval` bools. Pre-1.0 breaking; dashboard `CertmeshDetail` updated;
  CHANGELOG notes it.
- **D3 persist_roster policy.** One helper owning the spawn_blocking+clone+save mechanics,
  returning `Result`; each caller keeps its policy (`?` for core mutations, `let _=`/warn
  for telemetry like heartbeat last_seen). Avoids forcing one error policy on every site.
- **D4 Policy surface.** open-enrollment loses the deadline (opens indefinitely);
  set-policy (CIDR/domain scope) removed; enrollment scope validators deleted.
- **D5 ApprovalDecider.** signature `TrustProfile` → `requires_approval: bool`; koi-compose
  + the P07 approval tests updated in lockstep.
- **D6 ca_announcement deleted.** It was failover-only; the CA no longer auto-announces via
  mDNS. Manual `promote` is unaffected.
- **D7 Roster format break.** Existing roster.json files written with `trust_profile` may
  need `koi certmesh create` re-run (pre-1.0, no migration shims per charter). New bool
  fields are `#[serde(default)]` for forward-tolerance; documented as breaking.

## Risks

- Item 5 is the blast-radius hotspot (protocol, ceremony, CLI, http, dashboard, koi-compose,
  enrollment validators). Do it as its own commit, `cargo test` before moving on.
- Items 5↔6 interact (CreateCaRequest shape). Do 5 before 6 per the prompt; 6 then moves the
  already-flattened logic into the facade.
