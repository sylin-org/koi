# Koi — continuation prompt for a clean-slate session

You are continuing Koi (LAN connectivity substrate, Rust) toward stable 1.0.
Read FIRST, in order — then re-verify every premise against the tree (RL-11):

1. `SESSION-HANDOFF.md` — canonical ledger; trust it over this file where they
   diverge. The top paragraphs (W4 STATE AT HANDOFF, MESH DISCOVERY FACTS, MDNS
   RECEPTION VERDICT, WORKBENCH ARCS, REAL-INSTALL MESH CUTOVER) are tonight's.
2. `docs/lessons-learned.md` — RL-1..RL-13. RL-12 (test machines run the real
   installer), RL-13 (per-machine credentials), and RL-5 (payloads cross shells
   as files — you WILL be tempted to inline-quote again) are tonight's.
3. `docs/adr/032` (Windows parity, gates stable 1.0), `033` (koi-desktop
   workbench), `030` (adaptive mDNS, amended with the Windows measurement).
4. `local/NOTES.md` (untracked) — credential locations. `docs/MEMORY.md` —
   pointer index.

## Verified state (2026-08-25 ~04:45 local)

- Branches `dev` == `main` == `1c7efe4` on both repos; tree clean; pushed.
  - koi: query-burst endpoint + `koi mdns ping` (7abe320), ADR-033 + ADR-031
    amendment (619a2fb), heartbeat-touch meta-browse fix + ADR-030 Windows
    measurement (a6365be), mesh-mdns-enable script + garden-mDNS facts
    (59b7b16), W4 scenario code + per-run pipe name (e0a57aa), catalog grant
    windows mutations ["scm","firewall"] (1c7efe4).
  - koi-desktop (github.com/sylin-org/koi-desktop): Ghostlight stylesheet,
    lampband nav, Status/Discover/DNS/About panes, Rust-owned transport,
    event-driven lamp, Ping-the-pond, truthful stream state (704286e).
- Standing mesh: brook + granite run REAL `koi install` services (rc.2-era
  binary from the Aug 24 cutover); roster 3/3 via certmesh. **brook and
  granite do NOT announce mDNS** — the operator's `zen-garden.conf` owns
  resolved's mDNS on both; koi skips per ADR-030 (info-level, by design).
  Workstation: koi service (rc.2+ tonight's build) RUNNING, receives mDNS.
- **Locks are HELD** on both Linux nodes by run `v1-20260825T125244Z-879cc67a`
  (deploy succeeded there; a fresh musl artifact is staged under it). The
  scenario step refused because the catalog grant wasn't committed yet — it
  is now.

## THE exact next task: W4 physical run (ADR-032 row → green)

From an **elevated** shell in the repo (UAC one-shot pattern; the operator
approves the prompt):

```
cargo run -p koi-lab --locked -- certmesh-lifecycle-windows-ca --run-id v1-20260825T125244Z-879cc67a --member brook --allow-system-mutation
```

Before firing: verify the staged artifact is the fresh rc.2 build, not the
stale rc.1 one —
`ssh brook: cat koi-test/runs/v1-20260825T125244Z-879cc67a/artifact.sha256`
and confirm the sha is NOT `f9c3847c…` (that was the stale rc.1 reuse; the
fresh build replaced it — if it IS f9c3847c, instead run `.tmp/w4-run.ps1`
elevated, which stops the service, rebuilds, restores, redeploys with proper
run-id propagation, and runs the scenario).

Expected: JSON report with checks — wrong_pin_refusal_before_keygen,
member_join_local_custody (0600), ca_roster_contains_member,
renewal_rotates_identity_and_converges, revocation_pull_red (self_revocation),
renewal_and_rejoin_refused_identity_immutable, run_owned_cleanup. On green:
mark ADR-032 W4 row green (docs/adr/032 matrix), add the ledger paragraph,
`koi-lab cleanup --run-id v1-20260825T125244Z-879cc67a` (releases locks),
commit, push dev+main. On failure: the transcript is `.tmp/w4-run.log`;
diagnose before rerunning; `koi-lab cleanup --run-id <id>` recovers locks.

## Constraints (standing, unchanged)

- External publication/posts: operator-only. You draft, never post.
- Elevation + `--allow-system-mutation` for any workstation mutation; catalog
  grants are enforced (windows now ["scm","firewall"] — operator-approved).
- Workstations are daily drivers: run-scoped, preflighted, exactly restored.
- Full gates per landing: fmt, clippy -D warnings (--all-targets
  --all-features), locked workspace tests, audit. Commit per slice; push
  dev+main; clean tree before lab deploys.
- Credentials: brook/granite via DPAPI blob
  (`%LOCALAPPDATA%\Koi\lab-scheduler\lab-password.dpapi` → KOI_LAB_PASSWORD);
  test-01 is test/test → KOI_TEST01_PASSWORD (disposable, operator-sanctioned;
  see local/NOTES.md). Never commit values.
- Scratch lives in repo-local `.tmp/` (gitignored) — never %TEMP%, never the
  OS. The workbench debug sink follows the same rule.
- Stable 1.0 gate = ADR-032 matrix all green + extended full profile + clean
  soak incl. Windows participants. rc.3 only if findings force it.

## Queue after W4

1. Stale firewall-rule cleanup list for operator approval (dozens of dead
   `udp-*`/`koi_proxy-*`/old-path rules on this workstation).
2. Tickets: surface the daemon's firewall warning for unelevated `Run once`
   (W5); `dns/lookup` vs `dns/entries` normalization mismatch.
3. Next workbench pane in value order (health checks, then webhook sinks —
   sink CRUD needs a daemon-side API ticket first).
4. W5–W9+W12 breadth, W10 recovery, then extended full profile + soak.

## Do not

- Do not republish rc.1/rc.2 versions (registries immutable; RL-2).
- Do not touch the garden's `zen-garden.conf` on brook/granite (operator
  decision pending; mesh-mdns-enable.sh documents the conflict).
- Do not run the W1 lane or W4 while a koi daemon/service is running on this
  workstation (they refuse; that refusal is correct — stop the standing thing
  deliberately and restore it after).
- Do not parse CLI tables for assertions; use JSON/HTTP surfaces.
- Do not widen catalog grants or add system mutations without operator say-so.
