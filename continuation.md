# Koi — continuation prompt for a clean-slate session

You are continuing Koi (LAN connectivity substrate, Rust) toward stable 1.0.
Read FIRST, in order — then re-verify every premise against the tree (RL-11):

1. `SESSION-HANDOFF.md` — canonical ledger; trust it over this file where they
   diverge. The top paragraphs (W10 GREEN — matrix complete, W12 GREEN,
   W8 GREEN + WindowsLabDaemon, W7 GREEN, W5 GREEN + browser-defect fix,
   W6+W9 GREEN, W4 GREEN) are the current arc.
2. `docs/lessons-learned.md` — RL-1..RL-16 stand; RL-17 (loud guards + the
   cleanup-then-redeploy retry protocol) and RL-18 (probe vs wired path;
   per-node port namespaces) were added during the W12 arc.
3. `docs/adr/032` — Windows parity matrix, GATES STABLE 1.0. Current state
   below; re-verify against the file.
4. `local/NOTES.md` (untracked) — credential locations. `docs/MEMORY.md` —
   pointer index. `docs/distribution-prior-art.md` + `docs/adr/034` — the
   distribution arc (ratified, partially implemented).

## Verified state (2026-08-27 ~17:10 local)

- Branches `dev` == `main` == `origin` at `c66d2f9` + the W12-landing commits
  (`fd2f7e5`, `bfab513`, `8315d40`), the W10 lane (`36c0ed4`), its cleanup fix
  (`1e75a19`), and the docs. Tree state: re-verify with `git status`.
- **ADR-032 matrix COMPLETE: every lane green (W11 excluded-by-tag).**
  - W1 SCM, W2 pipe, W3 trust, W4 Windows CA rotation, W5 mDNS both
    directions, W6 DNS serve, W7 TLS proxy dual-stack, W8 webhooks,
    W9 health cross-host, W10 backup/cold recovery (run
    `v1-20260827T205903Z-e6881df9`), W12 ACME dns-01 (run
    `v1-20260827T203030Z-2c5a7de8`).
- Standing mesh: brook + granite run REAL `koi install` services; test01 is
  the avahi-equipped workstation (W5 peer). Windows workstation (LEO-MAIN /
  stone-leaded-sparkle) at 192.168.1.137; standing koi service RUNNING.
- Locks: released (post-W10 cleanup green on all nodes).

## Status: the stable-1.0 gate is CLOSED (2026-08-28)

The active product surface now has its own continuation:
`sylin-org/koi-desktop/continuation.md` (cycle 1: the joyful instrument - WP0-WP9,
mobile access + QR, browser raw lens, trust pane). Read it FIRST for UI work.

## Status: the stable-1.0 gate is CLOSED (2026-08-28)

All three ADR-032 requirements are met: matrix complete; extended full profile
green twice (`v1-20260828T165112Z-f6a23b30` and post-soak
`v1-20260828T173654Z-770faf21`, 25/25 each); bounded soak clean
(`v1-20260828T173214Z-403b0fdd`, 20/20 iterations). The remaining steps are
OPERATOR-GATED release mechanics — do not start them unprompted:

1. Version bump rc.2 → 1.0.0 across the workspace (Cargo.toml workspace deps),
   tags; RL-2: registries are immutable — publication is one-shot.
2. SignPath review follow-up + `SIGNPATH_ENABLED` flip (ADR-034; application
   submitted 2026-08-25, review pending).
3. Landing page hosting on sylin.org; npm trusted publishers +
   `NPM_PUBLISH_ENABLED` (P-B, operator console actions).
4. P-D packaging channels fill at the stable release (homebrew/winget/AUR/
   scoop scaffolds under `packaging/`).
5. The Windows koi service is currently UNINSTALLED on this workstation
   (operator-approved for W1 in-profile) — `koi install` restores it.

## Runner / deploy discipline (unchanged, proven)

- Deploy-locks protocol: `deploy` acquires the locks with ITS run id; the
  scenario runs with that SAME run id; lab `cleanup --run-id <id>` releases
  them. After ANY failed attempt: full cleanup, fresh deploy, FRESH run id
  (RL-17b — a reused run id inherits stale run-scoped state).
- Elevated one-shot runner pattern: `.tmp/w10-run.ps1` (parameterized by
  `-RunId`: stop standing service → sweep orphans → scenario → restore
  service → transcript to `.tmp/*.log`).
- WindowsLabDaemon is the one owner for staging/paths/env/flags/log/kill;
  its `root()` is the PREFIX-STRIPPED path — cleanup APIs that compare paths
  by identity want the constructed `windows_member_dir(run_id)` instead
  (the exact defect `1e75a19` fixed).

## Environment notes (measured, important)

- **Disk**: Docker vhdx on E: (C: copy is a symlink). C: ~291 GB free,
  E: ~433 GB free. **The disk-cleanup sweep has now twice taken build
  artifacts from `target\`**: after any sweep, the musl artifact
  (`target\x86_64-unknown-linux-musl\release\koi`, via Docker/cross) AND the
  Windows release binary (`target\release\koi.exe`, via
  `cargo build --locked --release -p koi-net` — WindowsLabDaemon stages THIS
  file) must be rebuilt before any deploy/lane. A missing koi.exe surfaces as
  "could not stage the run-owned Windows member executable (os error 2)".
- **Toolchain**: musl builds go through Docker/cross (cross 0.2.5; no host
  musl-gcc by design).
- **Windows mDNS/verifier facts** (ADR-032 W5/W6): ICS holds 53 with reuse
  semantics; Resolve-DnsName has no -Port; nslookup sends ZERO packets for
  non-53 ports; SO_REUSEADDR vs non-reuse holder = WSAEACCES 10013; avahi
  tools want types without the `.local` suffix; dig exit 9 = "no servers
  could be reached" (wrong port or unreachability — check which namespace a
  port came from, RL-18b).
- **Lab discipline**: evidence-before-cleanup is doctrine — and it now WORKS:
  daemon-launch guards fail loud (exit 71, self-describing stderr, fd2f7e5).
  Scenario error-cleanup sweeps the Windows member dir (daemon.log with it);
  the error text is the retained evidence — read it before retrying.
  Per-machine credentials (RL-13): test01 = test/test, NEVER the lab password.
- **plink quoting from a session shell**: write probe/runner .ps1 files into
  `.tmp/` and run them with `pwsh -File`; inline one-liners with embedded
  quotes/globs break at the bash→pwsh→plink layer boundaries.

## Standing constraints (unchanged)

- External publication/posts: operator-only. Draft, never post.
- Elevation + `--allow-system-mutation` for any workstation mutation; catalog
  grants enforced (windows mutations: ["scm","firewall"]).
- Workstations are daily drivers: run-scoped, preflighted, exactly restored.
  The standing koi service must be stopped deliberately before lanes that
  need it, and restored after (runners do this).
- Full gates per landing: fmt, clippy -D warnings (--all-targets
  --all-features), locked workspace tests, audit. Commit per slice; push
  dev+main; clean tree before lab deploys.
- Credentials: brook/granite via DPAPI blob
  (`%LOCALAPPDATA%\Koi\lab-scheduler\lab-password.dpapi` → KOI_LAB_PASSWORD);
  test-01 is test/test → KOI_TEST01_PASSWORD (RL-13: never reuse the lab
  password for test01). Never commit values.
- Scratch lives in repo-local `.tmp/` (gitignored) — never %TEMP%, never
  outside the project folder.
- Stable 1.0 gate = ADR-032 matrix all green (DONE) + extended full profile +
  clean soak incl. Windows participants. rc.3 only if findings force it.

## Distribution arc (ADR-034, paused by operator — resume after 1.0 or on demand)

- Landed: ADR-034 ratified; landing-page draft (`site/`); npm carrier pattern
  implemented (packages/npm); SignPath repo prep — **application SUBMITTED
  2026-08-25, review pending**; P-D channel scaffolds in `packaging/` (fill at
  stable 1.0); koi-desktop autostart + --minimized landed.
- Operator actions pending: npm trusted publishers + NPM_PUBLISH_ENABLED;
  SignPath approval follow-up; landing page hosting on sylin.org.
- Deferred by operator: Tauri updater feed (keys + latest.json).
