# Koi — continuation prompt for a clean-slate session

You are continuing Koi (LAN connectivity substrate, Rust) toward stable 1.0.
Read FIRST, in order — then re-verify every premise against the tree (RL-11):

1. `SESSION-HANDOFF.md` — canonical ledger; trust it over this file where they
   diverge. The top paragraphs (W12 GREEN, W8 GREEN + WindowsLabDaemon,
   W7 GREEN, W5 GREEN + browser-defect fix, W6+W9 GREEN, W4 GREEN) are the
   current arc.
2. `docs/lessons-learned.md` — RL-1..RL-16 stand; RL-17 (loud guards + the
   cleanup-then-redeploy retry protocol) and RL-18 (probe vs wired path;
   per-node port namespaces) were added during the W12 arc.
3. `docs/adr/032` — Windows parity matrix, GATES STABLE 1.0. Current state
   below; re-verify against the file.
4. `local/NOTES.md` (untracked) — credential locations. `docs/MEMORY.md` —
   pointer index. `docs/distribution-prior-art.md` + `docs/adr/034` — the
   distribution arc (ratified, partially implemented).

## Verified state (2026-08-27 ~17:00 local)

- Branches `dev` == `main` == `origin` at `c66d2f9` + the W12-landing commits
  (`fd2f7e5` loud guards, `bfab513` directory URL, `8315d40` DNS lane port,
  docs). Tree state: re-verify with `git status`.
- **ADR-032 matrix: 10 of 11 lanes green.**
  - Green: W1 (SCM), W2 (pipe), W3 (trust), W4 (Windows CA rotation),
    W5 (mDNS both directions), W6 (DNS serve, lane-scoped port), W7 (TLS
    proxy dual-stack), W8 (webhooks origin-on-Windows), W9 (health
    cross-host), **W12 (ACME dns-01 via Windows DNS, run
    `v1-20260827T203030Z-2c5a7de8`)**.
  - Remaining: **W10** (backup/cold recovery on Windows — not started; the
    Linux `certmesh-recovery` lane is the pattern, the Windows variant needs
    the WindowsLabDaemon + tracked trust machinery). W11 is excluded-by-tag.
- Standing mesh: brook + granite run REAL `koi install` services; test01 is
  the avahi-equipped workstation (W5 peer). Windows workstation (LEO-MAIN /
  stone-leaded-sparkle) at 192.168.1.137; standing koi service RUNNING.
- Locks: released (post-W12 cleanup green on all nodes).

## THE exact next task: W10 — backup/cold recovery on Windows (ADR-032 row)

Not started. The lane to build: encrypted backup → exact data loss → restore →
identity continuity, with a Windows-hosted CA and WindowsLabDaemon staging.

- `certmesh-recovery` (lab.rs ~line 960: backup → data loss → restore →
  CA restarts locked with same fingerprint → member renewal refused while
  locked → unlock with pre-restore passphrase) is the assertion pattern.
- Build on WindowsLabDaemon (tools/koi-lab/src/windows_daemon.rs) — the one
  owner for staging/paths/env/flags/log/kill. New lanes MUST use it.
- Reuse the elevated one-shot runner pattern: `.tmp/w12-run2.ps1` is
  parameterized by `-RunId` (stop standing service → sweep orphans →
  scenario → restore service → transcript to `.tmp/*.log`).
- Deploy-locks protocol: `deploy` acquires the locks with ITS run id; the
  scenario runs with that SAME run id; lab `cleanup --run-id <id>` releases
  them. After ANY failed attempt: full cleanup, fresh deploy, FRESH run id
  (RL-17b — a reused run id inherits stale run-scoped state).

## After W10: the 1.0 gate

- **Extended full profile** — fold all Windows lanes (W1/W2/W4 + windows-
  breadth/mdns/proxy/webhook/acme) into `run-profile full` (ADR-032
  stable-gate redefinition), then run it elevated end-to-end.
- **Soak** — clean soak incl. Windows participants. Gates stable 1.0.
- rc.3 only if findings force it (RL-2: registries immutable).

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
- **Lab discipline**: WindowsLabDaemon is the one owner for staging/paths/
  env/flags/log/kill. Evidence-before-cleanup is doctrine — and it now WORKS:
  daemon-launch guards fail loud (exit 71, self-describing stderr, fd2f7e5).
  Scenario error-cleanup still sweeps the Windows member dir (daemon.log with
  it); the error text is the retained evidence — read it before retrying.
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
- Stable 1.0 gate = ADR-032 matrix all green + extended full profile + clean
  soak incl. Windows participants. rc.3 only if findings force it.

## Distribution arc (ADR-034, paused by operator — resume after 1.0 or on demand)

- Landed: ADR-034 ratified; landing-page draft (`site/`); npm carrier pattern
  implemented (packages/npm); SignPath repo prep — **application SUBMITTED
  2026-08-25, review pending**; P-D channel scaffolds in `packaging/` (fill at
  stable 1.0); koi-desktop autostart + --minimized landed.
- Operator actions pending: npm trusted publishers + NPM_PUBLISH_ENABLED;
  SignPath approval follow-up; landing page hosting on sylin.org.
- Deferred by operator: Tauri updater feed (keys + latest.json).
