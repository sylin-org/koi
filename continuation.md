# Koi — continuation prompt for a clean-slate session

You are continuing Koi (LAN connectivity substrate, Rust) toward stable 1.0.
Read FIRST, in order — then re-verify every premise against the tree (RL-11):

1. `SESSION-HANDOFF.md` — canonical ledger; trust it over this file where they
   diverge. The top paragraphs (W8 GREEN + WindowsLabDaemon, W7 GREEN, W5 GREEN
   + browser-defect fix, W6+W9 GREEN, W4 GREEN) are the current arc.
2. `docs/lessons-learned.md` — RL-1..RL-13 stand; RL-14 (netsh vs \\?\ paths),
   RL-15 (pkill vs own transport argv), RL-16 (fail-loud exit codes are
   evidence) were added during this arc.
3. `docs/adr/032` — Windows parity matrix, GATES STABLE 1.0. Current state
   below; re-verify against the file.
4. `local/NOTES.md` (untracked) — credential locations. `docs/MEMORY.md` —
   pointer index. `docs/distribution-prior-art.md` + `docs/adr/034` — the
   distribution arc (ratified, partially implemented).

## Verified state (2026-08-27 ~00:45 local)

- Branches `dev` == `main` == `origin` == `b7053a9` + subsequent W12 work
  through `12d8dd8` (Cargo.lock refresh). Tree state: re-verify with
  `git status` — the W12 physical run had NOT yet been attempted green at
  the time of this writing.
- **ADR-032 matrix: 9 of 11 lanes green.**
  - Green: W1 (SCM), W2 (pipe), W3 (trust), W4 (Windows CA rotation),
    W5 (mDNS both directions, incl. browser-cache product fix),
    W6 (DNS serve, lane-scoped port), W7 (TLS proxy dual-stack verify),
    W8 (webhooks origin-on-Windows), W9 (health cross-host).
  - Remaining: **W12** (ACME dns-01 via Windows DNS — scenario IMPLEMENTED,
    physical run pending), **W10** (backup/cold recovery on Windows — not
    started). W11 is excluded-by-tag (no Docker Desktop requirement).
- Standing mesh: brook + granite run REAL `koi install` services; test01 is
  the avahi-equipped workstation (W5 peer). Windows workstation (LEO-MAIN /
  stone-leaded-sparkle) is at **192.168.1.137** (DHCP moved from .138; catalog
  updated). Standing koi service: RUNNING.
- Locks: released (last cleanup green). Fresh deploy required before any lane
  (musl artifact was rebuilt after the disk cleanup swept `target\`).

## THE exact next task: W12 physical run (ADR-032 row → green)

The scenario `windows-acme` is implemented and compiles clean. Four real
defects were already fixed through its debugging (see git log: a9c190d..HEAD):
CA-read retry (flush timing), CA persist to the path instant-acme opens,
ACME directory dials the daemon's hostname (leaf SAN coverage), and the
rustls CryptoProvider install (lab graph links both aws-lc-rs and ring).

From an **elevated** shell (UAC one-shot pattern — see `.tmp/w12-run.ps1`,
which is the ready runner: it stops the standing service, sweeps orphans,
runs the scenario, restores the service, transcripts to `.tmp/w12-run.log`):

1. `cargo run -p koi-lab --locked -- deploy --artifact
   target\x86_64-unknown-linux-musl\release\koi` (fresh run id, holds locks)
2. Run `.tmp\w12-run.ps1` elevated (verify its run_id matches the deploy).
3. Expected checks: instant-acme issued <name> via the Windows RFC 8555
   server; dns-01 TXT served by the Windows DNS runtime and observed
   cross-host by dig from brook; chain verified to the run CA; identity
   recorded in the certmesh roster; exact cleanup.
4. On green: ADR-032 W12 row → green, ledger paragraph, cleanup (releases
   locks), commit, push dev+main.
5. On red: READ THE RETAINED EVIDENCE FIRST (daemon.log tail rides the
   failure; WindowsLabDaemon.evidence()). Diagnose before touching anything.

## After W12: W10, then the 1.0 gate

- **W10** — backup/cold recovery on Windows (encrypted backup → exact data
  loss → restore → identity continuity). Not started. The Linux recovery lane
  (`certmesh-recovery`) is the pattern; the Windows variant needs the
  WindowsLabDaemon + tracked trust machinery.
- **Extended full profile** — fold all new lanes (windows-breadth,
  windows-mdns, windows-proxy, windows-webhook, windows-acme, plus W1/W2/W4)
  into `run-profile full` extended with the Windows cases (ADR-032 stable-gate
  redefinition), then run it elevated end-to-end.
- **Soak** — clean soak incl. Windows participants. Gates stable 1.0.
- rc.3 only if findings force it (RL-2: registries immutable).

## Environment notes (measured, important)

- **Disk**: Docker data vhdx moved to `E:\vhd\docker\docker_data.vhdx`
  (compacted to 3.6 GB; C:\...\docker_data.vhdx is now a symlink → E:).
  C: free ~291 GB, E: free ~433 GB. Never let rust/cross/docker content
  accumulate on C: again — it filled the disk and manufactured a whole
  failure loop (deploy/cleanup exit-1s that looked like code bugs).
- **Toolchain**: `rustup target add x86_64-unknown-linux-musl` was REINSTALLED
  (swept by disk cleanup). Linux musl builds should go through **Docker/cross**
  (cross 0.2.5 present; the host musl-gcc is absent by design).
- **Windows mDNS/verifier facts** (ADR-032 W5/W6): ICS holds 53 with reuse
  semantics; Resolve-DnsName has no -Port; nslookup sends ZERO packets for
  non-53 ports; SO_REUSEADDR vs non-reuse holder = WSAEACCES 10013; avahi
  tools want types without the `.local` suffix.
- **Lab discipline**: WindowsLabDaemon (tools/koi-lab/src/windows_daemon.rs)
  is the one owner for staging/paths/env/flags/log/kill — new lanes MUST
  build on it. Evidence-before-cleanup is doctrine. Orphan koi sweep is in
  the runners. Per-machine credentials (RL-13): test01 = test/test, NEVER the
  lab password.

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
  implemented (packages/npm); SignPath repo prep (CODE_SIGNING_POLICY.md,
  release.yml lane, verify script) — **SignPath application SUBMITTED
  2026-08-25, review pending**; P-D channel scaffolds in `packaging/`
  (fill at stable 1.0); koi-desktop autostart + --minimized landed.
- Operator actions pending: npm trusted publishers + NPM_PUBLISH_ENABLED;
  SignPath approval follow-up; landing page hosting on sylin.org.
- Deferred by operator: Tauri updater feed (keys + latest.json).
