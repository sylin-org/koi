# Hat: cachyos-linux (test-01, KDE Plasma 6 · Wayland)

Repo: /run/media/test/WORKBENCH/repos/github/sylin-org/koi (+ clone
koi-desktop beside it under repos/github/sylin-org/ for UX work).
You are the real system-service upgrade story and the Plasma UX reference.

Measured lived-in baseline (2026-08-31): the sole Koi is an enabled root-owned
systemd service (`/etc/systemd/system/koi.service`, `/usr/local/bin/koi`, standard
port 5641), not the earlier user-level cyclical shape. Its daemon is healthy and
holds an Authenticated member identity even though the older capability summary
incorrectly offered `certmesh create`; use `/v1/certmesh/diagnose` as the identity
oracle, not the member node's empty local-CA roster. The old
`~/koi-dogfood/runtime/daemon.pid` is stale. Treat measured state as truth and
correct it in place—do not revive the old user daemon or run a second Koi.

Current safety fact (2026-09-02): this host has no `/etc/koi/config.toml`; its standing
Koi owns the standard ports. The ownership-aware correction landed in `41ad76b` and
was accepted through the real installed service: upgrade retained `5641:5644` without
manufacturing a config, and a deliberately unhealthy replacement restored the exact
prior deployment.

## 2026-09-03 10:28 EDT Windows peer result

1. Windows run `ph4-e49b-win-avahi-01` passed against this host's unchanged exact-source
   Avahi artifact. PID `962933`, installed hash
   `f0e999b0077eb25935f1ad563aee33f2e659ffde915d3f3c55f5aa568691682b`,
   Koi/Avahi enablement and activity, interface/address/route, workbench, routes, and
   the one permanent publication all matched baseline after withdrawal. Do not repeat
   the accepted peer transaction or its local artifact gates.
2. Remain unchanged as Debian's read-only Pond reader. Debian owns every Pond/service
   mutation for `ph4-e49b-debian-pond-01`.
3. Reconcile PH-4 only after Alpine, Bluefin, and Debian publish exact-`e49bfe2`
   artifacts, Windows publishes `ph4-e49b-win-native-02`, and Debian publishes the
   exact-source Pond rerun. PH-5 remains prohibited.

## 2026-09-03 09:52 EDT exact-source artifact accepted

1. Complete: clean exact source
   `e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef` passed the full locked native gates
   and the public systemd install. The release and installed binary are byte-identical
   at SHA-256 `f0e999b0077eb25935f1ad563aee33f2e659ffde915d3f3c55f5aa568691682b`;
   the Linux bytes correctly remain identical to the former artifact because the
   withdrawal correction is Windows-gated. The 09:52 EDT journal entry is the
   authoritative installed baseline. Do not rebuild, reinstall, or repeat an
   unaffected local workbook.
2. Remain unchanged as the Avahi peer for Windows-owned run
   `ph4-e49b-win-avahi-01` and the read-only peer for Debian-owned run
   `ph4-e49b-debian-pond-01`. Permit only their run-owned product traffic; those hats
   own every service/provider/Pond mutation.
3. Pull and reconcile after Windows publishes both exact-source provider lanes,
   Debian publishes the exact-source Pond rerun, and all remaining hats publish their
   exact-`e49bfe2` installed artifact. Do not accept a superseded-source run or begin
   PH-5 early.

## 2026-09-03 09:20 EDT exact-source replacement and coordination

1. The former freeze is invalidated by the Windows withdrawal correction. Build from
   clean exact source `e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef`, run full locked
   native gates, and install through the existing systemd product path. Publish the
   release/installed hash, PID, exact service/provider/Pond baseline, and unchanged
   workbench provenance. Do not repeat the already-green local whole story or the
   Avahi/resolve1↔native lane; their Linux code paths did not change.
2. Remain unchanged as the Avahi peer for Windows run
   `ph4-e49b-win-avahi-01` and the Pond reader for Debian run
   `ph4-e49b-debian-pond-01`; those hats own their system mutations.
3. Reconcile PH-4 only after every hat publishes an exact-`e49bfe2` installed artifact,
   Windows publishes both final provider lanes, and Debian publishes its Pond lane.
   Do not begin PH-5 early.

## 2026-09-03 09:04 EDT PH-4 acceptance and final coordination

1. This hat's exact-source build/install and installed local journey are green in the
   09:04 EDT journal entry. Pond run `20260903T124749Z-924542` passed through Bluefin,
   and provider run `20260903T125812Z-925941` closed the CachyOS
   Avahi/resolve1/native↔Alpine/native lane. Do not rebuild, reinstall, or repeat
   either destructive workbook on unchanged artifacts.
2. Keep the accepted daemon/workbench and provider/network/firewall baseline unchanged
   as the physical Avahi peer for Windows run `ph4-5c89-win-avahi-01` and as the Pond
   reader for Debian run `ph4-5c89-debian-pond-01`. Those hats own their system
   mutations; this host supplies only run-owned product reads/publications.
3. Pull and reconcile once Windows has published both its Alpine/native and CachyOS/
   Avahi transactions and Debian has published its Pond transaction. Require their
   exact frozen artifact identities, withdrawal, singleton processes, and exact cleanup.
   If all are green, mark PH-4 complete and dispatch PH-5; otherwise update only the
   owning hat's next task. Do not start the soak early.

## 2026-09-03 PH-4 dispatch (frozen source `5c89e9de11bf23ab81fd8b5b0778c58477359360`)

1. Build a release artifact from a clean export or detached worktree of the exact
   frozen source, run its full locked native gates, and install it serially through the
   public systemd product path. Prove source/artifact identity, ownership, service
   health, standard-port retention, existing member identity, and one daemon. Retain
   the package-owned workbench only after recording its separate unchanged source and
   installed hash.
2. Drive this host's installed Find → Name → Trust → Serve/Pond journey with real
   run-owned workload/API state and an independent physical reader. Use the standing
   service and production endpoints; the isolated `koi-lab capability-story` mode is
   not acceptance. Include local-control, DNS/mDNS, trust diagnosis, derived health or
   proxy state where available, narrow Pond reads/denials/restart recovery, desktop
   truth, and exact reverse cleanup.
3. Read the other hats' newest PH-4 journal entries and coordinate the serial matrix
   as soon as each exact artifact is ready: Windows↔this Avahi host,
   Windows↔Alpine/native, and this Avahi/resolve1 host↔Alpine/native. Reuse the shared
   provider/Pond workbooks, one run ID per coordinated transaction, and product API
   traffic; every peer owns its provider/network mutations. Do not wait for a bespoke
   prompt once dependencies are visible on `origin/dev`.
4. Publish local and coordinated evidence directly to `dev`. If a product or package
   correction is necessary, mark the candidate invalid in the epic and freeze a new
   exact revision before continuing; a harness-only correction may land without moving
   the product candidate. Reconcile PH-4 only after all five hats are green, and do not
   start PH-5 early.

## 2026-09-03 pre-freeze dispatch (after `d54a1c0`)

1. Regression-accept the shared harness changes from the Alpine convergence work on
   this systemd workstation. Run the generalized provider transition through the real
   Avahi/resolve1/native profile and the generalized Pond workbook through its Python
   peer path, using this host's sole installed Koi and one unchanged physical peer.
   Require the existing structured convergence, PID/hash, negative-route, and exact
   provider/network/Pond restoration verdicts; script portability may not weaken them.
2. Fix any harness or product defect at its owning shared boundary, run the affected
   native gates, and publish the CachyOS evidence. Do not reinstall or repeat unrelated
   desktop/package gates when their bytes are unchanged.
3. Watch `dev` for the Windows, Bluefin, and Debian installer verdicts. When all three
   are green, reconcile PH-0 through PH-3 once, ensure no production correction is
   still in flight, and record one exact source revision as the PH-4 candidate. Do not
   start the soak or silently move the candidate after recording it.
4. Then drive the serial PH-4 cross-provider and Pond matrix. Each peer owns its own
   OS mutations; this hat coordinates run IDs and product traffic and never launches a
   second Koi on any host.

## 2026-09-02 convergence dispatch (after `911c590`)

1. **Complete (`41ad76b`).** Correct endpoint planning once at the shared installer
   boundary. Model the
   deployment being replaced as owned state: preserve its explicit or effective port
   run even while its listener is live, but continue to shift a fresh install around a
   genuinely foreign owner. Systemd and OpenRC consume that one decision. Cover
   no-config legacy installs, explicit config/drop-ins, real foreign listeners,
   failed replacement, and interrupted re-entry without another platform facade.
2. **Complete (`41ad76b`).** Complete `systemd-resolved` publication ownership in
   `koi-mdns`. Quiet initial
   settlement may acknowledge a lease, but conflict observation lives until withdrawal;
   a later `Conflicted` signal or dead signal stream invalidates the publication and
   reaches the existing session/control-plane reconciliation path. Avoid polling,
   provider-specific orchestration, and a second recovery owner. Exercise the real
   resolved/Avahi/native transition with an unchanged physical peer after focused tests.
3. **Complete.** The exact merged candidate is installed
   through this host's one system service. Standard `5641:5644` survived without
   `/etc/koi/config.toml`; a broken candidate restored the exact deployment; and run
   `20260903T000933Z-837819` proved truthful late-conflict counts and recovery. The
   installed package also passed fresh Plasma login, lock/unlock, real suspend/resume,
   primary-interface down/up with peer observation, and wrong-UID local control.
4. **Local reconciliation complete.** This hat's PH-0 claims and surface ledger match
   the accepted artifact. Remain an unchanged peer until the fleet converges and one
   revision is frozen for PH-4; do not begin the soak or repeat already-green package,
   decoration, notification, Pond, or Avahi gates unless relevant bytes change.

## Prior PH-001 dispatch (after `3a5a6d1`)

1. Start now by correcting endpoint planning once at the shared installer boundary.
   An existing Koi being upgraded is not a foreign port collision: preserve its explicit
   or effective run, while a fresh install still shifts around a genuinely foreign
   listener. Have systemd and OpenRC consume the same ownership-aware decision; expose
   the narrow contract Windows needs without copying platform recipes. Arm durable
   recovery before any service stop, and cover no-config legacy installs, explicit
   config, foreign listeners, and interrupted re-entry deterministically.
2. Deploy that exact merged candidate serially through `koi install` on this one service.
   Prove it stays on `5641:5644` without manufacturing `/etc/koi/config.toml`, preserves
   identity/operator policy, and restores byte-exact prior state after a failed candidate.
3. On the accepted artifact, close the remaining Plasma login, lock/unlock,
   suspend/resume, primary-interface churn, and wrong-user boundary. Keep the already
   proven package, decoration, SNI, notification, UFW/Pond, and provider gates green,
   but do not repeat them unless the relevant code or artifact changed.
4. Drive this hat's share of the frozen cross-host provider/Pond matrix only after the
   local correction and the other hats' lifecycle gates settle.

## Retained baseline gates

1. Protocol loop on the daemon: full gates, capture rollback evidence, then
   upgrade the standing system service to the current tree FOR REAL through
   `koi install`. Enroll this one deployment into the fleet mesh if a fresh
   hostname-bound invite is required; verify it reaches and retains
   Authenticated posture across a real service restart.
2. Clone koi-desktop; install its Linux build deps; build it. Verify:
   tray lamp appears in the Plasma systemtray (SNI), autostart toggle
   actually lands in XDG autostart, a watched-fade notification arrives
   through Plasma's notification server.
   First prove the installed/bundled executable path: do not enable an autostart
   entry that points into a source checkout. On Wayland, compare the visible
   decoration and controls with the established Ghostlight implementation on
   this same machine; a successful renderer launch is not sufficient visual proof.
3. Install the native `koi-desktop-git` Arch package, then validate the autostart,
   notification, and fresh-login path against `/usr/bin/koi-desktop`. Exercise the
   ADR-042 Pond physical gate from an independent fleet server, including explicit
   stop and restart recovery; do not use the checkout binary as acceptance evidence.
