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
