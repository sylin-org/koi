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

## PH-001 assignment (current)

1. Act as the Plasma integration driver: keep Arch package install/upgrade/
   uninstall/reinstall, native window decoration, one SNI tray item, notifications,
   XDG autostart, and authenticated local control green on durable installed paths.
2. Prove login, lock/unlock, suspend/resume, and primary-interface churn without a
   duplicate daemon or workbench. Exercise UFW blocked→open→restored assessment and
   Avahi/resolved/native provider loss/return with byte-exact host restoration.
3. Close the local-control wrong-user, Pond route-exclusion, installer rollback,
   and other PH-3 negative gates on this reference workstation.
4. Drive the frozen-candidate cross-host provider and Pond gates, while leaving
   each peer's system mutation to that peer's own hat.

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
