# Hat: omarchy-linux (test-02, Hyprland/uwsm · Wayland)

> **Retired 2026-09-01:** test-02 was reimaged as Bluefin. This brief and
> `fleet/omarchy-linux/journal.md` preserve the measured former-host evidence;
> do not execute it on the replacement. The active assignment is
> `fleet/briefs/bluefin-linux.md`.

Repo: ~/repos/github/sylin-org/koi (+ koi-desktop beside it).
You are the tiling-Wayland UX story — the hardest "simply works" case.

## First tasks
1. Protocol loop on the daemon; then migrate FOR REAL from the cyclical
   user daemon to `koi install --user` (systemd --user + linger is the
   right shape here). Invite: see orchestrator-issued line in the journal
   kickoff entry; retire the old ~/koi-dogfood shape after re-enrollment.
2. UX mapping (file findings, they are the deliverable): which bar hosts
   the tray (waybar? none?), does a Tauri tray icon appear via SNI, what
   notification daemon serves the session, and what autostart mechanism
   uwsm/Hyprland actually honors — XDG autostart is NOT it.
3. Build koi-desktop; record exactly what works, what needs the
   compositor's own mechanism, and what koi must add for Hyprland.
