# Hat: omarchy-linux (test-02, Hyprland/uwsm · Wayland)

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
