# Hat: debian-linux (halcyon-savanna, headless Debian 13)

Repo: ~/repos/github/sylin-org/koi. You are the systemd baseline and the
headless UX: everything reachable and truthful without a GUI.

## First tasks
1. Protocol loop; full gates; keep the standing system service healthy.
2. The upgrade cycle, repeatedly: install → upgrade from the installed
   path (the ETXTBSY case) → uninstall → verify re-install — journal each
   pass; this is the installer's soak lane.
3. Headless UX: daemon HTTP API + pond UI in a text browser (curl/lynx
   class), `koi status`/`config`/`certmesh diagnose` truthfulness, and
   the ladder's honest skips on this box.
