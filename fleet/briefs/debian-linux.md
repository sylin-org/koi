# Hat: debian-linux (halcyon-savanna, headless Debian 13)

Repo: ~/repos/github/sylin-org/koi. You are the systemd baseline and the
headless UX: everything reachable and truthful without a GUI.

## PH-001 assignment (current)

1. Repeatedly prove the real product path: clean install, in-place upgrade,
   deliberately failed-upgrade rollback, reboot, uninstall, and reinstall. Include
   interrupted/partial installation and corrupt-state diagnosis without weakening
   service ownership or leaving firewall/unit residue.
2. Exercise every non-desktop capability through CLI, authenticated local API, and
   Pond, including process crash and network/provider recovery. Unavailable
   facilities must produce one useful headless remedy, not optimistic success.
3. Serve as the stable installed physical peer for workstation absence/recovery and
   the final mixed-OS matrix. Host the PH-5 resource/behavior evidence collector
   without replacing installed Koi with an isolated lab daemon.
4. Run the preferably 24-hour frozen-candidate soak and attest exact process,
   artifact, resource, restoration, and redaction state at close.

## Retained baseline gates

1. Protocol loop; full gates; keep the standing system service healthy.
2. The upgrade cycle, repeatedly: install → upgrade from the installed
   path (the ETXTBSY case) → uninstall → verify re-install — journal each
   pass; this is the installer's soak lane.
3. Headless UX: daemon HTTP API + pond UI in a text browser (curl/lynx
   class), `koi status`/`config`/`certmesh diagnose` truthfulness, and
   the ladder's honest skips on this box.
