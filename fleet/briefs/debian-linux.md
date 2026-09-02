# Hat: debian-linux (halcyon-savanna, headless Debian 13)

Repo: ~/repos/github/sylin-org/koi. You are the systemd baseline and the
headless UX: everything reachable and truthful without a GUI.

Measured evidence (2026-09-02): durable systemd install/upgrade/failure rollback,
uninstall/reinstall, SIGKILL recovery, shifted legacy-config migration, authenticated
active-config discovery, and wrong-UID local-control denial are green on the standing
headless service at `127.0.0.1:24441`. Do not repeat them on an unchanged artifact.

## PH-001 next dispatch (after `3a5a6d1`)

1. Start now with the remaining headless PH-2/PH-3 workbook on the one installed service:
   Avahi/resolved/native loss and return, primary-link/address churn with pre-armed local
   recovery, honest firewall applicability, CLI/API recovery facts, and the real Pond
   allowlist plus tokenless mutation/excluded-read denials from an independent peer.
   Exercise bounded malformed network input where it naturally composes with that run;
   unavailable facilities must report one precise remedy rather than optimistic success.
2. Correct defects at shared domain/adapter boundaries, rerun the relevant native gates,
   and restore service, provider, resolver, link, firewall, ports, identity, and disabled
   Pond desire exactly. Keep this host available as the stable peer when it is not the
   mutation owner.
3. After the ownership-aware installer correction lands, independently validate the
   existing shifted config/drop-in migration plus physically interrupted and corrupt
   transaction recovery. The result must preserve `24441:24444`; no new port decision
   may arise from the service replacing itself.
4. Prepare the PH-5 resource/behavior collector around installed-service facts, but do
   not start or claim the long soak until PH-4 freezes one candidate for every hat.

## Retained baseline gates

1. Protocol loop; full gates; keep the standing system service healthy.
2. The upgrade cycle, repeatedly: install → upgrade from the installed
   path (the ETXTBSY case) → uninstall → verify re-install — journal each
   pass; this is the installer's soak lane.
3. Headless UX: daemon HTTP API + pond UI in a text browser (curl/lynx
   class), `koi status`/`config`/`trust diagnose` truthfulness, and
   the ladder's honest skips on this box.
