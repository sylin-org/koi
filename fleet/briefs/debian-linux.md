# Hat: debian-linux (halcyon-savanna, headless Debian 13)

Repo: ~/repos/github/sylin-org/koi. You are the systemd baseline and the
headless UX: everything reachable and truthful without a GUI.

Measured evidence (2026-09-02): durable systemd install/upgrade/failure rollback,
uninstall/reinstall, SIGKILL recovery, shifted legacy-config migration, authenticated
active-config discovery, and wrong-UID local-control denial are green on the standing
headless service at `127.0.0.1:24441`. The remaining local PH-2/PH-3 workbook is also
green: installed-service Avahi/resolved/native loss and return, pre-armed primary-link
recovery, honest no-backend firewall reporting, independent-peer Pond policy, and
bounded hostile DNS/mDNS/HTTP input. Do not repeat these gates on an unchanged artifact.

## 2026-09-02 convergence dispatch (after `911c590`)

1. Own the small reusable PH-5 installed-service collector now, following the existing
   `koi-lab` evidence/profile boundaries. It must sample artifact/service identity,
   health, RSS, descriptors, threads/tasks, cache size, provider generation and routes,
   retry/publication counts, and cross-host traffic over a bounded duration, emit one
   redaction-attested verdict, and restore run-owned traffic. Prove a short dry run on
   the one installed service; do not start or claim the six-to-24-hour soak.
2. Remain the unchanged physical peer for Alpine and CachyOS provider/security gates.
   Supply only run-owned Koi API traffic and observations under their run ID; do not
   mutate this host's provider/network/service state for another hat.
3. After the ownership-aware installer correction lands, independently validate the
   existing shifted config/drop-in migration plus interrupted and corrupt transaction
   recovery. The standing `24441:24444` run must survive; replacing Koi must not create
   a new decision. Exercise the resolved lifetime correction during the frozen matrix
   or earlier only if relevant provider bytes change.
4. Keep the accepted service ready as the PH-4 peer and later PH-5 soak anchor.

## Prior PH-001 dispatch (after `8f3d50b`)

1. Keep this host available as the stable peer for the remaining workstation recovery
   gates. Re-run the Debian provider, link, Pond, or hostile-input workbooks only when
   their relevant artifact changes or the frozen-candidate matrix explicitly requires it.
2. After the ownership-aware installer correction lands, independently validate the
   existing shifted config/drop-in migration plus physically interrupted and corrupt
   transaction recovery. The result must preserve `24441:24444`; no new port decision
   may arise from the service replacing itself.
3. Prepare the PH-5 resource/behavior collector around installed-service facts, but do
   not start or claim the long soak until PH-4 freezes one candidate for every hat.

## Retained baseline gates

1. Protocol loop; full gates; keep the standing system service healthy.
2. The upgrade cycle, repeatedly: install → upgrade from the installed
   path (the ETXTBSY case) → uninstall → verify re-install — journal each
   pass; this is the installer's soak lane.
3. Headless UX: daemon HTTP API + pond UI in a text browser (curl/lynx
   class), `koi status`/`config`/`trust diagnose` truthfulness, and
   the ladder's honest skips on this box.
