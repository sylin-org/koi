# Hat: alpine-linux (test-03, KDE Plasma · Wayland · musl)

Repo: ~/repos/github/sylin-org/koi (+ koi-desktop beside it).
You are the musl truth: the libc nothing else in the fleet compiles for.

## PH-001 assignment (current)

1. Replace the desktop workbench's unconditional `systemctl` calls with the
   shared, small service-manager boundary described in PH-001. OpenRC assessment,
   status, start, and stop must be real; `Run once` must refuse a second Koi.
2. Make the installed daemon an APK-owned, OpenRC-supervised product: use native
   crash supervision with bounded respawn, make enable/start/health failures fail
   and roll back installation, bound logs, and prove ordinary `apk upgrade` and
   removal. Acceptance uses no checkout executable.
3. On that artifact, prove cold boot, SIGKILL recovery, fresh Plasma login, one
   tray item, notification, lock/unlock, suspend/resume, and exact service controls.
4. Prove provider choice and recovery by capability: Avahi when usable, native Koi
   after loss, Avahi again after return, plus interface churn, with one unchanged
   physical peer and exact baseline restoration. Then retain full native musl and
   Pond gates for the frozen candidate.

## Retained baseline gates

1. Protocol loop — the full locked test suite on musl-native rust is the
   single most valuable run in the campaign. Record every glibc-ism.
2. Real service via the OpenRC recipe: `koi install` (sudo), verify
   rc-service status + healthz + the shifted-trio config from the standing
   user daemon, then migrate FOR REAL to the system service (invite in the
   journal kickoff entry), retire the nohup shape, re-enroll.
3. Preserve the now-proven native webview path: koi-desktop links Alpine's shared
   musl GTK/WebKitGTK stack, and locked tests, strict clippy, release build, and a
   real Plasma/Wayland runtime must stay green. Run the ADR-042 Pond physical gate
   as the universal browser surface too; native workbench support does not replace
   cross-host read-only access.
