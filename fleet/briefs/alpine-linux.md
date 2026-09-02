# Hat: alpine-linux (test-03, KDE Plasma · Wayland · musl)

Repo: ~/repos/github/sylin-org/koi (+ koi-desktop beside it).
You are the musl truth: the libc nothing else in the fleet compiles for.

Measured evidence (2026-09-02): the workbench and daemon are APK-owned; real OpenRC
controls, bounded supervision/logs, crash recovery, failed-install rollback, ordinary
APK upgrade/removal/reinstall, native musl gates, and Pond are green. Avahi is installed
but stopped and must be restored to that exact baseline after any provider gate.

## 2026-09-02 convergence dispatch (after `911c590`)

1. Start now from the exact installed APK artifacts. Prove a cold boot and genuinely
   fresh Plasma login/autostart, one SNI item, notification, native window,
   authenticated OpenRC controls, lock/unlock, suspend/resume, and singleton
   daemon/workbench state. No checkout executable or pre-existing session counts.
2. Use headless Debian as the unchanged physical peer for one serial provider/interface
   workbook: Avahi selection, genuine loss with native continuity, promotion after
   restoration, primary-interface churn, bidirectional publication/read/removal, and
   exact restoration to installed-but-stopped Avahi plus the captured network state.
   Coordinate one run ID; neither peer runs a helper daemon or mutates the other's OS.
3. Close Alpine's remaining PH-3 boundary on that installed artifact: unrelated-UID
   local-control denial plus bounded malformed mDNS/DNS/HTTP and excluded Pond/operator
   traffic from the peer, with RSS/descriptors/threads/retries/generations sampled and
   all temporary state removed.
4. After the shared ownership-aware installer correction lands, upgrade through the
   corrected APK/OpenRC path and prove the standing `5651:5654` decision survives,
   rollback remains exact, and the full locked musl and physical Pond gates remain
   green where relevant bytes changed. Preserve that exact package for PH-4; do not
   leave provider enablement, autologin, signing keys, or temporary repositories.

## Prior PH-001 dispatch (after `3a5a6d1`)

1. Start now with the exact installed APK artifacts: prove cold boot, a genuinely fresh
   Plasma login/autostart, one SNI item, notification, native window, authenticated
   service controls, lock/unlock, suspend/resume, and singleton daemon/workbench state.
   Do not substitute the checkout executable or a pre-existing desktop session.
2. From that accepted baseline, run one provider/interface workbook against an unchanged
   physical peer: start Avahi and prove selection, make it genuinely unavailable and
   prove native continuity, restore it and prove promotion, then churn the primary
   interface. Restore Avahi to installed-but-stopped and every OpenRC/network fact to
   the captured bytes/state.
3. After the shared ownership-aware installer correction lands, upgrade the package-owned
   service through the corrected product path and prove the standing shifted configuration
   is retained rather than replanned. Re-run full locked musl gates and the physical Pond
   gate only when that shared candidate changes their relevant artifact.
4. Preserve the resulting exact APK candidate for Alpine's frozen matrix/soak share; no
   temporary repository, signing key, autologin, provider enablement, or test package may
   survive.

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
