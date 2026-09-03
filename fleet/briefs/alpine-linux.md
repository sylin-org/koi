# Hat: alpine-linux (test-03, KDE Plasma · Wayland · musl)

Repo: ~/repos/github/sylin-org/koi (+ koi-desktop beside it).
You are the musl truth: the libc nothing else in the fleet compiles for.

Measured evidence (2026-09-02): the workbench and daemon are APK-owned; real OpenRC
controls, bounded supervision/logs, crash recovery, failed-install rollback, ordinary
APK upgrade/removal/reinstall, native musl gates, and Pond are green. Avahi is installed
but stopped and must be restored to that exact baseline after any provider gate.

## 2026-09-03 09:04 EDT peer handoff

1. CachyOS provider run `20260903T125812Z-925941` passed against this unchanged
   installed OpenRC/native peer. It recorded PID `24201`, exact artifact SHA-256
   `4db6a257b9303157bd8dff03887b478b2c8f5a20f777166d35a59f77436a95e9`, active+enabled
   Koi, installed-but-stopped/disabled Avahi, and one permanent publication before and
   after. Do not repeat or independently journal that CachyOS-owned lane.
2. Remain unchanged for Windows run `ph4-5c89-win-native-01`. Permit only its run-owned
   Koi API publications and reads; Windows owns every provider/profile/service mutation.
   After its journal lands, verify readiness read-only and report only a real mismatch
   or residue. Do not start PH-5.

## 2026-09-03 08:16 EDT convergence dispatch (after `4ce6a40`)

1. The exact re-frozen APK/OpenRC artifact and installed whole-story journey are green
   in the 05:56 UTC journal entry. Do not rebuild, reinstall, start Avahi, or repeat a
   destructive local gate.
2. Remain the unchanged native peer for Windows transaction
   `ph4-5c89-win-native-01`. The Windows driver owns its run-owned publications and
   reads through installed Koi APIs; it may not mutate this host's provider, network,
   service, package, firewall, or login state. Do not start an independent overlapping
   transaction. If invoked before the Windows run begins, verify readiness read-only,
   report the dependency, and leave the machine untouched.
3. After Windows publishes the shared run, independently verify this host still has
   the accepted artifact hash, one daemon/workbench, native Ready routes, Avahi stopped,
   original interface/default route, zero run-owned publications, and no credential or
   recovery residue. Add a journal entry only if this agent captured material peer-side
   evidence; otherwise do not manufacture a commit.
4. Stay ready for the later CachyOS Avahi/resolve1↔native run. PH-5 remains prohibited.

## 2026-09-03 PH-4 dispatch (frozen source `5c89e9de11bf23ab81fd8b5b0778c58477359360`)

1. Produce signed/indexed APKs from a clean source archive of the exact frozen commit,
   run the full locked musl gates, and upgrade the sole package-owned daemon/workbench
   through apk/OpenRC. Record source, APK, installed-binary, service/supervisor, desktop,
   and retained-index identities; preserve the standing `5651:5654` decision and one
   healthy process of each kind.
2. Execute Alpine's installed Find → Name → Trust → Serve/Pond journey with real
   run-owned state and a physical peer. Exercise authenticated OpenRC controls, native
   fallback, DNS/mDNS, current trust diagnosis, derived health/proxy state where
   available, the narrow Pond surface and denials, Plasma truth, service recovery, and
   exact reversal. The isolated `koi-lab capability-story` mode cannot count.
3. Participate directly in the serial Alpine/native rotations with Windows and
   CachyOS/Avahi-resolve1 when their frozen artifacts are ready. This hat owns Avahi
   start/stop, primary-interface, OpenRC, and local firewall/package state; restore
   Avahi to installed-but-stopped and all network state exactly. Use the shared run ID
   and installed Koi APIs, never a helper daemon.
4. Journal and push the complete slice. If frozen product/package bytes require a fix,
   invalidate and re-freeze the candidate before further acceptance; do not bless a
   one-off APK. Leave the accepted artifact ready for final PH-4 reconciliation and the
   later PH-5 soak.

## 2026-09-03 pre-freeze dispatch (after `d54a1c0`)

1. This hat's convergence dispatch is complete. The accepted APK/OpenRC deployment,
   provider/interface recovery, Plasma lifecycle, PH-3 boundary, ownership-aware
   upgrade, failed-candidate rollback, musl gates, and Debian-peer Pond gate are green.
   Pulling task updates must not trigger another install or destructive workbook.
2. Keep the exact installed service/workbench and retained package index healthy and
   unchanged. Supply run-owned Koi publications, reads, and observations when another
   hat names Alpine as a peer; do not mutate providers, networking, login state, or the
   service for that peer's gate.
3. Wait for CachyOS to record the frozen source revision. Then build APKs from exactly
   that source, install them serially through the real package/OpenRC path, and execute
   Alpine's PH-4 Find → Name → Trust → Serve/Pond and cross-provider slice. Only that
   frozen artifact begins Alpine's soak participation.

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
