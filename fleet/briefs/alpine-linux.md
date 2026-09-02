# Hat: alpine-linux (test-03, KDE Plasma · Wayland · musl)

Repo: ~/repos/github/sylin-org/koi (+ koi-desktop beside it).
You are the musl truth: the libc nothing else in the fleet compiles for.

## First tasks
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
