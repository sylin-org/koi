# cachyos-linux — journal

## 2026-08-31 12:40 UTC — canary v2 (orchestrator-driven)
commit: da6032b | gates: cargo check -p koi-net →     Finished `dev` profile [unoptimized + debuginfo] target(s) in 47.87s
koi state now: standing daemon on port 5641 (untouched by the canary)
stack: kwin_wayland kwin_wayland_wr plasmalogin plasmalogin-hel plasmashell startplasma-way 
ladder (head): {"capabilities":[{"healthy":false,"name":"mdns","summary":"disabled"},{"healthy":true,"name":"certmesh","summary":"ready — run certmesh create"},{"healthy":false,"name":"dns","summary":"stopped"},{"healthy":true,"name":"health","summary":"0 services up (0 total)"},{"healthy":true,"name":"proxy","s
findings: none (canary run)

## 2026-08-31 09:52 EDT — session 1, lived-in workbook
commit: c36511a + working fixes | gates: koi fmt/clippy/test/build pass before final role fix; desktop fmt/clippy/34 JS tests/release build pass
koi state now: exactly one root systemd daemon, enabled and active at `/usr/local/bin/koi --daemon` on standard 5641:5643; installed/release SHA-256 `0d343c08e6100beaf4dc7ae81484cd4ab8fbdaa87dbdb8b9be70163e2b9eb313`; Authenticated identity `test-01` retained across in-place `koi install` and explicit service restart. Exactly one live desktop workbench in the active Plasma Wayland session; SNI registered and `--poke` acknowledged without a second UI.
rollback: `/tmp/koi-test01-pre-fleet.tar`, 46131200 bytes, SHA-256 `85ab8f8ccd0a54c6a4301a087fae98d48f39ef7be80fe78d19a51d0e4cd7e9e9` (old binary, unit, `/var/lib/koi`)
findings:
1. Baseline brief was wrong: the standing shape was already a root system service and its member identity was healthy. The ladder confused leaf-only membership with Open; fixed to report `authenticated member` with a regression test.
2. Full parallel tests exposed a destructive shared-test-root race in installer detection. Cleanup now stays in a test-owned child; 20 repeated focused runs and the full suite passed.
3. The desktop did not compile on Linux because Windows process APIs were unconditional. Linux service inspection/control and a standard-endpoint guard against `Run once` duplicating the daemon were added.
4. The first native Wayland launch aborted with `Gdk-Message: Error 71` on this Intel/NVIDIA machine. The workbench now selects WebKitGTK's DMA-BUF compatibility renderer on Wayland unless the operator already chose a value; the release window and SNI remain live.
5. The first successful window used Tao 0.35.3's divergent custom Wayland header and looked much thicker than expected. Koi now pins the exact upstream Tao decoration fix already proven by Ghostlight here; capture shows KDE's roughly 28-pixel native server-side frame.
6. AppImage packaging is not viable from this CachyOS host: Tauri's bundled linuxdeploy strip rejects Arch `.relr.dyn` sections. Autostart, watched-fade notification, Pond browser parity, and real fresh-login proof remain pending until a durable Linux desktop install artifact/path exists; no checkout-targeting autostart entry was created.
7. Restart log soak found an enrolled member entering the CA self-enroll retry every five seconds. The trust-plane supervisor now requires local CA ownership, not merely Authenticated posture. Final full gates passed; the corrected binary was installed in place and a 26-second post-restart soak crossed five retry intervals with no recurrence.
