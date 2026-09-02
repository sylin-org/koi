# bluefin-linux — journal

## 2026-09-01 16:52 EDT — installed-service provider transition

commit: `d72a9f3` tree; installed artifact SHA-256 `8a0a14dda27b49dbd72f0bfeb79efc3e73cb3392c144c74924f2443f73bb6b27` | gates: physical transition PASS `20260901T205042Z-45196`
koi state then: exactly one enabled system `koi.service`, PID `37751`, `/usr/local/bin/koi --daemon`, standard ports; Avahi and systemd-resolved active+enabled; one permanent self-publication.
findings:

1. Bluefin replaced the former Omarchy installation on the same test-02 hardware/address. The measured host is Bluefin 44.20260714, GNOME Shell 50.3, Wayland; old Omarchy facts are historical only.
2. The one installed PID completed generations 9–13: `avahi → systemd-resolved+native → native → systemd-resolved+native → avahi`. Every phase held desired=established=3 and pending=failed=0. The unchanged test-01 peer was system PID `404624`, SHA-256 `1a994a78b8b40218bd27abf76f992db60b9fc42124187a43cf782c8ca887581c`.
3. Both Koi APIs performed bidirectional publish/resolve/TXT/removal in every phase, including explicit-address publication and one subscription across all generations. Cleanup restored Avahi service/socket, resolved service/activation sockets, enablement, and global/link mDNS facts exactly.

## 2026-09-01 17:29 EDT — native immutable-workstation acceptance

commit: koi `d72a9f3`; koi-desktop `f1e2cdc` | gates: desktop UI 34/34; Rust 8 pass/1 ignored; strict clippy; release build; native RPM install; fresh-login runtime
koi state then: one enabled system daemon and one XDG-autostarted `/usr/bin/koi-desktop --minimized`; `koi-0.1.0-1.x86_64` was the only rpm-ostree local package.
findings:

1. Build-only dependencies stayed in the Fedora 44 `koi-dev` toolbox. A native RPM installed the binary, desktop entry, and icon durably. Tauri's bundled linuxdeploy/strip cannot read Fedora 44 RELR sections, so AppImage is not a truthful artifact from this toolchain.
2. A real reboot and GNOME login launched exactly one workbench. The SNI registered at `/org/ayatana/NotificationItem/tray_icon_tray_app_koi`; its real `Open Workbench` menu item revealed the window without creating another process, and `--poke` also preserved singleton ownership.
3. GNOME/Wayland measured a 1100×37 titlebar over exact 1100×720 content; the earlier oversized decoration was absent. Discover, Browser, Diff, DNS, Trust, About, Glance, tray, service controls, and autostart were exercised against the real daemon.
4. The Status data-root tile incorrectly displayed the literal Windows placeholder `%ProgramData%\koi`. This became the authenticated local-control correction below.

## 2026-09-01 18:06 EDT — authenticated data root and 0.1.1 upgrade

commit: koi `ac9a98e`; koi-desktop `bd216cf` | gates: core local-control/client/serve tests; koi-net all-target + Windows GNU checks; strict clippy; UI 35/35; desktop Rust 9 pass/1 ignored; strict clippy; release build; Bluefin toolbox repeat; native RPM; reboot; AT-SPI; two-host mDNS
koi state now: exactly one enabled system daemon, PID `2237`, `/usr/local/bin/koi --daemon`, SHA-256 `e85e7ae89b33b68d97bcf8028b9078d75c4fb11fbf7d9d6dac0827796ed0a4dd`; exactly one `/usr/bin/koi-desktop --minimized`, PID `1738`; rpm-ostree local package `koi-0.1.1-1.x86_64`; Avahi owns all four mDNS routes at generation 1 with desired=established=1 and pending=failed=0.
findings:

1. The daemon composition root now hands its resolved data directory through the authenticated, versioned local-control response. It is absent from public `/v1/status`; old clients ignore it and new clients against old daemons render “not reported” instead of guessing. The installed desktop's live accessibility text interface returned exactly `/var/lib/koi` (12 characters).
2. The desktop RPM upgraded atomically from 0.1.0 to 0.1.1. A real boot launched one daemon and one minimized UI; both loopback health endpoints passed. Temporary GDM autologin was used only to create the physical Wayland seat, then `/etc/gdm/custom.conf` was restored byte-for-byte (SHA-256 `04022d30d148bf53461bc0fc6f8c5df8fbfcf590c06b684ce975e1e057894541`). Credential and accessibility helpers were deleted after validation.
3. A post-upgrade two-host gate published one run-owned `_koi-upgrade._tcp` record per machine. Bluefin resolved test-01's host/address/43101/TXT and test-01 resolved Bluefin's host/address/43102/TXT; both withdrawals were observed, leaving only each daemon's permanent registration.
4. The Pond bundle contains no machine-local path, its read-only CSS hides the data-root tile, and public status has no `data_root`. A second-host curl exposed a separate defect: Phone returns a LAN URL while the standard service is bound to `127.0.0.1:5641`. See `issues/001-pond-needs-read-only-listener.md`.
5. `systemd-remount-fs.service` (overlay reconfigure) and `ublue-nvctk-cdi.service` (NVIDIA driver not loaded) are degraded in both the pre-upgrade and current boots. They are base-image/hardware facts, not deployment regressions; Koi's journal has no warnings.

## 2026-09-01 20:55 EDT — ADR-042, native RPM 0.1.2, and fresh-boot acceptance

commit: koi product `dbd2466`, gate portability through `739b902`; koi-desktop source through `4c05ed2` | gates: full toolbox core gates; desktop Rust/UI/strict-clippy/release gates; native RPM upgrade; real GNOME login/SNI/AT-SPI; three-host Pond; current-candidate mDNS peer
koi state now: exactly one enabled system `koi.service`, PID `9720`, `/usr/local/bin/koi --daemon`, SHA-256 `89bc5ed0f0edfa7fd9163847a5cab0b23fa3a03fed9fc32789e39ea4d690658f`; operator HTTP remains `127.0.0.1:5641`; Pond is disabled and 5644 is closed; Avahi owns all mDNS routes. Exactly one installed `/usr/bin/koi-desktop --minimized`, PID `7087`, runs from rpm-ostree local package `koi-0.1.2-1.x86_64`.
findings:

1. Bluefin physical run `20260902T004557Z-9528` exercised ADR-042 from independent peers test-01 and test-03. Every allowlisted asset/read, refused mutation/excluded route, explicit stop, and restart recovery passed. The sole service changed serially from PID `5889→9720`; the executable hash stayed fixed and the original disabled desire returned.
2. Firewalld's existing FedoraWorkstation policy already permits the derived high TCP port, so no host firewall mutation was needed. The gate initially exposed that immutable hosts may have neither `socat` nor a traditional `nc`; the shared harness now talks to authenticated Unix control with the Python standard library when needed, without adding a host package or weakening the product path.
3. The fresh boot beginning `2026-09-01 20:11:49 EDT` produced one real GNOME session and one XDG-autostarted workbench at `20:41:59`. GNOME's live StatusNotifier watcher contains exactly Koi's Ayatana item, and `Open Workbench` revealed the native window. Status and Phone used authenticated local control; Stop sharing closed the listener.
4. Temporary GDM autologin existed only to establish the earlier physical seat and was removed; `/etc/gdm/custom.conf` still matches its byte-exact original SHA-256 `04022d30d148bf53461bc0fc6f8c5df8fbfcf590c06b684ce975e1e057894541`. No validation drop-in remains. The RPM owns the executable, desktop entry, and icon.
5. In current provider run `20260902T004825Z-546815`, this one installed Koi was the peer at unchanged PID `9720` and hash `89bc5e…658f` while test-01 completed all five plans. Bluefin's Koi unit, Avahi service/socket, and resolved service returned to their captured active+enabled facts.
