# Hat: bluefin-linux (bluefin / test-02, GNOME · Wayland)

Repo: `~/repos/github/sylin-org/koi` with `koi-desktop` beside it. This is an
immutable Bluefin workstation: build dependencies belong in the dedicated
`koi-dev` toolbox, not layered onto the host. Product runtime artifacts do
belong on the host through their real install paths.

Measured baseline (2026-09-01): Bluefin 44.20260714 (`bluefin-nvidia-open`),
GNOME Shell 50.3 on Wayland. Exactly one enabled system `koi.service` runs
`/usr/local/bin/koi --daemon` on the standard ports. The workbench is the
rpm-ostree-layered native RPM `/usr/bin/koi-desktop`; XDG autostart launches it
once minimized, and its SNI is registered with GNOME's StatusNotifier watcher.

## PH-001 assignment (current)

1. Build in `koi-dev`, then prove a product-owned Koi service and native desktop
   RPM through rpm-ostree install, in-place upgrade, rollback, reboot, removal,
   and reinstall. Build dependencies remain in the toolbox; acceptance artifacts
   and startup entries never point into a checkout.
2. From a fresh GNOME login, prove one autostarted workbench, SNI reveal,
   notification, native decoration, local control, lock/unlock, suspend/resume,
   and no duplicate process or status item.
3. Exercise firewalld applicability and Avahi/resolved/native route recovery after
   service and primary-interface churn. Capture and restore the exact host policy;
   coordinate provider assertions with an unchanged physical peer.
4. Independently validate shared PH fixes and run the immutable-workstation share
   of the frozen installed-candidate matrix and soak.

## Retained baseline gates

1. Start clean on `dev`, build in `koi-dev`, and upgrade the one system service
   through `koi install --operator test`. Never run a second daemon or use a
   sheltered data root. Keep Avahi and systemd-resolved as detected resources;
   provider mutations are permitted only inside the baseline-capturing physical
   transition gate.
2. Build and test `koi-desktop` in the toolbox, package a native RPM, and upgrade
   it with rpm-ostree as one immutable deployment. Do not layer compiler/header
   packages onto the host. AppImage is not the acceptance artifact while Tauri's
   bundled linuxdeploy cannot process Fedora 44 RELR sections.
3. Validate from a real GNOME login: one autostarted process, SNI reveal, window
   geometry/decorations, notification path, all workbench panes, authenticated
   local-control discovery, exact daemon-reported data root, and a fresh boot.
4. Run the ADR-042 Pond physical gate from an independent LAN host. The full
   daemon API remains loopback; the only LAN HTTP surface is the separately armed,
   allowlisted Pond router on the derived fourth port.
