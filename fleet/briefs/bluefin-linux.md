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

The native RPM/rpm-ostree lifecycle, fresh GNOME session, crash, lock, suspend,
primary-interface churn, Avahi/resolved/native recovery, wrong-UID local control, and
Pond/firewalld gate are already physically green. Do not repeat those gates against an
unchanged artifact.

## 2026-09-02 convergence dispatch (after `911c590`)

The hostile-input/resource gate named by the prior dispatch is physically green in
journal run `20260902T055318Z-19596`; do not repeat it on unchanged bytes.

1. Reconcile Bluefin's PH-0 contract now: compare advertised immutable install,
   workbench, provider, firewall, local-control, Pond, and lifecycle claims with the
   installed evidence. Correct stale public claims or a real defect at its owning
   boundary; do not create a framework or rerun a destructive green gate for prose.
2. Keep this installation available as an unchanged Avahi/systemd-resolved peer while
   CachyOS lands the shared corrections. Do not mutate another hat's provider or
   network state.
3. Once the ownership-aware installer correction reaches `dev`, independently prove
   rpm-ostree/systemd upgrade does not shift around Bluefin's own live Koi, a genuinely
   foreign listener still receives a safe plan, failure restores the exact prior
   deployment, and reboot activates the intended artifact. Recheck the resolved
   lifetime correction only if this host's selected route exercises it.
4. Leave the exact accepted deployment ready for PH-4. Do not start the long soak
   before one revision is frozen across every hat.

## Prior PH-001 dispatch (after `3a5a6d1`)

1. Start now with the remaining PH-3 hostile-input/resource-bound gate on the one
   installed immutable-workstation Koi. Use an independent physical peer to exercise
   malformed/truncated mDNS, DNS, and denied Pond/operator requests at a bounded rate;
   sample RSS, descriptors, threads, retry rate, provider generations, and process
   identity before/during/after. Prove no crash, privilege widening, secret exposure,
   unbounded growth, or manual re-arming. Extend the existing `koi-lab` surface only
   when reusable traffic generation is needed—no helper daemon or fake endpoint.
2. Correct any defect at its owning parser/adapter/router boundary and rerun the focused
   native gates plus the real installed assertion. Leave firewalld, Avahi, resolved,
   NetworkManager, login, and rpm-ostree state exact.
3. After the shared ownership-aware installer correction lands, independently prove on
   the immutable host that an upgrade does not shift around its own running Koi, a real
   foreign listener still causes a safe decision, failure restores the prior deployment,
   and reboot activates the intended product artifact.
4. Then run the Bluefin share of the frozen installed-candidate matrix and soak; earlier
   byte-identical GNOME/Pond/provider evidence remains valid input, not work to repeat.

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
