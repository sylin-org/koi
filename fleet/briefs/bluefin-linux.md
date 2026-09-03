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

## 2026-09-03 12:03 EDT PH-5 dispatch

1. PH-4 is green. Preserve the exact system daemon and rpm-ostree-owned GNOME
   workbench/SNI; do not repeat immutable lifecycle or whole-story gates.
2. From the ordinary GNOME session and a neutral host directory, prove the installed
   workbench/CLI entry and diagnostics without exposing toolbox, checkout, endpoint,
   token, or alternate-root mechanics. Capture the first useful result, truthful
   provider/trust/Pond state, and one actionable unavailable explanation.
3. When Debian's neutral collector change lands, build the harness inside `koi-dev`
   but run its short systemd observation canary against the real host installation and
   a Koi-owned peer surface. Require exact artifact/PID, resources, provider and
   publication counts, semantic traffic, one workbench/SNI, and no host build-package
   layering. Do not create an immutable-host-specific collector.
4. During the shared soak, own only Bluefin's assigned serial service/provider
   recovery window and exact firewalld/session restoration. Do not start it before all
   observer canaries and CachyOS's run ID are present.

## 2026-09-03 09:20 EDT exact-source replacement dispatch

1. Replace the now-invalidated daemon with a clean toolbox build from exact source
   `e49bfe2b3e403fa87d4b8b237b49f3bb9e5cb5ef`. Run full locked native gates and
   install serially through the public systemd path; keep build dependencies in
   `koi-dev` and keep the unchanged package-owned workbench/SNI provenance.
2. Publish release/installed hash, PID, service/operator/port facts, provider/Pond
   baseline, singleton processes, and exact cleanup. The correction is Windows-only,
   so do not repeat the green local whole-story, immutable lifecycle, desktop, or Pond
   workbooks. Remain an unchanged peer and do not begin PH-5.

## 2026-09-03 08:16 EDT convergence dispatch (after `4ce6a40`)

1. The installed `f53d568` PH-4 artifact is invalidated. Build from a clean detached
   worktree/export of exact source
   `5c89e9de11bf23ab81fd8b5b0778c58477359360` inside `koi-dev`, run full locked
   native gates, and serially install it through the public systemd path. Do not rebuild
   the unchanged workbench RPM or layer build dependencies onto the host.
2. Under coordination key `ph4-5c89-bluefin-local-02`, repeat the installed local
   Find → Name → Trust → Serve/Pond journey because product bytes changed. Exercise
   authenticated local control, real Avahi/resolve1/native and DNS/mDNS state, honest
   Open trust posture, supported health/proxy behavior, restoration-gated Pond from an
   independent physical reader, service restart reconstruction/removal, and one
   GNOME workbench/SNI. A genuinely unavailable certificate-backed proxy remains an
   explicit unavailable result, not a reason to invent identity or use an isolated Koi.
3. Use the pinned peer identity and test-lab credential already documented locally;
   do not treat an unset convenience variable as missing authorization. Keep secrets
   out of argv/evidence, use exactly one installed daemon, and restore all run-owned
   DNS/mDNS/health/proxy/Pond state plus credentials and build staging.
4. Record full source/artifact/PID/workbench provenance and exact restoration, commit,
   rebase, and push directly to `dev`. Then remain an unchanged Avahi/resolve1 peer for
   the CachyOS driver; do not repeat old immutable lifecycle gates or begin PH-5.

## 2026-09-03 PH-4 dispatch (frozen source `5c89e9de11bf23ab81fd8b5b0778c58477359360`)

1. Build Koi from a clean export/detached worktree of the exact frozen source inside
   `koi-dev`, run the full locked native gates there, and install it serially through
   the public systemd path. Keep build dependencies inside the toolbox. Record source,
   release/installed hashes, unit/port/operator facts, PID, and the separate unchanged
   native RPM/rpm-ostree workbench provenance.
2. Run the installed Find → Name → Trust → Serve/Pond slice using only the standing
   service, production endpoints, real run-owned workload/API state, and an independent
   physical reader. Include Avahi/resolve1/native truth, DNS/mDNS, current trust
   diagnosis, health/proxy where available, narrow Pond and excluded routes, GNOME
   workbench/local control, service recovery, and exact cleanup. The legacy isolated
   capability-story mode is not acceptance.
3. Supply this exact immutable-workstation artifact as the unchanged Avahi/resolve1,
   firewalld, and Pond peer whenever the CachyOS driver names a shared PH-4 run. Own
   every Bluefin provider/network/service mutation locally and retain toolbox/host
   separation; never copy another distribution's mechanism onto the host.
4. Push the evidence in the same session. A product or package-recipe defect invalidates
   the candidate and requires an explicit fleet re-freeze; evidence/harness corrections
   do not move it. Finish healthy with one service and one workbench, ready for PH-5
   only after the whole matrix closes.

## 2026-09-03 pre-freeze dispatch (after `d54a1c0`)

1. Pull current `dev`, build in the existing toolbox, and accept the ownership-aware
   installer through the sole installed system service. Its own live standard-port run
   must remain the same decision; a genuinely fresh deployment with a serially staged
   non-Koi incumbent must still choose a safe free run. Never overlap two Koi daemons.
2. Require an unhealthy candidate to restore the exact binary, unit, configuration,
   operator policy, activity/enablement, and port decision. Complete the intended
   immutable lifecycle through reboot activation and prove the one GNOME workbench and
   one service still target durable product-owned paths.
3. Correct defects only at their owning shared installer/systemd boundary, run the
   affected focused and full native gates, journal the physical verdict, and push it.
   The already-green provider, Pond, hostile-input, and desktop gates are retained
   evidence unless relevant bytes change.
4. Leave the accepted deployment ready and unchanged. Its next destructive work is
   the Bluefin PH-4 slice after CachyOS records the frozen source revision.

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
