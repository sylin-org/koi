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

## 2026-09-01 23:26 EDT — PH-1 transactional systemd lifecycle and immutable rollback

commit: this commit, based on `4c9f27e`; installed koi SHA-256 `d50ebc19e3f32b722dac0cebb4ab233665044d2a7892e743ee297ffa3df93fc9` | gates: fmt; strict all-target clippy; full locked workspace tests/doctests; release build; real upgrade/uninstall/reinstall
koi state now: exactly one enabled system `koi.service`, PID `16294`, `/usr/local/bin/koi --daemon`, matching the release artifact above; operator HTTP is `127.0.0.1:5641`, Pond is disabled/5644 closed, DNS cooperatively owns UDP+TCP on `127.0.0.1:53` and `192.168.1.95:53`, and Avahi owns every mDNS route. Exactly one booted `/usr/bin/koi-desktop --minimized`, PID `3046`, remains healthy from the rpm-ostree rollback deployment `koi-0.1.1-1`; the native `0.1.2` RPM (SHA-256 `562b214998c9a2bcc23b30bce575b65458fc5cdaa026342104f09d2ec9a03054`) is staged for the next boot.
peers/run: none — local PH-1 lifecycle; no cross-host assertion or peer mutation
restoration: pre-mutation archive `/tmp/koi-bluefin-ph1-pre.tar`, SHA-256 `23fbada56ad8719cb276623ada1d8a01d9566cd33b61d8d84415ed2f5ade7e2b`; Avahi, resolved, and firewalld remained active+enabled; rpm-ostree's refused live package replacement was reset, leaving `/usr/bin/koi-desktop` byte-identical to the booted 0.1.1 artifact (`f7e535f7104fd54149a87231e28f77907129b14ed53fe295c08648a4c7100393`).
findings:

1. The shared systemd installer previously stopped the real service, replaced product files, printed warnings for enable/start/health failure, and returned success. Installation now snapshots binary, unit, config, and local-operator policy bytes/modes; treats stop, reload, enable, start, and health as hard gates; and restores prior files, enablement, and running state on failure. Focused snapshot tests cover both replacement restoration and removal of a newly introduced file.
2. The one installed daemon completed an in-place upgrade (`2225→15464`), real uninstall (unit absent, service inactive, installed binary intentionally preserved), and reinstall from `/usr/local/bin/koi` (`16294`). The operator remained UID 1000, the artifact hash matched throughout the final install, the desktop stayed singleton, and a 150-second final soak crossed the provider retry interval with no Koi warnings.
3. The booted immutable deployment proved rollback from desktop RPM 0.1.2 to 0.1.1. rpm-ostree refused an unsafe same-name live replacement; its reset retained the booted 0.1.1 bytes and staged a normal 0.1.2 deployment. Activating and verifying that deployment requires the next real reboot and is not claimed by this entry.
4. Measured trust state is Open (`CA not initialized`), contrary to the older authenticated-member journal state. No invite was available or reused, so this session preserved the measured state instead of inventing enrollment evidence.

## 2026-09-02 00:21 EDT — PH-1 native RPM 0.1.2 reboot activation checkpoint

commit: koi source `c658cde`; installed daemon SHA-256 `d50ebc19e3f32b722dac0cebb4ab233665044d2a7892e743ee297ffa3df93fc9`; koi-desktop source `4c05ed2`; installed RPM `koi-0.1.2-1.x86_64`; installed desktop SHA-256 `89c74984af61f35d5a5d06905547963c67936364356b5f084c3d15d41ebd7ca2` | gates: rpm-ostree staged-deployment activation; real boot; systemd readiness; GNOME XDG autostart; live SNI registration; CLI/HTTP health
koi state now: boot ID `dfaf8186bef14923b35e124c938c09a8`; exactly one enabled system daemon, PID `2211`, `/usr/local/bin/koi --daemon`, with zero systemd restarts; exactly one `/usr/bin/koi-desktop --minimized`, PID `2975`, launched by the real GNOME session from product-owned XDG autostart; operator HTTP is `127.0.0.1:5641`; Pond is disabled and 5644 is closed; Avahi owns publish/browse/resolve; cooperative DNS owns UDP+TCP on `127.0.0.1:53` and `192.168.1.95:53`.
peers/run: none — local post-reboot PH-1 activation checkpoint; no cross-host assertion or peer mutation
restoration: no mutation in this continuation; the previously staged rpm-ostree deployment is now booted, no further staged deployment remains, and no temporary login, provider, firewall, credential, or test state was introduced.
findings:

1. The deferred 0.1.2 activation from the preceding entry is complete. `rpm -q` and ownership checks resolve `/usr/bin/koi-desktop` to `koi-0.1.2-1.x86_64`; the executable, desktop entry, and icon are package-owned, while the system daemon remains the recorded product-owned `/usr/local/bin/koi` candidate.
2. The real user GNOME/Wayland session launched one workbench at session initialization. GNOME Shell's live `org.kde.StatusNotifierWatcher` reports exactly `:1.48@/org/ayatana/NotificationItem/tray_icon_tray_app_koi`, with the host registered; no duplicate Koi process or item exists.
3. The daemon became ready at boot with PID `2211`, reports Koi `v1.0.0-rc.2`, healthy authenticated local control, Avahi routes, cooperative DNS, and disabled Pond. The only startup warning is the truthful absence of an optional Docker/Podman runtime backend.
4. This entry is the durable post-reboot checkpoint: the 0.1.2 activation must not be repeated by a later agent continuation.

## 2026-09-02 00:32 EDT — PH-2 GNOME lock recovery and shared-candidate native gates

commit: this commit, based on `a98c8d7`; installed daemon SHA-256 `d50ebc19e3f32b722dac0cebb4ab233665044d2a7892e743ee297ffa3df93fc9`; installed desktop RPM `koi-0.1.2-1.x86_64`, SHA-256 `89c74984af61f35d5a5d06905547963c67936364356b5f084c3d15d41ebd7ca2` | gates: fmt; strict all-target clippy; full locked workspace tests/doctests; release `koi-net` build; real GNOME lock/unlock; singleton UI poke; post-retry-interval service/UI health
koi state now: exactly one enabled system daemon, unchanged PID `2211`, with zero systemd restarts; exactly one `/usr/bin/koi-desktop --minimized`, unchanged PID `2975`; the unlocked GNOME shell reports exactly one Koi StatusNotifier item; operator HTTP is healthy on `127.0.0.1:5641`; Pond remains disabled and 5644 closed; Avahi owns publish/browse/resolve; cooperative DNS retains `127.0.0.1:53` and `192.168.1.95:53`.
peers/run: none — local PH-2 session recovery and native candidate gates; no cross-host assertion or peer mutation
restoration: GNOME session 2 returned to active and `LockedHint=no`; daemon, desktop, service unit, installed artifacts, Avahi, resolved, firewalld, interfaces, firewall rules, and Pond desire were not mutated. The attempted privileged crash injection was refused before mutation because this non-interactive session has no administrator authorization.
findings:

1. Locking the real GNOME/Wayland session changed `LockedHint` to yes while daemon PID `2211` and desktop PID `2975` remained unchanged. GNOME Shell's StatusNotifier watcher was unavailable while the shell was locked, then immediately restored the same single `:1.48@/org/ayatana/NotificationItem/tray_icon_tray_app_koi` registration after unlock. `koi-desktop --poke` acknowledged the existing process without creating a duplicate.
2. Bluefin independently found that shared commit `c658cde` failed `cargo fmt --check` in the new Windows Bonjour label decoder. The shared correction is rustfmt-only (one expression, no semantic or wire change); strict clippy, the complete locked workspace suite, doctests, and the optimized `koi-net` build pass in the Fedora 44 `koi-dev` toolbox afterward.
3. Crash, provider-service, firewalld, primary-interface, and suspend mutations require administrator authorization unavailable to this agent session. No gate is claimed for them, and no host policy was weakened to manufacture one.

## 2026-09-02 00:46 EDT — PH-2 crash, provider, and primary-interface recovery checkpoint

commit: `6f55416`; installed daemon SHA-256 `d50ebc19e3f32b722dac0cebb4ab233665044d2a7892e743ee297ffa3df93fc9`; installed desktop RPM `koi-0.1.2-1.x86_64`, SHA-256 `89c74984af61f35d5a5d06905547963c67936364356b5f084c3d15d41ebd7ca2` | gates: systemd SIGKILL recovery; Avahi/resolved/native local route loss and restoration; NetworkManager primary-interface loss and restoration
koi state now: exactly one enabled system daemon, PID `19596`, after the expected single systemd crash restart `2211→19596`; exactly one unchanged `/usr/bin/koi-desktop --minimized`, PID `2975`; operator HTTP is healthy on `127.0.0.1:5641`; Pond remains disabled; Avahi owns publish/browse/resolve; cooperative DNS owns `127.0.0.1:53` and restored `192.168.1.95:53` with its mDNS projection repopulated.
peers/run: none — local PH-2 fault recovery; no cross-host assertion or peer mutation
restoration: Avahi service/socket, resolved service/monitor/varlink sockets, and firewalld are active+enabled as captured; all runtime masks are absent; NetworkManager restored `Wired connection 1`, `192.168.1.95/24`, and the `192.168.1.1` default route; both root-owned timed restoration units completed or were canceled and no timer remains.
findings:

1. SIGKILL of the sole installed daemon produced systemd result `signal`; the unit's configured five-second recovery started exactly one replacement at PID `19596`, incremented `NRestarts` once, restored HTTP/local control/DNS/mDNS, and did not disturb desktop PID `2975`.
2. A plain Avahi stop was truthfully ineffective because socket/D-Bus activation restarted it. With interruption-safe runtime masks in place, Koi changed `Ready→Reconciling→Ready` and promoted from Avahi to native publish/browse with browse-based resolve fallback in five seconds, without a Koi restart. Masking resolved left the native route healthy. Restoring resolved did not promote it because the measured Bluefin policy is globally and per-link `-mDNS`; restoring Avahi reclaimed all three routes in nine seconds.
3. Disconnecting primary interface `enp0s31f6` removed LAN reachability while loopback health remained `OK`, Koi PID `19596` stayed unchanged, and discovery drained to zero records. The pre-armed NetworkManager restoration recovered the same connection, IPv4 address, route, Avahi ownership, cooperative DNS listener set, and 58-record projection without restarting Koi.
4. This is the durable pre-suspend checkpoint. A later continuation must perform post-suspend verification first and must not suspend the machine again merely because the initiating agent session ended.

## 2026-09-02 00:50 EDT — PH-2 suspend recovery and PH-3 Unix-control boundary

commit: `3901c64`; installed daemon SHA-256 `d50ebc19e3f32b722dac0cebb4ab233665044d2a7892e743ee297ffa3df93fc9`; installed desktop RPM `koi-0.1.2-1.x86_64`, SHA-256 `89c74984af61f35d5a5d06905547963c67936364356b5f084c3d15d41ebd7ca2` | gates: 32-second RTC suspend/resume; network/provider/DNS/UI recovery; intended-operator Unix socket access; unrelated-UID negative access
koi state now: boot ID remains `dfaf8186bef14923b35e124c938c09a8`; exactly one system daemon, unchanged PID `19596`, with only the earlier intentional crash restart; exactly one desktop, unchanged PID `2975`; GNOME session 2 is active and unlocked with exactly one Koi StatusNotifier item; HTTP, Avahi, cooperative DNS, and disabled Pond are healthy.
peers/run: none — local PH-2/PH-3 boundaries; the unchanged installed artifact retains prior three-host Pond/firewalld run `20260902T004557Z-9528`
restoration: no reboot occurred; Ethernet, address, route, Avahi/resolved/firewalld active+enabled facts, FedoraWorkstation zone bytes/semantics, and unlocked session state match baseline; temporary account `koi-boundary-probe`, runtime masks, and every run-owned restoration timer/unit are absent.
findings:

1. `rtcwake -m mem -s 30` suspended from `00:47:28` to `00:48:00` EDT. The first post-resume poll found the original boot ID, daemon PID `19596`, desktop PID `2975`, connected Ethernet, loopback health `OK`, Avahi ownership, 58-record DNS projection, and the same single tray registration; neither Koi process duplicated or restarted.
2. `/var/run/koi.sock` is `test:root 0600`. The intended operator opened it successfully. A run-owned locked system account at UID 992 received `PermissionError: EACCES` when opening the socket, proving an unrelated local identity cannot reach authenticated local control before protocol parsing.
3. The probe account was deleted immediately and its ten-minute root cleanup failsafe canceled. Final audit found no temporary users, timers, runtime masks, firewall rules, credentials, or test processes. No secret entered argv, journal evidence, URLs, or public status.
4. Firewalld remains the unchanged active+enabled FedoraWorkstation policy that admits the derived high Pond port; because the installed artifact is byte-identical to the earlier green physical Pond/firewalld gate, that destructive cross-host gate was not repeated.

## 2026-09-02 01:53 EDT — PH-3 hostile-input and resource-bound physical gate

commit: source under test `27b3d03`; installed daemon `/usr/local/bin/koi`, SHA-256 `d50ebc19e3f32b722dac0cebb4ab233665044d2a7892e743ee297ffa3df93fc9`, PID `19596`; installed desktop RPM `koi-0.1.2-1.x86_64`, SHA-256 `89c74984af61f35d5a5d06905547963c67936364356b5f084c3d15d41ebd7ca2`, PID `2975` | gates: fmt; focused strict clippy; locked `koi-dns`/`koi-mdns`/`koi-serve` tests and doctests; physical malformed DNS/mDNS/HTTP and denied-route load PASS
koi state now: exactly one enabled system daemon, unchanged PID `19596` and restart count `1`; exactly one unchanged desktop PID `2975`; operator HTTP is loopback-only on 5641; Pond desire is restored disabled and 5644 is closed; mDNS generation remains `3` with Avahi owning every route and desired=established=1, pending=failed=0; cooperative DNS remains healthy on `127.0.0.1:53` and `192.168.1.95:53`.
peers/run: `20260902T055318Z-19596` PASS; independent physical peer test-01 `192.168.1.109`, installed Koi PID `542996`, SHA-256 `8e3b94a9cfcaaa66f8c751bbb10e59f5b2196a2057d848c0ff8020d9395e24c3`
restoration: initial Pond desire was false; it is false again and the listener closed on the first poll. The root-owned ten-minute cleanup timer and helper, SSH control socket/session, peer traffic process, and all test state were removed. Firewalld, Avahi, resolved, NetworkManager, login, rpm-ostree, installed artifacts, DNS records, provider routes, and process identities were unchanged.
findings:

1. Test-01 sent a bounded corpus of 500 malformed/truncated UDP DNS datagrams, 100 truncated or length-mismatched TCP DNS sessions, 500 malformed multicast DNS datagrams, and 200 malformed/truncated raw HTTP sessions. It also required 100 excluded Pond requests across DNS mutation, certmesh log, Pond control, OpenAPI, and MCP to return 404, and proved 20 attempts to reach operator port 5641 from the LAN were refused.
2. Before load, Bluefin measured RSS 40,984 KiB, 17 descriptors, 8 threads, systemd memory 15,626,240 bytes, and 8 tasks. Across forty half-second samples, RSS peaked at 41,048 KiB (+64 KiB), descriptors transiently peaked at 19 then returned to 17, threads stayed 8, and tasks transiently peaked at 9 then returned to 8. After a 30-second settle, RSS was 41,088 KiB (+104 KiB); a later final sample was 40,020 KiB, below baseline.
3. The daemon never crashed or restarted, provider generation/routes/publication counts did not change, no resource or privilege widened, and no manual re-arming was needed. Logs contained no panic, fatal error, segmentation fault, out-of-memory, descriptor exhaustion, provider failure, route failure, token, or secret-bearing entry.
4. No access token or supplied machine credential entered argv, traffic, evidence, URLs, the journal, or public status. A cleanup invocation initially ran the root-owned helper as the unprivileged operator and was correctly denied; direct authenticated local control immediately restored disabled Pond before the session continued, and final cleanup found no residue.

## 2026-09-02 19:08 EDT — PH-0 advertised-contract reconciliation

commit: documentation reconciliation based on `a296f42`; installed daemon `/usr/local/bin/koi`, SHA-256 `d50ebc19e3f32b722dac0cebb4ab233665044d2a7892e743ee297ffa3df93fc9`; installed desktop RPM `koi-0.1.2-1.x86_64`, SHA-256 `89c74984af61f35d5a5d06905547963c67936364356b5f084c3d15d41ebd7ca2` | gates: PH-0 public-surface and installed-evidence audit
koi state now: exactly one active system daemon, unchanged PID `19596` and restart count `1`; exactly one unchanged `/usr/bin/koi-desktop --minimized`, PID `2975`; operator HTTP remains loopback-only, Pond remains disabled, Avahi owns mDNS routes, and firewalld retains the FedoraWorkstation policy measured by the prior physical gates.
peers/run: none — read-only local PH-0 reconciliation; no peer assertion or machine mutation
restoration: no product, service, provider, network, firewall, login, or rpm-ostree mutation was performed. An unrelated automatic Bluefin base-OS deployment is staged; it was not activated because this audit supplies no reason to repeat a lifecycle reboot.
findings:

1. The public surface ledger omitted Bluefin from platform supervision even though this journal already proves the immutable composition: toolbox-only build dependencies, transactional `/usr/local/bin/koi` systemd lifecycle, rpm-ostree desktop install/upgrade/rollback/activation, and singleton GNOME autostart/SNI. The ledger now records that evidence and its journal guard.
2. The README described Linux service integration as systemd-only despite the shipped OpenRC recipe. Its platform matrix now advertises both systemd and OpenRC `supervise-daemon`; the service guide's stale “all three” count now describes every supported recipe without inventing a platform count.
3. Workbench, provider, firewall, local-control, Pond, and lifecycle claims otherwise match the installed Bluefin evidence. The ownership-aware Linux installer correction remains a shared CachyOS-owned blocker, so no new rpm-ostree/systemd upgrade proof or PH-4 soak is claimed here.
