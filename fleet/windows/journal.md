# fleet/windows/journal.md — stone-leaded-sparkle (Windows workstation, orchestrator)

## 2026-09-02 (15) — PH-0 advertised Windows contract reconciled

commit: this commit, rebased on `8d6d3d6`; Koi Desktop `cbe5519` | gates: Koi fmt clean, strict full-workspace all-target clippy clean, focused help regressions green, full locked workspace tests green; desktop UI 38/38 and Rust 15 pass/1 environment-gated | installed artifacts intentionally unchanged

koi state now: the installed SCM service remains RUNNING as the sole Koi daemon, PID `29016`, from `C:\Program Files\Koi\koi.exe --daemon`, SHA-256 `7dfb0630454c7042471a3c7e4544dac175aed6567a48262240b9f8b10f08df09`, with health 200 on `127.0.0.1:5641`. Its control plane remains Ready at generation 5 with `publish=native explicit_publish=native browse=windows-dns-sd resolve=windows-dns-sd`, one desired/established permanent publication, runtime disabled, and Pond disabled. The installed workbench remains PID `16604`, SHA-256 `bb07bb2c232f1ea7398348b1cb4a215dc7d2de04c9c21461bc6fe092de05e245`, at `C:\Users\onose\AppData\Local\Koi\koi-desktop.exe`, owning only `127.0.0.1:5640` with the same durable `--minimized` Run entry.

### Public contract reconciliation

1. The platform matrix and mDNS guide now describe the measured Windows composition precisely: native publication, native explicit-address publication, and official Windows DNS-SD browse/resolve, with Bonjour conditional on both its service and runtime library. Provider names are no longer presented as blanket capability claims.
2. The authentication and wire references now distinguish the DAT breadcrumb from the authenticated local-control transport. They record the Windows named-pipe DACL and exact recorded-operator-SID authorization, the Unix owner/root boundary, versioned local-control requests, the HTTP-disabled path, and the installed workbench's breadcrumb-first behavior.
3. The port reference now includes Pond's derived HTTP+3 listener, read-only allowlist, disabled/no-socket truth, and advance program-scoped firewall rule alongside the DNS, operator HTTP, and mDNS rules.
4. The desktop contract now records authenticated named-pipe operation, one-operator ownership, one-shot watched-fade notifications, Windows notification-policy suppression, and Pond as a separate daemon-returned listener rather than a guessed operator URL.
5. A real public-help defect was corrected: Windows/macOS install and uninstall help no longer imply that `--user` services are supported. The text and a regression now state that per-user service mode is systemd Linux only; the existing Windows runtime rejection remains unchanged.
6. Installed lifecycle claims matched the physical baseline: Public Ethernet, enabled block-inbound firewalls, program-scoped installed rules, standard listeners on 53/5641, no 5644 listener, and no service or workbench duplication. No installed deployment was needed or performed during this reconciliation.

### Honest boundary and residue

- Shifted-port ADR-040 remains explicitly unclaimed because this host has no legitimate non-Koi incumbent on the standard trio. Fleet policy forbids manufacturing one, so the exact physical handoff stays for a genuine coexistence condition.
- The unchanged installed Windows service/workbench remain the physical peer while the Linux hats converge. The source candidate waits for the later exact-freeze PH-4 whole-story matrix and PH-5 soak.
- The full test run caused one automatic Windows Firewall TCP/UDP pair for the freshly rebuilt debug `koi.exe`. That exact current-run pair was removed and independently verified absent. A bounded inventory found older automatic rules under repository `target` roots; without a before-run ownership baseline they were not mass-deleted and are tracked in [issue 003](issues/003-cargo-test-firewall-rule-residue.md). Product-managed rules were untouched.
- [Issue 001](issues/001-scm-service-object-wedge.md) remains open; this reconciliation did not alter its state. No peer, provider, resolver, network profile, service registration, installed artifact, listener, or credential state was mutated.

## 2026-09-02 (14) — PH-001 installed Windows provider, link/profile, lock, and S3 gate closed

commit: this commit, on top of `569b67e` | candidate source `569b67e`, release SHA-256 `7dfb0630454c7042471a3c7e4544dac175aed6567a48262240b9f8b10f08df09` | gates: fmt clean, strict all-target clippy clean, full `cargo test --locked` green, locked release build green | run `20260902T223728Z-windows-provider` PASS | evidence `target/mdns-provider-transition/20260902T223728Z-windows-provider/`

koi state now: the exact pulled-tree candidate is installed through the product SCM upgrade path at `C:\Program Files\Koi\koi.exe`, RUNNING as the sole Koi PID `29016`, SHA-256 `7dfb0630454c7042471a3c7e4544dac175aed6567a48262240b9f8b10f08df09`, health 200 on `127.0.0.1:5641`. The control plane is Ready at generation 5 with `publish=native explicit_publish=native browse=windows-dns-sd resolve=windows-dns-sd` and the permanent self-publication is `desired=1 established=1 pending=0 failed=0`. The unchanged installed workbench remains the sole desktop PID `16604`, SHA-256 `bb07bb2c232f1ea7398348b1cb4a215dc7d2de04c9c21461bc6fe092de05e245`, owning only `127.0.0.1:5640`.

### One installed-service workbook, two physical provider families

- The candidate upgrade replaced the earlier installed SHA `452f3ae7...` and PID `28460` once, before the authoritative gate baseline. The serial workbook then held PID `29016` and its installed bytes unchanged through every phase; it never launched a second daemon, alternate port, isolated data root, or provider helper.
- Physical peers stayed fixed: CachyOS test-01/Avahi PID `542996`, `/usr/local/bin/koi` SHA-256 `8e3b94a9cfcaaa66f8c751bbb10e59f5b2196a2057d848c0ff8020d9395e24c3`, system unit active/enabled; Alpine test-03/native PID `2688`, `/usr/bin/koi` SHA-256 `8cedf10927a75189ac1e98262116b157138a9a994c55e650d292107202af3003`, OpenRC service active/enabled. Only run-owned Koi API publications and reads crossed those peers; their providers and system configuration were not mutated.
- With two Windows publications (ordinary plus explicit `192.168.1.137`) and one publication from each peer, generations 1→5 selected `native+windows-dns-sd → bonjour+native+windows-dns-sd → native+windows-dns-sd → bonjour+native+windows-dns-sd → native+windows-dns-sd`. Every phase held `desired=3 established=3 pending=0 failed=0`; both peers resolved both Windows records, Windows resolved both peer records with address/TXT/interface data, and the long-lived Windows subscription survived the route changes.
- Bonjour came only from Apple's official signed 2.0.2 artifacts: wrapper SHA-256 `7f1ec347...`, core MSI `db86c7cc...` / product `{B91110FB-33B4-468B-90C2-4D5E8AE3FAE1}`, print-services MSI `a8f6ced6...` / product `{0DA20600-6130-443B-9D4B-F30520315FA6}`. Installation promoted live publication; stopping `Bonjour Service` fell back without restart or stranded intent; starting it promoted again; uninstall returned to native publication. Final MSI registrations, service, `System32\dnssd.dll`, `Program Files\Bonjour`, and installer staging are absent. The still-running process truthfully reports Bonjour `unavailable installed=yes` because ADR-039 permits a successfully bound library to remain resident; the on-disk/service provider baseline is exact and the route is correctly native.

### Environmental recovery and restoration

- The active Ethernet profile changed Public→Private→Public. Both categories retained the same structured routes, three synchronized publications, peer traffic, PID, and artifact. The primary Realtek adapter then went fully Disabled for 12 seconds behind a pre-armed SYSTEM recovery task, returned Up on ifindex 4 with DHCP `192.168.1.137/24`, Public/Internet, and passed the complete bidirectional gate again.
- `LockWorkStation` retained daemon PID `29016`, workbench PID `16604`, routes, counts, and peer traffic while the console was locked. A real S3 transition followed: Kernel-Power event 42 recorded `Application API` sleep at `22:43:20Z`, Power-Troubleshooter event 1 recorded resume at `22:43:45Z` (wake source Power Button), and the full two-peer phase passed after resume with both PIDs unchanged.
- Cleanup withdrew all four run-owned publications, leaving exactly one permanent publication on Windows and on each peer. Ethernet/profile/IP, all three enabled firewall profiles, Dnscache Running/Automatic PID `3504`, unset LLMNR `EnableMulticast` values, power scheme, peer service identities, and installed desktop were preserved. No `Koi-Fleet-*` recovery/wake task, Bonjour product, Pond listener, or test registration remains. An independent exact-DAT scan found zero matches across all evidence files; the workbook's initial result flag was a predicate bug (`Select-String -Quiet` returned an array of per-file `False` values), corrected in the retained workbook and explicitly re-audited in `redaction-audit.json`. No product defect was found.

The dated Windows dispatch is now complete. The next dependency-ready work is this hat's share of the frozen-candidate whole-story matrix/installed-product soak, or a newer dispatch after synchronization.

## 2026-09-02 (13) — PH-001 installed workbench notification and session-transition gates closed

commit: koi `944bf21`; koi-desktop `dbd5033` | run: `20260902T220738Z-windows-workbench` PASS | gates: desktop UI 38/38; Rust 15 pass/1 environment-gated; fmt clean; strict all-target clippy; release + NSIS bundle; exact installed-artifact notification, tray/singleton, lock/unlock, and two genuine fresh-login passes

koi state now: the unchanged product-path SCM service is RUNNING as sole PID `28460`, `C:\Program Files\Koi\koi.exe --daemon`, SHA-256 `452f3ae7ed16fb1adea3c548af6b78a5ec2e50e4bc70ba7d7d05995d79cae0ee`, health 200 on standard operator port 5641, Pond disabled with 5644 closed, and the runtime capability truthfully disabled after Docker Desktop was restored stopped. The final packaged workbench is installed at `C:\Users\onose\AppData\Local\Koi\koi-desktop.exe`, version 0.1.2, SHA-256 `bb07bb2c232f1ea7398348b1cb4a215dc7d2de04c9c21461bc6fe092de05e245`; its final NSIS is SHA-256 `4fff29f3102067b0e6878c4e3bcfa6e6e0d517b2f03cbce898e4f0a52903c537`.

### Two physical defects removed at the transport/care boundaries

1. The workbench consumed canonical DAT-gated `/v1/events`, whose `data:` field is a versioned `KoiEventWire`, but forwarded that whole envelope as the domain payload. Sentences therefore said `something`, and runtime subjects keyed on the wire event UUID instead of the stable container name; a start could never re-arm the stop subject. `decode_daemon_event` now validates version 1 and matching event type, unwraps the nested domain data, skips unknown versions/mismatches, and retains compatibility with the older bare-payload stream. Physical SSE capture proved the before shape; the installed fix rendered and pinned the stable subject `container:koi-notify-gate-4` and named its start/stop sentences correctly.
2. The feed's 90-second flapping compaction returned before `watchedFade`/`watchedAlive`, suppressing care transitions during ordinary rapid lifecycle changes. Care now observes every lifecycle event before diary compaction. The new regression proves a watched start → stopped → start sequence inside the flapping window opens and re-arms the fade episode while the diary remains one row.

### Installed-artifact gates

- With Docker Desktop genuinely running and the installed daemon restarted through the real service-control path, the run-owned Alpine container was starred in the workbench, revived, and stopped with the workbench closed to its tray. Windows PushNotification-Platform recorded exactly one Koi toast, tracking ID `99713`: local receipt (2416), threadpool submission (2418), delivery begun (3052), and delivery complete (3153) to AppUserModelId `org.sylin.koi` on session 1 at `2026-09-02T18:07:38-04:00`. The host's Do Not Disturb policy suppressed the visible card, but the OS delivery pipeline accepted and delivered it; no Koi notification existed for the pre-fix attempts.
- Closing the native window retained one process and its `127.0.0.1:5640` listener; the real tray menu reopened it and `Quit Koi` removed both process and listener. A normal second executable launch exited 0, revealed and focused the resident PID, and never produced a second workbench.
- Lock/unlock preserved the exact pre-lock workbench PID `9572`, 5640 ownership, daemon PID `3260`, and HTTP 200. The subsequent controlled baseline restart changed only the daemon to PID `28460` after Docker shutdown.
- The final candidate crossed a real sign-out/sign-in. The console logon began at `18:12:17`; the Run entry `C:\Users\onose\AppData\Local\Koi\koi-desktop.exe --minimized` launched the exact installed hash once at `18:13:14` as hidden PID `16604`, which solely owned 5640. A normal second launch exited 0 and made PID `16604` the foreground Koi window; native close returned that same PID to the tray.

### Restoration and truthful remainder

The only run-owned containers (`koi-notify-gate` and `koi-notify-gate-4`) were removed; the standing Docker Desktop buildkit container was not altered. Docker Desktop and `com.docker.backend` are both absent, the runtime endpoint reports `capability_disabled`, all test watches were removed through the UI, the workbench is left hidden and autostart-enabled, and there is exactly one healthy installed Koi. No token, DAT, credential, firewall, resolver, provider, service-registration, data-root, or peer state was journaled or retained. The earlier Phone/Pond physical peer remained test-01; this continuation required no peer-side mutation.

**Shifted ADR-040 remains unclaimed by design.** No genuine non-Koi incumbent owns the standard trio on this host, and fleet policy forbids manufacturing one or launching an alternate test daemon. The next dependency-ready work is dispatch item 4's installed Windows mDNS/NIC/profile/lock/sleep coordination with physical Avahi/native peers, unless a legitimate coexistence condition appears first.

## 2026-09-02 (12) — PH-001 installed Windows workbench checkpoint; session-transition and legitimate-shift gates remain

commit: koi `eebd739`; koi-desktop `7cd2dca` | gates: desktop UI 37/37; Rust 11 pass/1 environment-gated; strict all-target clippy; release + NSIS bundle; physical install/tray/singleton/Phone/Pond/upgrade/uninstall-reinstall through the installed artifacts

koi state now: the unchanged product-path SCM service remains RUNNING as sole PID `26680`, `C:\Program Files\Koi\koi.exe --daemon`, SHA-256 `452f3ae7ed16fb1adea3c548af6b78a5ec2e50e4bc70ba7d7d05995d79cae0ee`, health 200 on the standard operator port 5641, and Pond disabled with 5644 closed. One current packaged workbench is installed and live as PID `21564` from `C:\Users\onose\AppData\Local\Koi\koi-desktop.exe`, version 0.1.2, SHA-256 `e8480f3bcae51e214b9d61527f7e70907f101a1e161fd6fde00169f3a3b46ca4`; its loopback singleton listener owns 5640 and its HKCU Run entry names that durable installed path with `--minimized`. Docker Desktop is restored stopped and the run-owned notification container is absent.

### Installed workbench gates closed

1. Built the synchronized desktop tree and its unsigned development NSIS installer (`Koi_0.1.2_x64-setup.exe`, SHA-256 `7ad1896782b6e1db2fed118f694023be400af1408647482fc62169b6b4c4ebcf`). The installer registered version 0.1.2 per-user at the durable product-owned path; the running executable is not a checkout artifact. A native screenshot captured the 1100×720 content in its decorated Tauri window with live `Calm / local control / posture open` state.
2. The real status Autostart control created `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Koi = C:\Users\onose\AppData\Local\Koi\koi-desktop.exe --minimized`. Closing the native window kept one resident workbench and its 5640 listener. The real tray context menu exposed its disabled posture row plus `Open Workbench` and `Quit Koi`; `Open Workbench` revealed the hidden window without another process, and a physical menu click on `Quit Koi` exited it. A simultaneous second executable launch also exited into the original singleton (one PID, one listener).
3. The installed workbench's Phone action published the exact daemon-returned `http://192.168.1.137:5644/`; it did not guess the operator endpoint. Independent physical peer test-01 loaded `/`, all four assets, and the four read-only health/status/mDNS/DNS routes with 200 and byte hashes, while GET/PUT `/v1/pond`, PUT `/v1/ui`, and `/openapi.json` were all 404. UI `Stop sharing` reported stopped, 5644 closed, the peer timed out, and 5641 stayed healthy.
4. Physical uninstall removed the executable, uninstaller, Start Menu shortcut, uninstall registry key, and enabled autostart entry while preserving the unrelated `lab-scheduler` directory and pre-existing workbench debug log. A detached clean historical tree built a real 0.1.1 NSIS (`17896db8...e887f`); 0.1.1 installed and launched from the same product path. The current 0.1.2 NSIS then upgraded it in place (registry/file version 0.1.2, current executable hash above), launched, and re-enabled autostart through the current UI. The historical build worktree and its run-owned container were removed; both repositories are otherwise clean, and the user's pre-sync debug-log content remains protected in the named desktop stash.

### Truthful remainder

- **Shifted ADR-040 remains unclaimed.** This host has no pre-existing non-Koi owner of the standard trio: the standing Koi genuinely owns 5641 and the other standard trio ports are free. Fleet coordination forbids manufacturing a collision or temporary alternate-port deployment merely for a test, and explicitly says standard-port pipe evidence is not a substitute. The shifted workbench gate therefore needs a real coexistence condition or an explicit protocol change.
- **Notification remains unclaimed.** Docker Desktop was initially stopped, so the installed daemon truthfully has its runtime adapter disabled. Docker was started and a run-owned Alpine container exercised, but no runtime event could reach the existing daemon; this unelevated session cannot restart SCM without the Windows UAC boundary. Docker and the container were restored exactly.
- **Fresh-login and lock/resume remain operator-present gates.** Autostart is armed at the installed path. A real sign-out/sign-in (and unlock credential) will terminate or secure the current interactive session, so the next continuation must cross that human Windows sign-in boundary, then verify exactly one minimized workbench, real tray reveal, notification foreground/background behavior, lock/unlock continuity, 5640 ownership, daemon health, and final cleanup/state.

Next dependency-ready assignment remains dispatch item 3's session-transition/notification portion plus the legitimately shifted ADR-040 condition; dispatch item 4 must not be claimed from this checkpoint.

## 2026-09-02 (11) — PH-001 parallel two-daemon port race removed

commit: this commit, on top of `8f3d50b` | gates: fmt clean; full-workspace strict all-target clippy clean; exact `two_daemon_certmesh` binary green once during implementation plus five consecutive default-parallel repetitions; two complete `cargo test --locked` workspace runs green with default parallelism, including the exact binary each time (32/32 aggregate exact-binary tests across eight runs); locked release build green, rebuilt PE SHA-256 `7dfb0630454c7042471a3c7e4544dac175aed6567a48262240b9f8b10f08df09`; run `20260902T195109Z-two-daemon-reservation` PASS

koi state now: unchanged installed product-path firewall candidate at `C:\Program Files\Koi\koi.exe`, SHA-256 `452f3ae7ed16fb1adea3c548af6b78a5ec2e50e4bc70ba7d7d05995d79cae0ee`, SCM service RUNNING as sole PID `26680`, health 200, Pond disabled, and zero `koi-tier2-*` temporary roots. This session changed integration-test code only, so the installed product was intentionally not replaced.

### Lifetime-owned listener handoff

- `free_port()` is gone from `two_daemon_certmesh`. Each HTTP/mTLS selection is now a `PortReservation`: the OS-bound listener protects allocation, a process-local registry keeps the number owned after that listener is released for the child, and `Drop` releases the registry entry on normal return, failure, or panic. Every daemon owns two distinct reservations for its entire lifetime.
- Only the unavoidable allocation/listener-release/`Command::spawn` handoff is mutex-serialized. The three real-process stories, readiness probes, HTTP work, mTLS work, and teardown remain default-parallel; there is no suite mutex, collision retry, or added sleep.
- Child stderr is retained in each daemon's already-owned temporary data root. Both HTTP readiness and post-create mTLS readiness call `Child::try_wait()` during the unchanged five-second polling contract; an early exit now reports PID, exit status, and the last 40 stderr lines, while a live timeout reports the same retained tail instead of mislabeling every failure as an absent listener.
- A deterministic regression pins ownership across listener release and exact release on reservation drop. Repeated exact-binary and full-workspace runs proved concurrent cleanup: all child processes were reaped, all run-owned data roots were removed, and the standing installed PID was the only remaining `koi.exe`.

Next dependency-ready assignment: dispatch item 3, close the shifted-port ADR-040 named-pipe path and installed workbench fresh-login/tray/notification/Phone/Pond/lock-resume/upgrade/uninstall-reinstall gates.

## 2026-09-02 (10) — PH-001 effective Windows Firewall policy truth closed

commit: this commit, on top of `a8b91ff` | gates: fmt clean; full-workspace strict all-target clippy clean; focused Windows firewall adapter 16/16 green (one unrelated live snapshot test ignored); ordinary parallel `cargo test --locked` green, including all three `two_daemon_certmesh` cases; locked release build green; release SHA-256 `452f3ae7ed16fb1adea3c548af6b78a5ec2e50e4bc70ba7d7d05995d79cae0ee`; elevated serial workbook `20260902T192334Z-active-store` product verdict PASS

koi state now: exact release candidate installed at `C:\Program Files\Koi\koi.exe`, SCM service RUNNING as PID `26680`, one `koi.exe`, health 200 on `127.0.0.1:5641`, Public active with effective firewall enabled, Pond restored disabled, and no SCM transaction, manifest, or backup residue.

### Effective read policy, local mutation ownership

- The shared startup/Pond assessment now queries `Get-NetFirewallProfile`, `Get-NetFirewallRule`, `Get-NetFirewallApplicationFilter`, and `Get-NetFirewallPortFilter` with `-PolicyStore ActiveStore`. This is the effective resultant policy after applicable stores, so a local rule is no longer mistaken for an admitted path when organizational policy changes the outcome. Typed `Open`, `Inactive`, blocked, and query-error behavior is unchanged.
- Installer snapshot and deletion now say `-PolicyStore PersistentStore` explicitly; replacement and restore remain the existing local `netsh` lifecycle. Deterministic command-shape tests pin both halves, preventing assessment from silently falling back to the default persistent view and preventing lifecycle cleanup from reaching effective/GPO-owned rules.
- Microsoft documents that [`Get-NetFirewallRule -PolicyStore ActiveStore`](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule) returns the collection of all applicable policy stores while an omitted selector reads `PersistentStore`; the [`Get-NetFirewallProfile`](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile), [`Get-NetFirewallApplicationFilter`](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallapplicationfilter), and [`Get-NetFirewallPortFilter`](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter) contracts expose the same store boundary for resultant profiles and associated filters.

### Installed observation (`.tmp/20260902T192334Z-active-store`)

The elevated serial workbook captured PID `5176`, one process, prior installed hash `1edfc72d...`, prior Pond desire `false`, Public active, three effective profiles enabled with inbound Block/outbound Allow, and six Koi rules sourced as `Local / PersistentStore`. It installed the exact candidate through `koi install --operator S-1-5-21-...-1001`; the transaction stopped the old service, replaced the product-path bytes, restored the managed local rules, started PID `26680`, image-verified it, and passed health.

The installed startup emitted five same-timestamp effective-policy `managed rule admits` verdicts (UDP 5353, TCP 5641, TCP 5644, UDP 53, TCP 53). Pond then returned `desired=true`, `running=true`, `http://192.168.1.137:5644/`, firewall `open`, and detail `Windows Firewall managed rule admits TCP 5644`; DELETE restored the exact prior disabled desire. Before/after comparisons found no semantic profile or Koi-rule difference, and no host firewall/profile setting was changed to manufacture the result. Final independent inspection matched candidate/installed hashes, health 200, one PID `26680`, Pond disabled, and zero transaction/backup residue.

The workbook's final summary serializer recursively expanded a CIM-backed object after all product assertions and consumed 4.2 GB; only that exact elevated PowerShell evidence-writer PID was terminated. Koi PID `26680` was untouched, and the verdict was reconstructed from the already-written baseline, install, effective-policy, Pond, and startup evidence plus the independent final inspection.

Next dependency-ready assignment: dispatch item 2, replace the `two_daemon_certmesh` check-then-use `free_port()` harness with lifetime-owned reservations and actionable early-exit stderr, then prove repeated default-parallel runs.

## 2026-09-02 (9) — PH-001 startup and Pond firewall truth unified; active-profile semantics closed

commit: this commit, on top of `f8b52e9` | gates: fmt clean; full-workspace strict clippy clean; adapter suite 14/14 plus live NetSecurity enumeration green; the ordinary parallel workspace run exposed one existing two-daemon listener race and its exact test passed alone; full `cargo test --locked -- --test-threads=1` green including named-pipe and all three two-daemon cases; locked release build green; release SHA-256 `1edfc72d07752681f57493238918291c25f271613653292718c26631d60ca540`; elevated serial workbook `20260902T185542Z-firewall-truth` PASS

koi state now: exact release candidate installed at `C:\Program Files\Koi\koi.exe`, SCM service RUNNING as PID `5176`, one `koi.exe`, health 200 on `127.0.0.1:5641`, active Ethernet category still `Public`, all three firewall profiles still enabled, Pond restored disabled, hashed TOTP credential count `0`, and no SCM manifest or installer backup residue.

### One verdict boundary, including startup

- `platform::windows::check_firewall` no longer runs or parses `netsh`. Startup diagnostics and Pond now both consume `koi_serve::windows_firewall::Assessment`, preserving `Open`, `Inactive`, both typed blocked reasons, and query failure. The shared adapter has one batched entry point for startup's rule set, so five verdicts come from one OS query; Pond's single-rule call delegates to the same path.
- The first focused integration run caught why batching matters: one PowerShell query per port delayed local control by about 13 seconds and failed the existing five-second named-pipe gate. The final batched implementation restores that gate without a timeout change. A deterministic regression proves one runner call and keeps display-name/filter correlation across results.
- Connection categories are canonicalized before applicability: documented `DomainAuthenticated` maps to firewall `Domain`, while `Private` and `Public` retain their exact identities. Unknown categories return an error instead of guessing. Enabled firewall profiles are intersected with active networks; an enabled profile with no active network no longer makes the firewall appear active.
- Deterministic tests pin Domain mapping, active-Public-disabled with only inactive Private enabled → `Inactive`, mixed active-profile complete-coverage behavior, unknown-category refusal, batch name correlation, command-spawn failure, and the pre-existing per-rule application/port/profile correlation.

Microsoft's [Windows Firewall overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/) identifies Domain, Private, and Public as firewall profiles and directs callers to `Get-NetConnectionProfile` for the active category. The [Get-NetConnectionProfile contract](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile) names its documented categories as Public, Private, and DomainAuthenticated; the [Get-NetFirewallProfile contract](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile) describes the separately configured Domain/Private/Public profiles. Those identities and the active/configured distinction are now explicit code rather than string coincidence.

### Installed observation (`.tmp/ph001-firewall-truth-20260902T185542Z`)

The one elevated PowerShell workbook captured the healthy baseline (PID `18300`, prior hash `4c92b163...`, Public active, Public firewall enabled, Pond disabled, zero credentials/residue), deployed the exact candidate through transactional `koi install`, and observed the candidate startup log. One timestamp emitted five typed `managed rule admits` facts for UDP 5353, TCP 5641, TCP 5644, UDP 53, and TCP 53 with no query failure. The installed Pond slice then returned `desired=true`, `running=true`, URL `http://192.168.1.137:5644/`, and firewall `open` with detail `Windows Firewall managed rule admits TCP 5644`; the workbook stopped sharing and restored `desired=false`.

No network category or firewall policy was changed for acceptance. Independent final inspection matched installed/candidate hashes, health 200, one PID `5176`, Public still active/enabled, Pond disabled, zero hashed credentials, and no transaction or backup residue.

Next dependency-ready assignment: dispatch item 2, the shifted-port ADR-040 pipe path and installed workbench fresh-login/tray/notification/Phone/Pond/lock-resume/upgrade/uninstall-reinstall gates.

## 2026-09-02 (8) — PH-001 TOTP credential ownership and exact cleanup closed physically

commit: this commit, on top of `c9cba31` | gates: fmt clean; full-workspace strict clippy clean; deterministic slot failure matrix green; focused real-store slot suite 19/19 and certmesh destroy slice green; full `cargo test --locked` green; locked release build green; release SHA-256 `4c92b163784da7bc28d44d3b5a957139a99faf6f4950386a3939d3922ea4453b`; serial workbook `20260902T173700Z-credential` PASS

koi state now: exact release candidate installed at `C:\Program Files\Koi\koi.exe`, SCM service RUNNING as PID `18300`, canonical product-path descriptor retained, one `koi.exe`, health 200 after settle, hashed TOTP credential count `0`, no installed certmesh slot table, and no SCM manifest or installer backup residue.

### Shared ownership transaction

- `SlotTable` now encapsulates its slot collection and persists a validated per-slot credential identifier before either exact label can be written. Add/replacement commits the new active slot before deleting the old labels; removal persists retirement before deletion. A crash at either durable boundary leaves enough aggregate state to clean the attempted or retired labels on the next load.
- Credential cleanup derives only `koi-certmesh-unlock-totp-<id>` and `koi-certmesh-totp-fallback-key-<id>` (or the exact v1 legacy labels) from aggregate-owned state. There is no product enumeration, wildcard deletion, process-ID naming workaround, or acceptance-only endpoint. Corrupt ownership identifiers fail before any store call.
- Platform deletion is typed `Removed | Absent`; Windows absence is classified by an exact entry read before `CredDeleteW`, making retry cleanup idempotent. `write_secret_file` now stages a unique restricted file and uses the shared atomic replace primitive, including overwrite on Windows.
- Certmesh destroy loads/reconciles the ownership ledger and removes the TOTP slot before deleting the slot table or clearing live state. A deterministic invalid-ledger regression proves destroy retains the file and returns an error instead of forgetting credentials.
- Fake store/persistence tests cover seal failure, persistence before seal, failed initial commit, failed replacement commit with the old slot retained, interrupted post-commit cleanup, deletion retry, exact replacement/removal, and foreign-label rejection. Every real-store test has an exact-label `Drop` guard; real replacement, remove, isolation, and destroy paths are included.

### Windows credential-store proof (`.tmp/ph001-credential-20260902T173700Z`)

The first external inventory found 24 stale hashed entries from pre-fix test runs. The installed product had no slot table, so those exact 24 TOTP labels were removed without touching foreign credentials; the clean baseline was zero. One non-elevated serial workbook then ran the complete 19-test unlock-slot suite three times and compared the full sorted target set after each iteration, followed by the real-store certmesh-destroy test. Every checkpoint returned to the exact zero baseline; the subsequent full locked workspace suite also left zero hashed TOTP and zero TPM-test entries.

The same workbook installed the exact release candidate. Its first elevated invocation was deliberately/accidentally interrupted by PowerShell output handling immediately after service stop; the armed v2 manifest retained the old binary and the next invocation recovered it to PID `24008`. A wrong operator-name input then failed before installation and rolled back to the healthy old PID `8540`. With the recorded SID supplied, the ordinary upgrade succeeded at PID `18300`. Final independent inspection after 12 seconds proved candidate hash equality, one healthy process, credential baseline zero, and no manifest/backup residue.

Next dependency-ready assignment: dispatch item 3, the shifted-port ADR-040 pipe path and installed workbench fresh-login/tray/notification/Phone/Pond/lock-resume/upgrade/uninstall-reinstall gates.

## 2026-09-02 (7) — PH-001 typed firewall adapter and legacy recovery boundary closed physically

commit: this commit, on top of `4a8f441` | gates: fmt clean; strict `koi-serve` + `koi-net` clippy clean; shared dependency architecture gate green; adapter suite 8 passed / 1 live NetSecurity facility test ignored in the normal suite and passed explicitly; Windows platform suite 8 passed; full locked workspace suite green; release SHA-256 `7827d4c764e7c00e83c29c32f1c28dbf0dd74f7a734a5d854509a6cf968761b3`; elevated serial workbook `20260902T155528Z-firewall` PASS

koi state now: installed product-path SCM service RUNNING, PID `25736`, canonical descriptor `"C:\Program Files\Koi\koi.exe" --daemon`, installed bytes equal the release candidate, API `127.0.0.1:5641/healthz` 200, six intended Koi-managed firewall rule objects, Pond disabled after its assessment check, exactly one koi.exe, and no SCM manifest, installer backup, rollback probe rule, or test residue.

### One firewall boundary

- `koi-serve::windows_firewall` is now the single typed adapter used by the SCM installer, durable rollback, uninstall, and Pond assessment. NetSecurity inspection/deletion is locale-independent and fail-closed; each rule's application, port, and profile filters stay correlated. Pond consumes the typed `open | inactive | blocked` verdict instead of owning a second PowerShell seam.
- Deletion returns `Removed | Absent | error`. Replacement never adds after a failed delete; rollback validates the complete snapshot, removes every target display name before the first recreation, and preserves multiple prior same-name rules without accumulating duplicates. Install, rollback, and uninstall propagate query/delete/add errors rather than warning or reporting false success.
- The transaction wire accepts the actual v1 JSON shape from `a34be05`, including absent `descriptor` and absent firewall `profile`. Legacy SCM fields still rebuild the prior descriptor. An armed v1 transaction with any profile-less rule now stops before file, SCM, or firewall mutation and reports that the manifest/backups were retained; no code invents `Any`. A v1 transaction with no firewall state remains recoverable because its prior semantics are provable.
- Regressions cover raw legacy JSON, nonzero command failure, command-spawn failure, `Removed` versus `Absent`, delete-before-add ordering, pre-command profile refusal, correlated assessment, complete v2 parsing, and duplicate-name restoration ordering/profile exactness. The live ignored adapter test also enumerated the real Windows Firewall successfully.

### Physical firewall rollback (`.tmp/ph001-firewall-20260902T155528Z`)

One elevated PowerShell workbook deployed the exact release candidate, changed only the installed firewall baseline by making `Koi Pond (TCP 5644)` Private-only, captured the complete typed rule set, armed an authentic v2 manifest and file backups, then removed all Koi rules and installed one Public-profile probe rule. The candidate's next `install` recovered the transaction before the deliberate invalid-operator refusal: it removed the divergent set, restored the Private-scoped snapshot semantically exactly, removed the probe, restarted and image-verified the installed SCM service, passed health, and committed the manifest/backups. The subsequent ordinary install restored the intended managed baseline.

Because Pond's implementation seam changed, the same workbook performed only its affected assessment slice: enabled the already-published Pond surface, observed `desired=true`, `running=true`, firewall `open` through the shared adapter, then disabled it again. The earlier peer/public-route and cooperative-DNS journeys were not repeated. Independent final inspection proved PID `25736`, one product-path process, candidate hash equality, six intended managed rules, Pond disabled, and zero manifest/backup/probe residue.

Next dependency-ready assignment: `fleet/windows/issues/002-credential-store-test-leak.md`, owned as a shared slot-lifecycle defect per dispatch item 2.

## 2026-09-02 (6) — PH-001 interruption-safe SCM recovery and profile-exact firewall rollback closed physically

commit: this commit, on top of `05b66a4` | gates: fmt clean; strict koi binary clippy clean; focused Windows platform suite 12 passed / 1 live-facility test ignored; full locked workspace suite green; release candidate SHA-256 `684a87fe4f6d4c3cac45ba57ae1430a033d17b134841112de2abad7785f4e6c3`; elevated serial workbook `20260902T134536Z-scm` PASS

koi state now: installed product-path service RUNNING, PID `7744`, canonical descriptor `"C:\Program Files\Koi\koi.exe" --daemon`, installed bytes equal the release candidate, API `127.0.0.1:5641/healthz` 200, standard managed firewall state restored, exactly one koi.exe, and no SCM transaction manifest, installer backup, probe rule, SYSTEM recovery task, or recovery-copy residue.

### Transaction closure

- Manifest version 2 captures a complete UTF-16 SCM descriptor (executable, lossless quoted arguments, display name, service type, start type, error control, dependencies, and account); v1 manifests remain recoverable. A same-name noncanonical service fails closed instead of being adopted.
- Every recovery-state transition is fallible and durable before its external mutation. `set_http_port`, firewall-rule intent, and service-creation intent can no longer advance memory after a failed manifest write. Stop/update/restore and lifecycle-policy calls no longer discard errors.
- Delete/recreate closes all service handles before waiting for SCM deletion. Recovery recreates an expected-but-missing prior service from the complete descriptor, reapplies description/failure actions/non-crash policy/log directory, and verifies SCM Running + nonzero PID + canonical process image before `/healthz` and commit.
- Windows command lines are split through `CommandLineToArgvW`, preserving embedded spaces and quoted arguments. The installed process image is measured with `OpenProcess` + `QueryFullProcessImageNameW` rather than inferred from the configured path.
- A physical interruption exposed one earlier boundary: the CLI parsed the transaction-owned, deliberately corrupted config before entering installer recovery. Windows install now performs durable recovery from the CLI/environment-selected data root before normal config-file parsing, then retains the in-installer check for custom roots.

### Physical interruption and rollback (`.tmp/ph001-scm-20260902T134536Z`)

One elevated PowerShell workbook armed a ten-minute SYSTEM recovery action before mutation; captured the installed binary/config/operator policy, complete SCM registration, and all Koi-owned firewall semantics; made the Pond rule Private-only; then stopped Koi, changed its launch descriptor to include a quoted spaced argument, corrupted all three backed-up files, removed the owned firewall rules, added a probe rule, deleted the SCM service, and waited for the final handle to drain. The release candidate's next `install`:

1. detected the armed manifest before parsing the corrupted config;
2. recreated the missing canonical service and lifecycle policy;
3. restored exact binary/config/policy bytes and the profile-scoped firewall set;
4. started PID `24792`, verified image `C:\Program Files\Koi\koi.exe`, and passed health before removing recovery state;
5. entered a second transaction with deliberately invalid `--operator not-a-sid`, refused it nonzero, and restored the prior service again (PID `8536`) with no residue.

Assertions then proved one running process, byte-identical files, semantically identical typed firewall rules including the Private-only Pond profile, probe removal, no manifest/backups, and health 200. A final valid install restored the intended managed `Any` profile state and candidate bytes (PID `7744`). The workbook removed its scheduled task and recovery copies; an independent `schtasks /Query` returned not found.

### Firewall rollback closure and residue

- NetSecurity enumeration now fails closed (`$ErrorActionPreference='Stop'` plus per-cmdlet `-ErrorAction Stop`) and correlates each rule with its own application, port, and profile filters. The typed snapshot preserves enabled/direction/action/protocol/ports/program/profile.
- Restore maps PowerShell `Inbound`/`Outbound` to valid `netsh dir=in/out`, preserves profile scope instead of widening to all profiles, and propagates recreation failures. Deterministic tests pin the vocabulary and profile behavior; the physical Private-only rollback proves semantic equality.
- The shared-adapter consolidation between installer snapshot/restore and Pond assessment remains the next Windows code seam. `issues/001-scm-service-object-wedge.md` remains open for the original transient mechanism; this run closes expected-missing recreation, not the unknown wedge cause.

## 2026-09-02 (5) — PH-001 dispatch 2: firewall facts locale-independent and executable/profile-scoped; Pond and cooperative DNS closed physically

commit: this commit, on top of ee76cac | gates: fmt/clippy `-D warnings` clean, koi-net platform suite 8/8 plus the live NetSecurity-enumeration ignored test, full workspace suite green after the credential-store remediation below; deployed through the transactional installer

koi state now: installed service RUNNING, PID `9952`, `C:\Program Files\Koi\koi.exe --daemon`, binary SHA-256 `97000bb3d4e72a3edc4d098518aea99b69f454f98717c6cd4867db7f465e131c` (the final tree build), API `127.0.0.1:5641` healthy on standard ports, baseline mDNS composite, one permanent self-publication, exactly one koi.exe, Pond **disabled** (baseline restored: desired=false, socket closed, peer-refused verified), DNS incumbent posture unchanged (ICS SharedAccess Running, adapter DNS `192.168.1.1`, daemon holds 53 cooperatively).

### Code (dispatch item 2, first half)

- **Pond firewall applicability** (epic immediate item 5): the Windows assessment now requires the managed rule to be enabled/inbound/allow AND scoped to the **running executable** (exact program-path filter) AND to cover **every active network category** (`Get-NetConnectionProfile` vs the rule profile set) — a display-name match alone is no longer an open-path verdict; uncovered profiles report `blocked` with the precise reason.
- **Installer rollback snapshot is locale-independent**: the Koi-owned rule enumeration switched from parsing localized `netsh` labels to a `NetSecurity` (`Get-NetFirewallRule` + filters) `ConvertTo-Json` pipeline with a single constant for the managed prefix; still fail-closed on unparseable output. New tests cover the single-object/array JSON shapes and missing-field refusal; a live ignored test enumerates the real store.

### Physical: Pond gate closed through the one installed service (peer = test-01)

Publish (`PUT /v1/ui`, 5 fixed files) → arm (`PUT /v1/pond`) → **running** on the derived fourth port `5644`, firewall verdict `open` under the hardened assessment → `netstat`: 5644 is the only new listener; the operator adapter stays on its configured bind → peer opened **all nine public routes 200 with byte-exact sizes** (/, 4 assets, /healthz, /v1/status, /v1/mdns/browser/snapshot, /v1/dns/entries) and every excluded route 404 (PUT/GET /v1/pond, PUT /v1/ui, /openapi.json) → explicit stop (DELETE) → peer connection refused + socket closed → re-arm → **full SCM stop/start cycle → Pond self-restored from persisted desire without any workbench** → final stop → baseline disabled, peer-refused re-verified. (Breadcrumb format note for future runs: the line is `endpoint` + `dat:<token>`; the pond operator routes take `x-koi-token`, not Bearer.)

### Physical: cooperative DNS against the real incumbents (peer = test-01)

`dig @192.168.1.137` from the peer: mDNS-bridged `test-03.local` answered **192.168.1.221 over both UDP and TCP** (served from Koi's mDNS cache, not the peer's own resolver); the `.internal` zone answered authoritatively (`stone-leaded-sparkle.internal` → 192.168.1.137); unknown names return a clean empty/NXDOMAIN shape. ICS (`SharedAccess`) stayed Running, the Ethernet adapter DNS stayed `192.168.1.1`, and no resolver/adapter policy was touched — the daemon holds 53 cooperatively (only koi holds TCP+UDP 53 this boot; earlier boots saw ICS with reuse semantics).

### Windows-gate catch: credential-store quota exhaustion (`issues/002`)

The full suite began failing deterministically in `koi-crypto::unlock_slots` (`CredWriteW` → Windows error 8). Root cause: **576 leaked `koi-certmesh-*` credentials** from repeated slot-table test runs had exhausted the user's credential-store quota; `keyring` has no enumeration API, so stranded labels are unreachable to product code. Deleted exactly the leaked labels (git push credential and all foreign entries untouched; the deterministic `koi-vault-master` label left in place) → suite green immediately. Test-hygiene fix candidates filed as `fleet/windows/issues/002-credential-store-test-leak.md`.

### Residue / next

1. Dispatch item 3 remainder: shifted-port ADR-040 pipe path + installed workbench tray/notification/Phone/Pond gates (operator-present session).
2. Dispatch item 4: cross-host mDNS/NIC/profile/lock/sleep coordination with CachyOS/Alpine peers.
3. `issues/002` for the shared crate owner; `issues/001` wedge mechanism remains open (signature-keyed recovery armed).


## 2026-09-02 (4) — PH-001 dispatch 1: SCM lifecycle hardened; wedge reproduction attempted; destructive transaction re-proven

commit: this commit, on top of 27b3d03 | gates: fmt/clippy `-D warnings` clean, koi-net platform suite 7/7 (incl. new `launch_command_lines_split_into_semantic_parts`), full build deployed through the product path; every physical claim below ran on the one installed service

koi state now: installed service RUNNING, PID `7444`, `C:\Program Files\Koi\koi.exe --daemon`, binary SHA-256 `d135a9fbddd713f0de12e8adf1a7836910ba66844486ff1be3ae47eb1d5e9df5` (the hardened tree build), API `127.0.0.1:5641` healthy on standard ports, baseline mDNS composite, one permanent `_mcp._tcp` self-publication peer-resolved by test-01 during the session, exactly one koi.exe, no manifest/backups/firewall residue.

### Wedge reproduction (issues/001) — not reproducible on demand

Six controlled experiments with raw SCM operations (no installer in the loop): plain stop/start; raced stop/start (surfaced rc 1056 already-running — the exact case `start_with_retry` tolerates); crash-loop exhaustion of an instant-exit binary with byte swap-back; good-byte swap during the SCM's 5 s restart delay; rename-replace staging (`Move-Item -Force`, the installer's `MoveFileEx` shape) with a broken binary; failure-actions-set + rename-replace. **None wedged.** Every staged variable from the original incident was exercised; the wedge remains a transient SCM-internal launch denial (sticky per service object). Verdict and matrix recorded in the issue. Consequence per the dispatch: the delete/recreate fallback keys on the physically observed *signature* (restored registration + verified bytes + persistent raw `ERROR_ACCESS_DENIED` at start), never on a mechanism guess, and never with a partial descriptor.

### Architecture hardening landed (dispatch items, in order)

1. **Durable recovery arms before the first service stop**: the manifest (with the fail-closed service snapshot and file backups) is written before the service is touched. The port decision reads the config substrate pre-stop (decisions need no probe); the probe runs only after the replaced daemon has stopped, and the manifest's health-check port is updated durably (`set_http_port`) when the plan shifts. The stop itself moved inside the mutation closure.
2. **Service inspection fails closed**: a transient SCM error during snapshot capture aborts the install; only a decisive "service does not exist" records `existed: false` (a guessed false would have made rollback *delete* a healthy registration).
3. **Semantic SCM configuration**: the snapshot stores binary and arguments separately (`split_launch_command`, quoted-path aware); restore rebuilds a proper descriptor (`restored_service_info`) instead of treating the whole command line as a path. Unit-tested; empty snapshot descriptors refuse to act.
4. **Manifest/backups retained until proven**: restore now restarts the registration and requires `/healthz` *before* removing the manifest and backups — an incomplete restoration stays recoverable by the next `koi install`.
5. **Gated delete/recreate fallback** in restore: on the wedge signature with a complete descriptor, the service object is recreated and held to the same start+health gate (see issue for the evidence basis).

### Physical proof

Hardened installer upgrade: clean (PID 24356 → final 7444 after the destructive leg). **Destructive failed-candidate transaction re-run** (fresh broken build `7e7bf2f7` carrying the same hardened installer): health gate failed → rollback completed fully for the first time — byte-exact restore (`d135a9fb` back), restart, healthz pass, *then* manifest removal; exit non-zero with "installation failed and the previous Koi installation was restored"; zero residue. A plain `koi install` on top re-verified healthy. This closes dispatch item 3's first half.

### Residue / next

1. Dispatch item 2: firewall snapshot/applicability independent of localized `netsh` labels (the parser is English-locale fail-closed today); Pond + cooperative DNS through the one installed service.
2. Dispatch item 3 remainder: shifted-port ADR-040 pipe path and the installed workbench's tray/notification/Phone/Pond gates (operator-present).
3. Dispatch item 4: cross-host mDNS/NIC/profile/lock/sleep coordination with CachyOS/Alpine peers.
4. issues/001 stays open for the wedge *mechanism* (signature-keyed recovery is armed; a future occurrence should now self-heal and be visible in the service log).


## 2026-09-02 (3) — PH-001 brief 3: authenticated local control physically closed under the installed service

commit: this commit, on top of 9a4e0ee | gates: fmt/clippy green on the changed example; every assertion below ran against the one installed service through its real named pipe; no product code changed — the ADR-040 implementation on `dev` was complete, this session closed its physical gates

koi state now: installed service RUNNING, PID `13384`, `C:\Program Files\Koi\koi.exe --daemon`, binary SHA-256 `fb8fa50c07a2cb0223366be9c7fe08c3c17caa0faa6aa3309c7fea91ca01bca1` (current-`dev` tree build, deployed through the transactional installer — an unplanned but real second in-place upgrade exercise), API `127.0.0.1:5641` healthy, standard ports, baseline mDNS composite (`publish=native`, browse/resolve `windows-dns-sd`), one permanent `_mcp._tcp` self-publication peer-resolved by test-01 during the session, operator SID `S-1-5-21-…-1001` recorded, exactly one koi.exe, no test residue (temp account deleted, public evidence file removed, breadcrumb restored).

### Gates closed (new `win32_local_control_probe` lab example; DAT never printed, only its length)

1. **Operator access over the pipe** — `access` hand-off returned endpoint (`http://127.0.0.1:5641`), DAT (len 43), and the resolved data root (`C:\ProgramData\koi`) without reading the owner-private breadcrumb. `info` returned data root + active config path. Explicit DACL in force per code: `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<operator SID>)` with `reject_remote_clients` and a post-connect peer-token SID check.
2. **Wrong unelevated account denied** — temp local user `koi_negtest` (created, exercised, deleted in one elevated script; `net user` confirms gone) running the probe's `expect-denied` phase got `Access is denied (os error 5)` at pipe open: the DACL rejects before any bytes are answered. Evidence captured via the probe's own cross-account evidence file (`C:\Users\Public`, removed after). Two infrastructure notes for the record: `schtasks /run` for a fresh local user never left state 0x41303 on this workstation, and `Start-Process -Credential` with output redirects deadlocks — the credential launch without redirects + self-evidencing probe is the working pattern.
3. **Breadcrumb is not a dependency** — with `C:\ProgramData\koi\koi.endpoint` renamed away, `koi status` and `koi mdns admin status` both returned full live daemon state through `KoiClient::from_local()`'s authenticated pipe path (ladder, generation 1, provider facts); breadcrumb restored by the same script.
4. **Broken client connection drains session registrations** — probe child registered a service over the pipe (admin status alive 1→2), died abruptly without goodbye after a 3 s hold, and the daemon drained the dead session back to baseline (alive→1) well inside the 25 s window. The register itself also proves mDNS session mutations through the pipe.

### Finding worth recording

The first `info` attempt fell through to the mDNS dispatcher with a parse error — the running daemon (built from pre-rebase `dev`) predated the `Info` variant (`c8b7887`, which landed during the Bluefin push wave). Not a defect: correct behavior for an older daemon meeting a newer client; resolved by upgrading the service to current `dev` through the transactional installer (which is exactly the seam ADR-040's versioned contract exists for).

### Residue / next

1. Brief 4 — Pond firewall applicability (executable/port/direction/action/active-profile facts) and cooperative DNS against the real port-53 incumbent.
2. The workbench-side leg of ADR-040 (tray posture, pond publish via the pipe-obtained URL) rides the koi-desktop install gate — operator-present session.
3. Remaining from earlier: `issues/001` SCM-wedge repro; two-host mDNS transition; sleep/resume matrix.


## 2026-09-02 (2) — PH-001 brief 2: transactional product-path SCM install; rollback exercised physically, port-planning and SCM-wedge defects found

commit: this commit, on top of c658cde | gates: fmt/clippy `-D warnings` clean, full `cargo test --locked` green, release `koi-net` built and deployed through the new installer itself; all acceptance through the one installed service

koi state now: **the installed service runs from the product-owned path** — `koi.service` RUNNING, PID `7712`, `BINARY_PATH_NAME : "C:\Program Files\Koi\koi.exe" --daemon`, binary SHA-256 `9104ca7bd8f25d8d7f95af5fe808ad95590dda3c45ee391c207b84791075e5fe` (byte-equal to the tree build; the checkout exe is no longer referenced by SCM), API `127.0.0.1:5641` healthy on the **standard** port run `5641:5642:5643:5644`, control plane gen 1 `ready` with the baseline composite (`publish=native`, browse/resolve `windows-dns-sd`), one desired/established permanent `_mcp._tcp` self-publication peer-resolved by test-01 during the session, config substrate back to its pre-session shape (operator's `http_bind = "0.0.0.0"` preserved, no port overrides), operator SID recorded in `state/local-access.json` (`S-1-5-21-…-1001`), exactly one koi.exe process, no transaction manifest or installer backups left, Koi firewall rules exactly the managed standard-port set (this session's shifted-run residue `Koi HTTP (TCP 5651)`/`Koi Pond (TCP 5654)` deleted; pre-existing legacy `Koi Web UI (tcp 5641)` left for operator-gated cleanup).

### What landed (brief assignment 2 / epic immediate item 4)

`koi install` on Windows is now a durable transaction mirroring the systemd recipe (`c83c01b`): binary staged to a **fixed product path** `%ProgramFiles%\Koi\koi.exe` (never the checkout the installer ran from — SCM no longer points into `target\`), prior **binary + service config (launch command/start type via ChangeServiceConfig, no delete/recreate gap) + operator policy + config substrate + exact Koi-owned firewall rules** are snapshotted to `<data>\state\scm-install-transaction.json` before the first mutation and roll back together when any step fails — including the health gate, which now **fails the install** (exit non-zero) instead of printing "NOT answering yet" and reporting success. Interrupted installs recover on the next run (Preparing/Armed manifest phases). `koi uninstall` removes the product binary, its directory when Koi-owned, and any manifest residue. Firewall snapshot parsing is fail-closed (an unparseable Koi rule aborts before mutation; noted locale limitation). 6 new unit tests (product path, netsh block parsing, fail-closed missing fields, start-type round-trip, manifest serde round-trip).

### Physical exercise (one installed Koi throughout)

1. **Real migration**: ran the new installer from the checkout against the standing checkout-registered service → in-place upgrade to the product path, healthz green, transaction committed clean (no manifest/backups).
2. **Port-planning defect caught by that run**: the healthy 5641 machine was shifted to `5651:5654` because ADR-036 port planning ran **while the old service still held the standard trio** (the old installer had the same latent order; no prior install ever ran against a live holder). Fixed: capture the pre-stop snapshot, stop the service being replaced, then plan. Machine restored to the standard run; the appended port block was removed from `config.toml` (operator's `http_bind` untouched; backup in `.tmp/config-with-shifted-ports.toml`).
3. **Failed-health rollback**: built a deliberately broken daemon (`run_service` exits before reporting; scratch git worktree, no product-code test hook) containing the same transactional installer, ran its `install` elevated → staging + start + health gate failed → rollback restored the prior binary **byte-exact** (hash-verified), config/policy/service config intact, manifest and backups gone, exit non-zero with the honest restoration message.
4. **Second rollback + the wedge**: re-ran with a start-retry build (first run exposed that a one-shot restart raced SCM recovery timing). The restart was still denied — and stayed denied for every later start: the SCM had **wedged the `koi` service object** (event 7000 access-denied per launch) while the identical binary at the identical path ran fine as a freshly created throwaway service. Sane DACL/registry/file ACLs/binary verified; remedy proven: `reg export` backup → `sc delete koi` → `koi install` fresh-install path → RUNNING, healthy, peer-visible. Filed as `issues/001-scm-service-object-wedge.md` (mechanism needs a controlled repro before any automatic delete+recreate is trusted).

### Defects fixed this session (shared/platform)

- Install exit semantics: success after failed health check (epic item 4 / PH-3 minimum "never report success after a failed start/health check").
- Port planning ordered after the replaced service's stop.
- Rollback restart: bounded retry (`ERROR_SERVICE_ALREADY_RUNNING` tolerated) and `{:?}` error formatting so raw OS codes survive reporting.
- `persist_plan` annotated for the Windows target (only the non-transactional recipes use it).

### Residue / next

1. `issues/001-scm-service-object-wedge.md` — repro + automatic last-resort recreation design.
2. Brief 3 (pipe DACL/wrong-user closure — ADR-040 already records the operator SID now), then brief 4 (Pond firewall applicability + cooperative DNS), then the two-host transition run and sleep/resume matrix (operator present).
3. Older rollback chain in `target/` (`koi.exe.pre-adr039`, `koi.exe.pre-ph001`, `koi.exe.a0f502`, `koi.exe.08023f`, `koi.exe.428f13`) now historical — SCM no longer references any of them; prune at leisure.


## 2026-09-02 (1) — PH-001 provider truth: LLMNR inference removed, Bonjour read fidelity completed and physically exercised

commit: this commit, on top of 5c1b96c | gates: fmt/clippy `-D warnings` clean, full `cargo test --locked` green (incl. the 3 real-facility ignored tests run live), release `koi-net` built and deployed through the installed service path; acceptance exercised through the one installed daemon's authenticated API plus the real Bonjour adapter session against the live mDNSResponder; peer evidence from test-01 (Avahi)

koi state now: **installed service runs the PH-001 provider-truth candidate** — `koi.service` Running, PID `12496`, binary SHA-256 `428f138b467c8529b80cbd54b62b753ebd992e7e59fe8e9f5c6644c44cce5283` (deployed file equals the final tree build; intermediate builds `a0f502c6`/`08023fbe` from this session retained in `target/` as rollback material), API `127.0.0.1:5641` healthy, control plane gen 1 `ready` with the baseline composite `publish=native explicit_publish=native browse=windows-dns-sd resolve=windows-dns-sd`, one desired/established permanent `_mcp._tcp` self-publication, zero pending/failed. Apple Bonjour **uninstalled** (baseline restored: service 1060, no dnssd.dll, no Program Files\Bonjour, staged installers removed). Dnscache untouched (protected). One koi.exe process exactly.

### Corrections landed (epic "Immediate correctness work" Windows 1+2)

1. **`EnableMulticast` is not an mDNS fact** (windows_dnsapi.rs). Microsoft's ADMX mapping (`Turn_Off_Multicast` → `Software\Policies\Microsoft\Windows NT\DNSClient!EnableMulticast`, re-verified against learn.microsoft.com this session) documents the value as the **LLMNR** switch. The registry inference is deleted; `configured` is now `NotApplicable` and the detail no longer claims "mDNS multicast enabled". Verified through the deployed service: the pre-fix baseline reported `configured: yes` + "mDNS multicast enabled"; the new candidate reports `configured: notapplicable` with the same routes.
2. **DNSAPI exports narrowed to the read routes** actually called (`Browse/BrowseCancel/Resolve/ResolveCancel/FreeInstance`); the four registration exports are no longer required for a facility that claims browse/resolve only.
3. **Bonjour `kDNSServiceFlagsAdd` was 0x1 — that is `kDNSServiceFlagsMoreComing`** (Apple dns_sd.h: Add = 0x2). The inverted bit misclassified browse adds/removes; never caught because the armed composite routes reads to windows-dns-sd (priority 200 > 150). Fixed, pinned by a unit test against the header values, and physically discriminated: the meta browse now surfaces adds (17 types found on a quiet morning LAN) where the old bit would have turned single-result adds into removes.
4. **Bonjour read fidelity completed**: browse callbacks now retain interface and domain identity (browse-driven resolves resolve on the reported interface and in the reported domain instead of assuming any/local), and every resolve completes through `DNSServiceGetAddrInfo` (IPv4+IPv6, interface-scoped, single-owner connection, acknowledged teardown) so Bonjour-resolved records carry real addresses with `interface_index` — matching Avahi/resolved/native fidelity. Two further defects this exposed and fixed:
   - Direct resolves timed out: `domain_of` returned unqualified `local`; dnssd answers only the qualified `local.` form (browse callbacks deliver `local.` themselves). Fixed + test.
   - dnssd delivers names in `\DDD` **decimal** presentation escapes (`Koi\032MCP\032(test-03)`); every other adapter surfaces real characters, so the hub could not correlate Bonjour records with the same peer's records from other providers. Names are now decoded at the adapter boundary (Resolved, Removed, and meta Found), pinned by tests. First decode attempt assumed octal (`\032`→0x1A) — the live probe's mangled output exposed it; the wire truth (space = 32 decimal) settled it.

### Physical exercise (one installed Koi throughout, no parallel daemon)

- **Deploy**: baseline PID 5380 (SHA `8239719A`, session-3 artifact) → rename-running-image swap → serial Stop/Start cutover → PID 7756 (`a0f502c6`) → post-probe fixes → PID 14512 (`08023fbe`) → cosmetic clippy swap → PID 12496 (`428f138b`, final tree). healthz green at every step; each intermediate retained as rollback material.
- **Bonjour cycle on the final tree** (verified Apple MSIs, hashes match session 2: Bonjour64 `db86c7cc…`, BonjourPS64 `a8f6ced6…`): install (both MSI exits 0) → the installed service promoted live to gen 2 `publish=bonjour` (and post-crash reboot armed gen 1 `publish=bonjour` directly, re-proving boot-time selection) → **`win32_bonjour_session_probe` (new lab example) drove the real `WindowsBonjourAdapter` session against the live mDNSResponder: PASS** — meta browse 17 types, `_mcp._tcp` browse resolved 5 instances with addresses + interface indices (e.g. `test-03` → `192.168.1.221`, `fd1c:…:ea09`, `fe80::…:ea09`, all ifindex 4), direct resolve returned full SRV/TXT/A data with clean names, teardown acknowledged → test-01 resolved the Bonjour-published self-announcement (`stone-leaded-sparkle.local / 192.168.1.137 / 5641` + full TXT; this install registered under the machine name, no `-2` conflict rename) → uninstall (both exits 0) → live degradation to gen 2 `publish=native`, bonjour `unavailable`/no session, desired=established=1, no restart, no strands → test-01 resolved the record again under the native identity.
- **Peer**: test-01 (Avahi) carried every observation; password auth per local/NOTES.md, host key pinned from lab.json.
- **Machine crash mid-session**: the workstation crashed during the first probe run; SCM auto-recovery restarted koi (new PID) and Bonjour auto-started, the worktree survived intact, cargo's crashed artifacts (one corrupt syn rlib, one LNK1207 PDB) were deleted and rebuilt. The post-reboot boot-arming observation above came from this.

### Shared-boundary defects found by the Windows gate (fixed here)

- `koi_common::persist::replace_file` lost races under concurrent writers to one path (`MoveFileExW(REPLACE_EXISTING)` → `ERROR_ACCESS_DENIED`/sharing violation); the pond bundle writer (`koi-serve/src/pond.rs:926`) and `write_json_pretty` share this path. Now retries sharing-class errors for a bounded 2 s window; the pond regression test failed 5/5 before, 8/8 green after.
- `koi_config::local_access` test named a temp directory after the libtest thread name — the module-qualified test path contains `::`, invalid in Windows filenames (`ERROR_INVALID_FILENAME`, deterministic). Uniqueness now derives from pid + nanos like persist's tests.

### Residue / next

1. The two-host installed-service Windows transition run and the sleep/resume + firewall-profile matrix remain (driver-level, operator present).
2. Epic items 3–6 (pipe DACL contract closure, transactional SCM install, Pond firewall applicability, cooperative DNS) are next in the brief's order.
3. `target/` rollback chain now holds `koi.exe.pre-adr039`, `koi.exe.pre-ph001`, `koi.exe.a0f502`, `koi.exe.08023f` — prune at the next accepted baseline.


## 2026-09-01 (3) — candidate deployed through the installed service; first installed-service acceptance evidence

commit: this commit, on top of 007cee4 (single-owner Bonjour connections) | gates: candidate built from the exact `dev` tree (`cargo build --release -p koi-net`), deployed through the product service path, and exercised only through the installed daemon's authenticated API; peer observations from test-01 (Avahi); clippy 0 / 114 tests on the pulled tree before deploy
koi state now: **the installed service runs the ADR-039 candidate** — `koi.service` Running, PID `30148`, binary SHA-256 `8239719A40A963F9281623ECBF767229A1103640F528AF667EB14544B0EC0EB2` (the deployed file equals the tree build), API `127.0.0.1:5641` healthy, control plane `ready` at generation 3, `publish=native explicit_publish=native browse=windows-dns-sd resolve=windows-dns-sd`, one desired/established permanent `_mcp._tcp` self-publication, zero pending/failed. Apple Bonjour uninstalled (baseline). Dnscache untouched (protected).

### Deploy path

- Baseline captured first: old artifact PID `5360`, SHA-256 `3154238B25916F8EBC8D61F4896D22D7F3027033F6BC469DCD7FF612991D8525`, pre-ADR-039 (no `control_plane` field in status).
- The running exe locks its own path, so the swap used the documented NTFS allowance for renaming a running image: rename `target\release\koi.exe` → `koi.exe.pre-adr039` (rollback material, retained), rebuild the candidate in place, then one elevated script (`Stop-Service koi` → `Start-Service`) restarted the unit onto the new binary. Elevated mutations remain single UAC-batched scripts with captured output.

### Acceptance through the one installed service (per the tightened gate)

- `GET /healthz` OK; `GET /v1/mdns/admin/status` returned the structured control plane: generation 1 `ready`, the designed composite `publish=native explicit_publish=native browse=windows-dns-sd resolve=windows-dns-sd`, windows-dns-sd `ready/session ready` with its read-routes-only detail, bonjour `absent`, native ready.
- Peer observation: test-01 Avahi fully resolved the deployed service's `_mcp._tcp` self-announcement (`stone-leaded-sparkle.local / 192.168.1.137 / 5641` + transport/version/path TXT).
- Mutation cycle through the service API: `POST /v1/mdns/announce` (`Koi Service Gate`, id `9082fd66`, heartbeat 90s) → test-01 resolved it fully including `txt pid=30148` → `DELETE /v1/mdns/unregister/9082fd66` acknowledged → test-01 browse returned empty. One operational note: the breadcrumb DAT line carries CRLF on Windows; shell extraction must strip `\r` or every authenticated call 401s.
- **Provider loss / adapter change, live, through the service** (three generations, no Koi restart):
  - gen 1 `publish=native` (Bonjour absent at boot);
  - installing official Apple Bonjour (same verified MSI set) was visible to the running daemon's assessments — **gen 2 promoted publication to `bonjour`**, all three sessions `ready`, and test-01 observed the self-announcement move to the mDNSResponder host identity `stone-leaded-sparkle-2.local`;
  - uninstalling Bonjour (the MSI stops mDNSResponder underneath the service) → **gen 3 failed publication back to `native`**, `desired=1 established=1 pending=0 failed=0`, bonjour `unavailable` with no session, and test-01 observed the record return under `stone-leaded-sparkle.local`. Nothing stranded; no failed count.
- This also exercised the incoming single-owner rework's negative-probe fix in the field: the daemon started with Bonjour absent and still promoted when it appeared, which the old process-lifetime cache would have blocked.

### Platform facts

- **Dnscache is protected**: even an elevated `Stop-Service Dnscache` is refused (`Cannot open Dnscache service`). The dnsapi route's provider-loss path therefore cannot be exercised by stopping the DNS Client on this build; the Bonjour install/uninstall cycle stands in as the adapter-change/loss proof. Brief DNS blips from that path are not a concern.
- test-02 stayed off the LAN (desktop sleep); test-01 carried the Avahi peer role for all observations.
- Remaining toward the full Windows gate: the two-host transition run (needs a second service-deployed Koi or the peer pair used by the Linux run) and the sleep/resume + firewall-profile matrix; both are driver-level exercises for a session with the operator present.

## 2026-09-01 (2) — Bonjour install → validate → provider-loss → uninstall cycle

commit: this commit, on top of 747ad45 | gates: clippy 0 warnings; koi-mdns 110 passed; live cycle exercised with the structured control-plane status probe (`tools/koi-lab/examples/win32_control_plane_probe.rs`); installed koi service (PID 5360) untouched throughout; end state byte-equal to the pre-install baseline
koi state now: installed service unchanged (pre-ADR-039 artifact, healthy, one `_mcp._tcp` self-publication); Apple Bonjour **uninstalled**; no firewall/profile mutations.

### Provenance

- Installer: Apple's official `BonjourPSSetup.exe` v2.0.2 (support.apple.com/en-us/106380 → download.info.apple.com). Authenticode **Valid, CN=Apple Inc.**; SHA-256 `7f1ec347cd429cfb25a34b2147e02231334f28290e0c28be213415b0f99da1a0` matches the microsoft/winget-pkgs manifest for `Apple.BonjourPrintServices 2.0.2.0` exactly.
- The exe wrapper's own `/quiet` path returned MSI 1603 (its bundled Apple Software Update step); the extracted `Bonjour64.msi` + `BonjourPS64.msi` installed cleanly with `msiexec /qn` (one elevated batch). Result: `Bonjour Service` (mDNSResponder) running, 64-bit `dnssd.dll` in `C:\Windows\System32` — found by the adapter's plain DLL-search `LoadLibraryW("dnssd.dll")` candidate path.

### Validation while installed (each UAC step is an SCM mutation, sanctioned for this node)

- Cold plan became the designed three-provider composition: `publish=bonjour, explicit_publish=native, browse=windows-dns-sd, resolve=windows-dns-sd` — all sessions Ready.
- **Bonjour publication is real**: the `publish=bonjour` record was fully resolved by test-01's Avahi (`stone-leaded-sparkle-2.local / 192.168.1.137 / 43201 / TXT source=bonjour-gate phase=adr039`). mDNSResponder registers its own host identity (`-2` suffix, conflict-avoidance against the OS name) — leases must not assume the constructed host survives (dnsapi showed the same class of behavior with `leo-main.local`). test-02 dropped off the LAN mid-test (desktop sleep); test-01 carried the peer role.
- **Provider-loss failover**: stopping `Bonjour Service` mid-registration flipped the adapter's assessment to `availability=unavailable running=no`, and the control plane transitioned `publish: bonjour → native` (generation bump, transition note `reconciling routes to windows-dns-sd+native`) **without a Koi restart**; the record stayed peer-visible, republished under the native host identity. Restarting the service started promotion hysteresis back toward the full composite (`reconciling routes to windows-dns-sd+bonjour+native`).
- **Defect found and fixed by this test**: `DNSServiceRefDeallocate` blocks indefinitely on a connection whose daemon died, freezing the control-plane actor mid-transition ("reconciling" forever). All dnssd deallocations (publication withdraw/drop, browse close, resolve cleanup, failure paths) now run on a helper thread with a bounded wait — a dead daemon costs one leaked helper thread, never a hung actor. This is exactly the class of platform truth the install/uninstall cycle exists to find.
- **Uninstall degradation**: after `msiexec /x` of both MSIs (service stopped and removed, `dnssd.dll` deleted, install dirs removed), a fresh core assessed `bonjour: availability=absent session=None running=unknown` with the precise missing fact, and armed `publish=native` — a full register/establish/withdraw/shutdown lifecycle ran cleanly and the peer resolved the native-published record. End state equals the pre-install baseline.

### Open items (updated from the previous entry)

1. Dnscache responder silence (previous entry, finding 3) still gates dnsapi publication; isolation still needs elevation.
2. Installed-service transition gate still pending the elevated redeploy.
3. ~~Bonjour validation~~ **done this entry** — with the caveat that the full mDNSResponder restart/sleep-resume matrix was exercised only via service stop/start; a longer soak was not run before uninstall.

## 2026-09-01 — ADR-039 Windows leg: Win32 DNS-SD + Bonjour adapters, standalone two-host validation

commit: this commit, based on 340da23 (`8975f43` ADR-039 control plane) | gates: workspace `cargo check` clean; `cargo clippy -p koi-mdns -p koi-compose -p koi-lab --all-targets` 0 warnings; koi-mdns 110 passed / 3 environment-gated ignored; gate binary built and exercised (see below); Linux cross-target check of the changed crates blocked only by `ring`'s C toolchain on this box (no linux-gcc) — the Linux fleet gates cover it
koi state now: unchanged installed `koi` service (PID 5360, LocalSystem, `target\release\koi.exe --daemon`, API on 127.0.0.1:5641) still on the pre-ADR-039 artifact; one healthy daemon, one `_mcp._tcp` self-publication alive and peer-resolvable throughout. No firewall, service-control, or network-profile mutation was applied (an attempted profile flip was refused — shell is not elevated).

### Baseline (measured 2026-09-01, unprivileged)

- Windows 10.0.26200; hostname `stone-leaded-sparkle`; Ethernet 192.168.1.137; **network profile: Public**.
- DNS Client (`Dnscache`) Running/Automatic. `EnableMulticast` unset in both Dnscache Parameters and the Policies key (OS default = enabled).
- Firewall: all three profiles on, default inbound NotConfigured; the OS built-in `mDNS (UDP-In)` Allow rules exist for Private/Domain/Public, scoped to `svchost.exe`/`dnscache`, local port 5353.
- UDP 5353 is shared by three binders: `Dnscache` (PID 3464), the installed `koi` service (PID 5360, mdns-sd), and Chrome's cast responder (PID 14872).
- **Bonjour is NOT installed**: no `Bonjour Service`, no `C:\Program Files\Bonjour`.

### Probe findings (`tools/koi-lab/examples/win32_dnssd_probe.rs`, real dnsapi.dll calls, JSON evidence lines)

1. **Register/deregister are real and acknowledged** under the workstation identity on the Public profile: `DnsServiceRegister` returns `DNS_REQUEST_PENDING` (9506) and the completion callback carries status 0. Names are stable (no auto-rename observed), the instance name must be the **full DNS-SD form** `<label>._<type>._tcp.local`, and the OS **overrides the advertised host** to its own mDNS identity (`leo-main.local`, not `stone-leaded-sparkle.local`). `DnsServiceDeRegister` completes with status 0.
2. **Announcements reach both Linux peers**: test-01 and test-02 Avahi both emitted `+` for every probe registration.
3. **The OS responder answers nothing**: while a dnsapi record was held alive, peers received no SRV/TXT/A answers — not to Avahi multicast resolves, not to QU-flagged queries, not to unicast `dig`, not even for the OS's own `leo-main.local` A record. Cross-checked controls: Windows received test-01's multicast answers fine (3 responses), and the local **mdns-sd** stack answered peers correctly throughout (test-02's Koi fully resolved the installed daemon's `_mcp._tcp` record). Candidate causes (Public-profile suppression, competing local responders) are not isolable without elevation — this box's `sudo` is disabled and the shell is non-admin.
4. **The consumer side is fully functional**: `DnsServiceBrowse` actively queries (it found long-announced `_mcp._tcp` records on test-01/02/03 plus the local daemon), the meta-query `_services._dns-sd._udp.local` enumerates types, and `DnsServiceResolve` returned complete SRV/TXT/A data for a third-party Bonjour-class peer (ZenGarden at .82).

### Implementation

- `crates/koi-mdns/src/windows_dnsapi.rs` — `windows-dns-sd` adapter (priority 200, `Win32DnsApi`). Assesses dnsapi exports, Dnscache state, and multicast policy (read-only SCM/registry queries, cached). Session contributes the **read routes only**: continuous browse (browse+resolve two-step, mirroring mdns-sd's Resolved events), browse-resolves, and direct point resolution; a health task drives `Ready ↔ Recovering` on Dnscache stop/start. Publication is deliberately **not claimed** — finding 3 means the route would strand announcements. This mirrors the resolve1/polkit pattern from ADR-039.
- `crates/koi-mdns/src/windows_bonjour.rs` — `bonjour` adapter (priority 150, `BonjourDnsSd`), full provider minus explicit-address. dnssd.dll is **runtime-loaded** (LoadLibrary + typed bindings; no import library and no load failure when absent); add/remove browse events map to Found/Removed, register/reply and resolve are acknowledged, conflicts map to typed errors. Bonjour is absent here, so `assess` reports `Absent` honestly and the session paths are real-but-unexercised — validation is pending a genuinely installed Bonjour (ignored tests included).
- Composition (`koi-compose/src/mdns.rs`) lists both ahead of the reserved native provider. The armed plan on this box is the designed composite: **`publish=native, browse=windows-dns-sd, resolve=windows-dns-sd`**.
- A live defect was caught and fixed during validation: `DnsServiceResolve` requires the full instance name while the control plane hands sessions the bare label — the adapter now joins label+regtype (unit-tested).

### Validation (standalone `koi --standalone mdns …`, artifact `target-gate/release/koi.exe`)

- Standalone core armed `publish=native, browse=windows-dns-sd, resolve=windows-dns-sd` (log line evidence).
- Windows → peers: `koi --standalone mdns announce` published via the native route; test-01's Avahi fully resolved it (`stone-leaded-sparkle.local / 192.168.1.137 / 43191 / "source=win-gate" "phase=adr039"`), test-02's Koi API resolved the same record with full TXT. A pinned-address announcement resolved with the pinned IP. After the acknowledged timeout withdrawal, Avahi emitted the `-` removal on the peer.
- Peers → Windows: `koi --standalone mdns discover` (meta and `_mcp._tcp`) enumerated types and resolved all four LAN Koi records through the dnsapi route; `koi --standalone mdns resolve "Koi MCP (test-02)._mcp._tcp.local"` returned host/IP/port/TXT via `DnsServiceResolve`.
- Peer-side probe evidence retained in this entry; capture files on the peers under `/tmp/win-probe-*.txt`, `/tmp/gate2b.txt`.

### Open items (honest residue)

1. **Dnscache responder silence** (finding 3) is the one defect blocking `windows-dns-sd` from claiming publication. Isolation needs elevation (flip the profile to Private, stop Chrome/koi responders, or capture 5353 with pktmon). If a probe proves peers can resolve dnsapi records, the descriptor widens and publication moves to the official API.
2. **Installed-service transition gate**: the deployment still runs the pre-ADR-039 artifact. Redeploying needs elevation (rename-locked-exe + graceful shutdown works only if SCM failure-actions restart; a graceful stop needs `sc start` rights). The two-host installed-service Windows gate (docs/testing/mdns-provider-transition.md adaptation) runs after that.
3. **Bonjour validation** on a host that genuinely has it (install Bonjour Print Services or use a machine with iTunes components).
4. Windows DNS cache serves stale mDNS records after a publisher dies (observed: a withdrawn record still resolved locally from cache until TTL) — platform cache behavior, noted for consumers.
