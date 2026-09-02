# fleet/windows/journal.md — stone-leaded-sparkle (Windows workstation, orchestrator)

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
